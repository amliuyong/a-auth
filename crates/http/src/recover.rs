//! 账户恢复(C9.3,P0.5 硬 gate)HTTP 端点。
//!
//! - `POST /recovery/generate`:已登录用户生成一组一次性恢复码,**show-once** 返回明文(仅此一次,
//!   之后只存 HMAC,不可再取);regenerate 覆盖旧集(旧码失效)。
//! - `POST /recover`:验恢复码 → 原子消费 → **恢复即通知**(旧联系邮箱)→ 建 AS 会话(登入,amr=recovery_code)
//!   → **吊销该 user 所有旧会话**(防旧攻击者会话续用)→ 引导绑新因子(前端 onboarding)。
//!   验码限流(per-user 5 次失败锁 15min)+ user_lookup 定位(码带非秘密前缀,失败也能按 user 锁)。
//!
//! 决策见 [[recovery-codes-design]];docs/DESIGN §7、CONFORMANCE C9.3。纯逻辑在 authn::recovery。

use agent_auth_authn::recovery::{
    code_hash, format_code, parse_code, DEFAULT_CODE_COUNT, SECRET_BYTES,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::login::current_session;
use crate::ports::{
    GraceStore, Notifier, PasskeyStore, PasswordStore, RecoveryAuthorityConsume, RecoveryCodeEntry,
    RecoveryConsumeRequest, RecoveryRecord, RecoveryStore, RecoverySuccessResult, RefreshStore,
    SessionRecord, SessionStore, StoreError, UsersStore,
};
use crate::state::AppState;

const SESSION_TTL_SECS: i64 = 3600;
const SESSION_COOKIE: &str = "__Host-agent_auth_session";
const RECOVERY_RESULT_TTL_SECS: i64 = 60;

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> i64 {
    crate::token::current_unix_secs_pub()
}

/// user_id → 非秘密 lookup(哈希;码带此前缀,让无效码也能按 user 定位限流)。
/// 取 SHA256 前 16 字节(128 bit):作 RecoveryTable 主键,碰撞概率可忽略(避免不同 user
/// 互相覆盖恢复记录,评审 codex#4/Kiro M1);仍为非秘密(不含 secret,不可反推 user_id)。
///
/// **口径单一权威源**:admin disable/delete 级联删恢复码(§1.4)MUST 用同一派生,否则删不到
/// (键=lookup);故 `pub(crate)` 供 admin.rs 复用,不另立第二实现。
pub(crate) fn user_lookup(user_id: &str) -> String {
    let h = Sha256::digest(user_id.as_bytes());
    URL_SAFE_NO_PAD.encode(&h[..16]) // 22 字符,128 bit,够定位、非秘密
}

fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

fn recovery_operation_key(state: &AppState, tenant: &str, operation_id: &str) -> Option<String> {
    let decoded = URL_SAFE_NO_PAD.decode(operation_id).ok()?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != operation_id {
        return None;
    }
    let mut mac =
        HmacSha256::new_from_slice(&state.server_secret).expect("HMAC accepts any key length");
    mac.update(b"recovery-operation:v1\0");
    mac.update(&(tenant.len() as u64).to_be_bytes());
    mac.update(tenant.as_bytes());
    mac.update(&decoded);
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn recovery_session_id(state: &AppState, tenant: &str, operation_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&state.server_secret).expect("HMAC accepts any key length");
    mac.update(b"recovery-session:v2\0");
    mac.update(&(tenant.len() as u64).to_be_bytes());
    mac.update(tenant.as_bytes());
    mac.update(operation_key.as_bytes());
    state.region.issue_id(format!(
        "r1.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn recovery_notification_id(state: &AppState, tenant: &str, operation_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&state.server_secret).expect("HMAC accepts any key length");
    mac.update(b"recovery-notification:v1\0");
    mac.update(&(tenant.len() as u64).to_be_bytes());
    mac.update(tenant.as_bytes());
    mac.update(operation_key.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn recovery_success(session: &SessionRecord, now: i64) -> axum::response::Response {
    let max_age = session
        .expires_at
        .saturating_sub(now)
        .clamp(0, SESSION_TTL_SECS);
    (
        [(
            header::SET_COOKIE,
            set_cookie(SESSION_COOKIE, &session.session_id, max_age),
        )],
        Json(RecoverResult {
            recovered: true,
            next: "bind_new_factor".to_string(),
        }),
    )
        .into_response()
}

async fn replay_recovery_result(
    state: &AppState,
    tenant: &str,
    lookup: &str,
    presented_hash: &str,
    result: RecoverySuccessResult,
    now: i64,
    client_ip: Option<&str>,
) -> axum::response::Response {
    let binding_matches = result.user_lookup == lookup
        && agent_auth_authn::recovery::hash_eq_b64(&result.presented_hash, presented_hash)
        && result.created_at <= now
        && result.expires_at > now
        && state.region.owns_id(&result.session_id);
    if !binding_matches {
        return (StatusCode::BAD_REQUEST, "invalid code").into_response();
    }
    let session = match state.sessions.get(tenant, &result.session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid code").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if session.user_id != result.user_id
        || session.credential_epoch != result.credential_epoch
        || session.created_at != result.created_at
        || session.expires_at <= now
        || !is_recovery_only_session(&session)
    {
        return (StatusCode::BAD_REQUEST, "invalid code").into_response();
    }
    if let Err(gate) = crate::user_gate::require_active_user_epoch(
        state,
        tenant,
        &result.user_id,
        result.credential_epoch,
    )
    .await
    {
        return match gate {
            crate::user_gate::UserGate::Unavailable => {
                audit_recovery_consume(state, tenant, &result.user_id, "failed").await;
                (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
            }
            crate::user_gate::UserGate::Blocked => {
                audit_recovery_consume(state, tenant, &result.user_id, "consumed").await;
                (StatusCode::BAD_REQUEST, "invalid code").into_response()
            }
            crate::user_gate::UserGate::Allowed => unreachable!(),
        };
    }
    match state.passwords.get(tenant, &result.user_id).await {
        Ok(Some(credential))
            if credential.user_id != result.user_id
                || credential.must_change
                || credential.revocation_pending =>
        {
            audit_recovery_consume(state, tenant, &result.user_id, "denied").await;
            return (StatusCode::FORBIDDEN, "password change required").into_response();
        }
        Ok(_) => {}
        Err(_) => {
            audit_recovery_consume(state, tenant, &result.user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    }
    let recovery_recipient = match recovery_contact_email(state, tenant, &result.user_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            audit_recovery_consume(state, tenant, &result.user_id, "failed").await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "contact channel unavailable",
            )
                .into_response();
        }
        Err(_) => {
            audit_recovery_consume(state, tenant, &result.user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    let notification_id = recovery_notification_id(state, tenant, result.operation_key.as_str());

    audit_recovery_consume(state, tenant, &result.user_id, "replayed").await;
    finish_recovery_side_effects(
        state,
        RecoverySideEffects {
            tenant,
            user_id: &result.user_id,
            credential_epoch: result.credential_epoch,
            recovery_recipient: &recovery_recipient,
            notification_id: &notification_id,
            recovered_at: result.created_at,
            client_ip,
        },
    )
    .await;
    if !state.region.owns_id(&result.session_id) {
        return (StatusCode::BAD_REQUEST, "invalid code").into_response();
    }
    recovery_success(&session, now)
}

async fn audit_recovery_consume(state: &AppState, tenant: &str, actor: &str, result: &'static str) {
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::UserCredentialOperation {
                action: "consume",
                tenant,
                actor,
                kind: "recovery",
                target: "self",
                result,
            },
        )
        .await;
}

async fn recovery_contact_email(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<Option<String>, StoreError> {
    Ok(state
        .users
        .get_by_id(tenant, user_id)
        .await?
        .map(|user| user.email)
        .filter(|email| {
            crate::local_identity::is_valid_email(email) && !email.starts_with("user:")
        }))
}

fn recovery_client_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
}

struct RecoverySideEffects<'a> {
    tenant: &'a str,
    user_id: &'a str,
    credential_epoch: u64,
    recovery_recipient: &'a str,
    notification_id: &'a str,
    recovered_at: i64,
    client_ip: Option<&'a str>,
}

async fn finish_recovery_side_effects(state: &AppState, effects: RecoverySideEffects<'_>) {
    if let Err(error) = state
        .notifier
        .notify_recovery(
            effects.tenant,
            effects.notification_id,
            effects.recovery_recipient,
            effects.recovered_at,
            effects.client_ip,
        )
        .await
    {
        eprintln!(
            "RECOVERY_NOTIFICATION_FAILED tenant={} user_id={} error={error:?}",
            effects.tenant, effects.user_id
        );
    }

    // Authority advanced atomically; physical cleanup is best effort and
    // idempotent so a recovered operation may safely resume it.
    let _ = state
        .sessions
        .delete_by_user_before_epoch(effects.tenant, effects.user_id, effects.credential_epoch)
        .await;
    if let Ok(family_ids) = state
        .refresh
        .revoke_by_user_before_epoch(effects.tenant, effects.user_id, effects.credential_epoch)
        .await
    {
        if let Some(grace) = &state.grace {
            for family_id in &family_ids {
                let _ = grace.delete_family(family_id).await;
            }
        }
    }
    crate::user_gate::touch_last_login(
        state,
        effects.tenant,
        effects.user_id,
        effects.recovered_at,
    )
    .await;
}

fn is_recovery_only_session(session: &SessionRecord) -> bool {
    session.amr.len() == 1 && session.amr[0] == "recovery_code"
}

async fn has_non_recovery_factor(
    state: &AppState,
    headers: &HeaderMap,
    tenant: &str,
    user_id: &str,
) -> Result<bool, StoreError> {
    let (password, passkeys) = tokio::join!(
        state.passwords.get(tenant, user_id),
        state.passkeys.list_by_user(tenant, user_id),
    );
    if password?.is_some_and(|credential| !credential.must_change && !credential.revocation_pending)
    {
        return Ok(true);
    }
    if !state.passkey_enabled {
        return Ok(false);
    }
    let Some((current_rp_id, _)) = crate::passkey_flow::rp_id_and_origin(state, headers) else {
        return Ok(false);
    };
    Ok(passkeys?
        .iter()
        .any(|credential| credential.rp_id == current_rp_id))
}

#[derive(Serialize, ToSchema)]
pub struct GenerateResponse {
    /// **show-once**:明文恢复码,仅此一次返回(之后只存 HMAC,不可再取)。请离线保存。
    pub recovery_codes: Vec<String>,
}

/// `POST /recovery/generate`:已登录用户生成一组恢复码(show-once)。
#[utoipa::path(
    post, path = "/recovery/generate", tag = "recovery",
    responses(
        (status = 200, description = "一组一次性恢复码(明文仅此一次返回,请离线保存)", body = GenerateResponse),
        (status = 401, description = "未登录"),
        (status = 403, description = "需要最近五分钟内重新认证"),
        (status = 409, description = "缺少可投递联系邮箱,另一凭据变更已获胜,或轮换会导致无可用非恢复因子"),
        (status = 429, description = "生成频率过高"),
        (status = 503, description = "凭据存储或吊销暂时不可用")
    )
)]
pub async fn recovery_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let (tenant, session) = match crate::account_credentials::require_fresh_session(
        &state, &headers, "rotate", "recovery",
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let user_id = session.user_id.clone();
    let recovery_recipient = match recovery_contact_email(&state, &tenant, &user_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            state
                .audit_credential_event(
                    crate::credential::CredentialAuditEvent::UserCredentialOperation {
                        action: "rotate",
                        tenant: &tenant,
                        actor: &user_id,
                        kind: "recovery",
                        target: "self",
                        result: "denied",
                    },
                )
                .await;
            return (
                StatusCode::CONFLICT,
                [(header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "error": "contact_channel_unavailable" })),
            )
                .into_response();
        }
        Err(_) => {
            state
                .audit_credential_event(
                    crate::credential::CredentialAuditEvent::UserCredentialOperation {
                        action: "rotate",
                        tenant: &tenant,
                        actor: &user_id,
                        kind: "recovery",
                        target: "self",
                        result: "failed",
                    },
                )
                .await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CACHE_CONTROL, "no-store")],
                "user store unavailable",
            )
                .into_response();
        }
    };
    if is_recovery_only_session(&session) {
        match has_non_recovery_factor(&state, &headers, &tenant, &user_id).await {
            Ok(true) => {}
            Ok(false) => {
                state
                    .audit_credential_event(
                        crate::credential::CredentialAuditEvent::UserCredentialOperation {
                            action: "rotate",
                            tenant: &tenant,
                            actor: &user_id,
                            kind: "recovery",
                            target: "self",
                            result: "lockout_prevented",
                        },
                    )
                    .await;
                return (
                    StatusCode::CONFLICT,
                    [(header::CACHE_CONTROL, "no-store")],
                    Json(serde_json::json!({ "error": "last_viable_factor" })),
                )
                    .into_response();
            }
            Err(_) => {
                state
                    .audit_credential_event(
                        crate::credential::CredentialAuditEvent::UserCredentialOperation {
                            action: "rotate",
                            tenant: &tenant,
                            actor: &user_id,
                            kind: "recovery",
                            target: "self",
                            result: "failed",
                        },
                    )
                    .await;
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::CACHE_CONTROL, "no-store")],
                    "credential store unavailable",
                )
                    .into_response();
            }
        }
    }
    // per-user 限流(C9.1 防滥刷生成 + 缓解 CSRF 使旧码失效副作用):键 = 认证后 user_id
    // (session 派生,不可伪造——绝不在鉴权前限流,遵 HIGH#2 keying 铁律)。超额 → 429。
    if crate::ratelimit_gate::recovery_generate_throttled(&state, &tenant, &user_id).await {
        state
            .audit_credential_event(
                crate::credential::CredentialAuditEvent::UserCredentialOperation {
                    action: "rotate",
                    tenant: &tenant,
                    actor: &user_id,
                    kind: "recovery",
                    target: "self",
                    result: "denied",
                },
            )
            .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "too many recovery code generations, please wait",
        )
            .into_response();
    }
    let lookup = user_lookup(&user_id);
    let mut plaintext = Vec::with_capacity(DEFAULT_CODE_COUNT);
    let mut entries = Vec::with_capacity(DEFAULT_CODE_COUNT);
    for _ in 0..DEFAULT_CODE_COUNT {
        let mut secret = [0u8; SECRET_BYTES];
        rand::thread_rng().fill_bytes(&mut secret);
        let code = format_code(&lookup, &secret);
        let hash = code_hash(&state.server_secret, &code);
        entries.push(RecoveryCodeEntry {
            hash_b64: URL_SAFE_NO_PAD.encode(hash),
            consumed: false,
        });
        plaintext.push(code);
    }
    // regenerate 覆盖旧集(旧码失效);清失败计数/锁定。键 = user_lookup。
    let mutation = match crate::account_credentials::begin_credential_mutation(
        &state, &tenant, &session,
    )
    .await
    {
        Ok(mutation) => mutation,
        Err(response) => {
            state
                .audit_credential_event(
                    crate::credential::CredentialAuditEvent::UserCredentialOperation {
                        action: "rotate",
                        tenant: &tenant,
                        actor: &user_id,
                        kind: "recovery",
                        target: "self",
                        result: "failed",
                    },
                )
                .await;
            return response;
        }
    };
    let commit = state
        .recovery
        .commit_rotation(
            &state.users,
            &tenant,
            RecoveryRecord {
                user_lookup: lookup,
                user_id: user_id.clone(),
                activation_id: state.region.issue_id("recovery"),
                code_hashes: entries,
                attempt_count: 0,
                locked_until: 0,
            },
            &recovery_recipient,
            mutation.owner(),
            crate::current_unix_secs(),
        )
        .await;
    match commit {
        Ok(true) => {}
        Ok(false) => {
            state
                .audit_credential_event(
                    crate::credential::CredentialAuditEvent::UserCredentialOperation {
                        action: "rotate",
                        tenant: &tenant,
                        actor: &user_id,
                        kind: "recovery",
                        target: "self",
                        result: "conflict",
                    },
                )
                .await;
            crate::account_credentials::abort_credential_mutation(
                &state, &tenant, &user_id, &mutation,
            )
            .await;
            return crate::account_credentials::clear_session(
                (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": "credential_change_conflict" })),
                )
                    .into_response(),
            );
        }
        Err(_) => {
            state
                .audit_credential_event(
                    crate::credential::CredentialAuditEvent::UserCredentialOperation {
                        action: "rotate",
                        tenant: &tenant,
                        actor: &user_id,
                        kind: "recovery",
                        target: "self",
                        result: "failed",
                    },
                )
                .await;
            crate::account_credentials::abort_credential_mutation(
                &state, &tenant, &user_id, &mutation,
            )
            .await;
            return crate::account_credentials::clear_session(
                (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
            );
        }
    }
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::UserCredentialOperation {
                action: "rotate",
                tenant: &tenant,
                actor: &user_id,
                kind: "recovery",
                target: "self",
                result: "success",
            },
        )
        .await;
    // 明文仅此一次返回;不落日志、不可再取。
    crate::account_credentials::clear_session((
        [(header::CACHE_CONTROL, "no-store")],
        Json(GenerateResponse {
            recovery_codes: plaintext,
        }),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryStatusResponse {
    /// 该登录用户是否已配置恢复码(存在记录且尚有未消费的码)。
    pub configured: bool,
    /// 剩余未消费的恢复码数(供前端提示"仅剩 N 个,建议重新生成")。
    pub remaining: u32,
}

/// `GET /recovery/status`:查**当前登录用户自己**是否已配置恢复码(configured + 剩余数)。
///
/// 补全 /account 恢复码设置区的 UX 闭环:此前前端无从得知用户是否已设恢复,只能无条件显示
/// "生成"按钮。本端点让前端能显示"已配置 ✓ / 剩 N 个 / 未配置"。
///
/// **零跨用户**:仅按调用方 session 派生的 user_lookup 查自己的记录——绝不接受任何用户输入定位
/// 他人,不泄露他人是否配置(与 /recovery/generate 同一鉴权面)。未登录 → 401。
#[utoipa::path(
    get, path = "/recovery/status", tag = "recovery",
    responses(
        (status = 200, description = "该用户恢复码配置状态", body = RecoveryStatusResponse),
        (status = 401, description = "未登录")
    )
)]
pub async fn recovery_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Some((_sid, user_id)) = current_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    let lookup = user_lookup(&user_id);
    match state.recovery.get(&tenant, &lookup).await {
        Ok(Some(rec)) => {
            if !state.region.owns_id(&rec.activation_id) {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "recovery state unavailable",
                )
                    .into_response();
            }
            let remaining = rec.code_hashes.iter().filter(|e| !e.consumed).count() as u32;
            Json(RecoveryStatusResponse {
                configured: remaining > 0,
                remaining,
            })
            .into_response()
        }
        // 无记录 = 未配置(不是错误)。
        Ok(None) => Json(RecoveryStatusResponse {
            configured: false,
            remaining: 0,
        })
        .into_response(),
        // 存储不可用:fail-closed 503(不谎报"未配置"误导用户去覆盖生成)。
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RecoverRequest {
    /// 完整恢复码(`v1.{lookup}.{secret}`)。
    pub code: String,
    /// 每次恢复操作新生成的 32-byte 无填充 base64url 随机标识；瞬时失败重试必须复用。
    pub operation_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct RecoverResult {
    /// 恢复成功已登入;前端应引导绑定新登录因子(邮箱/passkey)。
    pub recovered: bool,
    pub next: String,
}

/// `POST /recovery/verify`:验恢复码 → 消费 → 通知 → 建会话 → 吊销旧会话。
///
/// ⚠️ path 为 `/recovery/verify` 而非 `/recover`:CloudFront 统一入口按 **path**(非 method)选 origin,
/// SPA 页面 `/recover`(可 bookmark)与本"验码动作"若同 path 会冲突 → 动作挂 `/recovery/*` 组避让(spec 025)。
#[utoipa::path(
    post, path = "/recovery/verify", tag = "recovery",
    request_body = RecoverRequest,
    responses(
        (status = 200, description = "恢复成功,已建会话(引导绑新因子)", body = RecoverResult),
        (status = 400, description = "码无效"),
        (status = 403, description = "账户禁用或临时密码尚未更改"),
        (status = 429, description = "验码失败过多,锁定中"),
        (status = 503, description = "恢复存储或账户 authority 暂不可用")
    )
)]
pub async fn recover(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RecoverRequest>,
) -> impl IntoResponse {
    let now = now_secs();
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let client_ip = recovery_client_ip(&headers);
    let operation_key = match recovery_operation_key(&state, &tenant, &req.operation_id) {
        Some(key) => key,
        None => return (StatusCode::BAD_REQUEST, "invalid operation_id").into_response(),
    };
    // 解析码 → user_lookup + secret(码带非秘密前缀,失败也能按 user 定位限流,codex 评审)。
    let Some((lookup, _secret)) = parse_code(&req.code) else {
        return (StatusCode::BAD_REQUEST, "invalid code format").into_response();
    };
    // user_lookup 反查 user_id:P0.5 假用户下,user_id = "user:<email>",lookup 是其短哈希。
    // 我们不反查(单向哈希),而是让 RecoveryStore 按 user_id 存;这里用 lookup 作为 store key 的定位。
    // 简化:store 以 user_lookup 为键存(而非 user_id),消费后从记录取回真实 user_id。
    let presented_hash = URL_SAFE_NO_PAD.encode(code_hash(&state.server_secret, &req.code));
    match state
        .recovery
        .get_success_result(&tenant, &operation_key)
        .await
    {
        Ok(Some(result)) => {
            return replay_recovery_result(
                &state,
                &tenant,
                &lookup,
                &presented_hash,
                result,
                now_secs(),
                client_ip,
            )
            .await
        }
        Ok(None) => {}
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
    let recovery_record = match state.recovery.get(&tenant, &lookup).await {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid code").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if !state.region.owns_id(&recovery_record.activation_id) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery state unavailable",
        )
            .into_response();
    }
    let user_id = recovery_record.user_id.clone();
    let session_id = recovery_session_id(&state, &tenant, &operation_key);
    let notification_id = recovery_notification_id(&state, &tenant, &operation_key);
    let consumed_code = recovery_record.code_hashes.iter().any(|entry| {
        entry.consumed
            && agent_auth_authn::recovery::hash_eq_b64(&entry.hash_b64, presented_hash.as_str())
    });
    if consumed_code {
        match state
            .recovery
            .get_success_result(&tenant, &operation_key)
            .await
        {
            Ok(Some(result)) => {
                return replay_recovery_result(
                    &state,
                    &tenant,
                    &lookup,
                    &presented_hash,
                    result,
                    now_secs(),
                    client_ip,
                )
                .await
            }
            Ok(None) => {}
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
            }
        }
        audit_recovery_consume(&state, &tenant, &user_id, "consumed").await;
        return (StatusCode::BAD_REQUEST, "invalid code").into_response();
    }
    let expected_epoch = match crate::user_gate::active_user_epoch(&state, &tenant, &user_id).await
    {
        Ok(epoch) => epoch,
        Err(crate::user_gate::UserGate::Blocked) => {
            audit_recovery_consume(&state, &tenant, &user_id, "denied").await;
            return (StatusCode::FORBIDDEN, "account disabled").into_response();
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            audit_recovery_consume(&state, &tenant, &user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    };
    let recovery_recipient = match recovery_contact_email(&state, &tenant, &user_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            audit_recovery_consume(&state, &tenant, &user_id, "failed").await;
            eprintln!(
                "RECOVERY_NOTIFICATION_UNAVAILABLE tenant={tenant} user_id={user_id} reason=no_contact_email"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "contact channel unavailable",
            )
                .into_response();
        }
        Err(error) => {
            audit_recovery_consume(&state, &tenant, &user_id, "failed").await;
            eprintln!(
                "RECOVERY_NOTIFICATION_UNAVAILABLE tenant={tenant} user_id={user_id} reason=user_lookup_failed error={error:?}"
            );
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    let credential_epoch = match expected_epoch.checked_add(1) {
        Some(epoch) => epoch,
        None => {
            audit_recovery_consume(&state, &tenant, &user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    let recovered_session = SessionRecord {
        session_id: session_id.clone(),
        user_id: user_id.clone(),
        credential_epoch,
        auth_time: now,
        created_at: now,
        last_used_at: now,
        device: crate::login::session_device(&headers),
        expires_at: now + SESSION_TTL_SECS,
        acr: None,
        amr: vec!["recovery_code".to_string()],
    };
    let success_result = RecoverySuccessResult {
        operation_key,
        user_lookup: lookup.clone(),
        user_id: user_id.clone(),
        presented_hash: presented_hash.clone(),
        credential_epoch,
        session_id: session_id.clone(),
        created_at: now,
        expires_at: now.saturating_add(RECOVERY_RESULT_TTL_SECS),
    };

    let credential_epoch = match state
        .recovery
        .verify_and_consume_at_epoch(
            &state.users,
            &state.passwords,
            &state.sessions,
            RecoveryConsumeRequest {
                tenant: &tenant,
                user_lookup: &lookup,
                user_id: &user_id,
                expected_email: &recovery_recipient,
                expected_epoch,
                presented_hash: &presented_hash,
                now,
            },
            recovered_session.clone(),
            success_result,
        )
        .await
    {
        Ok(RecoveryAuthorityConsume::Valid { credential_epoch }) => {
            audit_recovery_consume(&state, &tenant, &user_id, "success").await;
            credential_epoch
        }
        Ok(RecoveryAuthorityConsume::Replayed { result }) => {
            return replay_recovery_result(
                &state,
                &tenant,
                &lookup,
                &presented_hash,
                result,
                now_secs(),
                client_ip,
            )
            .await
        }
        Ok(RecoveryAuthorityConsume::Locked { retry_after_secs }) => {
            audit_recovery_consume(&state, &tenant, &user_id, "locked").await;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after_secs.to_string())],
                "too many attempts",
            )
                .into_response();
        }
        Ok(RecoveryAuthorityConsume::Invalid | RecoveryAuthorityConsume::NotFound) => {
            // 不泄露账号是否存在:统一 400。
            audit_recovery_consume(&state, &tenant, &user_id, "denied").await;
            return (StatusCode::BAD_REQUEST, "invalid code").into_response();
        }
        Ok(RecoveryAuthorityConsume::PasswordChangeRequired) => {
            audit_recovery_consume(&state, &tenant, &user_id, "denied").await;
            return (StatusCode::FORBIDDEN, "password change required").into_response();
        }
        Ok(RecoveryAuthorityConsume::AuthorityChanged) => {
            audit_recovery_consume(&state, &tenant, &user_id, "conflict").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "account state changed").into_response();
        }
        Err(_) => {
            audit_recovery_consume(&state, &tenant, &user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };

    finish_recovery_side_effects(
        &state,
        RecoverySideEffects {
            tenant: &tenant,
            user_id: &user_id,
            credential_epoch,
            recovery_recipient: &recovery_recipient,
            notification_id: &notification_id,
            recovered_at: now,
            client_ip,
        },
    )
    .await;
    if !state.region.owns_id(&recovered_session.session_id) {
        return (StatusCode::SERVICE_UNAVAILABLE, "recovery state changed").into_response();
    }
    recovery_success(&recovered_session, now)
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(recovery_generate))
        .routes(routes!(recovery_status))
        .routes(routes!(recover))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::{
        MemoryRegionControlStore, RegionAdmission, RegionControlRecord, RegionControlStoreImpl,
        RegionRuntime,
    };

    #[test]
    fn recovery_operation_key_is_canonical_and_tenant_bound() {
        let state = AppState::dev("localhost");
        let operation_id = URL_SAFE_NO_PAD.encode([42_u8; 32]);
        let t1 = recovery_operation_key(&state, "t1", &operation_id).unwrap();
        let t2 = recovery_operation_key(&state, "t2", &operation_id).unwrap();

        assert_ne!(t1, t2);
        assert_eq!(
            t1,
            recovery_operation_key(&state, "t1", &operation_id).unwrap()
        );
        assert!(recovery_operation_key(&state, "t1", &format!("{operation_id}=")).is_none());
    }

    #[test]
    fn recovery_success_result_debug_redacts_replay_bearers() {
        let debug = format!(
            "{:?}",
            RecoverySuccessResult {
                operation_key: "operation-secret".to_string(),
                user_lookup: "lookup-secret".to_string(),
                user_id: "user:test@example.com".to_string(),
                presented_hash: "code-verifier-secret".to_string(),
                credential_epoch: 1,
                session_id: "session-bearer-secret".to_string(),
                created_at: 1_000,
                expires_at: 1_060,
            }
        );

        assert!(debug.contains("user:test@example.com"));
        for secret in [
            "operation-secret",
            "lookup-secret",
            "code-verifier-secret",
            "session-bearer-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[tokio::test]
    async fn expired_recovery_result_cannot_replay_a_session() {
        let state = AppState::dev("localhost");
        let now = crate::current_unix_secs();
        let response = replay_recovery_result(
            &state,
            "",
            "lookup",
            "presented-hash",
            RecoverySuccessResult {
                operation_key: "derived-operation-key".to_string(),
                user_lookup: "lookup".to_string(),
                user_id: "user:test@example.com".to_string(),
                presented_hash: "presented-hash".to_string(),
                credential_epoch: 1,
                session_id: "expired-session".to_string(),
                created_at: now - 60,
                expires_at: now,
            },
            now,
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn recovery_session_is_owned_by_exact_regional_activation() {
        let control = MemoryRegionControlStore::with_record(RegionControlRecord {
            active: true,
            activation_not_before: 0,
            revision: 9,
        });
        let runtime =
            RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(control.clone()))
                .unwrap();
        assert_eq!(
            runtime.admit(crate::current_unix_secs()).await.unwrap(),
            RegionAdmission::Active
        );

        let mut state = AppState::dev("localhost");
        state.region = runtime.clone();
        let session_id = recovery_session_id(&state, "", "presented-hash");
        assert!(runtime.owns_id(&session_id));
        assert_eq!(
            session_id,
            recovery_session_id(&state, "", "presented-hash")
        );

        control
            .set(Some(RegionControlRecord {
                active: true,
                activation_not_before: 0,
                revision: 10,
            }))
            .await;
        assert_eq!(
            runtime.admit(crate::current_unix_secs()).await.unwrap(),
            RegionAdmission::Active
        );
        assert!(!runtime.owns_id(&session_id));
    }
}
