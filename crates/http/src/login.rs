//! magic-link 登录后端(C9.1 发信防滥用 + 短命一次性 / C9.2 login-CSRF)。
//!
//! - `POST /login/magic-link`:per-email 固定窗口冷却(authn::cooldown)→ 生成 session nonce
//!   (存 `__Host-` cookie,绑定发起浏览器)+ magic-link(authn::magic_link,短命一次性,HMAC tag)
//!   → 落 MagicLinkStore → Notifier 发送(dev 打日志/回显链接,**不真发**)。
//! - `GET /login/callback`:校 tag + 过期 + **session nonce 绑定**(login-CSRF C9.2:link 绑定的
//!   nonce 必须 == 打开浏览器 cookie 的 nonce)+ 一次性消费 → 建立 AS 会话 cookie → 回跳续 OAuth 流。
//!
//! Email is a mutable alias. Both request and callback resolve it through UsersStore
//! before consulting canonical-id keyed credentials or creating a session.
//! 决策真相源:docs/DESIGN §7;docs/CONFORMANCE C9.1·C9.2。

use agent_auth_authn::cooldown::{check as cooldown_check, CooldownConfig, CooldownDecision};
use agent_auth_authn::magic_link::{compute_tag, open as open_link, MagicLink, OpenError};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Redirect},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    MagicLinkRecord, MagicLinkStore, Notifier, PasswordStore, SessionRecord, SessionStore,
    UserStatus, UsersStore,
};
use crate::state::AppState;

const COOLDOWN_SECS: i64 = 60; // per-email 冷却窗口(C9.1)
const LINK_TTL_SECS: i64 = 600; // magic-link ≤10min(§2.1)
pub(crate) const SESSION_TTL_SECS: i64 = 3600; // AS 会话有效期
/// 发起会话 nonce cookie(login-CSRF 绑定,C9.2)。`__Host-` 前缀 + HttpOnly/Secure/SameSite=Lax。
const NONCE_COOKIE: &str = "__Host-agent_auth_login_nonce";
/// AS 已认证会话 cookie。
pub(crate) const SESSION_COOKIE: &str = "__Host-agent_auth_session";

pub(crate) fn rand_id(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn now_secs() -> i64 {
    crate::token::current_unix_secs_pub()
}

async fn audit_magic_link_authentication(
    state: &AppState,
    tenant: &str,
    user_id: Option<&str>,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant,
            user_id,
            crate::security_event::AuthenticationMethod::MagicLink,
            outcome,
        ))
        .await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalSessionMethod {
    Password { credential_version: u64 },
    MagicLink,
}

impl LocalSessionMethod {
    fn amr(self) -> &'static str {
        match self {
            Self::Password { .. } => "pwd",
            Self::MagicLink => "email",
        }
    }

    fn security_method(self) -> crate::security_event::AuthenticationMethod {
        match self {
            Self::Password { .. } => crate::security_event::AuthenticationMethod::Password,
            Self::MagicLink => crate::security_event::AuthenticationMethod::MagicLink,
        }
    }
}

async fn magic_link_session_allowed(state: &AppState, tenant: &str, user_id: &str) -> bool {
    match state.passwords.get(tenant, user_id).await {
        Ok(None) => true,
        Ok(Some(credential)) => {
            credential.user_id == user_id
                && !credential.must_change
                && !credential.revocation_pending
        }
        Err(_) => false,
    }
}

async fn password_session_allowed(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    expected_version: u64,
) -> bool {
    match state.passwords.get(tenant, user_id).await {
        Ok(Some(credential)) => {
            credential.user_id == user_id
                && !credential.must_change
                && !credential.revocation_pending
                && credential.version == expected_version
        }
        Ok(None) | Err(_) => false,
    }
}

pub(crate) async fn establish_local_session(
    state: &AppState,
    tenant: &str,
    user_id: String,
    authorize_query: &str,
    method: LocalSessionMethod,
    device: String,
) -> Result<String, ()> {
    let now = now_secs();
    let credential_epoch = crate::user_gate::active_user_epoch(state, tenant, &user_id)
        .await
        .map_err(|_| ())?;
    let session_id = state.region.issue_id(rand_id(32));
    state
        .sessions
        .create(
            tenant,
            SessionRecord {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                credential_epoch,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device,
                expires_at: now + SESSION_TTL_SECS,
                acr: None,
                amr: vec![method.amr().to_string()],
            },
        )
        .await
        .map_err(|_| ())?;

    // Close the create-session/delete-user interleaving. If delete won before
    // this strong read, remove the just-created session. If delete wins after
    // this read, its strongly consistent cascade observes the session.
    match crate::user_gate::require_active_user(state, tenant, &user_id).await {
        crate::user_gate::UserGate::Allowed => {}
        crate::user_gate::UserGate::Blocked | crate::user_gate::UserGate::Unavailable => {
            let _ = state.sessions.delete(tenant, &session_id).await;
            return Err(());
        }
    }

    // Linearize session creation against credential provisioning/reset. If the
    // credential changed after authentication, remove this newly created
    // session; otherwise reset's later session cascade observes it.
    let credential_allows_session = match method {
        LocalSessionMethod::Password { credential_version } => {
            password_session_allowed(state, tenant, &user_id, credential_version).await
        }
        LocalSessionMethod::MagicLink => magic_link_session_allowed(state, tenant, &user_id).await,
    };
    if !credential_allows_session {
        let _ = state.sessions.delete(tenant, &session_id).await;
        return Err(());
    }

    // The authorization session is observability state. Its projection must
    // not turn a completed authentication into a failed login.
    if let Some(authz_session_id) = authorize_query
        .split('&')
        .find_map(|part| part.strip_prefix("authz_session_id="))
        .filter(|value| !value.is_empty())
    {
        if crate::authz_session::bind_user(state, tenant, authz_session_id, &user_id).await {
            crate::authz_session::transition(
                state,
                tenant,
                authz_session_id,
                agent_auth_authn::authz_session::AuthzState::PendingConsent,
                None,
            )
            .await;
        }
    }
    crate::user_gate::touch_last_login(state, tenant, &user_id, now).await;
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant,
            Some(&user_id),
            method.security_method(),
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;
    Ok(session_id)
}

/// 登录后 `next` 回跳的 open-redirect 防护(spec 003 §"登录后 next 回跳",P0.5)。
///
/// `next` 只承载 **AS 自己前端的同源相对路径**(如 `/approve?auth_req_id=…`);任何可能被浏览器解析成
/// 跨域的形态一律 **fail-closed 丢弃**(返 `None`,调用方回落默认目标),绝不据以重定向到外部站点。
/// 校验点在**兑现回跳时**,不信任请求侧输入。判定(全部 MUST 通过才放行):
/// - 以单个 `/` 开头(相对根路径);
/// - **不**以 `//` 或 `/\`(反斜杠被部分浏览器当 `/`)开头 —— 协议相对 / 网络路径会跨域;
/// - 只允许 **ASCII 可打印非空白**(`0x21..=0x7e`):拒控制字符 / ASCII 空白(`\r\n`/tab 头注入)、
///   **拒所有非 ASCII**(NBSP/零宽/BOM/IDEOGRAPHIC SPACE 等 Unicode 空白会引起 URL 解析歧义,评审 Kiro H2);
/// - 不含 `\`(统一按同源相对拒反斜杠)、不含裸 `:`(堵 `javascript:`/`http:` scheme,评审);
/// - **拒 percent-encoded 的斜杠/反斜杠**(`%2f`/`%5c`,大小写不敏感):虽然 RFC 3986 下 Location 头里的
///   `%2f` 应保持编码、浏览器不解码为路径分隔符(不构成跨域),但**不依赖下游框架/浏览器行为**——入口
///   即拒,把"理论安全"变"确定安全"(评审 Kiro H1;`next` 是我们自己前端路径,本就无需编码斜杠)。
fn sanitize_next(next: &str) -> Option<String> {
    if !next.starts_with('/') {
        return None; // 必须相对根路径
    }
    if next.starts_with("//") || next.starts_with("/\\") {
        return None; // 协议相对 / 反斜杠网络路径 → 跨域
    }
    // 只允许 ASCII 可打印非空白;拒反斜杠 / 裸冒号(控制字符、非 ASCII、Unicode 空白全在此拒)。
    if next
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'\\' || b == b':')
    {
        return None;
    }
    // 拒 percent-encoded 斜杠/反斜杠(大小写不敏感):不给"编码绕过"留任何理论缝隙(不依赖下游解码行为)。
    let lower = next.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return None;
    }
    Some(next.to_string())
}

/// 从 Cookie 头取某 cookie 值。
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// `__Host-` cookie 的 Set-Cookie 值(HttpOnly/Secure/SameSite=Lax/Path=/;无 Domain 是 __Host- 要求)。
pub(crate) fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

/// Persist a bounded, normalized browser/platform label instead of the raw user-agent.
pub(crate) fn session_device(headers: &HeaderMap) -> String {
    let Some(user_agent) = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
    else {
        return "Unknown device".to_string();
    };

    let browser = if user_agent.contains("Edg/") || user_agent.contains("EdgiOS/") {
        Some("Edge")
    } else if user_agent.contains("CriOS/") || user_agent.contains("Chrome/") {
        Some("Chrome")
    } else if user_agent.contains("FxiOS/") || user_agent.contains("Firefox/") {
        Some("Firefox")
    } else if user_agent.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let platform = if user_agent.contains("iPhone") {
        Some("iPhone")
    } else if user_agent.contains("iPad") {
        Some("iPad")
    } else if user_agent.contains("Android") {
        Some("Android")
    } else if user_agent.contains("Windows") {
        Some("Windows")
    } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS X") {
        Some("macOS")
    } else if user_agent.contains("CrOS") {
        Some("ChromeOS")
    } else if user_agent.contains("Linux") {
        Some("Linux")
    } else {
        None
    };

    match (browser, platform) {
        (Some(browser), Some(platform)) => format!("{browser} on {platform}"),
        (Some(browser), None) => browser.to_string(),
        (None, Some(platform)) => platform.to_string(),
        (None, None) => "Unknown device".to_string(),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct MagicLinkRequest {
    pub email: String,
    /// authorize 上下文(登录成功后据此续 OAuth 流);前端把 authorize query 原样带上。
    #[serde(default)]
    pub authorize_query: String,
    /// 登录后想去的 AS 前端页(同源相对路径,如 `/approve?auth_req_id=…`);兑现回跳时 sanitize。
    /// 无 authorize 上下文但带 `next` 时(如会话过期被拦在 /account、/approve)据此回原页。
    #[serde(default)]
    pub next: String,
}

#[derive(Serialize, ToSchema)]
pub struct MagicLinkResponse {
    pub sent: bool,
    /// dev 回显的 magic-link(真机/生产 MUST 为 None——只经 Notifier 发,不回响应)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_link: Option<String>,
}

/// `POST /login/magic-link`:请求登录链接(C9.1 冷却 + C9.2 会话绑定)。
#[utoipa::path(
    post, path = "/login/magic-link", tag = "login",
    request_body = MagicLinkRequest,
    responses(
        (status = 200, description = "已发送(或冷却中静默)", body = MagicLinkResponse),
        (status = 429, description = "per-email 冷却窗口内,请稍候")
    )
)]
pub async fn magic_link_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> impl IntoResponse {
    // tenant 分区(spec 020 §2.3,评审 codex High):magic-link + per-email 冷却按 tenant 隔离
    // (从入站 Host 派生;flag 关=空 tenant;控制面 Host→400 fail-closed)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Some(browser_origin) = crate::hostutil::browser_origin(&state, &headers) else {
        audit_magic_link_authentication(
            &state,
            &tenant,
            None,
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (StatusCode::BAD_REQUEST, "invalid browser origin").into_response();
    };
    let email = crate::local_identity::normalize_email(&req.email);
    // 拒空/无 @ / **控制字符**(评审 codex High:含 `\x1f`/US 的 email → `user:a\x1fb@x` 会让
    // tenant 分区 strip_tpk 在分隔符处误切 → 身份混淆 / gate 绕过。`\x1f` 是 tenant 键分隔符,
    // 逻辑标识 MUST NOT 含控制字符,spec 020 §2.3 tpk 编码前提)。
    if !crate::local_identity::is_valid_email(&email) {
        return (StatusCode::BAD_REQUEST, "invalid email").into_response();
    }
    let now = now_secs();

    // C9.1 per-email 固定窗口冷却(挡单邮箱重复触发)。
    let cfg = CooldownConfig::new(COOLDOWN_SECS);
    let last = state
        .magic_links
        .last_sent_at(&tenant, &email)
        .await
        .unwrap_or(None);
    if let CooldownDecision::Cooling { retry_after_secs } = cooldown_check(&cfg, last, now) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
        )
            .into_response();
    }

    // C9.1 **全局发信配额**(与 per-email 冷却语义不同的另一半):跨大量邮箱的发信洪水令牌桶,
    // 保护 SES 信誉不被拖垮。冷却挡"同邮箱重复",全局配额挡"跨邮箱总速率"。超额 → 429(fail-open)。
    if crate::ratelimit_gate::global_email_quota_exhausted(&state).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1".to_string())],
        )
            .into_response();
    }

    // Generate an equal-shape candidate for every valid email. Unknown,
    // blocked, and temporary-password users receive this unredeemable shape
    // without a MagicLinkStore row or notification.
    let session_nonce = rand_id(24);
    let link_id = state.region.issue_id(rand_id(24));
    let link = MagicLink {
        link_id: link_id.clone(),
        session_nonce: session_nonce.clone(),
        expires_at: now + LINK_TTL_SECS,
    };
    let tag = compute_tag(&state.server_secret, &link);
    let user_result = state.users.get_by_email(&tenant, &email).await;
    let fallback_user_id = format!("user:{email}");
    let credential_user_id = user_result
        .as_ref()
        .ok()
        .and_then(|user| user.as_ref())
        .map_or(fallback_user_id.as_str(), |user| user.user_id.as_str());
    let password_result = state.passwords.get(&tenant, credential_user_id).await;
    let eligible = matches!(
        (&user_result, &password_result),
        (Ok(Some(user)), Ok(password))
            if user.email == email
                && user.status == UserStatus::Active
                && !password.as_ref().is_some_and(|credential|
                    credential.must_change || credential.user_id != user.user_id)
    );
    let stored = if eligible {
        state
            .magic_links
            .put(
                &tenant,
                MagicLinkRecord {
                    link_id: link_id.clone(),
                    user_id: credential_user_id.to_string(),
                    email: email.clone(),
                    session_nonce: session_nonce.clone(),
                    authorize_query: req.authorize_query.clone(),
                    next: req.next.clone(),
                    expires_at: now + LINK_TTL_SECS,
                },
            )
            .await
            .is_ok()
    } else {
        false
    };
    // Mark cooldown for real and fake responses alike; otherwise the second
    // request would expose whether the first one created a real link.
    let _ = state.magic_links.mark_sent(&tenant, &email, now).await;

    // 组装 magic-link URL(指向后端 /login/callback;link_id + tag)。
    let link_url = format!(
        "{}/login/callback?link_id={}&tag={}",
        browser_origin, link_id, tag
    );
    if stored {
        let _ = state
            .notifier
            .send_magic_link(&tenant, &email, &link_url)
            .await;
    }

    // dev 回显链接(便于本地/e2e);真机(allow_login_placeholder=false)不回显。
    let dev_link = state.allow_login_placeholder.then(|| link_url.clone());

    // 发起会话 nonce 写 cookie(打开链接时校验同浏览器 = 同 nonce,C9.2 login-CSRF)。
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            set_cookie(NONCE_COOKIE, &session_nonce, LINK_TTL_SECS),
        )],
        Json(MagicLinkResponse {
            sent: true,
            dev_link,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub link_id: String,
    pub tag: String,
}

/// `GET /login/callback`:打开 magic-link(C9.1 一次性 + C9.2 login-CSRF)→ 建会话 → 回跳。
#[utoipa::path(
    get, path = "/login/callback", tag = "login",
    responses(
        (status = 302, description = "登录成功,建立会话 cookie 并回跳续 OAuth 流"),
        (status = 400, description = "链接无效/过期/已用/异浏览器打开(login-CSRF)")
    )
)]
pub async fn magic_link_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<CallbackParams>,
) -> impl IntoResponse {
    let now = now_secs();
    // tenant 分区(spec 020 §2.3):从入站 Host 派生一次,贯穿本请求所有 store 调用(flag 关=空 tenant;
    // 控制面 Host→400 fail-closed)。**须在 consume 之前**派生——link 按 tenant 隔离,绝不跨租户消费
    // 他租户 link(评审 codex High)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Some(browser_origin) = crate::hostutil::browser_origin(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "invalid browser origin").into_response();
    };
    if !state.region.owns_id(&p.link_id) {
        return (StatusCode::BAD_REQUEST, "link invalid or used").into_response();
    }
    let Some(cookie_nonce) = cookie(&headers, NONCE_COOKIE) else {
        audit_magic_link_authentication(
            &state,
            &tenant,
            None,
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (StatusCode::BAD_REQUEST, "login-csrf: different browser").into_response();
    };
    // 先强一致读取并完成完整签名/时效/浏览器绑定校验，再原子消费。
    // 错误 nonce、篡改 tag、过期或前置依赖失败都不得烧掉合法链接。
    let rec = match state.magic_links.get(&tenant, &p.link_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                None,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "link invalid or used").into_response();
        }
        Err(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                None,
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };

    // 重建 MagicLink 校验 tag + 过期 + session nonce 绑定(打开浏览器 cookie 的 nonce)。
    let link = MagicLink {
        link_id: rec.link_id.clone(),
        session_nonce: rec.session_nonce.clone(),
        expires_at: rec.expires_at,
    };
    match open_link(
        &state.server_secret,
        &link,
        &p.tag,
        now,
        false, // 一次性由下方 consume_bound 原子保证。
        Some(&cookie_nonce),
    ) {
        Ok(()) => {}
        Err(OpenError::SessionMismatch) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&rec.user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "login-csrf: different browser").into_response();
        }
        Err(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&rec.user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "link invalid or expired").into_response();
        }
    }

    // Local self-registration is closed (C9.7): callback performs a read-only
    // by-email lookup and never calls create/upsert.
    let norm_email = crate::local_identity::normalize_email(&rec.email);
    if !crate::local_identity::is_valid_email(&norm_email) {
        audit_magic_link_authentication(
            &state,
            &tenant,
            Some(&rec.user_id),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (StatusCode::FORBIDDEN, "account unavailable").into_response();
    }
    let user = match state.users.get_by_email(&tenant, &norm_email).await {
        Ok(Some(user)) if user.email == norm_email && user.user_id == rec.user_id => user,
        Ok(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&rec.user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::FORBIDDEN, "account unavailable").into_response();
        }
        Err(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&rec.user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    let credential = match state.passwords.get(&tenant, &user.user_id).await {
        Ok(credential) => credential,
        Err(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user.user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    if credential.as_ref().is_some_and(|password| {
        password.must_change || password.revocation_pending || password.user_id != user.user_id
    }) {
        audit_magic_link_authentication(
            &state,
            &tenant,
            Some(&user.user_id),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (StatusCode::FORBIDDEN, "account unavailable").into_response();
    }
    let user_id = rec.user_id.clone();
    // active-user gate(spec 003 §1.4):admin disable/delete(tombstone)后拒登录。
    match crate::user_gate::require_active_user(&state, &tenant, &user_id).await {
        crate::user_gate::UserGate::Allowed => {}
        crate::user_gate::UserGate::Blocked => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::FORBIDDEN, "account disabled").into_response();
        }
        crate::user_gate::UserGate::Unavailable => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    }
    // 所有不可变 link 与账户前置条件通过后，才原子夺取一次性链接。
    // 并发兑现仅一个请求能成功；错误浏览器与失败校验不会触发删除。
    match state
        .magic_links
        .consume_bound(&tenant, &p.link_id, &cookie_nonce)
        .await
    {
        Ok(Some(consumed)) if consumed == rec => {}
        Ok(Some(_)) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
        Ok(None) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "link invalid or used").into_response();
        }
        Err(_) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    }
    let session_id = match establish_local_session(
        &state,
        &tenant,
        user_id.clone(),
        &rec.authorize_query,
        LocalSessionMethod::MagicLink,
        session_device(&headers),
    )
    .await
    {
        Ok(session_id) => session_id,
        Err(()) => {
            audit_magic_link_authentication(
                &state,
                &tenant,
                Some(&user_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };

    // 回跳目标(清 nonce cookie):
    // 1. 有 authorize 上下文 → 续授权流(前端 /consent),协议流优先;
    // 2. 否则有合法 `next`(同源相对路径,sanitize 通过)→ 回原页(会话过期被拦处,如 /approve、/account);
    // 3. 否则进入已登录账户页。`next` 非法一律 fail-closed 丢弃、回落账户页
    //    (不 open-redirect、不拒登录,也不经 `/` 再被 SPA 导回 `/login`)。
    let dest = if !rec.authorize_query.is_empty() {
        format!("{}/consent?{}", browser_origin, rec.authorize_query)
    } else if let Some(safe_next) = sanitize_next(&rec.next) {
        format!("{}{}", browser_origin, safe_next)
    } else {
        format!("{}/account", browser_origin)
    };
    // 两条 Set-Cookie(建会话 + 清 nonce)必须**追加**(同名 header 用数组会互相覆盖)→ AppendHeaders。
    (
        AppendHeaders([
            (
                header::SET_COOKIE,
                set_cookie(SESSION_COOKIE, &session_id, SESSION_TTL_SECS),
            ),
            (
                header::SET_COOKIE,
                format!("{NONCE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
            ),
        ]),
        Redirect::to(&dest),
    )
        .into_response()
}

/// 已认证会话取用户(consent/authorize 用;校 expires_at,C10.4)。返回 (session_id, user_id)。
pub async fn current_session(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    current_session_full(state, headers)
        .await
        .map(|r| (r.session_id, r.user_id))
}

/// 同 `current_session`,但返回完整会话记录(含 `auth_time`,供 spec 003 C9.5a prompt/max_age 用)。
pub async fn current_session_full(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<crate::ports::SessionRecord> {
    // tenant 分区(spec 020 §2.3):会话按 tenant 隔离——从入站 Host 派生 tenant 查本租户会话
    // (flag 关=空 tenant=现网单租户;派生失败[控制面 Host]→当作无会话,fail-closed)。
    let tenant = crate::tenant::tenant_or_400(state, headers).ok()?;
    let sid = cookie(headers, SESSION_COOKIE)?;
    if !state.region.owns_id(&sid) {
        return None;
    }
    let rec = state.sessions.get(&tenant, &sid).await.ok()??;
    if agent_auth_infra_core::lifecycle::shortlived_is_expired(now_secs(), rec.expires_at) {
        return None;
    }
    if crate::user_gate::validate_session_authority(state, &tenant, &rec.session_id, &rec.user_id)
        .await
        == crate::user_gate::SessionAuthority::Allowed
    {
        let _ = state
            .sessions
            .touch_last_used(&tenant, &rec.session_id, now_secs())
            .await;
        return Some(rec);
    }
    None
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(magic_link_request))
        .routes(routes!(magic_link_callback))
}

#[cfg(test)]
mod tests {
    use super::{current_session_full, establish_local_session, sanitize_next, LocalSessionMethod};
    use crate::ports::{
        AuthzSessionStore, PasswordCredential, PasswordStore, SessionRecord, SessionStore,
        UserStatus, UsersStore,
    };

    // spec 003 §"登录后 next 回跳":合法同源相对路径放行。
    #[test]
    fn accepts_same_origin_relative_paths() {
        for ok in [
            "/",
            "/account",
            "/approve",
            "/approve?user_code=ABCD1234",
            "/approve?auth_req_id=abc-123",
            "/consent?client_id=x&state=y",
            "/a/b/c?q=1&r=2#frag",
        ] {
            assert_eq!(
                sanitize_next(ok).as_deref(),
                Some(ok),
                "应放行合法相对路径 {ok:?}"
            );
        }
    }

    // open-redirect 攻击面:一律 fail-closed 丢弃(返 None)。
    #[test]
    fn rejects_open_redirect_vectors() {
        for bad in [
            "",                         // 空/非 / 开头
            "account",                  // 缺前导 /
            "https://evil.example",     // 绝对 URL(scheme)
            "http://evil.example/x",    // 绝对 URL
            "//evil.example",           // 协议相对 → 跨域
            "//evil.example/path",      // 协议相对
            "/\\evil.example",          // 反斜杠网络路径(浏览器当 //)
            "/\\/evil.example",         // 反斜杠变体
            "javascript:alert(1)",      // 伪协议(不 / 开头,且含 :)
            "/x:evil",                  // 含裸冒号(scheme 混入护栏)
            "/path\r\nSet-Cookie: x=y", // CRLF 头注入
            "/path\nLocation: evil",    // LF 注入
            "/path\twith\ttab",         // 制表符
            "/ space",                  // 空格(0x20)
            "/\u{7f}del",               // DEL 控制字符
            // 编码绕过(评审 codex LOW / Kiro H1):不依赖下游解码,入口即拒。
            "/%2f%2fevil.example", // %2f%2f = 编码的 //
            "/%2F%2Fevil.example", // 大写编码
            "/%5c%5cevil.example", // %5c = 编码的 \\
            "/x%2Fy",              // path 中任意编码斜杠也拒
            // Unicode 空白 / 零宽 / BOM(评审 Kiro H2):非 ASCII 一律拒。
            "/\u{00a0}//evil", // NBSP
            "/\u{200b}//evil", // 零宽空格
            "/\u{feff}//evil", // BOM/ZWNBSP
            "/\u{3000}x",      // 全角空格
            "/café",           // 任意非 ASCII
        ] {
            assert_eq!(sanitize_next(bad), None, "应 fail-closed 丢弃 {bad:?}");
        }
    }

    #[tokio::test]
    async fn establish_session_cleans_up_when_delete_already_won() {
        let state = crate::AppState::dev("localhost");
        let email = "deleted-during-login@example.com";
        let user_id = format!("user:{email}");
        state.seed_dev_user(email).await;
        state
            .users
            .set_status("", &user_id, UserStatus::Tombstoned, 1)
            .await
            .unwrap();
        let (authz_session_id, _) = crate::authz_session::create_session(
            &state,
            "",
            "client",
            agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication,
            crate::token::current_unix_secs_pub(),
        )
        .await
        .unwrap();

        assert!(establish_local_session(
            &state,
            "",
            user_id.clone(),
            &format!("authz_session_id={authz_session_id}"),
            LocalSessionMethod::Password {
                credential_version: 0,
            },
            "Test browser".into(),
        )
        .await
        .is_err());
        assert_eq!(
            state
                .sessions
                .count_by_user("", &user_id, crate::token::current_unix_secs_pub())
                .await
                .unwrap(),
            0
        );
        let authz = state
            .authz_sessions
            .get("", &authz_session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            authz.state,
            agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication.as_str()
        );
    }

    #[tokio::test]
    async fn password_session_cleans_up_when_credential_version_changed() {
        let state = crate::AppState::dev("localhost");
        let email = "reset-during-login@example.com";
        let user_id = format!("user:{email}");
        state.seed_dev_user(email).await;
        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id: user_id.clone(),
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: false,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 2,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();

        assert!(establish_local_session(
            &state,
            "",
            user_id.clone(),
            "",
            LocalSessionMethod::Password {
                credential_version: 1,
            },
            "Test browser".into(),
        )
        .await
        .is_err());
        assert_eq!(
            state
                .sessions
                .count_by_user("", &user_id, crate::token::current_unix_secs_pub())
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn magic_link_session_cleans_up_when_admin_provisioning_won() {
        let state = crate::AppState::dev("localhost");
        let email = "provisioned-during-callback@example.com";
        let user_id = format!("user:{email}");
        state.seed_dev_user(email).await;
        let (authz_session_id, _) = crate::authz_session::create_session(
            &state,
            "",
            "client",
            agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication,
            crate::token::current_unix_secs_pub(),
        )
        .await
        .unwrap();

        // This is the state after callback's first credential read returned
        // None and concurrent Admin provisioning persisted its temporary row.
        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id: user_id.clone(),
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();

        assert!(establish_local_session(
            &state,
            "",
            user_id.clone(),
            &format!("authz_session_id={authz_session_id}"),
            LocalSessionMethod::MagicLink,
            "Test browser".into(),
        )
        .await
        .is_err());
        assert_eq!(
            state
                .sessions
                .count_by_user("", &user_id, crate::token::current_unix_secs_pub())
                .await
                .unwrap(),
            0
        );
        let authz = state
            .authz_sessions
            .get("", &authz_session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            authz.state,
            agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication.as_str()
        );
    }

    #[tokio::test]
    async fn current_session_rejects_and_deletes_residual_tombstoned_session() {
        let state = crate::AppState::dev("localhost");
        let email = "residual-session@example.com";
        let user_id = format!("user:{email}");
        let session_id = "residual-session".to_string();
        state.seed_dev_user(email).await;
        state
            .users
            .set_status("", &user_id, UserStatus::Tombstoned, 1)
            .await
            .unwrap();
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.clone(),
                    user_id,
                    credential_epoch: 0,
                    auth_time: crate::token::current_unix_secs_pub(),
                    created_at: crate::token::current_unix_secs_pub(),
                    last_used_at: crate::token::current_unix_secs_pub(),
                    device: "Test browser".into(),
                    expires_at: crate::token::current_unix_secs_pub() + 60,
                    acr: None,
                    amr: vec!["pwd".to_string()],
                },
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", axum::http::HeaderValue::from_static("localhost"));
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_static("__Host-agent_auth_session=residual-session"),
        );

        assert!(current_session_full(&state, &headers).await.is_none());
        assert!(
            state.sessions.get("", &session_id).await.unwrap().is_none(),
            "residual session should be removed after the account gate rejects it"
        );
    }

    #[tokio::test]
    async fn current_session_rejects_new_temporary_credential() {
        let state = crate::AppState::dev("localhost");
        let email = "legacy-session@example.com";
        let user_id = format!("user:{email}");
        let session_id = "legacy-email-session".to_string();
        state.seed_dev_user(email).await;
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.clone(),
                    user_id: user_id.clone(),
                    credential_epoch: 0,
                    auth_time: crate::token::current_unix_secs_pub(),
                    created_at: crate::token::current_unix_secs_pub(),
                    last_used_at: crate::token::current_unix_secs_pub(),
                    device: "Test browser".into(),
                    expires_at: crate::token::current_unix_secs_pub() + 60,
                    acr: None,
                    amr: vec!["pwd".to_string()],
                },
            )
            .await
            .unwrap();
        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id,
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", axum::http::HeaderValue::from_static("localhost"));
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_static("__Host-agent_auth_session=legacy-email-session"),
        );

        assert!(current_session_full(&state, &headers).await.is_none());
        assert!(state.sessions.get("", &session_id).await.unwrap().is_none());
    }
}
