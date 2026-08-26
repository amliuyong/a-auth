//! consent 同意后端(C10.9 anti-CSRF + authorize↔token 绑定)。
//!
//! - `GET /consent/context`:需已登录(会话 cookie)。返回 client/scope/resource + **per-request
//!   anti-CSRF token**(infra-core::websec,HMAC(session_id‖nonce),前端内存保存后供 POST 回带)。
//! - `POST /consent`:校 anti-CSRF token(常量时间)+ 会话 → 落授权码(绑定 client/redirect/
//!   challenge/resource/user)→ 返回回跳 URL(code + iss + state)。deny → 回跳 error=access_denied。
//!
//! 授权码签发逻辑与 authorize.rs 一致(CSPRNG code、redirect 精确匹配、PKCE challenge 绑定);
//! 真实 consent 取代 authorize 的 login_user 占位。决策真相源:docs/DESIGN §7·§8;C10.9/C4.1/C4.5。

use agent_auth_client::{match_redirect, MatchResult, RedirectMode};
use agent_auth_discovery::{derive_issuer, echo_state};
use agent_auth_infra_core::websec::{csrf_token, csrf_verify};
use axum::{
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::login::current_session;
use crate::ports::{AuthzSessionStore, CodeIssueOutcome, CodeRecord};
use crate::state::AppState;

const CODE_TTL_SECS: i64 = 60;

fn rand_code() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn consent_csrf_binding(session_id: &str, authorize_query: &str) -> String {
    format!("{session_id}\0{authorize_query}")
}

fn issue_consent_csrf(secret: &[u8], session_id: &str, authorize_query: &str) -> String {
    let nonce = rand_code();
    let binding = consent_csrf_binding(session_id, authorize_query);
    let mac = csrf_token(secret, &binding, &nonce);
    format!("{nonce}.{mac}")
}

fn verify_consent_csrf(
    secret: &[u8],
    session_id: &str,
    authorize_query: &str,
    presented: &str,
) -> bool {
    let Some((nonce, mac)) = presented.split_once('.') else {
        return false;
    };
    let binding = consent_csrf_binding(session_id, authorize_query);
    !nonce.is_empty()
        && !mac.is_empty()
        && !mac.contains('.')
        && csrf_verify(secret, &binding, nonce, mac)
}

fn host_issuer(state: &AppState, headers: &HeaderMap) -> Option<agent_auth_discovery::Issuer> {
    // issuer host(C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    let h = crate::hostutil::issuer_host(headers)?;
    derive_issuer(&h, &state.form).ok()
}

fn resources_allowed_in_phase(state: &AppState, resources: &[String]) -> bool {
    let phase = if state.phase.at_least(agent_auth_discovery::Phase::P1) {
        agent_auth_protocol::AuthorizePhase::P1Plus
    } else {
        agent_auth_protocol::AuthorizePhase::P0
    };
    agent_auth_protocol::AuthorizedResources::from_authorize(resources, phase).is_ok()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ConsentQuery {
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// RFC 9396 `authorization_details`(RAR;JSON 串)。consent 页据此**结构化展示**用户正在同意的
    /// 细粒度约束(DESIGN §11#8/§721 consent MUST 渲染 RAR)。serde_urlencoded 已 %-decode 为 JSON 串。
    #[serde(default)]
    pub authorization_details: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
    #[serde(default)]
    pub idp_hint: Option<String>,
    #[serde(default)]
    pub authz_session_id: Option<String>,
    #[serde(default)]
    pub cimd_digest: Option<String>,
    #[serde(default)]
    pub cimd_binding: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentContext {
    pub client_id: String,
    pub client_name: String,
    pub client_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri_host: Option<String>,
    pub scopes: Vec<String>,
    /// 兼容旧前端的首个 resource；完整授权集合以 `resources` 为准。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// 本次 authorize 声明的完整 RFC 8707 resource 集合。
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<String>,
    /// RFC 9396 `authorization_details`(RAR;结构化数组)。供前端 consent 页渲染"正在同意的细粒度约束"
    /// (DESIGN §721)。空/无 RAR 时省略。已过发行准入校验(与 authorize/consent 提交侧同口径 fail-closed)。
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authorization_details: Vec<serde_json::Value>,
    /// per-request anti-CSRF token(C10.9;前端从本响应读取并在 POST /consent 回带)。
    pub csrf_token: String,
}

/// `GET /consent/context`:已登录才返回 consent 展示上下文 + anti-CSRF token。
#[utoipa::path(
    get, path = "/consent/context", tag = "consent",
    params(ConsentQuery),
    responses(
        (status = 200, description = "consent 上下文 + anti-CSRF token", body = ConsentContext),
        (status = 400, description = "authorize query 缺必需字段、含重复 singleton 或阶段不允许"),
        (status = 401, description = "未登录(无有效会话)")
    )
)]
pub async fn consent_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let Some((session_id, _user)) = current_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let authorize_query = raw_query.as_deref().unwrap_or_default();
    let parsed = match parse_query(authorize_query) {
        Ok(parsed) => parsed,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: duplicate singleton parameter",
            )
                .into_response()
        }
    };
    let q = &parsed.values;
    let Some(client_id) = q.get("client_id") else {
        return (StatusCode::BAD_REQUEST, "missing client_id").into_response();
    };
    let Some(redirect_uri) = q.get("redirect_uri") else {
        return (StatusCode::BAD_REQUEST, "missing redirect_uri").into_response();
    };
    let resolved = match resolve_continuation_client(&state, &tenant, q).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let token = issue_consent_csrf(&state.server_secret, &session_id, authorize_query);
    // RAR 展示(DESIGN §721):解析并**准入校验** authorization_details,合规才回给前端渲染;
    // 不合规(未知 type/越界 locations 等)→ 空数组(不展示畸形 RAR)。resource 集合供越界校验。
    let resources = parsed.resources;
    if !resources_allowed_in_phase(&state, &resources) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_target: 当前阶段不允许多 resource",
        )
            .into_response();
    }
    let authorization_details: Vec<serde_json::Value> = q
        .get("authorization_details")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .filter(|parsed| {
            agent_auth_grant::rar::validate_admission_for_resources(parsed, &resources).is_ok()
        })
        .and_then(|parsed| parsed.as_array().cloned())
        .unwrap_or_default();
    Json(ConsentContext {
        client_id: client_id.clone(),
        client_name: resolved
            .cimd_snapshot
            .as_ref()
            .map(|snapshot| snapshot.client_name.clone())
            .unwrap_or_else(|| client_id.clone()),
        client_source: match resolved.source {
            crate::cimd::ClientSource::Registered => "registered",
            crate::cimd::ClientSource::Cimd => "cimd",
        }
        .to_string(),
        client_id_host: url::Url::parse(client_id)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string)),
        redirect_uri_host: url::Url::parse(redirect_uri)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string)),
        scopes: q
            .get("scope")
            .map(String::as_str)
            .unwrap_or("openid")
            .split_whitespace()
            .map(String::from)
            .collect(),
        resource: resources.first().cloned(),
        resources,
        authorization_details,
        csrf_token: token,
    })
    .into_response()
}

#[derive(Deserialize, ToSchema)]
pub struct ConsentDecision {
    pub decision: String, // "approve" | "deny"
    #[serde(default)]
    pub csrf: String,
    /// authorize 上下文(query 串:client_id/redirect_uri/scope/resource/state/code_challenge…)。
    pub authorize_query: String,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentResult {
    pub redirect: String,
}

struct ParsedQuery {
    values: BTreeMap<String, String>,
    resources: Vec<String>,
}

fn parse_query(q: &str) -> Result<ParsedQuery, ()> {
    let mut values = BTreeMap::new();
    let mut resources = Vec::new();
    for (key, value) in url_pairs(q) {
        if key == "resource" {
            if !value.is_empty() {
                resources.push(value);
            }
        } else if values.insert(key, value).is_some() {
            return Err(());
        }
    }
    Ok(ParsedQuery { values, resources })
}

async fn resolve_continuation_client(
    state: &AppState,
    tenant: &str,
    query: &BTreeMap<String, String>,
) -> Result<crate::cimd::ResolvedClient, axum::response::Response> {
    let client_id = query
        .get("client_id")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing client_id").into_response())?;
    let redirect_uri = query
        .get("redirect_uri")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing redirect_uri").into_response())?;
    let resolved = match crate::cimd::resolve_client(state, tenant, client_id).await {
        Ok(resolved) => resolved,
        Err(
            crate::cimd::ResolveClientError::Unknown | crate::cimd::ResolveClientError::Invalid(_),
        ) => return Err((StatusCode::BAD_REQUEST, "unknown or invalid client").into_response()),
        Err(crate::cimd::ResolveClientError::TemporarilyUnavailable) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "client metadata temporarily unavailable",
            )
                .into_response())
        }
        Err(crate::cimd::ResolveClientError::Store) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "client store error").into_response())
        }
    };
    let digest_matches = match resolved.cimd_snapshot.as_ref() {
        Some(snapshot) => {
            let Some(digest) = query.get("cimd_digest") else {
                return Err(
                    (StatusCode::BAD_REQUEST, "missing CIMD continuation digest").into_response(),
                );
            };
            let Some(binding) = query.get("cimd_binding") else {
                return Err(
                    (StatusCode::BAD_REQUEST, "missing CIMD continuation binding").into_response(),
                );
            };
            digest == &snapshot.digest()
                && crate::cimd::verify_continuation_binding(
                    &state.server_secret,
                    query
                        .get("authz_session_id")
                        .map(String::as_str)
                        .unwrap_or(""),
                    client_id,
                    digest,
                    binding,
                )
        }
        None => !query.contains_key("cimd_digest") && !query.contains_key("cimd_binding"),
    };
    if !digest_matches {
        return Err((
            StatusCode::BAD_REQUEST,
            "client metadata changed during authorization",
        )
            .into_response());
    }
    if resolved.cimd_snapshot.is_some() {
        let session_id = query
            .get("authz_session_id")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "missing CIMD authorization session",
                )
                    .into_response()
            })?;
        let now = crate::token::current_unix_secs_pub();
        match state.authz_sessions.get(tenant, session_id).await {
            Ok(Some(record))
                if record.expires_at > now
                    && record.client_id == resolved.audit_identifier()
                    && record.state
                        == agent_auth_authn::authz_session::AuthzState::PendingConsent.as_str() => {
            }
            Ok(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "stale or replayed CIMD authorization session",
                )
                    .into_response())
            }
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization session unavailable",
                )
                    .into_response())
            }
        }
    }
    if matches!(resolved.source, crate::cimd::ClientSource::Registered)
        && crate::register::validate_application_redirects(
            resolved.client.application_type(),
            std::slice::from_ref(redirect_uri),
        )
        .is_err()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri violates application_type policy",
        )
            .into_response());
    }
    let matched = if matches!(resolved.source, crate::cimd::ClientSource::Registered) {
        crate::register::registered_redirect_matches(&resolved.client, redirect_uri)
            .map_err(|message| (StatusCode::BAD_REQUEST, message).into_response())?
    } else {
        resolved.client.redirect_uris.iter().any(|registered| {
            matches!(
                match_redirect(&RedirectMode::Exact, registered, redirect_uri),
                MatchResult::Allow
            )
        })
    };
    if !matched {
        return Err((StatusCode::BAD_REQUEST, "redirect_uri not registered").into_response());
    }
    Ok(resolved)
}

/// 极简 x-www-form-urlencoded 解析(key/value 各做一次 %-decode 的空格/常见转义)。
fn url_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| kv.split_once('=').unwrap_or((kv, "")))
        .map(|(k, v)| (pct_decode(k), pct_decode(v)))
        .collect()
}

pub(crate) fn pct_decode(s: &str) -> String {
    // ⚠️ 纯**字节**解码,不按 str 切片(`%` 后跟多字节 UTF-8 时按字符边界切会 panic,评审 bug)。
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let hex = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%'); // 非法转义:原样保留 %
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `POST /consent/decision`:批准/拒绝(C10.9 anti-CSRF + 会话 → 签发 code)。
///
/// ⚠️ path 为 `/consent/decision` 而非 `/consent`:CloudFront 统一入口按 **path**(非 method)选 origin,
/// SPA 页面 `/consent`(可 bookmark)与本"批准动作"若同 path 会冲突 → 动作挂子路径避让(spec 025 收敛)。
#[utoipa::path(
    post, path = "/consent/decision", tag = "consent",
    request_body = ConsentDecision,
    responses(
        (status = 200, description = "决定已处理,返回回跳 URL(code+iss+state 或 error)", body = ConsentResult),
        (status = 400, description = "authorize query 缺必需字段、含重复 singleton 或参数无效"),
        (status = 401, description = "未登录"),
        (status = 403, description = "anti-CSRF 校验失败或账户已禁用"),
        (status = 503, description = "用户、客户端或授权码存储暂不可用")
    )
)]
pub async fn consent_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsentDecision>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Some((session_id, user_id)) = current_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    // C10.9 anti-CSRF:token 必须匹配本会话 + 本次 authorize 续流上下文。
    if !verify_consent_csrf(
        &state.server_secret,
        &session_id,
        &body.authorize_query,
        &body.csrf,
    ) {
        return (StatusCode::FORBIDDEN, "csrf check failed").into_response();
    }
    // **active-user gate(评审 codex Medium,spec 003 §1.4:"发或换 code")**:consent approve 会**发 code**
    // ——若 disable 级联删会话失败或存在竞态,残留会话仍可发 code,故发 code 前独立复查 status(登录 gate
    // 之外的第二道)。Blocked→拒登录(403,须重新认证)、查询失败→503。人类 user:* 均 gate。
    match crate::user_gate::require_active_user(&state, &tenant, &user_id).await {
        crate::user_gate::UserGate::Allowed => {}
        crate::user_gate::UserGate::Blocked => {
            return (StatusCode::FORBIDDEN, "account disabled").into_response()
        }
        crate::user_gate::UserGate::Unavailable => {
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
        }
    }

    let parsed = match parse_query(&body.authorize_query) {
        Ok(parsed) => parsed,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: duplicate singleton parameter",
            )
                .into_response()
        }
    };
    let q = &parsed.values;
    let Some(client_id) = q.get("client_id") else {
        return (StatusCode::BAD_REQUEST, "missing client_id").into_response();
    };
    let Some(redirect_uri) = q.get("redirect_uri") else {
        return (StatusCode::BAD_REQUEST, "missing redirect_uri").into_response();
    };
    let Some(issuer) = host_issuer(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };

    // Re-resolve and compare the authorize-bound CIMD digest. Registered clients
    // remain store-backed and must not carry a CIMD digest.
    let resolved_client = match resolve_continuation_client(&state, &tenant, q).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let audit_client_id = resolved_client.audit_identifier();

    // C4.1:与 authorize.rs 共用策略，防客户端跳过 /authorize、直接驱动 consent 拿到不合规
    // code。response_type 也须为 code(implicit/hybrid 永久不存在)。
    if q.get("response_type").map(String::as_str).unwrap_or("code") != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported_response_type").into_response();
    }
    match crate::authorize::check_authorization_code_policy(
        &state,
        &resolved_client.source,
        &resolved_client.client,
        q.get("code_challenge").map(String::as_str),
        q.get("code_challenge_method").map(String::as_str),
    ) {
        Ok(()) => {}
        Err(crate::authorize::AuthorizationCodePolicyError::Workload) => {
            return (
                StatusCode::BAD_REQUEST,
                "unauthorized_client: workload clients cannot use authorization_code flow",
            )
                .into_response()
        }
        Err(crate::authorize::AuthorizationCodePolicyError::MissingChallenge) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: 缺 code_challenge(PKCE policy)",
            )
                .into_response()
        }
        Err(crate::authorize::AuthorizationCodePolicyError::NotS256) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: code_challenge_method 须 S256",
            )
                .into_response()
        }
    }

    let state_param = q.get("state").map(String::as_str);

    let now = crate::token::current_unix_secs_pub();
    // spec 004:authorize 已建会话,其 id 随 authorize_query 透传到此;consent 迁移同一条(不新建)。
    let Some(authz_session_id) = q
        .get("authz_session_id")
        .filter(|session_id| !session_id.is_empty())
        .cloned()
    else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request: missing authorization session",
        )
            .into_response();
    };
    let authz_session = match state.authz_sessions.get(&tenant, &authz_session_id).await {
        Ok(Some(record))
            if record.expires_at > now
                && record.client_id == audit_client_id
                && matches!(
                    agent_auth_authn::authz_session::AuthzState::parse(&record.state),
                    Some(
                        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication
                            | agent_auth_authn::authz_session::AuthzState::PendingConsent
                    )
                ) =>
        {
            if record
                .user_id
                .as_deref()
                .is_some_and(|bound| bound != user_id)
            {
                return (StatusCode::FORBIDDEN, "authorization session unavailable")
                    .into_response();
            }
            record
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: stale or mismatched authorization session",
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization session unavailable",
            )
                .into_response()
        }
    };

    // deny → 回跳 error=access_denied(RFC 6749 §4.1.2.1)。
    if body.decision != "approve" {
        // spec 004:会话迁到终态 denied(可观测)。
        if !crate::authz_session::bind_user(&state, &tenant, &authz_session_id, &user_id).await {
            return (StatusCode::FORBIDDEN, "authorization session unavailable").into_response();
        }
        match crate::authz_session::try_transition(
            &state,
            &tenant,
            &authz_session_id,
            agent_auth_authn::authz_session::AuthzState::Denied,
            None,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_request: stale or replayed authorization session",
                )
                    .into_response()
            }
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization session unavailable",
                )
                    .into_response()
            }
        }
        let state_param = echo_state(state_param);
        let mut params = vec![("error", "access_denied"), ("iss", issuer.as_str())];
        if let Some(state_param) = state_param.as_deref() {
            params.push(("state", state_param));
        }
        let url = match crate::authorize::oauth_response_url(redirect_uri, &params) {
            Ok(url) => url,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "validated redirect URI became invalid",
                )
                    .into_response()
            }
        };
        return Json(ConsentResult { redirect: url }).into_response();
    }
    if !crate::authz_session::bind_user(&state, &tenant, &authz_session_id, &user_id).await {
        return (StatusCode::FORBIDDEN, "authorization session unavailable").into_response();
    }

    // approve → 落授权码(CSPRNG,绑定 client/redirect/challenge/resource/user/scope)。
    let resources = parsed.resources;
    if !resources_allowed_in_phase(&state, &resources) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_target: 当前阶段不允许多 resource",
        )
            .into_response();
    }
    let scope: Vec<String> = q
        .get("scope")
        .map(String::as_str)
        .unwrap_or("openid")
        .split_whitespace()
        .map(String::from)
        .collect();
    // RAR(spec 010 §4):从 authorize_query 透传的 authorization_details。**必须重新准入校验**——
    // authorize_query 来自 client 重建的 POST body(与 authorize 原始收到的无完整性绑定,评审 Q7.4),
    // 不能信任其已校验;consent 侧再过 grant::rar::validate_admission,不合规拒(fail-closed,防绕过)。
    // 用户在 consent 页 approve = 同意这份 RAR(展示义务见前端待办,spec 010 §4)。
    let authorization_details: Vec<serde_json::Value> = match q.get("authorization_details") {
        Some(raw) if !raw.is_empty() => {
            let parsed: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "invalid_authorization_details: 非合法 JSON",
                    )
                        .into_response()
                }
            };
            // 准入 + locations 越界校验(评审 codex HIGH;与 authorize 侧同口径,resources 取自 authorize_query)。
            if agent_auth_grant::rar::validate_admission_for_resources(&parsed, &resources).is_err()
            {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_authorization_details: 未通过内建词汇表准入校验(含 locations 越界)",
                )
                    .into_response();
            }
            parsed.as_array().cloned().unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let requested_max_age = match q.get("max_age") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) => Some(value),
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid max_age").into_response(),
        },
        None => None,
    };
    let requirement = match crate::assurance::resolve_requirement(
        &state.assurance_policy,
        q.get("acr_values").map(String::as_str),
        &authorization_details,
        requested_max_age,
    ) {
        Ok(requirement) => requirement,
        Err(_) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                    &tenant,
                    Some(&user_id),
                    &audit_client_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                ))
                .await;
            return (StatusCode::FORBIDDEN, "unmet_authentication_requirements").into_response();
        }
    };
    // Re-evaluate the step-up policy at the mutation boundary. `authorize_query`
    // is browser-controlled, so the earlier /authorize decision is not trusted.
    let session_rec = crate::login::current_session_full(&state, &headers).await;
    let authorization_time = authz_session
        .expires_at
        .saturating_sub(crate::authz_session::AUTHZ_SESSION_TTL_SECS);
    // A reauthentication performed for this authorization can occur after the
    // request began. Freeze max_age at the request boundary for an existing
    // session, but never evaluate a newly established session before auth_time.
    let assurance_time = session_rec
        .as_ref()
        .map(|session| authorization_time.max(session.auth_time))
        .unwrap_or(authorization_time);
    if !crate::assurance::session_satisfies(requirement, session_rec.as_ref(), assurance_time) {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                &tenant,
                Some(&user_id),
                &audit_client_id,
                crate::security_event::SecurityEventOutcome::Denied,
            ))
            .await;
        return (StatusCode::FORBIDDEN, "unmet_authentication_requirements").into_response();
    }
    let session_rec = session_rec.expect("session_satisfies requires a session");
    let auth_time = session_rec.auth_time;
    let credential_epoch = session_rec.credential_epoch;
    let acr = Some(
        crate::assurance::session_class(&session_rec)
            .acr()
            .to_string(),
    );
    let amr = session_rec.amr;
    let password_credential_version =
        match crate::user_gate::password_authority_snapshot(&state, &tenant, &user_id).await {
            Ok(version) => version,
            Err(crate::user_gate::PasswordGate::ChangeRequired) => {
                return (StatusCode::FORBIDDEN, "password change required").into_response()
            }
            Err(crate::user_gate::PasswordGate::Unavailable) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password authority unavailable",
                )
                    .into_response()
            }
            Err(crate::user_gate::PasswordGate::Allowed) => unreachable!(),
        };
    // Reserve the one-time consent continuation before storing a code. Concurrent
    // approvals race on the authorization-session CAS, so at most one can issue.
    // A later code-store failure consumes this attempt fail-closed rather than
    // leaving a replayable continuation.
    match crate::authz_session::try_transition(
        &state,
        &tenant,
        &authz_session_id,
        agent_auth_authn::authz_session::AuthzState::CodeIssuedAwaitingExchange,
        None,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: stale or replayed authorization session",
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization session unavailable",
            )
                .into_response()
        }
    }

    let code = state.region.issue_id(rand_code());
    let record = CodeRecord {
        code: code.clone(),
        client_id: client_id.clone(),
        cimd_snapshot: resolved_client.cimd_snapshot,
        redirect_uri: redirect_uri.clone(),
        code_challenge: q.get("code_challenge").cloned().unwrap_or_default(),
        resources,
        user_id: user_id.clone(),
        scope,
        expires_at: now + CODE_TTL_SECS,
        authz_session_id: Some(authz_session_id.clone()),
        // OIDC nonce(C2.9):从 authorize_query 透传(consent 迁移同一授权上下文)。
        nonce: q.get("nonce").filter(|s| !s.is_empty()).cloned(),
        auth_time,
        authorization_details, // RAR(consent 侧已重新准入校验;用户 approve 即同意)
        acr,
        amr,
        credential_epoch: Some(credential_epoch),
        password_credential_version,
    };
    match state
        .codes
        .put_authorized(&state.users, &tenant, record, credential_epoch)
        .await
    {
        Ok(CodeIssueOutcome::Stored) => {}
        Ok(CodeIssueOutcome::AuthorityChanged) => {
            return (StatusCode::FORBIDDEN, "user authority changed").into_response();
        }
        Ok(CodeIssueOutcome::CodeExists) | Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    }
    if requirement.step_up {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                &tenant,
                Some(&user_id),
                &audit_client_id,
                crate::security_event::SecurityEventOutcome::Success,
            ))
            .await;
    }
    let state_param = echo_state(state_param);
    let mut params = vec![("code", code.as_str()), ("iss", issuer.as_str())];
    if let Some(state_param) = state_param.as_deref() {
        params.push(("state", state_param));
    }
    let url = match crate::authorize::oauth_response_url(redirect_uri, &params) {
        Ok(url) => url,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "validated redirect URI became invalid",
            )
                .into_response()
        }
    };
    Json(ConsentResult { redirect: url }).into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(consent_context))
        .routes(routes!(consent_submit))
}
