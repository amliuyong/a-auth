//! 授权会话状态机 HTTP 面(spec 004,C6)。
//!
//! - `GET /sessions/{session_id}`:鉴权二选一——`session_token`(Bearer,常量时间比对)或
//!   confidential client 认证 + 归属校验;绝不只凭 id(C6.1)。未命中统一 404、响应体一致(C6.2)。
//! - `GET /sessions?client_id=me`:confidential 凭 client 认证列自己名下会话 id(C6.1 发现路径)。
//!
//! 迁移辅助(供 authorize/consent/token 调用):create / transition + 发投影事件(带序号,C6.5)。
//! 状态机合法性由纯逻辑 `agent_auth_authn::authz_session` 保证。真相源 docs §4 / CONFORMANCE C6。
//!
//! **P1 已知取舍(评审 codex,后续 P1+/P2 收紧)**:
//! - 会话在 **consent approve/deny** 或 authorize 占位路径创建(推进到 code_issued/denied),而非在
//!   `GET /authorize` 受理时就建 `created→pending_*`:真实登录流是浏览器重定向(authorize→login→
//!   consent),P1 无客户端在此期间轮询会话,故 `created/pending_*` 前缀对 P1 可观测性非必需;端到端
//!   要覆盖需把 session_ref 串过 login→consent 重定向链(P1+)。code_issued 起的可观测态已完整覆盖。
//!
//! token 语义失败的 code finalize 与 `exchange_failed` 迁移由 store backend 原子提交:
//! DynamoDB 使用单次 `TransactWriteItems`,Memory adapter 在同一临界区先校验后提交(C6.3b)。

use agent_auth_authn::authz_session::{session_token_hash, session_token_matches, AuthzState};
use axum::{
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    AuthzEventSink, AuthzSessionRecord, AuthzSessionStore, ClientStore, StoreError,
};
use crate::state::AppState;

/// 授权会话 TTL(spec 004:发起 + 30min,覆盖 login+consent+兑换全程)。
pub const AUTHZ_SESSION_TTL_SECS: i64 = 1800;

/// 生成高熵不透明串(session_id / session_token)。
fn rand_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// authorize 受理时创建授权会话。返回 (session_id, session_token)。
/// `initial`:据登录态选初始迁移目标(created 后立即迁到 pending_*)。
pub async fn create_session(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    initial: AuthzState,
    now: i64,
) -> Option<(String, String)> {
    let session_id = state.region.issue_id(rand_token());
    let session_token = rand_token();
    let rec = AuthzSessionRecord {
        session_id: session_id.clone(),
        client_id: client_id.to_string(),
        user_id: None,
        state: AuthzState::Created.as_str().to_string(),
        session_token_hash: session_token_hash(&state.server_secret, &session_token),
        sequence: 0,
        last_error: None,
        expires_at: now + AUTHZ_SESSION_TTL_SECS,
    };
    state.authz_sessions.create(tenant, rec).await.ok()?;
    if let Err(e) = state
        .authz_events
        .emit(&session_id, 0, AuthzState::Created.as_str())
        .await
    {
        eprintln!("AUTHZ_EVENT_EMIT_FAIL seq=0 state=created err={e:?}");
    }
    // 立即迁到初始态(created→pending_user_authentication / pending_consent)。
    transition(state, tenant, &session_id, initial, None).await;
    Some((session_id, session_token))
}

/// Attach the authenticated user before a code or user-visible terminal state
/// can outlive its code record. The post-bind read rejects erasure that already
/// won; code issuance must additionally use the active-user conditional write
/// so erasure cannot win after this read and before code persistence.
pub async fn bind_user(state: &AppState, tenant: &str, session_id: &str, user_id: &str) -> bool {
    let now = crate::token::current_unix_secs_pub();
    let bound = matches!(
        state
            .authz_sessions
            .bind_user(tenant, session_id, user_id, now)
            .await,
        Ok(Some(_))
    );
    if !bound {
        return false;
    }
    if crate::user_gate::active_existing_user_epoch(state, tenant, user_id)
        .await
        .is_ok()
    {
        return true;
    }
    if let Err(error) = state.authz_sessions.delete(tenant, session_id).await {
        eprintln!("AUTHZ_SESSION_USER_FENCE_DELETE_FAIL session={session_id} err={error:?}");
    }
    false
}

/// 条件迁移会话状态 + 发投影事件(带迁移后的序号)。
///
/// 返回 `false` 表示会话不存在、已被并发请求迁移或迁移非法。需要把状态迁移作为协议
/// 一次性闸门的调用方必须检查该结果；投影仍是非阻断旁路。
pub async fn try_transition(
    state: &AppState,
    tenant: &str,
    session_id: &str,
    to: AuthzState,
    last_error: Option<String>,
) -> Result<bool, StoreError> {
    let now = crate::token::current_unix_secs_pub();
    let Some(rec) = state
        .authz_sessions
        .transition(tenant, session_id, to.as_str(), last_error, now)
        .await?
    else {
        return Ok(false);
    };
    emit_transition_event(state, &rec).await;
    Ok(true)
}

pub(crate) fn prepare_exchange_failure_transition(
    mut current: AuthzSessionRecord,
    last_error: String,
) -> Result<AuthzSessionRecord, StoreError> {
    let Some(from) = AuthzState::parse(&current.state) else {
        return Err(StoreError::Transient(
            "authorization session state is invalid".into(),
        ));
    };
    if !from.can_transition_to(AuthzState::ExchangeFailed) {
        return Err(StoreError::Transient(
            "authorization session state changed during exchange failure".into(),
        ));
    }
    current.sequence = current
        .sequence
        .checked_add(1)
        .ok_or_else(|| StoreError::Permanent("authorization session sequence exhausted".into()))?;
    current.state = AuthzState::ExchangeFailed.as_str().to_string();
    current.last_error = Some(last_error);
    Ok(current)
}

pub(crate) async fn emit_transition_event(state: &AppState, rec: &AuthzSessionRecord) {
    // 投影发出(可观测旁路,不阻断迁移;权威源是 DynamoDB 会话记录)。失败**不静默吞**——打
    // `AUTHZ_EVENT_EMIT_FAIL` 标记到 stderr(CloudWatch metric filter 可告警;评审 Kiro H2:持续失败
    // 时审计湖静默残缺,运维须有信号)。绝不因投影失败拒迁移。
    if let Err(e) = state
        .authz_events
        .emit(&rec.session_id, rec.sequence, &rec.state)
        .await
    {
        eprintln!(
            "AUTHZ_EVENT_EMIT_FAIL seq={} state={} err={e:?}",
            rec.sequence, rec.state
        );
    }
}

/// 迁移会话状态 + 发投影事件。仅用于可观测旁路不应阻断主流程的调用点。
pub async fn transition(
    state: &AppState,
    tenant: &str,
    session_id: &str,
    to: AuthzState,
    last_error: Option<String>,
) {
    let _ = try_transition(state, tenant, session_id, to, last_error).await;
}

/// device/CIBA 流的**主动投影**(spec 004 §3.3 / C6.5):把 device/CIBA 状态迁移也投影到审计湖。
/// 复用 authz-code 的 EventBridge sink/bus/CloudWatch Logs 消费方。
///
/// **投影键 = HMAC(server_secret, flow_cred)**——**绝不投影 device_code / auth_req_id 原值**(它们是活的
/// 轮询凭证 = bearer secret,进审计日志即泄露)。哈希键仍稳定(同一流各态映到同键,消费方可按 (键,seq)
/// 去重排序回放)、不可逆推凭证。`sequence` 由 `ciba_state_seq` 派生(无需在热轮询记录加计数器字段)。
/// 失败**不静默吞**(打 `AUTHZ_EVENT_EMIT_FAIL`,不阻断 flow;权威源是 Ciba/DeviceStore 记录)。
pub async fn emit_flow_projection(
    state: &AppState,
    flow_cred: &str,
    ciba_state: agent_auth_ciba::CibaState,
) {
    let key = flow_credential_fingerprint(state, flow_cred);
    let seq = agent_auth_ciba::ciba_state_seq(ciba_state);
    let st = agent_auth_ciba::ciba_state_str(ciba_state);
    if let Err(e) = state.authz_events.emit(&key, seq, st).await {
        eprintln!("AUTHZ_EVENT_EMIT_FAIL flow seq={seq} state={st} err={e:?}");
    }
}

pub fn flow_credential_fingerprint(state: &AppState, flow_cred: &str) -> String {
    session_token_hash(&state.server_secret, flow_cred)
}

// ---- 查询端点 ----

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// 会话对外视图(不含 session_token_hash 等敏感内部字段)。
#[derive(serde::Serialize)]
struct SessionView {
    session_id: String,
    client_id: String,
    state: String,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<serde_json::Value>,
}

fn view(rec: &AuthzSessionRecord, now: i64) -> SessionView {
    // fail-closed 过期:读时若已过 expires_at,对外呈 expired(C10.4;不改库,读投影)。
    let state = if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, rec.expires_at)
        && !AuthzState::parse(&rec.state)
            .map(|s| s.is_terminal())
            .unwrap_or(false)
    {
        AuthzState::Expired.as_str().to_string()
    } else {
        rec.state.clone()
    };
    SessionView {
        session_id: rec.session_id.clone(),
        client_id: rec.client_id.clone(),
        state,
        sequence: rec.sequence,
        last_error: rec
            .last_error
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok()),
    }
}

#[derive(Deserialize, IntoParams)]
pub struct ListQuery {
    /// confidential 客户端发现自己名下会话:MUST = "me"(魔术值=当前认证身份)。
    pub client_id: String,
    /// 调用方 client_id(client_secret_post)。
    #[serde(default)]
    pub auth_client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct SessionClientAuthForm {
    #[serde(default)]
    pub auth_client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct SessionListForm {
    /// MUST be "me"; cross-client enumeration is not supported.
    pub client_id: String,
    #[serde(default)]
    pub auth_client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
}

/// 统一 404(未命中/无权/归属不符;响应体一致,不泄露存在性,C6.2)。
fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// `GET /sessions/{session_id}`(C6.1/C6.2)。
#[utoipa::path(
    get, path = "/sessions/{session_id}", tag = "sessions",
    params(("session_id" = String, Path, description = "授权会话 id")),
    responses(
        (status = 200, description = "会话状态(含 last_error 若有)"),
        (status = 404, description = "未命中/无权/归属不符(统一 404,不泄露存在性)")
    )
)]
pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    get_session_with_clock(
        State(state),
        headers,
        Path(session_id),
        crate::token::current_unix_secs_pub,
        || {},
    )
    .await
}

async fn get_session_with_clock<N, H>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    clock: N,
    after_authority_read: H,
) -> axum::response::Response
where
    N: Fn() -> i64,
    H: FnOnce(),
{
    // tenant 分区(spec 020 §2.3):会话按 tenant 隔离,从入站 Host 派生(flag 关=空 tenant;
    // 控制面 Host→400 fail-closed)。绝不跨租户命中他租户会话(评审 codex Blocker:GSI/PK 均 tpk)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !state.region.owns_id(&session_id) {
        return not_found();
    }
    let rec = match state.authz_sessions.get(&tenant, &session_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(), // 不存在 → 404
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    after_authority_read();

    // 鉴权二选一。(a) session_token(Bearer,常量时间比对)。
    if let Some(tok) = bearer(&headers) {
        if session_token_matches(&state.server_secret, &tok, &rec.session_token_hash) {
            return Json(view(&rec, clock())).into_response();
        }
        // token 不匹配 → 统一 404(不泄露"会话存在但 token 错")。
        return not_found();
    }

    // (b) confidential client 认证 + 归属校验:GET /sessions/{id} 用 Basic(无 query 凭证)。
    // 复用 client_auth:调用方须是 owner client 且认证通过。
    if let Ok(caller) = confidential_caller(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Session(&session_id),
        &headers,
        None,
        crate::client_auth::PresentedClientAuth::new(None, None, None),
    )
    .await
    {
        if caller == rec.client_id {
            return Json(view(&rec, clock())).into_response();
        }
        return not_found(); // 认证了但不是 owner → 404(不泄露归属)
    }

    // 既无 session_token 也无 client 认证 → 绝不只凭 id 放行(C6.1)。
    not_found()
}

/// 校验 confidential 调用方,返回认证通过的 client_id。
/// 调用方 id:优先 Basic username;否则 `auth_client_id`(client_secret_post 场景)。
/// secret:Basic 头 / `form_secret`(post)。public(none)不算 confidential。
async fn confidential_caller(
    state: &AppState,
    tenant: &str,
    endpoint: crate::client_auth::ClientAuthEndpoint<'_>,
    headers: &HeaderMap,
    auth_client_id: Option<&str>,
    presented: crate::client_auth::PresentedClientAuth<'_>,
) -> Result<String, crate::client_auth::ClientAuthError> {
    let caller_id = crate::client_auth::resolve_client_id_with_assertion(
        auth_client_id,
        headers,
        presented.client_assertion,
    )?
    .ok_or(crate::client_auth::ClientAuthError::InvalidClient(
        "client identity required",
    ))?;
    let client = state
        .clients
        .get(tenant, &caller_id)
        .await
        .map_err(|_| crate::client_auth::ClientAuthError::TemporarilyUnavailable)?
        .ok_or(crate::client_auth::ClientAuthError::InvalidClient(
            "unknown client",
        ))?;
    if !client.is_confidential_auth_client() {
        return Err(crate::client_auth::ClientAuthError::InvalidClient(
            "confidential client required",
        ));
    }
    let client = crate::client_auth::authenticate_loaded_snapshot(
        state, tenant, endpoint, &client, headers, presented,
    )
    .await?;
    if !client.is_confidential_auth_client() {
        return Err(crate::client_auth::ClientAuthError::InvalidClient(
            "confidential client required",
        ));
    }
    Ok(client.client_id)
}

/// `GET /sessions?client_id=me`(C6.1 confidential 发现路径)。
#[utoipa::path(
    get, path = "/sessions", tag = "sessions",
    params(ListQuery),
    responses(
        (status = 200, description = "自己名下会话 id 列表"),
        (status = 400, description = "client_id 非 me(不支持跨客户端查询)"),
        (status = 401, description = "调用方认证失败(非 confidential)")
    )
)]
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    // 只支持 me 魔术值(当前认证身份);传具体 id 拒(防跨客户端查询)。
    if q.client_id != "me" {
        return (StatusCode::BAD_REQUEST, "client_id must be 'me'").into_response();
    }
    // tenant 分区(spec 020 §2.3):从入站 Host 派生;confidential_caller 内部亦按同 tenant 校 client。
    // list_by_client 的 GSI Query MUST 按 tpk(tenant, client_id) 过滤,绝不跨租户列他租户会话
    // (评审 codex Blocker:同逻辑 client_id 在不同租户下必须隔离)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let caller = match confidential_caller(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Sessions,
        &headers,
        q.auth_client_id.as_deref(),
        crate::client_auth::PresentedClientAuth::new(q.client_secret.as_deref(), None, None),
    )
    .await
    {
        Ok(caller) => caller,
        Err(crate::client_auth::ClientAuthError::TemporarilyUnavailable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
        }
        Err(crate::client_auth::ClientAuthError::ServerMisconfigured) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "server misconfigured").into_response()
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                "confidential client auth required",
            )
                .into_response()
        }
    };
    match state.authz_sessions.list_by_client(&tenant, &caller).await {
        Ok(ids) => Json(serde_json::json!({
            "sessions": ids
                .into_iter()
                .filter(|id| state.region.owns_id(id))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

/// `POST /sessions?` equivalent using form credentials for private_key_jwt.
#[utoipa::path(
    post, path = "/sessions", tag = "sessions",
    request_body(content = SessionListForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "自己名下会话 id 列表"),
        (status = 400, description = "client_id 非 me"),
        (status = 401, description = "调用方认证失败")
    )
)]
pub async fn list_sessions_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SessionListForm>,
) -> impl IntoResponse {
    if form.client_id != "me" {
        return (StatusCode::BAD_REQUEST, "client_id must be 'me'").into_response();
    }
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let caller = match confidential_caller(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Sessions,
        &headers,
        form.auth_client_id.as_deref(),
        crate::client_auth::PresentedClientAuth::new(
            form.client_secret.as_deref(),
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
        ),
    )
    .await
    {
        Ok(caller) => caller,
        Err(crate::client_auth::ClientAuthError::TemporarilyUnavailable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
        }
        Err(crate::client_auth::ClientAuthError::ServerMisconfigured) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "server misconfigured").into_response()
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                "confidential client auth required",
            )
                .into_response()
        }
    };
    match state.authz_sessions.list_by_client(&tenant, &caller).await {
        Ok(ids) => Json(serde_json::json!({
            "sessions": ids
                .into_iter()
                .filter(|id| state.region.owns_id(id))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    }
}

/// `POST /sessions/{session_id}` supports private_key_jwt without query credentials.
#[utoipa::path(
    post, path = "/sessions/{session_id}", tag = "sessions",
    params(("session_id" = String, Path, description = "授权会话 id")),
    request_body(content = SessionClientAuthForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "会话状态"),
        (status = 404, description = "未命中/无权/归属不符")
    )
)]
pub async fn get_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Form(form): Form<SessionClientAuthForm>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !state.region.owns_id(&session_id) {
        return not_found();
    }
    let rec = match state.authz_sessions.get(&tenant, &session_id).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return not_found(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    match confidential_caller(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Session(&session_id),
        &headers,
        form.auth_client_id.as_deref(),
        crate::client_auth::PresentedClientAuth::new(
            form.client_secret.as_deref(),
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
        ),
    )
    .await
    {
        Ok(caller) if caller == rec.client_id => {
            Json(view(&rec, crate::token::current_unix_secs_pub())).into_response()
        }
        Err(crate::client_auth::ClientAuthError::TemporarilyUnavailable) => {
            (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
        }
        Err(crate::client_auth::ClientAuthError::ServerMisconfigured) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "server misconfigured").into_response()
        }
        Ok(_) | Err(_) => not_found(),
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_session, get_session_post))
        .routes(routes!(list_sessions, list_sessions_post))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{AuthzSessionStore, UserStatus, UsersStore};
    use agent_auth_authn::authz_session::ProjectionEvent;
    use std::sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn authoritative_session_record_and_projection_share_monotonic_sequence() {
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let mut state = AppState::dev("localhost");
        state.authz_events = Arc::new(crate::state::AuthzEventSinkImpl::Memory(events.clone()));

        let (session_id, _) = create_session(
            &state,
            "",
            "client",
            AuthzState::PendingConsent,
            crate::current_unix_secs(),
        )
        .await
        .expect("authorization session");
        let record = state
            .authz_sessions
            .get("", &session_id)
            .await
            .expect("authoritative session read")
            .expect("persisted authorization session");
        assert_eq!(record.state, AuthzState::PendingConsent.as_str());
        assert_eq!(record.sequence, 1);
        assert_eq!(
            events.lock().await.as_slice(),
            [
                ProjectionEvent {
                    session_id: session_id.clone(),
                    sequence: 0,
                    state: AuthzState::Created.as_str().to_string(),
                },
                ProjectionEvent {
                    session_id,
                    sequence: 1,
                    state: AuthzState::PendingConsent.as_str().to_string(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn session_get_resamples_expiry_after_authority_read() {
        let state = AppState::dev("localhost");
        let (session_id, session_token) = create_session(
            &state,
            "",
            "client",
            AuthzState::PendingConsent,
            1_000 - AUTHZ_SESSION_TTL_SECS,
        )
        .await
        .expect("authorization session");
        let now = Arc::new(AtomicI64::new(999));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {session_token}").parse().unwrap(),
        );

        let response = get_session_with_clock(
            State(state),
            headers,
            Path(session_id),
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
            {
                let now = now.clone();
                move || now.store(1_000, Ordering::SeqCst)
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], AuthzState::Expired.as_str());
    }

    #[test]
    fn c6_2_session_token_path_uses_hmac_and_constant_time_comparison() {
        let endpoint_source = include_str!("authz_session.rs");
        let bearer_branch = endpoint_source
            .split_once("// 鉴权二选一。(a) session_token(Bearer,常量时间比对)。")
            .expect("bearer branch start")
            .1
            .split_once("// (b) confidential client 认证 + 归属校验")
            .expect("bearer branch end")
            .0;
        let normalized = bearer_branch.split_whitespace().collect::<String>();
        assert_eq!(
            normalized,
            "ifletSome(tok)=bearer(&headers){ifsession_token_matches(&state.server_secret,&tok,&rec.session_token_hash){returnJson(view(&rec,clock())).into_response();}//token不匹配→统一404(不泄露\"会话存在但token错\")。returnnot_found();}",
            "the bearer branch must have one fail-closed verification path"
        );

        let authn_source = include_str!("../../authn/src/authz_session.rs");
        let matcher_body = authn_source
            .split_once("pub fn session_token_matches(")
            .expect("session_token_matches source")
            .1
            .split_once("{\n")
            .expect("session_token_matches body start")
            .1
            .split_once("\n}\n")
            .expect("session_token_matches body end")
            .0;
        assert_eq!(
            matcher_body.split_whitespace().collect::<String>(),
            "token_hash_eq(&session_token_hash(server_secret,presented_token),expected_hash,)",
            "the public matcher must only HMAC-normalize then use token_hash_eq"
        );

        let compare_body = authn_source
            .split_once("pub fn token_hash_eq(")
            .expect("token_hash_eq source")
            .1
            .split_once("{\n")
            .expect("token_hash_eq body start")
            .1
            .split_once("\n}\n")
            .expect("token_hash_eq body end")
            .0;
        assert_eq!(
            compare_body.split_whitespace().collect::<String>(),
            "let(a,b)=(a.as_bytes(),b.as_bytes());ifa.len()!=b.len(){returnfalse;}a.ct_eq(b).into()",
            "token_hash_eq must remain an exact length guard followed by ConstantTimeEq"
        );
    }

    #[tokio::test]
    async fn user_binding_is_stable_and_removes_a_session_after_erasure_wins() {
        let state = AppState::dev("localhost");
        let email = "authz-owner@example.com";
        let user_id = format!("user:{email}");
        state.seed_dev_user(email).await;

        let (session_id, _) = create_session(
            &state,
            "",
            "client",
            AuthzState::PendingConsent,
            crate::current_unix_secs(),
        )
        .await
        .unwrap();
        assert!(bind_user(&state, "", &session_id, &user_id).await);
        assert_eq!(
            state
                .authz_sessions
                .get("", &session_id)
                .await
                .unwrap()
                .unwrap()
                .user_id
                .as_deref(),
            Some(user_id.as_str())
        );
        assert!(state
            .authz_sessions
            .bind_user(
                "",
                &session_id,
                "user:other@example.com",
                crate::current_unix_secs(),
            )
            .await
            .unwrap()
            .is_none());

        let (late_session_id, _) = create_session(
            &state,
            "",
            "client",
            AuthzState::PendingConsent,
            crate::current_unix_secs(),
        )
        .await
        .unwrap();
        state
            .users
            .set_status("", &user_id, UserStatus::Tombstoned, 1)
            .await
            .unwrap();
        assert!(!bind_user(&state, "", &late_session_id, &user_id).await);
        assert!(state
            .authz_sessions
            .get("", &late_session_id)
            .await
            .unwrap()
            .is_none());

        let (deleted_user_session_id, _) = create_session(
            &state,
            "",
            "client",
            AuthzState::PendingConsent,
            crate::current_unix_secs(),
        )
        .await
        .unwrap();
        let deleted_user_id = "user:deleted-authz-owner@example.com";
        assert!(!bind_user(&state, "", &deleted_user_session_id, deleted_user_id).await);
        assert!(state
            .authz_sessions
            .get("", &deleted_user_session_id)
            .await
            .unwrap()
            .is_none());
    }
}
