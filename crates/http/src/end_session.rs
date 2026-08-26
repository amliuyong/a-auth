//! RP-initiated logout `/end-session`(spec 003 C9.6,P1a)。OIDC RP-Initiated Logout。
//!
//! GET + POST 双支持(OIDC 强制 GET;POST 防 Referer 泄露 id_token_hint)。行为:
//! - 清 AS 会话:删 SessionStore 记录 + Set-Cookie 同属性 Max-Age=0(属性不一致浏览器不清)。
//! - `id_token_hint`(可选):带则校验(RS256/ES256 签名 + 未过期 + aud=本 client),**无效/过期 → 拒不清**
//!   (防伪造 hint 强制登出受害者);不带则按当前 cookie 清(OIDC 允许)。
//! - `post_logout_redirect_uri`(可选):按 client 注册的 `post_logout_redirect_uris` **精确匹配**,
//!   未注册拒;client 由 id_token_hint.aud 或显式 client_id 定;无法定 client 不重定向;带回跳 echo state。
//! - 联动上游登出:仅联邦会话(会话标 upstream_idp_id)——P1 无联邦,占位不做。
//!
//! 决策真相源 docs/DESIGN §7 / §1 端点表 / CONFORMANCE C9.6。

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{ClientStore, SessionStore, Signer};
use crate::state::AppState;

const SESSION_COOKIE: &str = "__Host-agent_auth_session";

#[derive(Deserialize, IntoParams, utoipa::ToSchema, Default)]
pub struct EndSessionParams {
    /// 可选:上次签发的 ID token(校验后据 aud 定 client)。
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// 可选:显式 client_id(无 id_token_hint 时定 client 用)。
    #[serde(default)]
    pub client_id: Option<String>,
    /// 可选:登出后回跳(须 ∈ client 注册的 post_logout_redirect_uris)。
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    /// 可选:回跳时 echo。
    #[serde(default)]
    pub state: Option<String>,
}

/// 清会话 cookie 的 Set-Cookie(与建 cookie 同属性 + Max-Age=0,否则浏览器不清)。
fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn unverified_hint_aud(hint: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let mut parts = hint.split('.');
    let (_header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if signature.is_empty() || parts.next().is_some() {
        return None;
    }
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    crate::verify::single_aud(&claims)
}

/// GET /end-session。
#[utoipa::path(
    get, path = "/end-session", tag = "logout",
    params(EndSessionParams),
    responses(
        (status = 303, description = "已登出(清 cookie);带合法 post_logout_redirect_uri 时回跳"),
        (status = 400, description = "id_token_hint 无效 / post_logout_redirect_uri 未注册")
    )
)]
pub async fn end_session_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<EndSessionParams>,
) -> axum::response::Response {
    handle(state, headers, p).await
}

/// POST /end-session(参数从 form body 取;防 Referer 泄露 id_token_hint)。
#[utoipa::path(
    post, path = "/end-session", tag = "logout",
    request_body(content = EndSessionParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 303, description = "已登出"),
        (status = 400, description = "id_token_hint 无效 / post_logout_redirect_uri 未注册")
    )
)]
pub async fn end_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(p): Form<EndSessionParams>,
) -> axum::response::Response {
    handle(state, headers, p).await
}

async fn handle(
    state: AppState,
    headers: HeaderMap,
    p: EndSessionParams,
) -> axum::response::Response {
    let now = crate::token::current_unix_secs_pub();
    // tenant 分区(spec 020 §2.3):会话/client 查询按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // 1. id_token_hint(若带)MUST 校验;无效 → 拒不清会话(防伪造 hint 强制登出)。
    //    校验通过后取其 aud 作为 client 身份来源。
    let mut hint_client: Option<String> = None;
    if let Some(hint) = p.id_token_hint.as_deref() {
        let Some(aud) = unverified_hint_aud(hint) else {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: id_token_hint 无效",
            )
                .into_response();
        };
        let registered = matches!(state.clients.get(&tenant, &aud).await, Ok(Some(_)));
        let mismatch = matches!(&p.client_id, Some(client_id) if client_id != &aud);
        let issuer = crate::hostutil::issuer_host(&headers)
            .and_then(|host| agent_auth_discovery::derive_issuer(&host, &state.form).ok());
        if !registered || mismatch || issuer.is_none() {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: id_token_hint 无效(aud 非注册 client / 与 client_id 不符)",
            )
                .into_response();
        }
        let signer = match crate::tenant_keys::signer_or_503(&state, &tenant).await {
            Ok(signer) => signer,
            Err(response) => return response,
        };
        let ec_jwks = match signer.public_jwks().await {
            Ok(keys) => keys,
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "signer unavailable").into_response()
            }
        };
        let rsa_jwks = match signer.public_rsa_jwks().await {
            Ok(keys) => keys,
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "signer unavailable").into_response()
            }
        };
        let mut jwks = ec_jwks.iter().map(crate::jwks::to_jwk).collect::<Vec<_>>();
        jwks.extend(rsa_jwks.iter().map(crate::jwks::rsa_to_jwk));
        match crate::verify::verify_authorization_id_token_hint(
            hint,
            &jwks,
            issuer.as_ref().expect("checked issuer").as_str(),
            &aud,
            now,
        ) {
            Ok(_) => hint_client = Some(aud),
            Err(_) => {
                // 伪造/过期/篡改 → 拒,MUST NOT 清会话。
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_request: id_token_hint 无效",
                )
                    .into_response();
            }
        }
    }

    // 2. 清 AS 会话:删 SessionStore 记录(据当前 cookie)+ Set-Cookie 清除。
    // fail-closed(评审 codex HIGH):删记录失败 → 不当作登出成功(旧 cookie 仍可重放)→ 503。
    if let Some(sid) = cookie(&headers, SESSION_COOKIE) {
        if state.sessions.delete(&tenant, &sid).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::SET_COOKIE, clear_cookie())],
                "temporarily_unavailable: 会话删除失败,请重试",
            )
                .into_response();
        }
    }
    let clear = clear_cookie();

    // 3. post_logout_redirect_uri(若带)按注册精确匹配;client 由 hint.aud 或显式 client_id 定。
    if let Some(plr) = p.post_logout_redirect_uri.as_deref() {
        let client_id = hint_client.as_deref().or(p.client_id.as_deref());
        let Some(cid) = client_id else {
            // 无法确定 client → **本地登出已完成**(会话已清),只是不能安全回跳 → 200 不重定向
            // (评审 codex/Kiro:返 400 会让客户端误以为登出失败)。
            return (
                StatusCode::OK,
                [(header::SET_COOKIE, clear)],
                "logged out (no client identity; redirect skipped)",
            )
                .into_response();
        };
        let registered = match state.clients.get(&tenant, cid).await {
            Ok(Some(c)) => c.post_logout_redirect_uris.iter().any(|u| u == plr),
            _ => false,
        };
        if !registered {
            // 未注册的回跳值 MUST 拒(防开放重定向);本地登出仍已完成。
            return (
                StatusCode::BAD_REQUEST,
                [(header::SET_COOKIE, clear)],
                "invalid_request: post_logout_redirect_uri 未注册",
            )
                .into_response();
        }
        // 精确匹配通过 → 回跳(echo state)+ 清 cookie。
        let mut url = plr.to_string();
        if let Some(st) = &p.state {
            let sep = if url.contains('?') { '&' } else { '?' };
            url.push_str(&format!("{sep}state={}", crate::authorize::pct_encode(st)));
        }
        return ([(header::SET_COOKIE, clear)], Redirect::to(&url)).into_response();
    }

    // 4. 无回跳 → 只清会话,返回简单确认(清 cookie 头)。
    (StatusCode::OK, [(header::SET_COOKIE, clear)], "logged out").into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(end_session_get))
        .routes(routes!(end_session_post))
}
