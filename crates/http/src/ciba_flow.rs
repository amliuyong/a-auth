//! CIBA(Client-Initiated Backchannel Authentication,OpenID)异步授权 —— spec 013 C7b.1–C7b.3。
//!
//! 编排纯逻辑(`agent_auth_ciba`:hint 分类 / poll_decision / 态映射)+ CibaStore,不重述规则:
//! - `POST /bc-authorize`:强制 `login_hint`/`login_hint_token`/`id_token_hint` **三选一**(缺/多则拒,
//!   C7b.1),归一到内部 `user_id`,铸 `auth_req_id`(高熵不透明),下发 `expires_in`/`interval`。
//! - `/token` `grant_type=urn:openid:params:grant-type:ciba`:凭 `auth_req_id` 轮询(`poll_decision`
//!   矩阵:authorization_pending / slow_down / expired_token / access_denied / invalid_grant /
//!   IssueToken,C7b.2)。批准(status=approved)后签 **3LO 形态** access token(sub=用户、sub_type=user)。
//! - 轮询链**完全不经过 `/sessions`**(C7b.3):poll 只读写 CibaStore,`/sessions` 仅可观测旁路。
//!
//! **并发/一次性**与 device flow 同源(device 评审 F1/F2 教训):consume/decide/claim_poll 全走
//! 字段级/条件 CAS,绝不整对象读-改-写。批准页 handler(§2b)+ per-user 节流(§3)属后续增量。
//!
//! 决策真相源 docs §5.2 / spec 013 C7b.1–C7b.3 + CONFORMANCE C7b。

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::{Deserialize, Serialize};

use crate::poll_claim::{classify_poll_claim, PollClaimAction};
use crate::ports::{CibaAuthRequest, CibaStore, ClientStore};
use crate::state::AppState;
use crate::token::{err, sign_tenant_access_token, AccessTokenClaims, TokenResponse};
use agent_auth_ciba::{normalize_key, poll_decision, HintKind, PollOutcome, PollStatus};
use agent_auth_discovery::derive_issuer;
use agent_auth_token::SubType;

/// CIBA grant type(OpenID CIBA)。
pub(crate) const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";
/// auth_req 有效期(秒;≤有效期,docs §2.1)。
const CIBA_AUTH_REQ_TTL_SECS: i64 = 600;
/// 轮询间隔(秒)。
const CIBA_POLL_INTERVAL: i64 = 5;
/// per-login_hint 批准疲劳冷却窗(秒;与 magic-link per-email 冷却 C9.1 同量级,C7b.6)。
const CIBA_AUTHORIZE_COOLDOWN_SECS: i64 = 60;
/// binding_message 最大长度(≤200 字符,批准页展示;超长拒,C7b.6)。
const BINDING_MESSAGE_MAX: usize = 200;
/// login_hint 最大长度(防畸形/超长串造记录;email/opaque user_id 远短于此,2b.5)。
const LOGIN_HINT_MAX: usize = 256;

/// `POST /bc-authorize` 请求(OpenID CIBA §7.1;用户标识三选一)。
#[derive(Deserialize, utoipa::ToSchema)]
pub struct BcAuthorizeRequest {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    /// 用户标识三型(C7b.1,MUST 恰一个)。
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub login_hint_token: Option<String>,
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// 可选 binding_message(≤200 字符;批准页展示,C7b.6)。
    #[serde(default)]
    pub binding_message: Option<String>,
    /// client_secret(confidential ping/push client 走 client_secret_post 认证时;basic 走 Authorization 头)。
    #[serde(default)]
    pub client_secret: Option<String>,
    /// RFC 7523 private_key_jwt authentication.
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
    /// per-request `client_notification_token`(OIDC CIBA Core §7.1;ping/push MUST 带,≥128-bit、≤1024)。
    /// AS 回调时放 `Authorization: Bearer` 供 client 验回调来源。poll 不需要。
    #[serde(default)]
    pub client_notification_token: Option<String>,
}

/// `POST /bc-authorize` 响应(OpenID CIBA §7.3)。
#[derive(Serialize, utoipa::ToSchema)]
pub struct BcAuthorizeResponse {
    pub auth_req_id: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// login_hint 三型分派 + `login_hint` 归一/格式校验(**纯逻辑**,C7b.1 / spec 013 §0.3/§2b.5)。
///
/// **login_hint 语义 = 用户面 email 标识**(DESIGN §5.2:"邮箱等常见标识";用户拍板 2026-07-12)。
/// 本函数只做无 IO 的归一 + 格式闸,返回**归一后的 email**(trim+lowercase);存在性解析(查 users 表
/// 换内部 `user_id`)在 handler 里异步做(见 `resolve_user_id_via_store`)。归一口径与 magic-link 登录
/// (`login.rs`)+ users 表 GSI email-index key 一致——节流键、批准归属校验、token sub 派生三者同源。
///
/// 分类后的用户标识输入(**纯分类结果**,IO/验签在 handler 的异步 `resolve_hint_to_user_id` 做)。
/// H2(评审 Kiro/codex):分类保持纯函数(可单测"恰一个 hint"不变量),验签+jti 解析放异步层。
enum HintInput {
    /// `login_hint`:已归一(trim+lowercase)的 email,待查 users 表定位 user_id。
    Email(String),
    /// `id_token_hint`:原始 id_token JWT,待 RS256 验签(aud==client_id)+ jti→user_id 映射。
    IdTokenHint(String),
}

/// **纯分类 + login_hint 格式闸**(无 IO):恰一个 hint → 分类;login_hint 顺带做纯格式校验(长度/控制字符)。
/// `login_hint_token`(AS 自签 opaque)本切片仍 fail-closed 未实现;0/多个 hint → 拒(C7b.1)。
fn classify_hint(req: &BcAuthorizeRequest) -> Result<HintInput, &'static str> {
    match HintKind::classify(
        req.login_hint.as_deref(),
        req.login_hint_token.as_deref(),
        req.id_token_hint.as_deref(),
    ) {
        Some(HintKind::LoginHint) => {
            let email = req
                .login_hint
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            // 格式校验(防造畸形记录/存储滥用 + 挡明显非 email):非空 + 长度上限 + 无控制字符。
            if email.is_empty() {
                Err("login_hint 空")
            } else if email.len() > LOGIN_HINT_MAX {
                Err("login_hint 过长")
            } else if email.bytes().any(|b| b < 0x20 || b == 0x7f) {
                Err("login_hint 含控制字符")
            } else {
                Ok(HintInput::Email(email))
            }
        }
        // id_token_hint:原始 JWT 交给异步层验签+解析(不在纯分类里做 IO/密码学)。
        Some(HintKind::IdTokenHint) => Ok(HintInput::IdTokenHint(
            req.id_token_hint.as_deref().unwrap_or("").to_string(),
        )),
        // login_hint_token(AS 自签 opaque)本切片仍 fail-closed(独立 token 型,后续切片)。
        Some(HintKind::LoginHintToken) => Err("login_hint_token 验签未实现(fail-closed)"),
        // 0 个或 >1 个用户标识 → C7b.1 拒。
        None => Err("MUST 恰带一个用户标识(login_hint/login_hint_token/id_token_hint)"),
    }
}

/// hint 解析的错误(handler 映到 OAuth 错误码 + HTTP 状态)。
enum HintError {
    /// 用户标识无法解析成合法用户(未注册 / 验签失败 / 无 jti 映射 / 映射过期 / 用户被禁)→ 400 invalid_request。
    Invalid(&'static str),
    /// 依赖存储/JWKS 瞬时不可用 → 503 temporarily_unavailable(不降级 400,评审 M1)。
    Unavailable,
}

/// **异步归一:HintInput → 内部 `user_id`**(spec 013 §2b.5;所有 hint 型汇聚到同一 user_id 出口)。
///
/// - `Email`:查 users 表 GSI(`resolve_user_id_via_store`);未注册 → Invalid,store 瞬时 → Unavailable。
/// - `IdTokenHint`(评审 codex High + Kiro H1,复用 011 subject 解析):
///   1. RS256 验签,**aud == 本请求 client_id**(codex High:CIBA 无源 Grant,不绑 aud 则他 client 的
///      id_token 可被重放当本 client 的 hint)——传 `Some(client_id)` 给 `verify_id_token`;
///   2. 取 jti → `JtiStore.get(jti_tenant, jti)`(jti tenant 空→"default",与 token-exchange/签发一致);
///   3. 校 `jrec.expires_at > now`(codex Med:过期映射不得解析出用户);
///   4. 返回 `jrec.user_id`。
///
/// 之后 handler 统一对返回的 user_id 过 `require_active_user`(Kiro H1:与 login_hint 的"须已注册"对称)。
async fn resolve_hint_to_user_id(
    state: &AppState,
    tenant: &str,
    as_issuer: &str,
    client_id: &str,
    hint: HintInput,
    now: i64,
) -> Result<String, HintError> {
    match hint {
        HintInput::Email(email) => match resolve_user_id_via_store(state, tenant, &email).await {
            Ok(u) => Ok(u),
            Err(HintResolveError::NotRegistered) => {
                Err(HintError::Invalid("login_hint 未对应已注册用户"))
            }
            Err(HintResolveError::Unavailable) => Err(HintError::Unavailable),
        },
        HintInput::IdTokenHint(jwt) => {
            use crate::jti_authority::JtiAuthority;
            use crate::ports::Signer;
            // 1. RS256 验签 + aud==client_id(codex High)。RSA JWKS 取失败 → Unavailable(不降级)。
            let signer = state
                .tenant_keys
                .resolve(tenant)
                .await
                .map_err(|_| HintError::Unavailable)?;
            let rsa_keys = signer
                .public_rsa_jwks()
                .await
                .map_err(|_| HintError::Unavailable)?;
            let jwks: Vec<crate::jwks::Jwk> =
                rsa_keys.iter().map(crate::jwks::rsa_to_jwk).collect();
            // Verify signature and identity claims before checking Region ownership.
            // Temporal validation follows ownership so a delayed drill cannot pass
            // its previous-activation assertion merely because the token expired.
            let verified =
                crate::verify::verify_id_token_identity(&jwt, &jwks, as_issuer, Some(client_id))
                    .map_err(|_| {
                        HintError::Invalid("id_token_hint 验签失败(RS256/typ/iss/aud!=client_id)")
                    })?;
            let jti = verified
                .claims
                .get("jti")
                .and_then(|v| v.as_str())
                .ok_or(HintError::Invalid("id_token_hint 缺 jti(无法解析主体)"))?;
            if !state.region.owns_id(jti) {
                return Err(HintError::Invalid(
                    "id_token_hint belongs to a previous regional activation",
                ));
            }
            crate::verify::validate_id_token_time(&verified, now)
                .map_err(|_| HintError::Invalid("id_token_hint 时效校验失败(exp/nbf/iat)"))?;
            // 2. jti tenant(空→"default",与 token-exchange/签发侧一致;codex Med)。
            let jti_tenant = if tenant.is_empty() { "default" } else { tenant };
            let Some(jti_store) = state.jti_store.as_ref() else {
                // 本部署未启用 jti 映射 = 无法解析 id_token_hint 主体(fail-closed)。
                return Err(HintError::Invalid("本部署未启用 id_token_hint 主体解析"));
            };
            let jrec = match crate::jti_authority::read_current_jti(
                jti_store.as_ref(),
                jti_tenant,
                jti,
                crate::token::current_unix_secs_pub,
            )
            .await
            {
                Ok(JtiAuthority::Current(r)) => r,
                Ok(JtiAuthority::Missing) => {
                    return Err(HintError::Invalid("id_token_hint 无对应 jti 映射"))
                }
                Ok(JtiAuthority::Expired) => {
                    return Err(HintError::Invalid("id_token_hint 的 jti 映射已过期"))
                }
                Err(crate::ports::StoreError::Transient(_)) => return Err(HintError::Unavailable),
                Err(_) => return Err(HintError::Unavailable),
            };
            Ok(jrec.user_id)
        }
    }
}

/// login_hint(归一 email)→ 内部 `user_id` 的**存在性解析**(spec 013 §2b.5,用户拍板 2026-07-12)。
///
/// 查 users 表 GSI email-index:
/// - **命中** → 返回稳定 canonical `user_id`(legacy `user:{email}` 或随机 SCIM id;批准归属校验/token
///   sub 据此,与真实登录会话对齐);
/// - **未注册** → `Err(NotRegistered)`(用户拍板:未注册直接拒 `invalid_request`,不静默照发 auth_req_id;
///   接受"泄露 email 注册态"的枚举面换取"绝不造无法批准的僵尸记录");
/// - **store 瞬时不可用** → `Err(Unavailable)`(handler 映 503,fail-closed,不静默放行)。
enum HintResolveError {
    NotRegistered,
    Unavailable,
}

async fn resolve_user_id_via_store(
    state: &AppState,
    tenant: &str,
    email: &str,
) -> Result<String, HintResolveError> {
    use crate::ports::UsersStore;
    match state.users.get_by_email(tenant, email).await {
        Ok(Some(rec)) => Ok(rec.user_id),
        Ok(None) => Err(HintResolveError::NotRegistered),
        Err(_) => Err(HintResolveError::Unavailable),
    }
}

/// `POST /bc-authorize`(OpenID CIBA §7.1;spec 013 C7b.1)。
#[utoipa::path(
    post, path = "/bc-authorize", tag = "ciba",
    request_body(content = BcAuthorizeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "auth_req_id(CIBA)", body = BcAuthorizeResponse),
        (status = 400, description = "invalid_request(缺/多用户标识)/ 未知 client"),
        (status = 404, description = "CIBA 未在当前阶段启用")
    )
)]
pub async fn bc_authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<BcAuthorizeRequest>,
) -> impl IntoResponse {
    // 阶段门控(C1.2:/bc-authorize 是 P2 端点)。
    if !agent_auth_protocol::endpoint_available(state.phase, "/bc-authorize") {
        return (StatusCode::NOT_FOUND, "CIBA 未在当前阶段启用").into_response();
    }
    // issuer 派生(校 Host 合法)。id_token_hint 验签需以本 AS issuer 作 iss 校验,故捕获而非仅判 is_none。
    let Some(issuer) =
        crate::hostutil::issuer_host(&headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response();
    };
    // tenant 分区(spec 020 §2.3):client/user 解析按 tenant 隔离(auth_req_id 本身高熵不透明,不分区)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // client 必须存在。分两条准入路径(spec 013 §4):
    //   - **poll**(缺省 delivery_mode):须 **public**——CIBA poll 无 client 认证(靠 auth_req_id 高熵+一次性),
    //     拒 confidential/workload(与 device flow 同源,评审 F3)。
    //   - **ping/push**:须 **confidential** 且**过 client 认证**(auth_req_id 裸值不足取 confidential token,
    //     codex 二轮 High);投递按快照 delivery_mode/endpoint,须 ping/push 能力已上线(P3+gate)。
    // 快照(投递按此,不读当前 ClientRecord,防发起↔批准间 PATCH 篡改):
    let (snap_delivery_mode, snap_notification_endpoint): (Option<String>, Option<String>) =
        match state.clients.get(&tenant, &req.client_id).await {
            Ok(Some(c)) => {
                use agent_auth_workload::ClientType;
                let mode = c
                    .backchannel_token_delivery_mode
                    .as_deref()
                    .unwrap_or("poll");
                match mode {
                    "poll" => {
                        if c.client_type() != ClientType::Public {
                            return err(
                                StatusCode::BAD_REQUEST,
                                "unauthorized_client",
                                "CIBA poll 仅限 public client;confidential 须走 ping/push(client 认证)、workload 不走用户授权",
                            )
                            .into_response();
                        }
                        (None, None) // poll:无回调快照
                    }
                    "ping" | "push" => {
                        // 能力门控:未上线拒(与 DCR 一致;防注册后关 gate 仍可发起)。
                        if !state.ciba_ping_push_active() {
                            return err(
                                StatusCode::BAD_REQUEST,
                                "unauthorized_client",
                                "ping/push 投递当前未启用(需 Phase≥P3 且开启 ping/push 能力)",
                            )
                            .into_response();
                        }
                        // confidential + client 认证(codex 二轮 High:真做认证,非仅比对 client_id)。
                        if !c.is_confidential_auth_client() {
                            return err(
                                StatusCode::BAD_REQUEST,
                                "unauthorized_client",
                                "ping/push client MUST 是 confidential",
                            )
                            .into_response();
                        }
                        let c = match crate::client_auth::authenticate_loaded_snapshot(
                            &state,
                            &tenant,
                            crate::client_auth::ClientAuthEndpoint::BackchannelAuthentication,
                            &c,
                            &headers,
                            crate::client_auth::PresentedClientAuth::new(
                                req.client_secret.as_deref(),
                                req.client_assertion_type.as_deref(),
                                req.client_assertion.as_deref(),
                            ),
                        )
                        .await
                        {
                            Ok(client) => client,
                            Err(error) => return client_auth_error(error),
                        };
                        if !c.is_confidential_auth_client()
                            || !matches!(
                                c.backchannel_token_delivery_mode.as_deref(),
                                Some("ping" | "push")
                            )
                        {
                            return err(
                                StatusCode::BAD_REQUEST,
                                "unauthorized_client",
                                "authenticated client no longer permits CIBA ping/push",
                            )
                            .into_response();
                        }
                        // notification endpoint 快照(注册时已过 SSRF 结构校验;投递前再 DNS 复校)。
                        (
                            c.backchannel_token_delivery_mode.clone(),
                            c.backchannel_client_notification_endpoint.clone(),
                        )
                    }
                    _ => {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "server_error",
                            "client 投递模式非法(注册校验漏网)",
                        )
                        .into_response();
                    }
                }
            }
            Ok(None) => {
                return err(StatusCode::BAD_REQUEST, "invalid_client", "未知 client")
                    .into_response()
            }
            Err(crate::ports::StoreError::Transient(_)) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
            Err(_) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response()
            }
        };

    // ping/push MUST 带 per-request client_notification_token(OIDC CIBA Core §7.1,≥128-bit、≤1024)。
    let snap_notification_token: Option<String> = if snap_delivery_mode.is_some() {
        let Some(tok) = req.client_notification_token.as_deref() else {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "ping/push 请求 MUST 带 client_notification_token(CIBA Core §7.1)",
            )
            .into_response();
        };
        // 长度闸:≤1024 字符;熵由 client 负责(≥128-bit),此处校下限 ≥ 16 字节防空串/太短。
        if tok.len() > 1024 || tok.len() < 16 {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_notification_token 长度须 16..=1024",
            )
            .into_response();
        }
        Some(tok.to_string())
    } else {
        None
    };

    // binding_message 长度上限(C7b.6:带了才展示;这里只做入库前上限校验)。
    if let Some(bm) = req.binding_message.as_deref() {
        if bm.chars().count() > BINDING_MESSAGE_MAX {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_binding_message",
                "binding_message 过长(≤200 字符)",
            )
            .into_response();
        }
    }

    // 用户标识三选一 → **纯分类**(C7b.1;login_hint 顺带纯格式闸,不查库/不验签)。
    // 验签/查库放异步 `resolve_hint_to_user_id`(H2:分类保持纯,IO 在异步层)。
    let hint = match classify_hint(&req) {
        Ok(h) => h,
        Err(m) => return err(StatusCode::BAD_REQUEST, "invalid_request", m).into_response(),
    };

    let now = crate::token::current_unix_secs_pub();
    let auth_req_id = crate::token::new_jti(&state); // 高熵不透明串
    let scope: Vec<String> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    // CIBA 是 OIDC 流:请求 scope MUST 含 `openid`(评审 Kiro LOW-2;区别于 RFC 8628 device flow)。
    // 置于查库前:bad-scope 请求不触达 users 表 / 不做验签(省一次 IO + 不据以探测标识存在态)。
    if !scope.iter().any(|s| s == "openid") {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "CIBA 是 OIDC 流,scope MUST 含 openid",
        )
        .into_response();
    }

    // **验签前 per-client 粗兜底节流**(评审 codex Med:防"已知 public client_id 反复送非法
    // id_token_hint 逼本地 RSA 验签烧 CPU"的 DoS——per-user 冷却在 user_id 解析后才占,挡不住"验签前"的
    // 计算面)。复用 per-client 令牌桶(与 device flow 铸码节流同源):poll 无 client 认证、client_id 自称,
    // 此为粗兜底——轮换 client_id 归 per-IP/WAF 层(§3.2);此闸挡单 client_id 的验签放大。fail-open。
    // 置于 scope 校验后、hint 验签/查库前:合法请求正常放行,洪水在触达验签前被限。
    if let Some(resp) = crate::ratelimit_gate::check(&state, &tenant, &req.client_id).await {
        return resp;
    }

    // hint → 内部 user_id(spec 013 §2b.5):login_hint 查注册 / id_token_hint 验签+jti 映射(§ Requirement
    // id_token_hint 实现约束)。未注册/验签失败/无映射/映射过期 → invalid_request(不造僵尸批准记录);
    // JWKS/store 瞬时 → 503(评审 M1 不降级)。置于 scope 后、active-gate 与节流占窗前:非法/伪造标识不占
    // 受害者冷却窗(评审 M2 throttle-before-verify)。
    let user_id =
        match resolve_hint_to_user_id(&state, &tenant, issuer.as_str(), &req.client_id, hint, now)
            .await
        {
            Ok(u) => u,
            Err(HintError::Invalid(m)) => {
                return err(StatusCode::BAD_REQUEST, "invalid_request", m).into_response()
            }
            Err(HintError::Unavailable) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "用户目录 / JWKS 瞬时不可用",
                )
                .into_response()
            }
        };

    // **active-user gate(评审 Kiro H1 + codex 认同,spec 003 §1.4)**:解析出的 user_id 须过 gate——
    // 与 login_hint 的"须已注册用户"对称,并覆盖 id_token_hint 场景(jti 映射还在但用户已 disable/删除
    // → 拒,不造无法批准的僵尸记录)。Disabled/Tombstoned → invalid_request;查询失败 → 503。
    match crate::user_gate::require_active_user(&state, &tenant, &user_id).await {
        crate::user_gate::UserGate::Allowed => {}
        crate::user_gate::UserGate::Blocked => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "标识对应的用户不存在或已禁用",
            )
            .into_response()
        }
        crate::user_gate::UserGate::Unavailable => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "用户目录瞬时不可用",
            )
            .into_response()
        }
    }

    // 防批准疲劳节流(C7b.6,与 magic-link per-email 冷却 C9.1 对称):同一用户(归一 user_id)
    // 在冷却窗内狂发 /bc-authorize → 429(防 MFA 推送轰炸误触)。校在请求合法性通过后(不让非法请求
    // 占用受害者冷却窗)、落库前。**原子占用**(评审 codex/Kiro M1:check+mark 合一,防并发突发绕过):
    // try_arm_throttle 一次 CAS 完成"判窗 + 占窗",同一 user_id 并发只一个 true。
    // **节流键 tenant-aware**(评审 codex M2:`normalize_key(jti_tenant, user_id)` 长度前缀编码,
    // 防 SaaS 下同 `user:{email}` 跨租户冷却串扰;jti_tenant 空→"default" 与 hint 解析口径一致)。
    let throttle_tenant = if tenant.is_empty() {
        "default"
    } else {
        &tenant
    };
    let throttle_key = normalize_key(throttle_tenant, &user_id);
    match state
        .ciba
        .try_arm_throttle(&tenant, &throttle_key, now, CIBA_AUTHORIZE_COOLDOWN_SECS)
        .await
    {
        Ok(true) => {} // 占用成功 → 放行
        Ok(false) => {
            // 窗内 → 429。错误码用 temporarily_unavailable(评审 Kiro L2:`slow_down` 是 token 轮询
            // 端点的标准 polling 错误码,OIDC CIBA 未定义其用于 /bc-authorize;此处非轮询)。
            // Retry-After 用冷却窗上界(不补读精确剩余,足够;避免额外一次读)。
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    CIBA_AUTHORIZE_COOLDOWN_SECS.to_string(),
                )],
                axum::Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "同一用户批准请求过于频繁,请稍候(防批准疲劳,C7b.6)"
                })),
            )
                .into_response();
        }
        // 节流存储瞬时错误 → fail-open 放行(anti-abuse 闸优先可用性,非安全闸;评审 codex/Kiro 认可
        // 取舍。真机可加 Transient 计量,见 L3)。
        Err(_) => {}
    }

    let resources: Vec<String> = req.resource.iter().cloned().collect();

    let record = CibaAuthRequest {
        auth_req_id: auth_req_id.clone(),
        tenant: tenant.clone(),
        client_id: req.client_id.clone(),
        user_id,
        authz_session_id: None,
        scope,
        resources,
        binding_message: req.binding_message.clone(),
        interval: CIBA_POLL_INTERVAL,
        last_poll_at: None,
        expires_at: now + CIBA_AUTH_REQ_TTL_SECS,
        status: "pending".to_string(),
        consumed: false,
        // ping/push 投递快照(spec 013 §4:投递按此,不读当前 ClientRecord;client_notification_token 明文
        // 存 port 层[Memory dev],真机 DynamoStore MUST envelope-encrypt)。poll 时三者均 None。
        delivery_mode: snap_delivery_mode,
        notification_endpoint: snap_notification_endpoint,
        client_notification_token: snap_notification_token,
        password_credential_version: None,
    };
    if state.ciba.put(&tenant, record).await.is_err() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "存储瞬时不可用",
        )
        .into_response();
    }
    // 主动投影(spec 004 §3.3 / C6.5):CIBA 发起 = AuthorizationPending。哈希 auth_req_id 作投影键(不投原值)。
    crate::authz_session::emit_flow_projection(
        &state,
        &auth_req_id,
        agent_auth_ciba::CibaState::AuthorizationPending,
    )
    .await;

    Json(BcAuthorizeResponse {
        auth_req_id,
        expires_in: CIBA_AUTH_REQ_TTL_SECS,
        interval: CIBA_POLL_INTERVAL,
    })
    .into_response()
}

/// `/token` 的 `grant_type=urn:openid:params:grant-type:ciba` 轮询(OpenID CIBA §11;spec 013 C7b.2)。
/// 轮询链**不经过 `/sessions`**(C7b.3):只读写 CibaStore。
pub async fn handle_token(
    state: &AppState,
    headers: &HeaderMap,
    req: &crate::token::TokenRequest,
) -> axum::response::Response {
    let Some(auth_req_id) = req.auth_req_id.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "缺 auth_req_id").into_response();
    };
    if !state.region.owns_id(auth_req_id) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "auth_req_id belongs to another Region",
        )
        .into_response();
    }
    let Some(client_id) = req.client_id.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "缺 client_id").into_response();
    };
    // tenant 分区(spec 020 §2.3):client/user gate 按 tenant 隔离(auth_req_id 高熵不透明,不分区)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let record = match state.ciba.get(&tenant, auth_req_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return err(StatusCode::BAD_REQUEST, "invalid_grant", "auth_req_id 无效")
                .into_response()
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response()
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response()
        }
    };

    // confidential 认证契约(codex 二轮 High):若该 auth_req_id 关联 client 是 **confidential**(ping/push),
    // CIBA `/token` MUST 先做 client 认证——被截获的 auth_req_id 裸值 MUST NOT 足以让人取 confidential token。
    // public(poll)client 保持仅 client_id 比对(其安全靠 auth_req_id 高熵 + 一次性)。快照 delivery_mode 有值
    // 即 ping/push(confidential)。reload client 记录做认证(tombstone 闸在签发分支另做)。
    let authenticated_client = if record.delivery_mode.is_some() {
        match state.clients.get(&tenant, client_id).await {
            Ok(Some(c)) => {
                // **拒降级绕过(codex 提交前评审 Medium)**:ping/push 记录要求 confidential 认证,但若 client
                // 在发起后被元数据更新降级为 `auth_method=none`,verify_client_auth 对 none 会"无 secret 即过"→
                // 无认证签出 token。故先要求**当前** client 仍是 Confidential;降级为 public → 拒(不给 none 蒙混)。
                if !c.is_confidential_auth_client() {
                    return err(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "ping/push 记录要求 confidential 认证;client 已降级为非 confidential",
                    )
                    .into_response();
                }
                let c = match crate::client_auth::authenticate_loaded_snapshot(
                    state,
                    &tenant,
                    crate::client_auth::ClientAuthEndpoint::Token,
                    &c,
                    headers,
                    crate::client_auth::PresentedClientAuth::new(
                        req.client_secret.as_deref(),
                        req.client_assertion_type.as_deref(),
                        req.client_assertion.as_deref(),
                    ),
                )
                .await
                {
                    Ok(client) => client,
                    Err(error) => return client_auth_error(error),
                };
                if !c.is_confidential_auth_client() {
                    return err(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "ping/push 记录要求 confidential 认证;client 已降级为非 confidential",
                    )
                    .into_response();
                }
                Some(c)
            }
            Ok(None) => {
                return err(StatusCode::BAD_REQUEST, "invalid_client", "未知 client")
                    .into_response()
            }
            Err(crate::ports::StoreError::Transient(_)) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
            Err(_) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response()
            }
        }
    } else {
        None
    };

    let now = crate::token::current_unix_secs_pub();
    let status = match record.status.as_str() {
        "approved" => PollStatus::Approved,
        "denied" => PollStatus::Denied,
        _ => PollStatus::Pending,
    };
    let outcome = poll_decision(
        record.client_id == client_id, // 归属:presented client_id == 记录 client_id
        record.consumed,
        record.expires_at,
        now,
        record.last_poll_at,
        record.interval,
        status,
    );

    // C10.7:CIBA poll 的 form client_id 仍是调用方自报值。只有 artifact 归属与 confidential
    // client 认证通过后，才按记录中的权威 client_id 消费聚合桶；置于 claim_poll 前，429 不推进轮询槽位。
    if outcome != PollOutcome::InvalidGrant {
        if let Some(response) =
            crate::ratelimit_gate::check(state, &tenant, &record.client_id).await
        {
            return response;
        }
    }

    // 原子占用轮询槽位(除 InvalidGrant)。条件写绑定本次读到的 last_poll_at,并发 poll 只有
    // 一个可继续;过期仍按 poll_decision 的更高优先级返回。
    if outcome != PollOutcome::InvalidGrant {
        match classify_poll_claim(
            outcome,
            state
                .ciba
                .claim_poll(&tenant, auth_req_id, record.last_poll_at, now)
                .await,
        ) {
            PollClaimAction::Proceed => {}
            PollClaimAction::SlowDown => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "slow_down",
                    "轮询频率超过 interval",
                )
                .into_response()
            }
            PollClaimAction::TemporarilyUnavailable => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
            PollClaimAction::ServerError => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response()
            }
        }
    }

    match outcome {
        PollOutcome::IssueToken => {
            // tombstone 闸(spec 005 §9.3,C10.5):poll 签发前**不 reload client**(只比对 client_id 串),
            // 补一次 client tombstone 读——回收中的 client 拒签出 CIBA token(仅签发分支读,不放大每次 poll)。
            // 同时取 require_dpop(评审 H2:device/CIBA 也 MUST 尊重 client 的 require_dpop,不硬编码 false)。
            let issuance_client = if let Some(client) = authenticated_client {
                client
            } else {
                match state.clients.get(&tenant, client_id).await {
                    Ok(Some(client)) => client,
                    // **fail-closed(评审 codex/Kiro,与 device 对称)**:client 记录缺失 → 拒,不把读失败静默降级为
                    // require_dpop=false(否则 require_dpop 的 public poll client 在记录回收/读抖动窗拿到 bearer,
                    // H2 同类绕过)。此读在 consume 之前,无需 release_consume。
                    Ok(None) => {
                        return err(StatusCode::BAD_REQUEST, "invalid_client", "未知 client")
                            .into_response()
                    }
                    Err(_) => {
                        return err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "存储瞬时不可用",
                        )
                        .into_response()
                    }
                }
            };
            if issuance_client.is_tombstoned() {
                return err(StatusCode::BAD_REQUEST, "invalid_client", "client 已回收")
                    .into_response();
            };
            let require_dpop = issuance_client.require_dpop;
            // active-user gate(spec 003 §1.4):签发前查 user status——disable/tombstone 后拒签
            // CIBA token(**非批准 UI;在 consume 之前**,查询失败/被禁均不 consume,防绕过/防误烧)。
            // 所有人类 user:* 主体统一过 status gate(含联邦 canonical-user)。
            match crate::user_gate::require_active_user(state, &tenant, &record.user_id).await {
                crate::user_gate::UserGate::Allowed => {}
                crate::user_gate::UserGate::Blocked => {
                    return err(StatusCode::BAD_REQUEST, "access_denied", "account disabled")
                        .into_response()
                }
                crate::user_gate::UserGate::Unavailable => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "user status 查询失败",
                    )
                    .into_response()
                }
            }
            match crate::user_gate::require_password_authority_version(
                state,
                &tenant,
                &record.user_id,
                record.password_credential_version,
            )
            .await
            {
                crate::user_gate::PasswordGate::Allowed => {}
                crate::user_gate::PasswordGate::ChangeRequired => {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "password authority changed after approval",
                    )
                    .into_response()
                }
                crate::user_gate::PasswordGate::Unavailable => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "password authority 查询失败",
                    )
                    .into_response()
                }
            }
            // **先原子消费**(同 device 评审 F1:一次性须原子,防写失败/并发 TOCTOU 双发)。
            match state.ciba.consume(&tenant, auth_req_id).await {
                Ok(true) => {}
                Ok(false) => {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "auth_req_id 已使用",
                    )
                    .into_response();
                }
                Err(crate::ports::StoreError::Transient(_)) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "存储瞬时不可用",
                    )
                    .into_response();
                }
                Err(_) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "存储错误",
                    )
                    .into_response();
                }
            }
            // DPoP 绑定(spec 010 §5.2):有 proof → cnf.jkt;失败/重放 → 拒 + 释放消费(可重试)。
            let dpop_jkt = match crate::hostutil::issuer_host(headers)
                .and_then(|h| derive_issuer(&h, &state.form).ok())
            {
                Some(iss) => {
                    // 尊重 client 的 require_dpop(评审 H2:不硬编码 false;缺 proof 且 require_dpop→拒)。
                    match crate::dpop::resolve_dpop_binding(
                        state,
                        headers,
                        &tenant,
                        iss.as_str(),
                        require_dpop,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(resp) => {
                            let _ = state.ciba.release_consume(&tenant, auth_req_id).await;
                            return resp;
                        }
                    }
                }
                None => None,
            };
            let resp = issue_ciba_token(state, headers, &record, dpop_jkt.as_deref(), now).await;
            // 签名 503:字段级回滚 consumed(同 device,让客户端可重试)。
            if resp.1.is_err() {
                let _ = state.ciba.release_consume(&tenant, auth_req_id).await;
            } else {
                // 签发成功 → 记 client 最后使用日(spec 005 §9.2,C10.5)+ 主动投影 Complete(C6.5)。
                crate::token::touch_client_last_used(state, &tenant, client_id, now).await;
                crate::authz_session::emit_flow_projection(
                    state,
                    auth_req_id,
                    agent_auth_ciba::CibaState::Complete,
                )
                .await;
            }
            resp.0
        }
        other => {
            let code = other.error_code().unwrap_or("invalid_grant");
            // CIBA/RFC:轮询错误用 400 + 标准 error code(slow_down/authorization_pending 亦 400)。
            err(StatusCode::BAD_REQUEST, code, "CIBA 轮询").into_response()
        }
    }
}

fn client_auth_error(error: crate::client_auth::ClientAuthError) -> axum::response::Response {
    use crate::client_auth::ClientAuthError;

    match error {
        ClientAuthError::InvalidRequest(_) => err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            error.description(),
        )
        .into_response(),
        ClientAuthError::InvalidClient(_) => err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            error.description(),
        )
        .into_response(),
        ClientAuthError::TemporarilyUnavailable => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            error.description(),
        )
        .into_response(),
        ClientAuthError::ServerMisconfigured => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            error.description(),
        )
        .into_response(),
    }
}

/// 签 CIBA 批准后的 3LO access token(sub=用户、sub_type=user)。返回 (响应, 是否成功签发)。
async fn issue_ciba_token(
    state: &AppState,
    headers: &HeaderMap,
    record: &CibaAuthRequest,
    cnf_jkt: Option<&str>, // DPoP 绑定(spec 010 §5.2);None=bearer
    now: i64,
) -> (axum::response::Response, Result<(), ()>) {
    let issuer = match crate::hostutil::issuer_host(headers)
        .and_then(|h| derive_issuer(&h, &state.form).ok())
    {
        Some(i) => i,
        None => {
            return (
                err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response(),
                Err(()),
            )
        }
    };
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("ciba-token"),
    )
    .await
    {
        return (
            err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "issuer does not belong to tenant",
            )
            .into_response(),
            Err(()),
        );
    }
    // tenant 分区(spec 020 §2.3):Grant 落库按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return (resp, Err(())),
    };
    let credential_epoch =
        match crate::user_gate::active_user_epoch(state, &tenant, &record.user_id).await {
            Ok(epoch) => epoch,
            Err(crate::user_gate::UserGate::Blocked) => {
                return (
                    err(StatusCode::BAD_REQUEST, "invalid_grant", "account disabled")
                        .into_response(),
                    Err(()),
                )
            }
            Err(_) => {
                return (
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "user status 查询失败",
                    )
                    .into_response(),
                    Err(()),
                )
            }
        };
    // aud:单值 resource(有则)否则 /userinfo(与 device / code 路径同轴)。
    let aud = match record.resources.first() {
        Some(r) => r.clone(),
        None => format!("{}/userinfo", issuer.as_str()),
    };
    // sub:按形态派生(pairwise 用 aud sector;public=user_id)。
    let mode = crate::token::subject_mode(state.subject_type_for_tenant(&tenant));
    let sub = agent_auth_token::derive_user_sub(mode, &state.server_secret, &record.user_id, &aud);
    let scope_str = record.scope.join(" ");
    let jti = crate::token::new_jti(state);
    // Grant 接入(spec 011 §5.1 / 013;CIBA 同 3LO)。grant_id 签名前生成作 auth_grant、Grant 签名成功后
    // 落库(时序防孤儿)、fail-closed(CIBA 无 refresh 兜底)、有效期=access TTL、actor_allowlist=[]。与 device 同轴。
    let grant_id = crate::refresh_flow::new_family_id(state);
    if let Some(response) = crate::ratelimit_gate::kms_sign_tenant_gate(state, &tenant).await {
        return (response, Err(()));
    }
    if let Some(response) = crate::ratelimit_gate::kms_sign_gate(state).await {
        return (response, Err(()));
    }
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return (response, Err(())),
    };
    let jwt = match sign_tenant_access_token(
        state,
        headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: issuer.as_str(),
            sub: &sub,
            aud: &aud,
            client_id: &record.client_id,
            scope: &scope_str,
            jti: &jti,
            auth_grant: &grant_id, // 稳定 grant_id(introspect/`/grants` 据此定位吊销)
            sub_type: SubType::User, // CIBA = 3LO 用户
            authorization_details: &[], // CIBA 暂不接受 RAR 参数(spec 010 §4 仅 code flow 发行)
            cnf_jkt,
            auth_time: None,
            acr: None,
            now,
        },
        crate::security_event::SecurityActor::system("ciba-token"),
    )
    .await
    {
        Ok(j) => j,
        Err(crate::token::TokenSignError::Transient) => {
            return (
                crate::token::err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "签名瞬时失败,请重试",
                    1,
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            return (
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            return (
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "issuer does not belong to tenant",
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::Permanent) => {
            return (
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "签名失败",
                )
                .into_response(),
                Err(()),
            )
        }
    };
    // Grant 落库(签名成功后;fail-closed——CIBA 无 family/refresh 兜底,建 Grant 失败则 token 不可吊销 → 不签出)。
    let mut ciba_grant = agent_auth_grant::Grant {
        grant_id: grant_id.clone(),
        user_id: record.user_id.clone(),
        client_id: record.client_id.clone(),
        per_resource: record
            .resources
            .iter()
            .map(|r| agent_auth_grant::ResourceGrant {
                resource: r.clone(),
                scopes: record.scope.clone(),
                authorization_details: vec![],
            })
            .collect(),
        // effective/pv/ip/revision:flag 关默认空(spec 005 §7);flag 开由 apply_policy_to_grant 填(T7.5)。
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch,
        revision: 0,
        constraints: agent_auth_grant::GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: now + crate::token::ACCESS_TTL,
        },
        status: agent_auth_grant::GrantStatus::Active,
    };
    // T7.5:flag 开则 Cedar 预判收窄 effective + 打 pv 戳。fail-closed 分档(补强 ⑯):Transient→503 可重试;
    // Denied(有可评估单元被策略全 deny)→ 403 access_denied 永久拒。flag 关 no-op。
    if let Err(e) = crate::authz_gate::apply_policy_to_grant(state, &tenant, &mut ciba_grant).await
    {
        eprintln!("[authz] ciba Grant 策略预判失败(fail-closed):{e}");
        let resp = match e {
            crate::authz_gate::ApplyPolicyError::Denied(_) => {
                state
                    .record_security_event(crate::security_event::SecurityEventDraft::grant(
                        &tenant,
                        crate::security_event::SecurityActor::user(&record.user_id),
                        &grant_id,
                        crate::security_event::GrantAction::Deny,
                        crate::security_event::SecurityEventOutcome::Denied,
                    ))
                    .await;
                err(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "授权被策略拒绝(policy denies requested access)",
                )
            }
            crate::authz_gate::ApplyPolicyError::Transient(_) => err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "授权策略暂不可用,请重试",
            ),
        };
        return (resp.into_response(), Err(()));
    }
    if !matches!(
        state.put_grant_for_client(&tenant, ciba_grant, true).await,
        Ok(true)
    ) {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::grant(
                &tenant,
                crate::security_event::SecurityActor::user(&record.user_id),
                &grant_id,
                crate::security_event::GrantAction::Create,
                crate::security_event::SecurityEventOutcome::Failure,
            ))
            .await;
        return (
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "授权记录落库失败,请重试",
            )
            .into_response(),
            Err(()),
        );
    }
    state
        .record_security_event(crate::security_event::SecurityEventDraft::grant(
            &tenant,
            crate::security_event::SecurityActor::user(&record.user_id),
            &grant_id,
            crate::security_event::GrantAction::Create,
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;
    match crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        &record.user_id,
        record.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        authority => {
            let cleanup_ok = crate::grants::revoke_with_audit(
                state,
                &tenant,
                crate::security_event::SecurityActor::system("ciba-token"),
                &grant_id,
            )
            .await;
            let response = match (authority, cleanup_ok) {
                (crate::user_gate::PasswordGate::ChangeRequired, true) => err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "password authority changed during token issuance",
                ),
                _ => err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "password authority verification failed",
                ),
            };
            return (response.into_response(), Err(()));
        }
    }
    if crate::user_gate::require_active_user_epoch(
        state,
        &tenant,
        &record.user_id,
        credential_epoch,
    )
    .await
    .is_err()
    {
        crate::grants::revoke_with_audit(
            state,
            &tenant,
            crate::security_event::SecurityActor::system("ciba-token"),
            &grant_id,
        )
        .await;
        return (
            err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "user lifecycle changed during token issuance",
            )
            .into_response(),
            Err(()),
        );
    }
    (
        Json(TokenResponse {
            access_token: jwt,
            token_type: crate::token::token_type_for(cnf_jkt),
            expires_in: crate::token::ACCESS_TTL,
            scope: (!scope_str.is_empty()).then_some(scope_str),
            refresh_token: None, // CIBA P2 先不发 refresh(简化,与 device 同)
            id_token: None,
            resource: None,
        })
        .into_response(),
        Ok(()),
    )
}

/// CIBA 批准动作(spec 013 §2b):按 auth_req_id 定位 + **批准者身份绑定** + 原子 approve/deny。
///
/// `approving_user_id` = 批准页的**已认证登录用户**。MUST 校验 `approving_user_id == record.user_id`
/// ——评审 Kiro MED-1:`record.user_id` 源自调用方 `/bc-authorize` 时提交的不可信 `login_hint`,若批准
/// 时不校验"当前登录用户就是被代表的用户",恶意 client 用 `login_hint=<victim>` 铸请求 → 别人误批准 →
/// 签出 `sub=victim` 的 token(冒充)。故批准者与被代表用户不符 → 拒(`user_mismatch`,不推进状态)。
/// (真批准页 handler 还须会话认证 + CSRF;此函数是其可测装配核心。)
pub async fn approve_by_auth_req_id(
    state: &AppState,
    tenant: &str,
    auth_req_id: &str,
    approving_user_id: &str,
    approve: bool,
) -> Result<(), &'static str> {
    if !state.region.owns_id(auth_req_id) {
        return Err("wrong Region activation");
    }
    let Some(record) = state
        .ciba
        .get(tenant, auth_req_id)
        .await
        .map_err(|_| "store")?
    else {
        return Err("unknown auth_req_id");
    };
    let now = crate::token::current_unix_secs_pub();
    if record.expires_at <= now {
        return Err("expired");
    }
    if record.status != "pending" {
        return Err("already decided");
    }
    // 批准者身份绑定(MED-1):被代表用户 = 建档时的 record.user_id;批准者 MUST 是同一人。
    if approving_user_id != record.user_id {
        return Err("user_mismatch");
    }
    let password_credential_version = if approve {
        crate::user_gate::password_authority_snapshot(state, tenant, approving_user_id)
            .await
            .map_err(|gate| match gate {
                crate::user_gate::PasswordGate::ChangeRequired => "password change required",
                _ => "store",
            })?
    } else {
        None
    };
    // **原子** CAS(同 device 评审 F1:不整对象写回,防旧快照重开已消费记录)。
    match state
        .ciba
        .decide(tenant, auth_req_id, password_credential_version, approve)
        .await
        .map_err(|_| "store")?
    {
        true => {
            // 主动投影(spec 004 §3.3 / C6.5):批准→ApprovedAwaitingPoll(等客户端轮询取);拒→Denied。
            let st = if approve {
                agent_auth_ciba::CibaState::ApprovedAwaitingPoll
            } else {
                agent_auth_ciba::CibaState::Denied
            };
            crate::authz_session::emit_flow_projection(state, auth_req_id, st).await;
            if !approve {
                let operation_id =
                    crate::authz_session::flow_credential_fingerprint(state, auth_req_id);
                state
                    .record_security_event(crate::security_event::SecurityEventDraft::grant_denial(
                        tenant,
                        crate::security_event::SecurityActor::user(approving_user_id),
                        &record.client_id,
                        &operation_id,
                    ))
                    .await;
            }
            Ok(())
        }
        false => Err("already decided"),
    }
}

/// 批准页信息(spec 013 §2b):展示发起方 client_id + binding_message(带了必展示,C7b.6)。
#[derive(Serialize, utoipa::ToSchema)]
pub struct BcApproveInfo {
    pub client_id: String,
    pub scope: Vec<String>,
    pub resources: Vec<String>,
    /// 带了才有(C7b.6:MUST 展示)。
    pub binding_message: Option<String>,
    pub status: String,
}

/// `GET /bc-approve/{auth_req_id}`(spec 013 §2b):**已登录用户**查看待批准请求(展示发起方 +
/// binding_message)。**IDOR-safe**:仅当前登录 user == 记录 user_id 才可见(他人/不存在 → 404)。
#[utoipa::path(
    get, path = "/bc-approve/{auth_req_id}", tag = "ciba",
    params(("auth_req_id" = String, Path, description = "CIBA auth_req_id")),
    responses(
        (status = 200, description = "待批准请求详情", body = BcApproveInfo),
        (status = 401, description = "未登录"),
        (status = 404, description = "不存在或非本人")
    )
)]
pub async fn bc_approve_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(auth_req_id): Path<String>,
) -> axum::response::Response {
    let user = match require_login(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // tenant 分区(spec 020 §2.3):按本请求 Host 派生的 tenant 定位记录(绝不跨租户读他人 CIBA 请求)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !state.region.owns_id(&auth_req_id) {
        return (StatusCode::NOT_FOUND, "不存在").into_response();
    }
    match state.ciba.get(&tenant, &auth_req_id).await {
        // IDOR-safe:非本人(被代表 user)一律 404,不泄露存在性。
        Ok(Some(r)) if r.user_id == user => Json(BcApproveInfo {
            client_id: r.client_id,
            scope: r.scope,
            resources: r.resources,
            binding_message: r.binding_message,
            status: r.status,
        })
        .into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, "不存在").into_response(),
        Err(crate::ports::StoreError::Transient(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response(),
    }
}

/// 批准动作请求体。
#[derive(Deserialize, utoipa::ToSchema)]
pub struct BcApproveDecision {
    /// true=批准、false=拒绝。
    pub approve: bool,
}

/// `POST /bc-approve/{auth_req_id}`(spec 013 §2b):**已登录用户**批准/拒绝。批准者 = 当前登录 user,
/// MUST == 记录 user_id(跨用户批准拒,Scenario 64-69)。CSRF 靠 session cookie SameSite=Lax。
#[utoipa::path(
    post, path = "/bc-approve/{auth_req_id}", tag = "ciba",
    params(("auth_req_id" = String, Path, description = "CIBA auth_req_id")),
    request_body(content = BcApproveDecision, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 204, description = "已批准/拒绝"),
        (status = 401, description = "未登录"),
        (status = 404, description = "不存在或非本人")
    )
)]
pub async fn bc_approve_decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(auth_req_id): Path<String>,
    Form(body): Form<BcApproveDecision>,
) -> axum::response::Response {
    let user = match require_login(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // tenant 分区(spec 020 §2.3):按本请求 Host 派生的 tenant 批准(绝不跨租户审批他人 CIBA 请求)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // approve_by_auth_req_id 内校 approving_user == record.user_id(user_mismatch)+ pending + 原子 decide。
    match approve_by_auth_req_id(&state, &tenant, &auth_req_id, &user, body.approve).await {
        Ok(()) => {
            // 批准成功后:按快照 delivery_mode 分派 ping/push 回调(spec 013 §4;poll 无回调)。
            // 投递失败**不影响批准结果的 204**(用户已批准是事实);push 的签发后失败处置在 dispatch 内做。
            if body.approve {
                dispatch_ciba_callback(&state, &headers, &auth_req_id).await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        // user_mismatch / unknown / already decided / expired 一律 404(不泄露具体原因/存在性)。
        Err(_) => (StatusCode::NOT_FOUND, "不存在或不可批准").into_response(),
    }
}

/// 批准后按快照 `delivery_mode` 分派 ping/push 回调(spec 013 §4,C7b.5)。poll → 直接返回(无回调)。
/// - **ping**:POST `{auth_req_id}` 到快照 endpoint(带 client_notification_token);token 未消费,投递失败
///   client 仍可轮询取(fail-safe 天然)。
/// - **push**:签发 token(**签发前**原子 consume)→ POST 完整 token 响应。签发前失败(SSRF 复校拒)→ 不消费、
///   退化 poll;**签发后投递失败(模糊态)→ 已消费终态,MUST NOT 重签/退化 poll**(codex 二轮 High,防复制凭证)。
async fn dispatch_ciba_callback(state: &AppState, headers: &HeaderMap, auth_req_id: &str) {
    use crate::ports::{CibaCallbackDelivery, CibaCallbackRequest, CibaDeliveryOutcome};
    // tenant 分区(spec 020 §2.3):push 分支的 client/user gate 按 tenant 隔离(派生失败→静默退化 poll)。
    let tenant = crate::tenant::tenant_or_400(state, headers)
        .ok()
        .unwrap_or_default();
    let Ok(Some(record)) = state.ciba.get(&tenant, auth_req_id).await else {
        return;
    };
    let mode = record.delivery_mode.as_deref().unwrap_or("poll");
    // poll 无回调;缺 endpoint/token(理论不该发生,发起时已校)→ 静默退化 poll。
    let (Some(endpoint), Some(token)) = (
        record.notification_endpoint.clone(),
        record.client_notification_token.clone(),
    ) else {
        return;
    };
    // **全局推送配额**(spec 013 §4,C7b.5+):跨 auth_req 的主动推送洪水防线(保护自身出网 / 回调目标 /
    // 限 SSRF 尝试放大)。超额 → **跳过本次主动推送**(ping/push 均在 consume/签发**之前**返回:token 未
    // 消费,client 仍可轮询取,fail-safe 天然)。fail-open(store 未配/瞬时错误 → 放行,anti-abuse 非安全闸)。
    if crate::ratelimit_gate::ciba_push_quota_exhausted(state).await {
        eprintln!("[ciba-callback] 全局推送配额耗尽,跳过主动推送(client 可轮询取),auth_req_id 保 approved");
        return;
    }
    match mode {
        "ping" => {
            // ping:通知 client 来取(token 未消费);投递结果不改状态(失败也可轮询)。
            let req = CibaCallbackRequest {
                notification_endpoint: endpoint,
                client_notification_token: token,
                body: serde_json::json!({ "auth_req_id": auth_req_id }),
            };
            let _ = state.ciba_delivery.deliver(req).await;
        }
        "push" => {
            // **tombstone 闸(评审 Kiro H2,spec 005 §9.3/C10.5)**:poll 的 IssueToken 路径签发前会重读
            // client 拒回收态;push 直投也 MUST 同闸——否则 client 在发起↔批准窗口(≤600s)被回收后,
            // push 仍签出 token+建 Grant 并投递到旧端点,绕过 fail-closed 不变量。回收态 → 不 consume/不签,
            // 记录留 approved(poll 路径同样会拒,无 token 泄露)。
            match state.clients.get(&tenant, &record.client_id).await {
                Ok(Some(c)) if c.is_tombstoned() => {
                    eprintln!("[ciba-push] client 已回收(tombstoned),拒 push 签发,auth_req_id 留 approved");
                    return;
                }
                Ok(Some(_)) => {}
                // client 不存在 / 存储错误 → fail-closed 不签(不冒险签出无主 token)。
                _ => return,
            }
            // **active-user gate(评审 codex High,spec 003 §1.4)**:push 是 CIBA 签发路径,与 poll 的
            // IssueToken 分支同样 MUST 过 gate——disable/tombstone 后不 push 签出 token。**consume 之前**
            // 检查(被禁/查询失败均不 consume,不烧 auth_req_id;record 留 approved,poll 侧同样会拒)。
            match crate::user_gate::require_active_user(state, &tenant, &record.user_id).await {
                crate::user_gate::UserGate::Allowed => {}
                // Blocked/Unavailable 都不签、不 consume;留 approved,不投递(fail-closed)。
                _ => return,
            }
            // 与 poll 路径一致,在 consume/签名前拒绝批准后发生过密码 reset 的授权。
            // issue_ciba_token 内仍会在 Grant 创建后复核,用于闭合本检查后的并发 reset。
            match crate::user_gate::require_password_authority_version(
                state,
                &tenant,
                &record.user_id,
                record.password_credential_version,
            )
            .await
            {
                crate::user_gate::PasswordGate::Allowed => {}
                // ChangeRequired/Unavailable 都不签、不 consume;保留 approved 供故障恢复,
                // 但密码 authority 已变化时后续 poll 同样会稳定返回 invalid_grant。
                _ => return,
            }
            // push:签发前原子 consume(赢家才签,防并发/重放双签)。
            match state.ciba.consume(&tenant, auth_req_id).await {
                Ok(true) => {}
                _ => return, // 已消费/并发落败 → 不重复签发
            }
            let now = crate::token::current_unix_secs_pub();
            // 复用 issue_ciba_token 的签发核心,但取其 TokenResponse JSON 作 push body(+ auth_req_id)。
            // push 是**AS 主动投递**(非客户端出示 proof 的请求)→ 恒 bearer(cnf_jkt=None);
            // DPoP 绑定只在 client 主动走 /token(poll/ping 取)时成立(RFC 9449 是请求侧机制)。
            let (resp, signed) = issue_ciba_token(state, headers, &record, None, now).await;
            if signed.is_err() {
                // **签发前/签发中失败** → token 未成功产出 → 回滚 consume、退化 poll(client 可轮询重取)。
                let _ = state.ciba.release_consume(&tenant, auth_req_id).await;
                let _ = resp; // 丢弃(不投递)
                return;
            }
            // push 与 poll 同属成功签发路径。投递结果不改变 token 已铸造且 auth_req_id 已消费的事实,
            // 因此在解析/投递前记录 client 活动;观测写失败不反向破坏签发。
            crate::token::touch_client_last_used(state, &tenant, &record.client_id, now).await;
            // 取签发出的 token 响应 JSON 作 push body。
            let body = match response_to_token_json(resp).await {
                Some(mut v) => {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("auth_req_id".into(), serde_json::json!(auth_req_id));
                    }
                    v
                }
                None => return, // 无法取出 body(不应发生);token 已消费,不退化(避免双签)
            };
            let req = CibaCallbackRequest {
                notification_endpoint: endpoint,
                client_notification_token: token,
                body,
            };
            match state.ciba_delivery.deliver(req).await {
                CibaDeliveryOutcome::Delivered => {
                    // 成功:token 已消费(上面 consume),/token 再来拒 invalid_grant(已消费)。
                    crate::authz_session::emit_flow_projection(
                        state,
                        auth_req_id,
                        agent_auth_ciba::CibaState::Complete,
                    )
                    .await;
                }
                CibaDeliveryOutcome::BlockedBySsrf => {
                    // **签发后**才发现 SSRF(投递前复校拒)——token 已签+已消费,MUST NOT 退化 poll(防复制)。
                    // 记审计终态(评审 Kiro M3:走投影而非仅 eprintln,使"已消费未投递"可观测;投影键 HMAC,
                    // 不含 token/body)。不回滚 consume。仍标 Complete(已消费终态),运维据审计判投递失败。
                    eprintln!("[ciba-push] delivery blocked by SSRF after issuance, auth_req_id 已消费(不退化)");
                    crate::authz_session::emit_flow_projection(
                        state,
                        auth_req_id,
                        agent_auth_ciba::CibaState::Complete,
                    )
                    .await;
                }
                CibaDeliveryOutcome::Failed => {
                    // 模糊态(已发出,不知 client 是否收到)→ MUST 视为已消费终态,不重签/不退化 poll。
                    // 同上走投影记终态(M3);运维据投递失败审计判需否重新发起 CIBA。
                    eprintln!("[ciba-push] delivery failed (ambiguous), auth_req_id 已消费(不重签/不退化)");
                    crate::authz_session::emit_flow_projection(
                        state,
                        auth_req_id,
                        agent_auth_ciba::CibaState::Complete,
                    )
                    .await;
                }
            }
        }
        _ => {} // poll / 未知:无回调
    }
}

/// 从签发响应里取出 token 响应 JSON body(push 投递用)。仅在成功签发(200 + JSON body)时返回 Some。
async fn response_to_token_json(resp: axum::response::Response) -> Option<serde_json::Value> {
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// 批准端点的登录鉴权(P2 门控 + 会话)。返回当前登录 user_id。
async fn require_login(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, axum::response::Response> {
    if !agent_auth_protocol::endpoint_available(state.phase, "/bc-authorize") {
        return Err((StatusCode::NOT_FOUND, "").into_response());
    }
    match crate::login::current_session(state, headers).await {
        Some((_sid, user_id)) => Ok(user_id),
        None => Err((StatusCode::UNAUTHORIZED, "需登录(无有效会话)").into_response()),
    }
}

pub fn router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::router::OpenApiRouter;
    OpenApiRouter::new()
        .merge(protocol_router())
        .merge(approve_router())
}

/// 协议 POST 端点(`/bc-authorize`):CIBA 发起,**不带浏览器 cookie**(靠 login_hint + auth_req_id
/// 轮询),CORS 分类②(`Allow-Origin: *`,C10.10)。
pub fn protocol_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::{router::OpenApiRouter, routes};
    OpenApiRouter::new().routes(routes!(bc_authorize_handler))
}

/// 批准端点(`GET/POST /bc-approve/{id}`):**登录会话 cookie 鉴权**(current_session),CORS 分类④
/// 会话端点(不发 CORS 头、拒跨域,防 CSRF;统一入口下前端同源,C10.10)。
pub fn approve_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::{router::OpenApiRouter, routes};
    OpenApiRouter::new().routes(routes!(bc_approve_info, bc_approve_decide))
}
