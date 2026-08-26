//! `POST /token`(C2.8 / C4.1 / C4.2 / C2.5a / C10.15a):authorization_code 兑换(P0 code flow)。
//!
//! 编排纯逻辑 crate,不重述规则:
//! - grant 阶段门控(`grant_accepted`,protocol/006)
//! - 原子消费授权码(CodeStore,一次性)
//! - PKCE 校验(`verify_exchange`,client/002 C4.1)
//! - redirect_uri 精确匹配(`match_redirect`,client/002 C4.5)
//! - audience 选择(`select_audience`,protocol/006 C2.8;单元素 aud,C2.5a)
//! - claim 形状(`namespace_object`/`encode_aud`/`validate_shape`,token/001 C2)
//! - access 恒 ES256(`assert_access_es256`,infra-core/005 C10.15a)
//! - 签名经 Signer 端口(真机 KMS + der_to_jose;本地进程内 P-256)
//!
//! P0 仅 authorization_code(refresh_token 等后续)。省略 resource 的 audience 优先级、
//! pairwise sub 派生的唯一权威仍在 docs §2.8 / spec 001,本层只调用、不复述。

use agent_auth_client::{match_redirect, verify_exchange, MatchResult, RedirectMode};
use agent_auth_discovery::derive_issuer;
use agent_auth_infra_core::alg::assert_access_es256;
use agent_auth_protocol::{
    grant_accepted, select_audience, AudienceSelection, AuthorizePhase, AuthorizedResources,
    ClientRegistration,
};
use agent_auth_token::{encode_aud, namespace_object, validate_shape, SubType};
use axum::{
    extract::{FromRequest, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    ClientStore, CodeStore, GraceStore, JtiStore, LeaseAcquire, RefreshStore, Signer,
};
use crate::state::AppState;

/// access token 有效期(秒,P0 默认;§2.1 生命周期)。
const ACCESS_TTL_SECS: i64 = 900;

/// discovery 的 subject_type → token crate 的 SubjectMode(pairwise 派生用)。
pub(crate) fn subject_mode(t: agent_auth_discovery::SubjectType) -> agent_auth_token::SubjectMode {
    match t {
        agent_auth_discovery::SubjectType::Pairwise => agent_auth_token::SubjectMode::Pairwise,
        agent_auth_discovery::SubjectType::Public => agent_auth_token::SubjectMode::Public,
    }
}
/// signing lease 的 TTL(秒,C10.1):占 lease 后此秒内别的请求得 Locked;到期可重占重试。
const LEASE_TTL_SECS: i64 = 30;
/// Grant 有效期(秒;spec 011 §5.1)。3LO 授权较长命(与 refresh 生命周期同量级),默认 30 天;
/// 用户吊销走 status=Revoked(不靠 TTL)。token-exchange 换发时按 `constraints.expires_at` fail-closed 校。
const GRANT_TTL_SECS: i64 = 30 * 24 * 3600;

async fn revoke_code_issued_authorization(
    state: &AppState,
    tenant: &str,
    grant_id: &str,
) -> Result<(), crate::ports::StoreError> {
    // Attempt every cleanup even if one store fails. Either Grant or family revocation is enough
    // for online token validation to fail closed, while the error still asks the caller to retry.
    let grant_result = crate::grants::revoke_with_audit_result(
        state,
        tenant,
        crate::security_event::SecurityActor::system("authorization-code-reuse"),
        grant_id,
    )
    .await;
    let refresh_result = state.refresh.revoke(tenant, grant_id).await;
    let grace_result = match &state.grace {
        Some(grace) => grace.delete_family(grant_id).await,
        None => Ok(()),
    };

    grant_result.map(|_| ())?;
    refresh_result?;
    grace_result
}

/// `POST /token` 请求(application/x-www-form-urlencoded)。各 grant 只读取自己的参数槽。
#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    /// grant 类型；包含 RFC 6749/OIDC grant，以及 opt-in EMA JWT bearer grant。
    pub grant_type: String,
    /// authorization code(`/authorize` 返回)。
    pub code: Option<String>,
    /// PKCE code_verifier(RFC 7636;public 客户端必带)。
    pub code_verifier: Option<String>,
    /// 与 `/authorize` 一致的 redirect_uri(精确匹配,C4.5)。
    pub redirect_uri: Option<String>,
    /// 客户端标识。
    pub client_id: Option<String>,
    /// client_secret(confidential 客户端 client_secret_post 时;basic 走 Authorization 头)。
    pub client_secret: Option<String>,
    /// 目标 RS(RFC 8707;可省,按 C2.8 优先级)。
    pub resource: Option<String>,
    /// refresh_token grant 的 refresh token(不透明串)。
    pub refresh_token: Option<String>,
    /// 可选 scope(RFC 6749 §6:refresh 可请求更窄 scope)。**refresh downscope 已实现**(spec 006 §3.3:
    /// 签发 = 授权集 ∩ 请求,超集拒 invalid_scope;read-gate 置 consume 前;C3.6 只窄本次不动 family.scope)+
    /// **进宽限窗指纹**(C3.2:改 scope 参数 → 指纹变 → 按复用处理)。也是 client_credentials(2LO)请求的 scope。
    pub scope: Option<String>,
    /// client_assertion(RFC 7521/7523):workload 平台身份断言(spec 012 workload_oidc_jwt 时 = 平台 OIDC JWT)。
    pub client_assertion: Option<String>,
    /// client_assertion_type:workload_oidc_jwt 用标准 `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`。
    pub client_assertion_type: Option<String>,
    /// EMA ID-JAG authorization grant。与 `client_assertion` 客户端认证槽严格分离。
    pub assertion: Option<String>,
    /// EMA v1 不接受 request-level RAR；出现即返回 `invalid_authorization_details`。
    pub authorization_details: Option<String>,
    /// token-exchange(RFC 8693,spec 011):被代表的用户身份 token(access_token / id_token)。
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    /// token-exchange:发起 agent 的 workload 身份 token(平台 OIDC JWT;actor 认证复用 workload_oidc_jwt)。
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    /// device flow(RFC 8628,spec 013):`grant_type=device_code` 轮询用的 device_code。
    pub device_code: Option<String>,
    /// CIBA(spec 013):`grant_type=urn:openid:params:grant-type:ciba` 轮询用的 auth_req_id。
    pub auth_req_id: Option<String>,
    /// token-exchange 跨 Grant 换发(spec 011 §4,C7.7):grant-ref(独立参数,不复用 subject/actor_token 槽)。
    /// 带则受理侧选 grant_ref 指向的 Grant(经绑定闸 + 归属闸 + 双闸);不带维持 jti 单指针(跨 Grant fail-closed)。
    pub grant_ref: Option<String>,
}

/// `POST /token` 成功响应(RFC 6749 §5.1)。
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// OIDC id_token(scope=openid 时签发;spec 001 C2.6/C2.7/C2.9)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// RFC 8707 / EMA 单目标响应回显。既有 grant 不回显时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// OAuth 错误响应(RFC 6749 §5.2)。
#[derive(Serialize, ToSchema)]
pub struct TokenError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl TokenError {
    pub(crate) fn new(code: &str, description: &str) -> Self {
        let description = if description
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            description.to_string()
        } else {
            format!("{code} request rejected")
        };
        Self {
            error: code.to_string(),
            error_description: Some(description),
        }
    }
}

pub(crate) fn err(status: StatusCode, code: &str, desc: &str) -> (StatusCode, Json<TokenError>) {
    (status, Json(TokenError::new(code, desc)))
}

pub(crate) fn invalid_client_response(
    headers: &HeaderMap,
    default_status: StatusCode,
    desc: &str,
) -> axum::response::Response {
    if !headers.contains_key(axum::http::header::AUTHORIZATION) {
        return err(default_status, "invalid_client", desc).into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Basic realm=\"token\"",
        )],
        Json(TokenError::new("invalid_client", desc)),
    )
        .into_response()
}

/// 带 `Retry-After` 的错误响应(C10.2:KMS throttle 等瞬时失败的 503 MUST 带 Retry-After,
/// 提示客户端退避重试;`retry_secs` 保守取值,签名后端瞬时不可用一般秒级恢复)。
pub(crate) fn err_retry_after(
    status: StatusCode,
    code: &str,
    desc: &str,
    retry_secs: u64,
) -> impl axum::response::IntoResponse {
    (
        status,
        [(axum::http::header::RETRY_AFTER, retry_secs.to_string())],
        Json(TokenError::new(code, desc)),
    )
}

/// access token 有效期(供 refresh_flow 复用)。
pub(crate) const ACCESS_TTL: i64 = ACCESS_TTL_SECS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TokenSignError {
    IssuerMismatch,
    Transient,
    TooLarge,
    Permanent,
}

pub(crate) const TOKEN_TOO_LARGE_ERROR_DESCRIPTION: &str =
    "access token exceeds the 7 KiB size limit; narrow scope or authorization_details; use token introspection only when the Grant-backed introspection profile is enabled";

/// 签发一枚 access token 所需的 claim 材料(打包传参,避免过多位置参数)。
pub(crate) struct AccessTokenClaims<'a> {
    pub issuer: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub client_id: &'a str,
    pub scope: &'a str,
    /// token 唯一标识(jti,C7.8)。调用方生成并传入(以便签发后据同一 jti 落 jti→user_id 映射)。
    pub jti: &'a str,
    /// 命名空间 auth_grant 引用(code flow 用 code、refresh flow 用 family_id、2LO 用 "client_credentials")。
    pub auth_grant: &'a str,
    /// 主体类型(C2.3):3LO=User、2LO workload=Agent、2LO service=Service。
    pub sub_type: SubType,
    /// RFC 9396 `authorization_details`(RAR;spec 010 §4)。空 = 无 RAR、不写 claim(不编造)。
    /// **只放本次 aud(resource)按 locations 归属的条目**(单 aud token 不塞全数组;调用方过滤后传入)。
    pub authorization_details: &'a [serde_json::Value],
    /// DPoP sender-constraint(RFC 9449,spec 010 §5.2/C8.7b):有 DPoP proof 时 = proof 公钥的 RFC 7638
    /// thumbprint(写 `cnf.jkt`);无 proof(bearer)= None。默认 None(bearer,不破坏 P0–P2 假设)。
    pub cnf_jkt: Option<&'a str>,
    /// Original user authentication event. Omitted for 2LO and flows without such evidence.
    pub auth_time: Option<i64>,
    /// Canonical Agent Auth assurance class for that event.
    pub acr: Option<&'a str>,
    pub now: i64,
}

pub(crate) struct SignedAccessToken {
    pub token: String,
    pub grant_backed_rar: bool,
}

pub(crate) async fn sign_tenant_access_token(
    state: &AppState,
    headers: &HeaderMap,
    signer: &crate::state::SignerImpl,
    claims: &AccessTokenClaims<'_>,
    actor: crate::security_event::SecurityActor,
) -> Result<String, TokenSignError> {
    sign_tenant_access_token_with_delivery(state, headers, signer, claims, false, actor)
        .await
        .map(|signed| signed.token)
}

pub(crate) async fn sign_tenant_access_token_with_delivery(
    state: &AppState,
    headers: &HeaderMap,
    signer: &crate::state::SignerImpl,
    claims: &AccessTokenClaims<'_>,
    grant_backed_rar_enabled: bool,
    actor: crate::security_event::SecurityActor,
) -> Result<SignedAccessToken, TokenSignError> {
    if !crate::tenant::issuer_belongs_to_request_tenant(state, headers, claims.issuer, actor).await
    {
        return Err(TokenSignError::IssuerMismatch);
    }
    sign_access_token_with_delivery(signer, claims, grant_backed_rar_enabled).await
}

/// 组装 + 签名一枚 access token(C2.5a/C10.15a),code flow 与 refresh flow 共用。
/// 返回 JWT 串;区分签名瞬时失败、体积超限与永久失败，供各发行流程保留自己的状态机语义。
#[cfg(test)]
async fn sign_access_token(
    signer: &crate::state::SignerImpl,
    c: &AccessTokenClaims<'_>,
) -> Result<String, TokenSignError> {
    sign_access_token_with_delivery(signer, c, false)
        .await
        .map(|signed| signed.token)
}

async fn sign_access_token_with_delivery(
    signer: &crate::state::SignerImpl,
    c: &AccessTokenClaims<'_>,
    grant_backed_rar_enabled: bool,
) -> Result<SignedAccessToken, TokenSignError> {
    let mut claims = serde_json::json!({
        "iss": c.issuer,
        "sub": c.sub,
        "aud": encode_aud(c.aud),
        "iat": c.now,
        "exp": c.now + ACCESS_TTL_SECS,
        // jti(spec 011 C7.8):唯一 token 标识(调用方传入,以便同 jti 落 jti→user_id 映射)。
        "jti": c.jti,
        "client_id": c.client_id,
        "scope": c.scope,
        agent_auth_token::NAMESPACE: namespace_object(c.sub_type, c.auth_grant, None),
    });
    // RFC 9396 authorization_details:**顶层 claim**(RFC 9068/9396 §7,与 SDK enforce_rar 读取 +
    // introspect 回带位置一致);非空才写(不编造)。调用方已按本次 aud 的 locations 过滤 + 准入校验过。
    if !c.authorization_details.is_empty() {
        claims["authorization_details"] =
            serde_json::Value::Array(c.authorization_details.to_vec());
    }
    // DPoP sender-constraint(RFC 9449 §4.2,spec 010 §5.2):有 proof 时写顶层 `cnf.jkt`(validate_shape
    // 放行顶层 cnf;introspect if-present 自动回带)。无 proof = bearer,不写(opt-in)。
    if let Some(jkt) = c.cnf_jkt {
        claims["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    if let Some(auth_time) = c.auth_time {
        claims["auth_time"] = serde_json::Value::Number(auth_time.into());
    }
    if let Some(acr) = c.acr {
        claims["acr"] = serde_json::Value::String(acr.to_string());
    }
    if !validate_shape(&claims).is_empty() {
        return Err(TokenSignError::Permanent);
    }
    let kid = match signer.active_kid().await {
        Ok(k) => k,
        Err(crate::ports::SignerError::Transient(_)) => return Err(TokenSignError::Transient),
        Err(_) => return Err(TokenSignError::Permanent),
    };
    if assert_access_es256("ES256").is_err() {
        return Err(TokenSignError::Permanent);
    }
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
    let build_signing_input = |claims: &serde_json::Value| {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        )
    };
    let mut signing_input = build_signing_input(&claims);
    let mut grant_backed_rar = false;
    if grant_backed_rar_enabled
        && !c.authorization_details.is_empty()
        && !matches!(
            es256_jwt_size_budget(&signing_input),
            agent_auth_token::SizeBudget::WithinTarget
        )
    {
        claims["authorization_details"] =
            serde_json::Value::Array(vec![crate::rar_delivery::summary(
                c.aud,
                c.authorization_details,
            )]);
        signing_input = build_signing_input(&claims);
        if !matches!(
            es256_jwt_size_budget(&signing_input),
            agent_auth_token::SizeBudget::WithinTarget
        ) {
            return Err(TokenSignError::TooLarge);
        }
        grant_backed_rar = true;
    }
    // 体积预算硬上限(C8.10):最终 JWT = signing_input + "." + 86B(ES256 JOSE 签名 base64url)。
    // 超硬上限**签发前拒**(不静默发超大 token、省 KMS 调用)。
    if es256_jwt_exceeds_limit(&signing_input) {
        return Err(TokenSignError::TooLarge);
    }
    match signer.sign_es256(signing_input.as_bytes()).await {
        Ok(sig) => Ok(SignedAccessToken {
            token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)),
            grant_backed_rar,
        }),
        Err(crate::ports::SignerError::Transient(_)) => Err(TokenSignError::Transient),
        Err(_) => Err(TokenSignError::Permanent),
    }
}

fn es256_jwt_size_budget(signing_input: &str) -> agent_auth_token::SizeBudget {
    const ES256_SIG_SUFFIX_BYTES: usize = 87;
    agent_auth_token::check_jwt_size(signing_input.len() + ES256_SIG_SUFFIX_BYTES)
}

/// ES256 最终 JWT 是否超体积硬上限(C8.10):signing_input + 87B(`.`+86B JOSE 签名)> 7KB。
/// 签发前判定(省 KMS 调用),true = MUST 拒签。
fn es256_jwt_exceeds_limit(signing_input: &str) -> bool {
    matches!(
        es256_jwt_size_budget(signing_input),
        agent_auth_token::SizeBudget::ExceedsHardLimit
    )
}

/// 签**委托 token**(spec 011 token-exchange):像 access token(恒 ES256、aud 单元素、at+jwt),但带
/// `act.sub`=发起 agent(纯 RFC 8693)+ 命名空间 `actor_types`(agent 类型叠加视图)。
/// sub=用户在目标 sector 的派生 sub;sub_type=User(委托 token 代表用户,非 2LO)。返回 (jwt);Err 同 sign_access_token。
///
/// `inbound_act` / `inbound_actor_types`:入站 subject_token 的委托链(多级委托,P2)。有则本跳的 `act`
/// **把旧链嵌套进内层**(RFC 8693:外层=最近执行者=本跳 actor、内层=更早委托方),`actor_types` 并入
/// 旧链的类型视图——否则多跳会丢 prior actor、且链深不增(评审 codex MEDIUM:防链长闸绕过)。P1 前身
/// max_act_chain=1 时入站恒无 act,二者为 None,退化成单层。
///
/// `cnf_jkt`(spec 011 §7.2,RFC 9449 §5,C7.9):有则委托 token 写顶层 `cnf.jkt`——sender-constraint
/// **重绑到下一持有者(发起 actor)自己出示的 DPoP proof key**(非双绑、不含入站 subject_token 的 user
/// key)。None = bearer 委托 token(现状)。调用方据此把响应 `token_type` 置 `DPoP`/`Bearer`。
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
async fn sign_delegation_token(
    signer: &crate::state::SignerImpl,
    issuer: &str,
    sub: &str,
    aud: &str,
    client_id: &str,
    scope: &str,
    auth_grant: &str,
    act_sub: &str,
    inbound_act: Option<serde_json::Value>,
    inbound_actor_types: Option<serde_json::Value>,
    authorization_details: &[serde_json::Value],
    cnf_jkt: Option<&str>,
    auth_time: Option<i64>,
    acr: Option<&str>,
    jti: &str,
    now: i64,
) -> Result<String, TokenSignError> {
    sign_delegation_token_with_delivery(
        signer,
        issuer,
        sub,
        aud,
        client_id,
        scope,
        auth_grant,
        act_sub,
        inbound_act,
        inbound_actor_types,
        authorization_details,
        cnf_jkt,
        auth_time,
        acr,
        jti,
        now,
        false,
    )
    .await
    .map(|signed| signed.token)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sign_tenant_delegation_token_with_delivery(
    state: &AppState,
    headers: &HeaderMap,
    signer: &crate::state::SignerImpl,
    issuer: &str,
    sub: &str,
    aud: &str,
    client_id: &str,
    scope: &str,
    auth_grant: &str,
    act_sub: &str,
    inbound_act: Option<serde_json::Value>,
    inbound_actor_types: Option<serde_json::Value>,
    authorization_details: &[serde_json::Value],
    cnf_jkt: Option<&str>,
    auth_time: Option<i64>,
    acr: Option<&str>,
    jti: &str,
    now: i64,
    grant_backed_rar_enabled: bool,
    actor: crate::security_event::SecurityActor,
) -> Result<SignedAccessToken, TokenSignError> {
    if !crate::tenant::issuer_belongs_to_request_tenant(state, headers, issuer, actor).await {
        return Err(TokenSignError::IssuerMismatch);
    }
    sign_delegation_token_with_delivery(
        signer,
        issuer,
        sub,
        aud,
        client_id,
        scope,
        auth_grant,
        act_sub,
        inbound_act,
        inbound_actor_types,
        authorization_details,
        cnf_jkt,
        auth_time,
        acr,
        jti,
        now,
        grant_backed_rar_enabled,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sign_delegation_token_with_delivery(
    signer: &crate::state::SignerImpl,
    issuer: &str,
    sub: &str,
    aud: &str,
    client_id: &str,
    scope: &str,
    auth_grant: &str,
    act_sub: &str,
    inbound_act: Option<serde_json::Value>,
    inbound_actor_types: Option<serde_json::Value>,
    authorization_details: &[serde_json::Value],
    cnf_jkt: Option<&str>,
    auth_time: Option<i64>,
    acr: Option<&str>,
    jti: &str,
    now: i64,
    grant_backed_rar_enabled: bool,
) -> Result<SignedAccessToken, TokenSignError> {
    // act:本跳 actor 在最外层;入站旧链(若有)嵌套进 `act.act`(RFC 8693 nested,链深 +1)。
    let mut act = serde_json::Map::new();
    act.insert("sub".into(), serde_json::Value::String(act_sub.to_string()));
    if let Some(prior) = inbound_act {
        act.insert("act".into(), prior);
    }
    // actor_types:本跳 agent 类型 + 并入入站旧链的类型视图(叠加,C2.2a)。
    let mut actor_types = serde_json::Map::new();
    if let Some(serde_json::Value::Object(prior_types)) = inbound_actor_types {
        for (k, v) in prior_types {
            actor_types.insert(k, v);
        }
    }
    actor_types.insert(
        act_sub.to_string(),
        serde_json::Value::String("agent".into()),
    );
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": sub,
        "aud": encode_aud(aud),
        "iat": now,
        "exp": now + ACCESS_TTL_SECS,
        "jti": jti,
        "client_id": client_id,
        "scope": scope,
        // act 纯 RFC 8693(只含 sub / 嵌套 act);类型信息落命名空间 actor_types(C2.2a)。
        "act": serde_json::Value::Object(act),
        agent_auth_token::NAMESPACE: namespace_object(SubType::User, auth_grant, Some(serde_json::Value::Object(actor_types))),
    });
    // RAR 透传(spec 010 §4 / DESIGN §5.2:510 委托⊆源 Grant):委托 token MUST 带源 Grant 该 resource 的
    // authorization_details,否则 RS enforce_rar 回退 scope 级放行 → 委托 token 比源 Grant 宽 = 扩权。
    // 顶层 claim(与 access token / SDK 读取 / introspect 回带一致);非空才写。
    if !authorization_details.is_empty() {
        claims["authorization_details"] = serde_json::Value::Array(authorization_details.to_vec());
    }
    // DPoP sender-constraint 重绑(spec 011 §7.2,RFC 9449 §5):有则写顶层 `cnf.jkt`=发起 actor 的 proof
    // key(validate_shape 放行顶层 cnf;introspect if-present 自动回带)。无 = bearer(现状,不写)。
    if let Some(jkt) = cnf_jkt {
        claims["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    if let Some(auth_time) = auth_time {
        claims["auth_time"] = serde_json::Value::Number(auth_time.into());
    }
    if let Some(acr) = acr {
        claims["acr"] = serde_json::Value::String(acr.to_string());
    }
    if !validate_shape(&claims).is_empty() {
        return Err(TokenSignError::Permanent);
    }
    let kid = match signer.active_kid().await {
        Ok(k) => k,
        Err(crate::ports::SignerError::Transient(_)) => return Err(TokenSignError::Transient),
        Err(_) => return Err(TokenSignError::Permanent),
    };
    if assert_access_es256("ES256").is_err() {
        return Err(TokenSignError::Permanent);
    }
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
    let build_signing_input = |claims: &serde_json::Value| {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        )
    };
    let mut signing_input = build_signing_input(&claims);
    let mut grant_backed_rar = false;
    if grant_backed_rar_enabled
        && !authorization_details.is_empty()
        && !matches!(
            es256_jwt_size_budget(&signing_input),
            agent_auth_token::SizeBudget::WithinTarget
        )
    {
        claims["authorization_details"] =
            serde_json::Value::Array(vec![crate::rar_delivery::summary(
                aud,
                authorization_details,
            )]);
        signing_input = build_signing_input(&claims);
        if !matches!(
            es256_jwt_size_budget(&signing_input),
            agent_auth_token::SizeBudget::WithinTarget
        ) {
            return Err(TokenSignError::TooLarge);
        }
        grant_backed_rar = true;
    }
    // 体积预算硬上限(C8.10):委托 token 是最易超限的路径(深 act 链 + RAR)。超硬上限签发前拒。
    if es256_jwt_exceeds_limit(&signing_input) {
        return Err(TokenSignError::TooLarge);
    }
    match signer.sign_es256(signing_input.as_bytes()).await {
        Ok(sig) => Ok(SignedAccessToken {
            token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)),
            grant_backed_rar,
        }),
        Err(crate::ports::SignerError::Transient(_)) => Err(TokenSignError::Transient),
        Err(_) => Err(TokenSignError::Permanent),
    }
}

/// id_token claims + 签名参数(spec 001 C2.6/C2.7/C2.9)。
pub(crate) struct IdTokenClaims<'a> {
    pub issuer: &'a str,
    pub sub: &'a str,
    /// aud = client_id(C2.6;与 access token aud=RS 隔离)。
    pub client_id: &'a str,
    pub auth_time: i64,
    /// nonce(C2.9):Some 则 echo。
    pub nonce: Option<&'a str>,
    /// 客户端注册的 alg(RS256/ES256;缺省 RS256,C2.7)。
    pub alg: &'a str,
    /// jti(C7.8a):调用方传入(以便同 jti 落 jti→user_id 映射)。
    pub jti: &'a str,
    pub now: i64,
    /// Canonical authentication assurance ACR; omitted when unavailable.
    pub acr: Option<&'a str>,
    /// 认证方法 amr(C9.5b:联邦/本地登录方法;空则不写)。
    pub amr: &'a [String],
}

/// id_token 有效期(秒)。
pub(crate) const ID_TOKEN_TTL_SECS: i64 = 900;

/// grant-ref 有效期(秒;spec 011 §4:短时自焚,够一次 token-exchange 往返,无需吊销存储)。
pub(crate) const GRANT_REF_TTL_SECS: i64 = 300;

/// 签 grant-ref token(spec 011 §4,C7.7):ES256 JWT,**header typ=`grant-ref+jwt`**(专用 verifier
/// 强制,与 access token `at+jwt` 隔离防混淆);claims `{grant_id, bound_agent, iss, iat, exp}`。
/// 短时自焚 + 绑定(受理侧 actor==bound_agent)封死泄露,无需吊销存储。Err 语义同 sign_access_token
/// (true=瞬时可重试[KMS throttle]、false=永久)。
pub(crate) async fn sign_tenant_grant_ref(
    state: &AppState,
    headers: &HeaderMap,
    signer: &crate::state::SignerImpl,
    grant_id: &str,
    bound_agent: &str,
    issuer: &str,
    now: i64,
    actor: crate::security_event::SecurityActor,
) -> Result<String, TokenSignError> {
    if !crate::tenant::issuer_belongs_to_request_tenant(state, headers, issuer, actor).await {
        return Err(TokenSignError::IssuerMismatch);
    }
    sign_grant_ref(signer, grant_id, bound_agent, issuer, now)
        .await
        .map_err(|transient| {
            if transient {
                TokenSignError::Transient
            } else {
                TokenSignError::Permanent
            }
        })
}

async fn sign_grant_ref(
    signer: &crate::state::SignerImpl,
    grant_id: &str,
    bound_agent: &str,
    issuer: &str,
    now: i64,
) -> Result<String, bool> {
    let kid = match signer.active_kid().await {
        Ok(k) => k,
        Err(crate::ports::SignerError::Transient(_)) => return Err(true),
        Err(_) => return Err(false),
    };
    let header = serde_json::json!({ "alg": "ES256", "typ": "grant-ref+jwt", "kid": kid });
    let claims = serde_json::json!({
        "grant_id": grant_id,
        "bound_agent": bound_agent,
        "iss": issuer,
        "iat": now,
        "exp": now + GRANT_REF_TTL_SECS,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    match signer.sign_es256(signing_input.as_bytes()).await {
        Ok(sig) => Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))),
        Err(crate::ports::SignerError::Transient(_)) => Err(true),
        Err(_) => Err(false),
    }
}

/// 组装 + 签名 id_token(spec 001 C2.6/C2.7/C2.9)。按 client 的 alg 选签名 key:
/// RS256 → RSA key(KMS RSA / 本地 rsa);ES256 → 复用 EC key。header typ 不设 at+jwt(非 access)。
/// 返回 JWT;瞬时失败 Err(true=可重试)、永久/未配 RSA Err(false)。
pub(crate) async fn sign_tenant_id_token(
    state: &AppState,
    headers: &HeaderMap,
    signer: &crate::state::SignerImpl,
    c: &IdTokenClaims<'_>,
    actor: crate::security_event::SecurityActor,
) -> Result<String, TokenSignError> {
    if !crate::tenant::issuer_belongs_to_request_tenant(state, headers, c.issuer, actor).await {
        return Err(TokenSignError::IssuerMismatch);
    }
    sign_id_token(signer, c).await.map_err(|transient| {
        if transient {
            TokenSignError::Transient
        } else {
            TokenSignError::Permanent
        }
    })
}

async fn sign_id_token(
    signer: &crate::state::SignerImpl,
    c: &IdTokenClaims<'_>,
) -> Result<String, bool> {
    let mut claims = serde_json::json!({
        "iss": c.issuer,
        "sub": c.sub,
        "aud": c.client_id,          // C2.6:单值 client_id(id_token 不用数组)
        "iat": c.now,
        "exp": c.now + ID_TOKEN_TTL_SECS,
        "auth_time": c.auth_time,    // C2.7:3LO id_token 一律含(简化;OIDC max_age 时 MUST)
        // jti(spec 011 C7.8a:id_token 作 subject_token 须带 jti;调用方传入以便落映射)。
        "jti": c.jti,
    });
    if let Some(n) = c.nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string()); // C2.9:带则 echo
    }
    // Canonical acr plus observed amr methods as OIDC top-level authentication context.
    if let Some(acr) = c.acr {
        claims["acr"] = serde_json::Value::String(acr.to_string());
    }
    if !c.amr.is_empty() {
        claims["amr"] = serde_json::Value::Array(
            c.amr
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        );
    }
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    match c.alg {
        "RS256" => {
            // header{alg,kid}(不含 at+jwt);kid MUST = **活跃 RSA key** 的 kid(与 sign_rs256 实际用的 key 对齐)。
            // **评审 Blocker(spec 005 §8)**:轮换重叠期 RSA published 多把时,`public_rsa_jwks().first()` 可能是
            // retiring 旧 key 或 publish-ahead 新 key ≠ 活跃签名 key → header.kid 与签名 key 错配、id_token 验签失败。
            // 故用 `active_rsa_kid()`(恒 = sign_rs256 用的活跃 key)。
            let rsa_kid = match signer.active_rsa_kid().await {
                Ok(k) => k,
                Err(crate::ports::SignerError::Transient(_)) => return Err(true),
                Err(_) => return Err(false), // 未配 RSA key
            };
            let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": rsa_kid });
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                payload_b64
            );
            match signer.sign_rs256(signing_input.as_bytes()).await {
                Ok((_kid, sig)) => Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))),
                Err(crate::ports::SignerError::Transient(_)) => Err(true),
                Err(_) => Err(false),
            }
        }
        "ES256" => {
            let kid = match signer.active_kid().await {
                Ok(k) => k,
                Err(crate::ports::SignerError::Transient(_)) => return Err(true),
                Err(_) => return Err(false),
            };
            let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                payload_b64
            );
            match signer.sign_es256(signing_input.as_bytes()).await {
                Ok(sig) => Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))),
                Err(crate::ports::SignerError::Transient(_)) => Err(true),
                Err(_) => Err(false),
            }
        }
        _ => Err(false), // 未知 alg(不该到这;DCR 已白名单)
    }
}

pub(crate) fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    // issuer host(C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    crate::hostutil::issuer_host(headers)
}

async fn parse_token_request(
    raw: axum::body::Bytes,
) -> Result<TokenRequest, axum::response::Response> {
    let request = axum::extract::Request::builder()
        .method("POST")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(raw.clone()))
        .expect("static token form request");
    match Form::<TokenRequest>::from_request(request, &()).await {
        Ok(Form(request)) => Ok(request),
        Err(_) => Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token request form is invalid",
        )
        .into_response()),
    }
}

fn token_form_is_ema(raw: &[u8]) -> bool {
    url::form_urlencoded::parse(raw)
        .any(|(name, value)| name == "grant_type" && value == agent_auth_ema::JWT_BEARER_GRANT)
}

fn has_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
}

/// `/token` 端点。EMA 使用独立 JWT bearer dispatch，不进入 RFC 8693 token exchange。
#[utoipa::path(
    post,
    path = "/token",
    tag = "token",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "签发 access token(aud 单元素、恒 ES256)", body = TokenResponse),
        (status = 400, description = "invalid_request / invalid_grant / invalid_target / invalid_scope / invalid_authorization_details / unsupported_grant_type", body = TokenError),
        (status = 401, description = "invalid_client", body = TokenError),
        (status = 500, description = "不可恢复的签发或配置错误", body = TokenError),
        (status = 503, description = "签名、JWKS 或存储依赖瞬时不可用", body = TokenError)
    )
)]
pub async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    // mTLS 客户端证书(spec 012 §1.4 / C5.7):仅当连接层有 API Gateway 已验链证书时存在(可测缝 mtls.rs)。
    client_cert: Option<axum::Extension<crate::mtls::ClientCertPem>>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    Box::pin(token_handler_inner(state, headers, client_cert, request)).await
}

async fn token_handler_inner(
    state: AppState,
    headers: HeaderMap,
    client_cert: Option<axum::Extension<crate::mtls::ClientCertPem>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let raw = match axum::body::Bytes::from_request(request, &()).await {
        Ok(raw) => raw,
        Err(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token request body is invalid",
            )
            .into_response()
        }
    };
    if !has_form_content_type(&headers) {
        if token_form_is_ema(&raw) {
            return crate::ema_flow::no_store(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "token request content type is invalid",
                )
                .into_response(),
            );
        }
        return err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "token request content type is invalid",
        )
        .into_response();
    }
    let req = match parse_token_request(raw).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    // EMA 是独立 opt-in grant；必须在通用 grant matrix 与 RFC 8693 dispatch 前识别。
    // feature-off 保持原 `unsupported_grant_type` 行为与协议面。
    if req.grant_type == agent_auth_ema::JWT_BEARER_GRANT {
        if state.ema_active() {
            let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
                Ok(tenant) => tenant,
                Err(response) => return crate::ema_flow::no_store(response),
            };
            if state.ema_active_for_tenant(&tenant) {
                return crate::ema_flow::handle(&state, &headers, &req).await;
            }
        }
        return crate::ema_flow::no_store(
            err(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "该 grant 在当前部署未启用",
            )
            .into_response(),
        );
    }

    // 1. grant 阶段门控(006):P0 只受理 authorization_code / refresh_token;其余(含 implicit)拒。
    if !grant_accepted(state.phase, &req.grant_type) {
        return err(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "该 grant 在当前阶段不受理",
        )
        .into_response();
    }

    // ⚠️ per-client 应用层限流(C10.7)**接线待"认证后 keying"设计**(评审 codex/Kiro HIGH#2):
    // 入口用 form `client_id` 限流是错的——code flow 的 client_id 在 code 校验前**未认证**(public+PKCE,
    // 任何人可声称任意 client_id → 打满受害者桶 = DoS 放大);且各 grant 真实 client 主体来源不同
    // (refresh=Basic/fam_rec、2LO=认证后 identity.client_id、token-exchange=actor)。正确做法是各 flow
    // **认证/绑定后**按真实 client 主体限流。令牌桶纯逻辑 + RateLimitStore(重试 CAS)+ 内存/Dynamo adapter
    // 已就绪(state.rate_limit),接线留该设计落地(spec 005 §3.1)。
    // refresh_token grant 走独立路径(C3 rotation + 复用检测)。
    if req.grant_type == "refresh_token" {
        return crate::refresh_flow::handle(&state, &headers, &req).await;
    }
    // client_credentials 走独立 2LO 路径：预注册 service 用标准 client auth，workload 用
    // OIDC/SigV4/SPIFFE/mTLS 身份(spec 001 C2.3 / spec 012 C5)。
    if req.grant_type == "client_credentials" {
        // X.509-SVID / mTLS(§1.4 / C5.7):**连接层证书身份排他**(评审 H1)——检测到已验链证书 + feature 开
        // + SelfHosted 即走 X.509 专用前导(**忽略 body 里的 client_assertion**),防"cert=A 建连 + body 塞 B 断言"。
        // 证书扩展仅 lambda 层从 requestContext 真实证书注入(H3:execute-api/CloudFront 路径恒无 → 不激活)。
        if let Some(axum::Extension(cert)) = client_cert.as_ref() {
            if state.mtls_svid_enabled {
                return crate::workload_flow::handle_x509(&state, &headers, &req, &cert.0).await;
            }
        }
        return crate::workload_flow::handle(&state, &headers, &req).await;
    }
    // token-exchange(RFC 8693 委托,spec 011 C7;grant_accepted 门控 P2)。
    if req.grant_type == crate::token_exchange::TOKEN_EXCHANGE_GRANT {
        return crate::token_exchange::handle(&state, &headers, &req).await;
    }
    // device_code(RFC 8628 device flow 轮询,spec 013 C7b.4;grant_accepted 门控 P2)。
    if req.grant_type == crate::device_flow::DEVICE_CODE_GRANT {
        return crate::device_flow::handle_token(&state, &headers, &req).await;
    }
    // CIBA poll(spec 013 C7b.2;grant_accepted 门控 P2)。
    if req.grant_type == crate::ciba_flow::CIBA_GRANT {
        return crate::ciba_flow::handle_token(&state, &headers, &req).await;
    }
    if req.grant_type != "authorization_code" {
        return err(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "本端点实现 authorization_code / refresh_token / client_credentials(2LO)",
        )
        .into_response();
    }

    let Some(code) = req.code.as_deref() else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺 code / client_id",
        )
        .into_response();
    };
    // RFC 6749 §2.3.1:client_secret_basic 的 client_id 来自 Basic username;
    // form client_id 可省。若两处都给则必须一致,防 client 身份混淆。
    let resolved_client_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        &headers,
        req.client_assertion.as_deref(),
    ) {
        Ok(Some(client_id)) => client_id,
        Err(error) => {
            return invalid_client_response(
                &headers,
                StatusCode::UNAUTHORIZED,
                error.description(),
            );
        }
        Ok(None) => {
            if headers.contains_key(axum::http::header::AUTHORIZATION) {
                return invalid_client_response(
                    &headers,
                    StatusCode::UNAUTHORIZED,
                    "Authorization client credentials invalid",
                );
            }
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺 code / client_id",
            )
            .into_response();
        }
    };
    let client_id = resolved_client_id.as_str();

    let now = current_unix_secs();
    // tenant 分区(spec 020 §2.3):从入站 Host 派生一次,贯穿 code/client/refresh/grant 全链
    // (codex M1:替代 tenant_from_issuer 硬编码 default;flag 关=空 tenant=现网单租户)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !state.region.owns_id(code) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code belongs to another Region",
        )
        .into_response();
    }

    // 2. 两阶段 lease 第①步(C10.1):原子占 signing lease——**尚未消费 code**。
    // 并发只一个占到;其余 Locked(处理中)。所有校验在 finalize 前做 → 校验失败/瞬时失败
    // 都不烧掉 code(修评审的"检查在消费后 DoS" + C10.1 三失败分治缺口)。
    let lease_owner = new_jti(&state);
    let lease_ttl = now + LEASE_TTL_SECS;
    let (record, code_replay, replay_issued_grant_id) = match state
        .codes
        .acquire_lease(&tenant, code, &lease_owner, now, lease_ttl)
        .await
    {
        Ok(LeaseAcquire::Acquired(record)) => (record, false, None),
        Ok(LeaseAcquire::AlreadyConsumed {
            record,
            issued_grant_id,
        }) => (record, true, issued_grant_id),
        Ok(LeaseAcquire::Locked) => {
            // 别人正在签(未过期 lease)→ 处理中,不重复签、不消费。
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "处理中,请稍后重试",
            )
            .into_response();
        }
        Ok(LeaseAcquire::NotFound) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "code 无效或已使用",
            )
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
        Err(crate::ports::StoreError::Permanent(e)) => {
            // 永久存储错(配置/表结构等)→ 500;记 stderr 供 CloudWatch 排障(不含敏感值)。
            eprintln!("acquire_lease permanent error: {e}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response();
        }
    };

    // **reject!**(pre-auth,release lease、不消费):用于客户端认证**之前**的失败(过期、
    // client_id 与 code 不匹配、client 查找/认证)——**故意 release 不消费**:偷 code + 错 client_id
    // 不能烧掉受害者 code(anti-DoS)。不迁会话(可能是攻击者,非 owner 的合法兑换)。
    macro_rules! reject {
        ($status:expr, $c:expr, $d:expr) => {{
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return err($status, $c, $d).into_response();
        }};
    }
    macro_rules! reject_invalid_client {
        ($status:expr, $d:expr) => {{
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return invalid_client_response(&headers, $status, $d);
        }};
    }
    // **reject_consumed!**(post-auth 语义失败,finalize 消费 code + 会话 exchange_failed):
    // 用于**客户端已认证之后**的语义失败(redirect_uri/PKCE/audience 不符)——此时是**已证明身份的
    // 合法 client** 发的坏请求,按 OAuth 2.1 一次性 code 语义消费,失败后同 code 不可重试(C6.3a);
    // 会话迁终态 exchange_failed + last_error(C6.3b,可观测)。
    macro_rules! reject_consumed {
        ($status:expr, $c:expr, $d:expr) => {{
            let last_error = serde_json::json!({
                "error": $c, "error_description": $d, "at": "token_endpoint", "ts": now
            })
            .to_string();
            let transition = state
                .codes
                .finalize_exchange_failure(
                    &state.authz_sessions,
                    &tenant,
                    code,
                    &record.client_id,
                    record.expires_at,
                    current_unix_secs(),
                    &lease_owner,
                    record.authz_session_id.as_deref(),
                    last_error,
                )
                .await;
            let transition = match transition {
                Ok(transition) => transition,
                Err(error) => {
                    eprintln!("authorization code exchange failure commit failed: {error:?}");
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "exchange failure commit failed, retry later",
                    )
                    .into_response();
                }
            };
            if let Some(session) = transition {
                crate::authz_session::emit_transition_event(&state, &session).await;
            }
            return err($status, $c, $d).into_response();
        }};
    }
    // A consumed code has no lease to finalize again. A replay must still prove the original
    // redirect/PKCE binding before it may revoke the first result; a mismatched binding is only
    // rejected and cannot be used as a revocation oracle.
    macro_rules! reject_bound_semantics {
        ($status:expr, $c:expr, $d:expr) => {{
            if code_replay {
                return err($status, $c, $d).into_response();
            }
            reject_consumed!($status, $c, $d);
        }};
    }

    // 3. 短命项 fail-closed 过期校验(C10.4)。
    if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, record.expires_at) {
        reject!(StatusCode::BAD_REQUEST, "invalid_grant", "code 已过期");
    }

    // 4. client_id 与 code 绑定一致(在 finalize 前;偷 code + 错 client_id 不会烧掉受害者 code)。
    if record.client_id != client_id {
        reject!(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id 与 code 不匹配"
        );
    }

    // 5. 客户端认证策略来自 code-bound authority:
    // - CIMD code 使用授权时已验证并持久化的快照，绝不在兑换时重取可变远端文档；
    // - 预注册/DCR code 继续强读 ClientStore，使删除/tombstone/凭据轮换立即生效。
    let client = match record.cimd_snapshot.as_ref() {
        Some(snapshot) if snapshot.client_id == record.client_id => snapshot.as_client_record(),
        Some(_) => reject!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "authorization code client metadata is inconsistent"
        ),
        None => match state.clients.get(&tenant, client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => reject_invalid_client!(StatusCode::BAD_REQUEST, "未知 client"),
            Err(crate::ports::StoreError::Transient(_)) => {
                reject!(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用"
                )
            }
            Err(_) => reject!(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误"
            ),
        },
    };
    let code_uses_pkce = !record.code_challenge.is_empty();
    let audit_identifier = record
        .cimd_snapshot
        .as_ref()
        .map(crate::cimd::CimdClientSnapshot::audit_identifier)
        .unwrap_or_else(|| client.client_id.clone());
    let client = match crate::client_auth::authenticate_loaded_snapshot_with_audit_identifier(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Token,
        &client,
        &headers,
        crate::client_auth::PresentedClientAuth::new(
            req.client_secret.as_deref(),
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
        ),
        &audit_identifier,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return match error {
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::ServerMisconfigured => err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidRequest(_) => err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidClient(_) => {
                    invalid_client_response(&headers, StatusCode::UNAUTHORIZED, error.description())
                }
            };
        }
    };
    // All client policy below uses the exact snapshot whose credentials were verified.
    if client.is_tombstoned() {
        reject_invalid_client!(StatusCode::BAD_REQUEST, "client 已回收");
    }
    if client.is_workload() {
        reject_invalid_client!(
            StatusCode::BAD_REQUEST,
            "workload clients cannot use authorization_code flow"
        );
    }
    if !code_uses_pkce
        && (record.cimd_snapshot.is_some()
            || !state.allows_authorization_code_without_pkce(&client))
    {
        reject_invalid_client!(
            StatusCode::BAD_REQUEST,
            "client 不再允许无 PKCE 的 authorization code 兑换"
        );
    }

    // —— 以下为**客户端已认证之后**的语义失败:用 reject_consumed!(消费 code + 会话 exchange_failed,
    //    C6.3a/b);已证明身份的 client 发的坏请求按一次性 code 语义处理,不可重试同 code ——

    // 6. redirect_uri 精确匹配(C4.5):authorize 绑定了 redirect_uri 时 token MUST 带且一致。
    if !record.redirect_uri.is_empty() {
        match req.redirect_uri.as_deref() {
            None => reject_bound_semantics!(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "缺 redirect_uri(须与 authorize 一致)"
            ),
            Some(ru) => match match_redirect(&RedirectMode::Exact, &record.redirect_uri, ru) {
                MatchResult::Allow => {}
                MatchResult::Reject(_) => {
                    reject_bound_semantics!(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "redirect_uri 不匹配"
                    )
                }
            },
        }
    }

    // 7. PKCE 校验(C4.1):challenge 存在时强制 verifier；无 challenge 时 verifier MUST NOT 出现。
    if code_uses_pkce {
        let Some(verifier) = req.code_verifier.as_deref() else {
            reject_bound_semantics!(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺 code_verifier(PKCE 强制)"
            );
        };
        if !verify_exchange(verifier, &record.code_challenge) {
            reject_bound_semantics!(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE 校验失败");
        }
    } else if req.code_verifier.is_some() {
        reject_bound_semantics!(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求未使用 PKCE，不得提交 code_verifier"
        );
    }

    if code_replay {
        match state
            .codes
            .record_replay(&tenant, code, current_unix_secs())
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "authorization code expired before replay handling",
                )
                .into_response()
            }
            Err(_) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization code replay state unavailable",
                )
                .into_response()
            }
        }
        if let Some(grant_id) = replay_issued_grant_id.as_deref() {
            if revoke_code_issued_authorization(&state, &tenant, grant_id)
                .await
                .is_err()
            {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization code replay cleanup unavailable",
                )
                .into_response();
            }
        }
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code was already used",
        )
        .into_response();
    }

    // per-client 限流(C10.7 / spec 005 §3.1):已认证且 redirect/PKCE 绑定正确的 replay
    // 必须先完成撤销，不能被普通签发限流跳过。新签发被限流时释放自己的 lease、
    // 不消费 code，返回 429 + Retry-After，允许稍后安全重试。
    if let Some(resp) = crate::ratelimit_gate::check(&state, &tenant, client_id).await {
        match state
            .codes
            .release_lease(&tenant, code, &lease_owner, current_unix_secs())
            .await
        {
            Ok(()) => return resp,
            Err(crate::ports::StoreError::Transient(_)) => {
                return err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization code lease release unavailable",
                    LEASE_TTL_SECS as u64,
                )
                .into_response()
            }
            Err(crate::ports::StoreError::Permanent(error)) => {
                eprintln!("release_lease permanent error after client throttling: {error}");
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "authorization code lease release failed",
                )
                .into_response();
            }
        }
    }

    // 7b. Codes issued before an account or credential authority change
    // cannot cross that fence. Legacy records have no safe authority snapshot.
    let Some(credential_epoch) = record.credential_epoch else {
        reject_consumed!(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code missing user authority"
        )
    };
    match crate::user_gate::require_active_user_epoch(
        &state,
        &tenant,
        &record.user_id,
        credential_epoch,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::user_gate::UserGate::Blocked) => {
            reject_consumed!(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "user authority changed after authorization"
            )
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            reject!(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "user authority 查询失败"
            )
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    }
    match crate::user_gate::require_password_authority_version(
        &state,
        &tenant,
        &record.user_id,
        record.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        crate::user_gate::PasswordGate::ChangeRequired => {
            reject_consumed!(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "password authority changed after authorization"
            )
        }
        crate::user_gate::PasswordGate::Unavailable => {
            reject!(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "password authority 查询失败"
            )
        }
    }

    // 8. audience 选择(C2.8):token 显式 resource > 继承 code-bound 单值 > default/userinfo。
    let issuer = match host_from_headers(&headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    {
        Some(i) => i,
        None => reject_consumed!(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法"),
    };
    // C10.22a 跨租户防伪造闸(spec 020):待签 iss MUST 属本请求租户。**当前结构上恒成立**(iss 由
    // 请求 Host 派生、非客户端/存储提供),此闸是**纵深防御 + 回归护栏**——若将来某重构让 iss 来自
    // 别处(存储的 family issuer / 客户端参数),本闸 fail-closed 拦住跨租户伪造。共享 CMK 下这是唯一
    // 应用层租户边界。
    if !crate::tenant::issuer_belongs_to_request_tenant(
        &state,
        &headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("authorization-code-token"),
    )
    .await
    {
        reject_consumed!(StatusCode::BAD_REQUEST, "invalid_request", "iss 不属本租户");
    }
    // record.resources 已在 authorize 时按部署阶段门控(P0 单值/P1+ 多值);token 侧只**加载**该集合、
    // 由 select_audience 收窄到单值(C2.5b),不再二次阶段门控——故用 P1Plus 装载(不会因多值报错把授权集合
    // 误清空、导致合法 token resource 被拒)。
    let authorized = AuthorizedResources::from_authorize(&record.resources, AuthorizePhase::P1Plus)
        .unwrap_or_else(|_| {
            AuthorizedResources::from_authorize(&[], AuthorizePhase::P1Plus).unwrap()
        });
    let reg = ClientRegistration {
        default_resource: client.default_resource.clone(),
    };
    let token_resources: Vec<String> = req.resource.iter().cloned().collect();
    let aud = match select_audience(&token_resources, &authorized, &reg) {
        Ok(AudienceSelection::Resource(r)) => r,
        Ok(AudienceSelection::UserinfoFallback) => format!("{}/userinfo", issuer.as_str()),
        Err(_) => reject_consumed!(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource 不属授权集合"
        ),
    };

    // pairwise sub 派生(spec 001 C2.11 / §2.8;评审收敛)。两个 sector:
    // - OIDC sector(id_token / aud=<issuer>/userinfo 的 token)= client 的 oidc_sector(注册持久化)。
    // - MCP sector(aud=某 RS 的 access token)= aud(每 RS 不同 sub)。
    // pairwise 下 OIDC sector 算不出(多 host 无 sector_identifier_uri)→ 拒签(sub 不可确定)。
    // 惰性:仅当真需要 OIDC sub(签 id_token 或 aud=/userinfo)才算/才可能因缺 sector 拒;
    // 纯 MCP token(aud=RS 且无 openid)不需要 OIDC sub,不受多 host pairwise 限制。
    let mode = subject_mode(state.subject_type_for_tenant(&tenant));
    let userinfo_aud = format!("{}/userinfo", issuer.as_str());
    let wants_openid = record.scope.iter().any(|s| s == "openid");
    let needs_oidc_sub = aud == userinfo_aud || wants_openid;
    let oidc_sub = if needs_oidc_sub {
        Some(match mode {
            agent_auth_token::SubjectMode::Public => record.user_id.clone(),
            agent_auth_token::SubjectMode::Pairwise => match client.oidc_sector() {
                Some(sector) => {
                    agent_auth_token::pairwise_sub(&state.server_secret, &record.user_id, &sector)
                }
                None => reject_consumed!(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "pairwise 下无法确定 OIDC sector(多 redirect host 须 sector_identifier_uri)"
                ),
            },
        })
    } else {
        None
    };
    // access token 的 sub:aud=/userinfo 用 OIDC sub(与 id_token 一致,C2.11);否则按 aud(RS)派生。
    let access_sub = if aud == userinfo_aud {
        oidc_sub
            .clone()
            .expect("needs_oidc_sub 在 aud==userinfo_aud 时必为 true")
    } else {
        agent_auth_token::derive_user_sub(mode, &state.server_secret, &record.user_id, &aud)
    };

    // RAR(spec 010 §4):token 单 aud → **只带按 locations 归属本 aud 的 authorization_details 条目**
    // (无 locations=全局适用;有=匹配 resource 才带)。单 aud token 不塞全数组(评审 Q3)。
    let rar_for_aud: Vec<serde_json::Value> = record
        .authorization_details
        .iter()
        .filter(|e| agent_auth_grant::rar::location_matches(e, &aud))
        .cloned()
        .collect();

    // family_id 提前生成(下方建 refresh family + Grant 用同一 id;grant_id=family_id 迁移不变式)。
    // **auth_grant 用稳定 family_id/grant_id(非 ephemeral code)**:令 access token 的命名空间 auth_grant
    // 指向源 Grant,introspect 得以按 auth_grant 反查 Grant 反映吊销(C7.6b/§5.1;refresh 承接同 id)。
    let family_id = if state.phase.at_least(agent_auth_discovery::Phase::P3)
        && !record.authorization_details.is_empty()
    {
        crate::refresh_flow::new_grant_backed_rar_family_id(&state)
    } else {
        crate::refresh_flow::new_family_id(&state)
    };

    // 逐租户 ECC Sign 公平闸(spec 020 §3.1 / C10.14):全局闸之前——noisy 租户超份额即 503、不扣全局桶。
    // 超额同全局闸处置:release lease + 不消费 code(可重试)。默认关字节等价。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_tenant_gate(&state, &tenant).await {
        let _ = state
            .codes
            .release_lease(&tenant, code, &lease_owner, current_unix_secs())
            .await;
        return resp;
    }
    // 全局 KMS Sign 前置并发闸(spec 005 §1.4 / C10.2):KMS Sign 前主动 shed,保护该区 Sign 配额、
    // 防"throttle→重试→更多 Sign"正反馈雪崩。超额 → 503+Retry-After + release lease + 不消费 code(可重试,
    // 与反应式 KMS throttle 同处置)。默认关(未配容量则放行),启用后全局单桶。置于所有校验之后、Sign 之前。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_gate(&state).await {
        let _ = state
            .codes
            .release_lease(&tenant, code, &lease_owner, current_unix_secs())
            .await;
        return resp;
    }

    // DPoP 绑定(spec 010 §5.2,C8.7b):有 DPoP proof → 校验得 jkt 写 cnf.jkt;无 → bearer。
    // 校验失败/重放 → invalid_dpop_proof(不降级)。置于签名前(release lease、不消费)。
    let dpop_jkt = match crate::dpop::resolve_dpop_binding(
        &state,
        &headers,
        &tenant,
        issuer.as_str(),
        client.require_dpop,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => {
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return resp;
        }
    };

    // Resolve one immutable EC/RSA generation for the entire exchange. Access
    // and ID tokens from this response must never straddle a rotation commit.
    let tenant_signer = match crate::tenant_keys::signer_or_503(&state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => {
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return response;
        }
    };

    // 9-10. 组装 + 签名 access token(共用 helper;C2.5a/C10.15a)。签名**在 finalize 前**。
    let scope_str = record.scope.join(" ");
    let access_jti = new_jti(&state);
    let signed_access_token = match sign_tenant_access_token_with_delivery(
        &state,
        &headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: issuer.as_str(),
            sub: &access_sub,
            aud: &aud,
            client_id,
            scope: &scope_str,
            jti: &access_jti,
            auth_grant: &family_id, // 稳定 grant_id(=family_id),introspect 据此反查 Grant 反映吊销
            sub_type: SubType::User, // 3LO code flow
            authorization_details: &rar_for_aud,
            cnf_jkt: dpop_jkt.as_deref(),
            auth_time: Some(record.auth_time),
            acr: record.acr.as_deref(),
            now,
        },
        state.phase.at_least(agent_auth_discovery::Phase::P3),
        crate::security_event::SecurityActor::system("authorization-code-token"),
    )
    .await
    {
        Ok(j) => j,
        // C10.1 ①/C10.2:签名瞬时失败(KMS throttle 等)→ release lease、不消费 code、可重试;
        // **503 + Retry-After**(C10.2:提示客户端退避重试,签名后端秒级恢复)。
        Err(TokenSignError::Transient) => {
            let _ = state
                .codes
                .release_lease(&tenant, code, &lease_owner, current_unix_secs())
                .await;
            return err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "签名瞬时失败(KMS throttle),请退避重试",
                1,
            )
            .into_response();
        }
        Err(TokenSignError::TooLarge) => reject!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            TOKEN_TOO_LARGE_ERROR_DESCRIPTION
        ),
        Err(TokenSignError::IssuerMismatch) => {
            reject!(StatusCode::BAD_REQUEST, "invalid_request", "iss 不属本租户")
        }
        Err(TokenSignError::Permanent) => reject!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "签名失败"
        ),
    };
    let jwt = signed_access_token.token.clone();

    // 11. 第③步:finalize 消费 code(签名成功后)。finalize 失败则不返 token、保留 lease(C10.1 ③)。
    if state
        .codes
        .finalize(
            &tenant,
            code,
            &record.client_id,
            record.expires_at,
            current_unix_secs(),
            &lease_owner,
            Some(&family_id),
        )
        .await
        .is_err()
    {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "finalize 失败,请重试",
        )
        .into_response();
    }
    // spec 004:兑换成功 → 授权会话迁到终态 complete(可观测旁路)。
    if let Some(sid) = record.authz_session_id.as_deref() {
        crate::authz_session::transition(
            &state,
            &tenant,
            sid,
            agent_auth_authn::authz_session::AuthzState::Complete,
            None,
        )
        .await;
    }

    // 12. 签发 refresh token(C3):新建 family(version 0),refresh token = family_id.version
    // (不透明串;绑定整个 resource 集合 C3.6)。family_id 已在签名前生成(auth_grant 用它)。
    // family 与 Grant 是 access token 在线吊销的两套权威记录；普通发行可单独降级但不能同时缺失。
    // 带 RAR marker 的 family 若 Grant 未落盘，只可保留 inline access token，不得把注定无法
    // refresh 的 handle 返回客户端；若 access token 已用 Grant-backed summary 则整次拒绝。
    let refresh_token = crate::refresh_flow::encode_refresh(&family_id, 0);
    let fam = crate::ports::RefreshFamilyRecord {
        family_id: family_id.clone(),
        current_version: 0,
        revoked: false,
        client_id: client_id.to_string(),
        cimd_snapshot: record.cimd_snapshot.clone(),
        user_id: record.user_id.clone(),
        credential_epoch,
        resources: record.resources.clone(),
        scope: record.scope.clone(),
        // 普通 3LO 不授委托(actor_allowlist 空 → token-exchange 身份闸拒);委托授权源待 authorize/Grant 扩展。
        actor_allowlist: vec![],
        max_act_chain: 1,
        // DPoP 绑定延续(spec 010 §5.2/B1):DPoP-bound 首签把 jkt 存进 family → refresh 换发须匹配 proof。
        dpop_jkt: dpop_jkt.clone(),
        pkce_code_challenge: (!record.code_challenge.is_empty())
            .then(|| record.code_challenge.clone()),
        auth_time: Some(record.auth_time),
        acr: record.acr.clone(),
        password_credential_version: record.password_credential_version,
    };
    let family_created = state.refresh.create(&tenant, fam).await.is_ok();
    let mut refresh_out = family_created.then(|| refresh_token.clone());
    let post_create_user_authority = crate::user_gate::require_active_user_epoch(
        &state,
        &tenant,
        &record.user_id,
        credential_epoch,
    )
    .await;
    let post_create_password_authority = crate::user_gate::require_password_authority_version(
        &state,
        &tenant,
        &record.user_id,
        record.password_credential_version,
    )
    .await;
    if post_create_user_authority.is_err()
        || post_create_password_authority != crate::user_gate::PasswordGate::Allowed
    {
        let cleanup_ok = !family_created || state.refresh.revoke(&tenant, &family_id).await.is_ok();
        if !cleanup_ok {
            eprintln!("TOKEN_POST_AUTHORITY_CLEANUP_FAIL tenant={tenant}");
        }
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "user authority changed during token issuance",
        )
        .into_response();
    }

    // spec 011 §5.1(P2):**正式化 Grant 对象**为授权权威源(family 回归纯 token 轮换记录)。
    // 3LO code flow 授权:per_resource 由 authorize 声明的 resource 集合 + scope 构成;委托约束用
    // migration_constraints(max_act_chain=1、actor_allowlist 仅 owning agent、expires_at 继承 family)。
    // 普通 3LO 无 workload agent 概念,owning agent = client_id(code-flow client;token-exchange 身份闸
    // 仍要求 actor 是已认证 workload,故普通 3LO 的 Grant 实际不授委托——与前身语义一致)。Grant 与
    // family 同 id(grant_id=family_id)便于关联。Grant 创建不依赖 family 创建，确保单个存储
    // 瞬时失败时 access token 仍有可供 replay/在线验证吊销的权威记录。
    let per_resource: Vec<agent_auth_grant::ResourceGrant> = record
        .resources
        .iter()
        .map(|r| agent_auth_grant::ResourceGrant {
            resource: r.clone(),
            scopes: record.scope.clone(),
            // RAR(spec 010 §4):按 locations 归本 resource 的 authorization_details 条目(无 locations
            // =全局适用挂每个 resource;有=匹配才挂)——Grant 是 RAR 权威源,再发行(refresh/委托)据此透传。
            authorization_details: record
                .authorization_details
                .iter()
                .filter(|e| agent_auth_grant::rar::location_matches(e, r))
                .cloned()
                .collect(),
        })
        .collect();
    let mut grant = agent_auth_grant::Grant {
        grant_id: family_id.clone(),
        user_id: record.user_id.clone(),
        client_id: client_id.to_string(),
        per_resource,
        // effective/pv/ip/revision:flag 关默认空(effective_view 回退 per_resource,字节等价);
        // flag 开由 authz_gate::apply_policy_to_grant 填(spec 005 §7 T7.5)。
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch,
        revision: 0,
        constraints: agent_auth_grant::migration_constraints(client_id, now + GRANT_TTL_SECS),
        status: agent_auth_grant::GrantStatus::Active,
    };
    // T7.5:flag 开则 Cedar 预判收窄 effective + 打 pv 戳;策略缺失/坏 → fail-closed 不落 Grant。
    let mut grant_client_conflict = false;
    let grant_created =
        match crate::authz_gate::apply_policy_to_grant(&state, &tenant, &mut grant).await {
            Ok(()) => match state
                .put_grant_for_client(&tenant, grant, record.cimd_snapshot.is_none())
                .await
            {
                Ok(true) => true,
                Ok(false) => {
                    grant_client_conflict = true;
                    false
                }
                Err(_) => false,
            },
            Err(e) => {
                eprintln!("[authz] Grant 策略预判失败(fail-closed 不落 Grant):{e}");
                false
            }
        };
    state
        .record_security_event(crate::security_event::SecurityEventDraft::grant(
            &tenant,
            crate::security_event::SecurityActor::user(&record.user_id),
            &family_id,
            crate::security_event::GrantAction::Create,
            if grant_created {
                crate::security_event::SecurityEventOutcome::Success
            } else {
                crate::security_event::SecurityEventOutcome::Failure
            },
        ))
        .await;
    if grant_client_conflict {
        if family_created && state.refresh.revoke(&tenant, &family_id).await.is_err() {
            eprintln!("TOKEN_CLIENT_FENCE_REFRESH_CLEANUP_FAIL tenant={tenant}");
        }
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client authority changed during token issuance",
        )
        .into_response();
    }
    if !grant_created && crate::refresh_flow::requires_grant_backed_rar(&family_id) {
        refresh_out = None;
    }
    if signed_access_token.grant_backed_rar && !grant_created {
        if family_created && state.refresh.revoke(&tenant, &family_id).await.is_err() {
            eprintln!("TOKEN_GRANT_BACKED_RAR_REFRESH_CLEANUP_FAIL tenant={tenant}");
        }
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "grant-backed authorization persistence failed",
        )
        .into_response();
    }
    if !family_created && !grant_created {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "authorization state persistence failed",
        )
        .into_response();
    }

    // spec 011 C7.8:落 access token 的 jti→{user_id, family_id, grant_id} 映射(token-exchange subject
    // 解析用;绝不解 pairwise sub)。**jti tenant = 本请求派生的 tenant**(codex M1:不再硬编码 default;
    // 空 tenant[flag 关]→ jti 沿用历史 "default" 分区键[jti store 一贯用 default],保持后向兼容;
    // 非空 → 真租户,token-exchange 反查同租户命中)。失败不阻断签发。
    let tenant_id = if tenant.is_empty() {
        "default".to_string()
    } else {
        tenant.clone()
    };
    let jti_family = family_created.then(|| family_id.clone());
    let jti_grant = grant_created.then(|| family_id.clone());
    if let Some(jti_store) = &state.jti_store {
        let _ = jti_store
            .put(crate::ports::JtiRecord {
                jti: access_jti.clone(),
                tenant_id: tenant_id.clone(),
                user_id: record.user_id.clone(),
                family_id: jti_family.clone(),
                grant_id: jti_grant.clone(),
                expires_at: now + ACCESS_TTL_SECS,
            })
            .await;
    }

    // 13a. scope 含 openid → 签 id_token(spec 001 C2.6/C2.7/C2.9)。sub = oidc_sub(pairwise 下按
    // client OIDC sector 派生,与 /userinfo 一致 C2.11;public 下 = user_id)。alg 按 client 注册(缺省 RS256)。
    // id_token 签名失败**不阻断** access_token 返回(降级:返回无 id_token,记日志);OIDC client 会察觉缺失。
    let id_token = if wants_openid {
        // wants_openid ⇒ needs_oidc_sub ⇒ oidc_sub 必为 Some(否则上文已因缺 sector 拒)。
        let oidc_sub = oidc_sub
            .as_deref()
            .expect("wants_openid 时 oidc_sub 必已算出");
        let id_jti = new_jti(&state);
        match sign_tenant_id_token(
            &state,
            &headers,
            tenant_signer.as_ref(),
            &IdTokenClaims {
                issuer: issuer.as_str(),
                sub: oidc_sub, // C2.11:id_token 用 OIDC sector sub,与同 sector 的 /userinfo 一致
                client_id,
                auth_time: record.auth_time,
                nonce: record.nonce.as_deref(),
                alg: client.id_token_alg(),
                jti: &id_jti,
                now,
                // Preserve the canonical assurance event and observed methods from the code.
                acr: record.acr.as_deref(),
                amr: &record.amr,
            },
            crate::security_event::SecurityActor::system("authorization-code-id-token"),
        )
        .await
        {
            Ok(t) => {
                // C7.8a:id_token 作 subject_token 须能反查 → 落其 jti 映射(同 family)。
                if let Some(jti_store) = &state.jti_store {
                    let _ = jti_store
                        .put(crate::ports::JtiRecord {
                            jti: id_jti,
                            tenant_id: tenant_id.clone(),
                            user_id: record.user_id.clone(),
                            family_id: jti_family.clone(),
                            grant_id: jti_grant.clone(),
                            expires_at: now + ID_TOKEN_TTL_SECS,
                        })
                        .await;
                }
                Some(t)
            }
            Err(_) => {
                eprintln!(
                    "[id_token] 签发失败(alg={}),降级返回无 id_token",
                    client.id_token_alg()
                );
                None
            }
        }
    } else {
        None
    };

    // A replay can arrive after finalize but before the family/Grant writes above complete.
    // The replay request records a durable marker before attempting revocation; this final
    // strong read closes that race and suppresses any token response whose cleanup was early.
    match state.codes.replay_detected(&tenant, code).await {
        Ok(false) => {}
        Ok(true) => {
            let cleanup_ok = revoke_code_issued_authorization(&state, &tenant, &family_id)
                .await
                .is_ok();
            if !cleanup_ok {
                eprintln!("TOKEN_CODE_REPLAY_CLEANUP_FAIL tenant={tenant}");
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization code replay cleanup unavailable",
                )
                .into_response();
            }
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code was reused during token issuance",
            )
            .into_response();
        }
        Err(_) => {
            let _ = revoke_code_issued_authorization(&state, &tenant, &family_id).await;
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authorization code replay state unavailable",
            )
            .into_response();
        }
    }

    // 13. code flow 恒返回 access_token(C2.8)+ refresh_token(+ openid 时 id_token)。
    // 记预注册 client 最后使用日。CIMD identity 没有 ClientStore 行，快照本身已绑定到 code/family。
    if record.cimd_snapshot.is_none() {
        touch_client_last_used(&state, &tenant, client_id, now).await;
    }

    // Final authority check after every successful-path await above (Grant/JTI
    // persistence, ID-token signing, and client touch). A reset that completed
    // during any of that work must suppress the response and revoke the newly
    // created authorization state. Keep this as the final awaited operation on
    // the successful response path.
    let final_epoch = crate::user_gate::require_active_user_epoch(
        &state,
        &tenant,
        &record.user_id,
        credential_epoch,
    )
    .await;
    // Password authority is deliberately last: reset uses a separate
    // credential store and the C9.8 contract requires this read to follow
    // every other successful-path await.
    let final_authority = crate::user_gate::require_password_authority_version(
        &state,
        &tenant,
        &record.user_id,
        record.password_credential_version,
    )
    .await;
    if final_authority != crate::user_gate::PasswordGate::Allowed || final_epoch.is_err() {
        let mut cleanup_ok =
            !family_created || state.refresh.revoke(&tenant, &family_id).await.is_ok();
        if grant_created {
            cleanup_ok &= crate::grants::revoke_with_audit(
                &state,
                &tenant,
                crate::security_event::SecurityActor::system("token-final-authority"),
                &family_id,
            )
            .await;
        }
        if final_authority == crate::user_gate::PasswordGate::Unavailable
            || matches!(final_epoch, Err(crate::user_gate::UserGate::Unavailable))
        {
            eprintln!("TOKEN_FINAL_AUTHORITY_UNAVAILABLE tenant={tenant}");
        }
        if !cleanup_ok {
            eprintln!("TOKEN_FINAL_AUTHORITY_CLEANUP_FAIL tenant={tenant}");
        }
        // The code was finalized above, so this response must not invite a
        // retry with an authorization code that can no longer succeed.
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "user authority changed during token issuance",
        )
        .into_response();
    }

    Json(TokenResponse {
        access_token: jwt,
        token_type: token_type_for(dpop_jkt.as_deref()),
        expires_in: ACCESS_TTL_SECS,
        scope: (!scope_str.is_empty()).then_some(scope_str),
        refresh_token: refresh_out,
        id_token,
        resource: None,
    })
    .into_response()
}

/// token 响应的 `token_type`(RFC 9449 §5:DPoP-bound token[带 cnf.jkt]MUST 标 `DPoP`,否则客户端会按
/// `Authorization: Bearer` 用 → 正确执行 cnf 的 RS 拒、或诱导降级)。有 cnf → `DPoP`;无 → `Bearer`(评审 M/codex)。
pub(crate) fn token_type_for(cnf_jkt: Option<&str>) -> String {
    if cnf_jkt.is_some() {
        "DPoP".to_string()
    } else {
        "Bearer".to_string()
    }
}

/// 新 jti(CSPRNG,base64url;spec 011 C7.8:token 唯一标识,不透明)。
pub(crate) fn new_jti(state: &AppState) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    state.region.issue_id(URL_SAFE_NO_PAD.encode(b))
}

/// 系统时钟(Unix 秒)。纯逻辑 crate 不读墙上时钟;HTTP 边界这里取一次注入下游。
fn current_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 供 authorize 模块复用的系统时钟(同 `current_unix_secs`)。
pub fn current_unix_secs_pub() -> i64 {
    current_unix_secs()
}

/// 天级桶(`floor(now/86400)`,spec 005 §9.2):client `last_used_day` 追踪用。
pub fn day_bucket(now_secs: i64) -> i64 {
    now_secs.div_euclid(86_400)
}

/// 尽力而为记 client 最后使用日(spec 005 §9.2,C10.5):签发成功后调用。
/// **不影响签发**——瞬时失败只 `warn!`(可挂 CloudWatch metric filter 告警;评审:陈旧 last_used
/// 方向不安全须可观测),同日条件写天然去重(不放大热路径)。
pub async fn touch_client_last_used(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    now_secs: i64,
) {
    use crate::ports::ClientStore;
    if let Err(e) = state
        .clients
        .touch_last_used(tenant, client_id, day_bucket(now_secs))
        .await
    {
        // 失败吞掉不拒签;打标记到 stderr(CloudWatch metric filter 可匹配 `TOUCH_LAST_USED_FAIL` 告警——
        // 持续失败 → 全体看似闲置 → 批量误回收;评审:陈旧 last_used 方向不安全须可观测)。
        eprintln!("TOUCH_LAST_USED_FAIL client={client_id} err={e:?}");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::adapters::memory::MemorySigner;
    use crate::state::SignerImpl;

    fn decode_claims(jwt: &str) -> serde_json::Value {
        let payload = jwt.split('.').nth(1).expect("JWT payload");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
            .expect("JSON claims")
    }

    fn object_keys(value: &serde_json::Value) -> BTreeSet<&str> {
        value
            .as_object()
            .expect("JSON object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    fn assert_rfc8693_act(value: &serde_json::Value) {
        let object = value.as_object().expect("act must be an object");
        assert!(
            object.contains_key("sub"),
            "every RFC 8693 act layer must contain sub"
        );
        assert!(
            object.keys().all(|key| key == "sub" || key == "act"),
            "act must contain only RFC 8693 sub/act fields: {object:?}"
        );
        if let Some(prior) = object.get("act") {
            assert_rfc8693_act(prior);
        }
    }

    #[tokio::test]
    async fn c10_22a_shared_signer_rejects_foreign_issuer_before_signing() {
        let mut state = AppState::dev("auth.example.com");
        let isolated_signer =
            std::sync::Arc::new(SignerImpl::Memory(MemorySigner::from_seed([85; 32])));
        state.signer = isolated_signer.clone();
        state.tenant_keys = std::sync::Arc::new(crate::tenant_keys::TenantKeyService::shared(
            isolated_signer,
        ));
        state.form = agent_auth_discovery::Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "t1.aws.example.com".parse().unwrap());
        let t1_signer = state.tenant_keys.resolve("t1").await.unwrap();
        let t2_signer = state.tenant_keys.resolve("t2").await.unwrap();
        assert_eq!(
            t1_signer.active_kid().await.unwrap(),
            t2_signer.active_kid().await.unwrap(),
            "claims-tier fixture must use one shared signing key"
        );
        let crate::state::SignerImpl::Memory(memory_signer) = t1_signer.as_ref() else {
            panic!("test fixture must use MemorySigner");
        };
        let claims = AccessTokenClaims {
            issuer: "https://t2.aws.example.com",
            sub: "user-1",
            aud: "https://rs.example",
            client_id: "client-1",
            scope: "read",
            jti: "jti-1",
            auth_grant: "authorization_code",
            sub_type: SubType::User,
            authorization_details: &[],
            cnf_jkt: None,
            auth_time: None,
            acr: None,
            now: 1_000,
        };
        let sign_count_before = memory_signer.es256_sign_count();

        let error = sign_tenant_access_token(
            &state,
            &headers,
            t1_signer.as_ref(),
            &claims,
            crate::security_event::SecurityActor::system("c10.22a-test"),
        )
        .await
        .unwrap_err();
        assert_eq!(error, TokenSignError::IssuerMismatch);
        assert_eq!(
            memory_signer.es256_sign_count(),
            sign_count_before,
            "foreign issuer must be rejected before the shared signer is called"
        );

        let unguarded = sign_access_token(t1_signer.as_ref(), &claims)
            .await
            .expect("the shared key can cryptographically sign the foreign issuer");
        assert_eq!(
            decode_claims(&unguarded)["iss"],
            "https://t2.aws.example.com"
        );
        assert_eq!(
            memory_signer.es256_sign_count(),
            sign_count_before + 1,
            "the counterexample must prove that only the application guard prevents forgery"
        );

        let id_token_claims = IdTokenClaims {
            issuer: claims.issuer,
            sub: claims.sub,
            client_id: claims.client_id,
            auth_time: claims.now,
            nonce: None,
            alg: "ES256",
            jti: "id-jti",
            now: claims.now,
            acr: None,
            amr: &[],
        };
        let id_token_error = sign_tenant_id_token(
            &state,
            &headers,
            t1_signer.as_ref(),
            &id_token_claims,
            crate::security_event::SecurityActor::system("c10.22a-id-token-test"),
        )
        .await
        .unwrap_err();
        assert_eq!(id_token_error, TokenSignError::IssuerMismatch);
        assert_eq!(
            memory_signer.es256_sign_count(),
            sign_count_before + 1,
            "foreign ID-token issuer must be rejected before signing"
        );

        let unguarded_id_token = sign_id_token(t1_signer.as_ref(), &id_token_claims)
            .await
            .expect("the shared key can sign a foreign-issuer ID token");
        assert_eq!(
            decode_claims(&unguarded_id_token)["iss"],
            "https://t2.aws.example.com"
        );
        assert_eq!(memory_signer.es256_sign_count(), sign_count_before + 2);

        let delegation_error = match sign_tenant_delegation_token_with_delivery(
            &state,
            &headers,
            t1_signer.as_ref(),
            claims.issuer,
            claims.sub,
            claims.aud,
            claims.client_id,
            claims.scope,
            claims.auth_grant,
            "agent-1",
            None,
            None,
            &[],
            None,
            None,
            None,
            "delegated-jti",
            claims.now,
            false,
            crate::security_event::SecurityActor::system("c10.22a-delegation-test"),
        )
        .await
        {
            Ok(_) => panic!("foreign delegation issuer must be rejected"),
            Err(error) => error,
        };
        assert_eq!(delegation_error, TokenSignError::IssuerMismatch);
        assert_eq!(
            memory_signer.es256_sign_count(),
            sign_count_before + 2,
            "foreign delegation issuer must be rejected before signing"
        );

        let unguarded_delegation = sign_delegation_token(
            t1_signer.as_ref(),
            claims.issuer,
            claims.sub,
            claims.aud,
            claims.client_id,
            claims.scope,
            claims.auth_grant,
            "agent-1",
            None,
            None,
            &[],
            None,
            None,
            None,
            "delegated-jti",
            claims.now,
        )
        .await
        .expect("the shared key can sign a foreign-issuer delegation token");
        assert_eq!(
            decode_claims(&unguarded_delegation)["iss"],
            "https://t2.aws.example.com"
        );
        assert_eq!(memory_signer.es256_sign_count(), sign_count_before + 3);

        let grant_ref_error = sign_tenant_grant_ref(
            &state,
            &headers,
            t1_signer.as_ref(),
            "grant-1",
            "spiffe://agent.example/worker",
            claims.issuer,
            claims.now,
            crate::security_event::SecurityActor::system("c10.22a-grant-ref-test"),
        )
        .await
        .unwrap_err();
        assert_eq!(grant_ref_error, TokenSignError::IssuerMismatch);
        assert_eq!(
            memory_signer.es256_sign_count(),
            sign_count_before + 3,
            "foreign grant-ref issuer must be rejected before signing"
        );

        let unguarded_grant_ref = sign_grant_ref(
            t1_signer.as_ref(),
            "grant-1",
            "spiffe://agent.example/worker",
            claims.issuer,
            claims.now,
        )
        .await
        .expect("the shared key can sign a foreign-issuer grant-ref");
        assert_eq!(
            decode_claims(&unguarded_grant_ref)["iss"],
            "https://t2.aws.example.com"
        );
        assert_eq!(memory_signer.es256_sign_count(), sign_count_before + 4);
    }

    #[tokio::test]
    async fn access_token_signer_namespaces_all_private_claims() {
        let signer = SignerImpl::Memory(MemorySigner::dev());
        let jwt = sign_access_token(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: "https://rs.example",
                client_id: "client-1",
                scope: "read",
                jti: "jti-1",
                auth_grant: "authorization_code",
                sub_type: SubType::User,
                authorization_details: &[],
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
        )
        .await
        .expect("access-token signing must succeed");
        assert!(
            jwt.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES,
            "ordinary access tokens should remain below the 4 KiB target"
        );
        let claims = decode_claims(&jwt);

        assert_eq!(
            object_keys(&claims),
            BTreeSet::from([
                "aud",
                "client_id",
                "exp",
                "iat",
                "iss",
                "jti",
                "scope",
                "sub",
                agent_auth_token::NAMESPACE,
            ]),
            "access-token top-level claims must contain only the canonical public set"
        );
        let namespace = &claims[agent_auth_token::NAMESPACE];
        assert_eq!(
            object_keys(namespace),
            BTreeSet::from(["auth_grant", "sub_type"])
        );
        assert_eq!(namespace["sub_type"], "user");
        assert_eq!(namespace["auth_grant"], "authorization_code");
        assert!(
            validate_shape(&claims).is_empty(),
            "signed access-token claims must satisfy the canonical shape"
        );
    }

    #[tokio::test]
    async fn delegation_token_signer_namespaces_private_claims_and_keeps_act_pure() {
        let signer = SignerImpl::Memory(MemorySigner::dev());
        let jwt = sign_delegation_token(
            &signer,
            "https://issuer.example",
            "user-1",
            "https://rs.example",
            "client-1",
            "read",
            "grant-1",
            "current-actor",
            Some(serde_json::json!({
                "sub": "prior-actor",
                "act": { "sub": "earliest-actor" }
            })),
            Some(serde_json::json!({
                "prior-actor": "agent",
                "earliest-actor": "agent"
            })),
            &[],
            None,
            None,
            None,
            "jti-1",
            1_000,
        )
        .await
        .expect("delegation-token signing must succeed");
        assert!(
            jwt.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES,
            "ordinary delegation tokens should remain below the 4 KiB target"
        );
        let claims = decode_claims(&jwt);

        assert_eq!(
            object_keys(&claims),
            BTreeSet::from([
                "act",
                "aud",
                "client_id",
                "exp",
                "iat",
                "iss",
                "jti",
                "scope",
                "sub",
                agent_auth_token::NAMESPACE,
            ]),
            "delegation-token top-level claims must contain only the canonical public set"
        );
        let namespace = &claims[agent_auth_token::NAMESPACE];
        assert_eq!(
            object_keys(namespace),
            BTreeSet::from(["actor_types", "auth_grant", "sub_type"])
        );
        assert_eq!(namespace["sub_type"], "user");
        assert_eq!(namespace["auth_grant"], "grant-1");
        assert_eq!(
            namespace["actor_types"],
            serde_json::json!({
                "current-actor": "agent",
                "prior-actor": "agent",
                "earliest-actor": "agent"
            })
        );
        assert_rfc8693_act(&claims["act"]);
        assert_eq!(
            claims["act"],
            serde_json::json!({
                "sub": "current-actor",
                "act": {
                    "sub": "prior-actor",
                    "act": { "sub": "earliest-actor" }
                }
            })
        );
        assert!(
            validate_shape(&claims).is_empty(),
            "signed delegation-token claims must satisfy the canonical shape"
        );
    }

    #[tokio::test]
    async fn access_token_signer_classifies_oversize_before_signing() {
        let memory_signer = MemorySigner::from_seed([8u8; 32]);
        memory_signer.fail_next_es256(false);
        let signer = SignerImpl::Memory(memory_signer);
        let oversized_scope = "scope".repeat(2_000);
        let error = sign_access_token(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: "https://rs.example",
                client_id: "client-1",
                scope: &oversized_scope,
                jti: "jti-1",
                auth_grant: "authorization_code",
                sub_type: SubType::User,
                authorization_details: &[],
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
        )
        .await
        .expect_err("access token above the hard limit must be rejected");

        assert_eq!(error, TokenSignError::TooLarge);

        let pending_sign_error = sign_access_token(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: "https://rs.example",
                client_id: "client-1",
                scope: "read",
                jti: "jti-2",
                auth_grant: "authorization_code",
                sub_type: SubType::User,
                authorization_details: &[],
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
        )
        .await
        .expect_err("oversize rejection must leave the injected signing failure pending");
        assert_eq!(pending_sign_error, TokenSignError::Permanent);
    }

    #[tokio::test]
    async fn delegation_token_signer_classifies_oversize_before_signing() {
        let memory_signer = MemorySigner::from_seed([9u8; 32]);
        memory_signer.fail_next_es256(false);
        let signer = SignerImpl::Memory(memory_signer);
        let oversized_scope = "scope".repeat(2_000);
        let error = sign_delegation_token(
            &signer,
            "https://issuer.example",
            "user-1",
            "https://rs.example",
            "client-1",
            &oversized_scope,
            "grant-1",
            "current-actor",
            None,
            None,
            &[],
            None,
            None,
            None,
            "jti-1",
            1_000,
        )
        .await
        .expect_err("delegation token above the hard limit must be rejected");

        assert_eq!(error, TokenSignError::TooLarge);

        let pending_sign_error = sign_delegation_token(
            &signer,
            "https://issuer.example",
            "user-1",
            "https://rs.example",
            "client-1",
            "read",
            "grant-1",
            "current-actor",
            None,
            None,
            &[],
            None,
            None,
            None,
            "jti-2",
            1_000,
        )
        .await
        .expect_err("oversize rejection must leave the injected signing failure pending");
        assert_eq!(pending_sign_error, TokenSignError::Permanent);
    }

    #[tokio::test]
    async fn grant_backed_rar_delivery_is_opt_in_and_preserves_small_rar() {
        let signer = SignerImpl::Memory(MemorySigner::from_seed([10u8; 32]));
        let resource = "https://rs.example";
        let small_details = vec![serde_json::json!({
            "type": "agent_auth_rar_v1",
            "locations": [resource],
            "identifier": "policy-small",
            "max_records": 5
        })];
        let small = sign_access_token_with_delivery(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: resource,
                client_id: "client-1",
                scope: "read",
                jti: "jti-small",
                auth_grant: "grant-small",
                sub_type: SubType::User,
                authorization_details: &small_details,
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
            true,
        )
        .await
        .expect("small RAR must remain signable");
        assert!(
            !small.grant_backed_rar,
            "the P3 delivery profile must not summarize a token already within the soft target"
        );
        assert_eq!(
            decode_claims(&small.token)["authorization_details"],
            serde_json::Value::Array(small_details)
        );

        let padding = "policy-segment-".repeat(45);
        let large_details: Vec<serde_json::Value> = (0..4)
            .map(|index| {
                serde_json::json!({
                    "type": "agent_auth_rar_v1",
                    "locations": [resource],
                    "identifier": format!("policy-{index}-{padding}"),
                    "max_records": index + 1
                })
            })
            .collect();
        let disabled = sign_access_token_with_delivery(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: resource,
                client_id: "client-1",
                scope: "read",
                jti: "jti-disabled",
                auth_grant: "grant-disabled",
                sub_type: SubType::User,
                authorization_details: &large_details,
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
            false,
        )
        .await
        .expect("a below-hard-limit P2 token must remain signable without offload");
        assert!(
            disabled.token.len() >= agent_auth_token::JWT_SOFT_TARGET_BYTES,
            "fixture must exceed the 4 KiB soft target"
        );
        assert!(
            disabled.token.len() <= agent_auth_token::JWT_HARD_LIMIT_BYTES,
            "fixture must stay below the 7 KiB hard limit"
        );
        assert!(
            !disabled.grant_backed_rar,
            "the disabled/P0-P2 path must never activate Grant-backed delivery"
        );
        assert_eq!(
            decode_claims(&disabled.token)["authorization_details"],
            serde_json::Value::Array(large_details.clone())
        );

        let enabled = sign_access_token_with_delivery(
            &signer,
            &AccessTokenClaims {
                issuer: "https://issuer.example",
                sub: "user-1",
                aud: resource,
                client_id: "client-1",
                scope: "read",
                jti: "jti-enabled",
                auth_grant: "grant-enabled",
                sub_type: SubType::User,
                authorization_details: &large_details,
                cnf_jkt: None,
                auth_time: None,
                acr: None,
                now: 1_000,
            },
            true,
        )
        .await
        .expect("the P3 delivery profile must summarize a large RAR token");
        assert!(enabled.grant_backed_rar);
        assert!(enabled.token.len() < agent_auth_token::JWT_SOFT_TARGET_BYTES);
        let enabled_details = decode_claims(&enabled.token)["authorization_details"]
            .as_array()
            .expect("authorization_details array")
            .clone();
        assert_eq!(enabled_details.len(), 1);
        assert_eq!(
            enabled_details[0]["type"],
            crate::rar_delivery::GRANT_SUMMARY_TYPE
        );
    }
}

async fn add_token_cache_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(token_handler))
        .layer(axum::middleware::from_fn(add_token_cache_headers))
}
