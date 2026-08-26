//! `POST /introspect`(RFC 7662)—— spec 010 C8.6 / C8.7a(P1a,AS 侧)。
//!
//! **决策真相源:docs/DESIGN §6。** 供不做离线 JWT 校验的 MCP RS 查询 access token 状态。
//! 契约(spec 010 收敛后):
//! - **调用方认证**:出示 RS 注册记录里 `introspect_enabled=true` 的凭证(复用 C4.2 client_auth
//!   + introspect 权限门);匿名/无权限 client MUST 拒(不当匿名探针放行)。
//! - **aud 跨 RS 隔离**:被查 token 的单元素 `aud` MUST ∈ caller 绑定的 `resource_ids`;否则
//!   返回 `active: false`(RFC 7662 标准做法,不泄露存在性)——防 RS-A 凭证窥探 aud=RS-B 的 token。
//! - **active 判定(P1+P2)**:签名有效 + 未过期(verify_es256)+ aud 属 caller;**P2 起叠加 Grant 吊销
//!   即时反映**——token 命名空间 `auth_grant`=源 Grant id,反查 Grant,不 usable(Revoked/Expired)→
//!   active:false(C7.6b:`/grants` DELETE 吊销后其 token introspect 即时失活);无对应 Grant(code/device/
//!   2LO 前身)回退按签名判;store 瞬时 → fail-closed 503。无 aud 输入(refresh token)→ active:false。
//! - **回带字段(C8.7a,P1)**:命名空间 `sub_type`/`auth_grant`;`act`/`actor_types` if present
//!   (P1 非委托 token 无,不编造)。RAR(C8.7a',P2)、cnf(C8.7b,P3)后续。

use agent_auth_token::claims::NAMESPACE;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{ClientStore, GrantStore, Signer};
use crate::state::AppState;
use crate::verify::{single_aud_strict, verify_access_token};

#[derive(Deserialize, ToSchema)]
pub struct IntrospectRequest {
    /// 被查 token(access token)。
    pub token: String,
    /// 可选 token_type_hint(RFC 7662;本实现只受理 access token,hint 不改行为)。
    #[serde(default)]
    pub token_type_hint: Option<String>,
    /// client_secret_post 认证时的 secret(client_secret_basic 走 Authorization 头)。
    #[serde(default)]
    pub client_secret: Option<String>,
    /// 调用方 client_id(RFC 7662 调用方认证;public client 不适用于 introspect)。
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
}

/// RFC 7662:token 不 active 时**只**回 `{"active": false}`,不泄露任何其它信息。
fn inactive() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "active": false }))
}

/// `/introspect` 端点(C8.6/C8.7a)。
#[utoipa::path(
    post,
    path = "/introspect",
    tag = "mcp",
    request_body(content = IntrospectRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "RFC 7662 introspection 响应({active:true,...} 或 {active:false})"),
        (status = 401, description = "调用方认证失败 / 无 introspect 权限")
    )
)]
pub async fn introspect_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<IntrospectRequest>,
) -> impl IntoResponse {
    // tenant 分区(spec 020 §2.3):caller/grant/family 查询按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // 1. 调用方认证:必须是已注册 client + 认证方式匹配(C4.2)+ 具 introspect 权限(C8.6)。
    // caller_id 取 form client_id;若 Authorization: Basic 也带 username,两者 MUST 一致
    // (评审 codex LOW:防 Basic/form client_id 不一致的混淆);form 缺省时可用 Basic username。
    let caller_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        &headers,
        req.client_assertion.as_deref(),
    ) {
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "Basic 与 form client_id 不一致").into_response();
        }
        Ok(Some(client_id)) => client_id,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "introspect 需调用方认证").into_response();
        }
    };
    let caller = match state.clients.get(&tenant, &caller_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "未知调用方").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    // introspection 调用方 MUST 是 confidential(可认证)——`none` 无凭证方法即便标了
    // introspect_enabled 也 MUST 拒(否则无凭证即可 introspect;评审 codex HIGH,fail-closed)。
    if !caller.is_confidential_auth_client() {
        return (
            StatusCode::UNAUTHORIZED,
            "introspect 调用方必须是可认证的 confidential client",
        )
            .into_response();
    }
    let caller = match crate::client_auth::authenticate_loaded_snapshot(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Introspection,
        &caller,
        &headers,
        crate::client_auth::PresentedClientAuth::new(
            req.client_secret.as_deref(),
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
        ),
    )
    .await
    {
        Ok(caller) => caller,
        Err(error) => {
            return match error {
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::ServerMisconfigured => {
                    (StatusCode::INTERNAL_SERVER_ERROR, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::InvalidRequest(_) => {
                    (StatusCode::BAD_REQUEST, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::InvalidClient(_) => {
                    (StatusCode::UNAUTHORIZED, "调用方认证失败").into_response()
                }
            }
        }
    };
    if !caller.is_confidential_auth_client() {
        return (
            StatusCode::UNAUTHORIZED,
            "introspect 调用方必须是可认证的 confidential client",
        )
            .into_response();
    }
    // introspect 权限门:普通机密 client 不因认证通过就获得 introspect 权限(评审 codex/Kiro)。
    if !caller.introspect_enabled {
        return (StatusCode::UNAUTHORIZED, "该 client 无 introspect 权限").into_response();
    }

    // 2. 验 token(sig + exp/nbf);任一不过 → active:false(不泄露原因)。
    let signer = match crate::tenant_keys::signer_or_503(&state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return response,
    };
    let jwks_keys = match signer.public_jwks().await {
        Ok(k) => k,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "signer unavailable").into_response(),
    };
    let jwks: Vec<crate::jwks::Jwk> = jwks_keys.iter().map(crate::jwks::to_jwk).collect();
    let now = crate::token::current_unix_secs_pub();
    // 严格 access token 基线:sig + exp/nbf + typ=at+jwt + 顶层 client_id(评审 codex MEDIUM:
    // 防同 signer 签出的非 access/形状不合规 JWT 被判 active)。
    let Ok(verified) = verify_access_token(&req.token, &jwks, now) else {
        return inactive().into_response();
    };

    // 3. aud 跨 RS 隔离:token 单值 aud MUST ∈ caller 绑定的 resource_ids。
    //    严格单元素数组(拒裸字符串,C2.5a);无 aud(如 refresh token)或不属该 caller
    //    → active:false(不泄露存在性)。
    let Some(aud) = single_aud_strict(&verified.claims) else {
        return inactive().into_response();
    };
    if !caller.resource_ids.iter().any(|r| r == &aud) {
        return inactive().into_response();
    }

    // 3b. **吊销即时反映(P2,C7.6b / spec 011 §5.1)**:签名有效 ≠ 授权仍在。
    // UserInfo 与 introspection 共用 Grant/family/user authority 判定，避免两个在线验证面漂移。
    let auth_grant = verified
        .claims
        .get(NAMESPACE)
        .and_then(|ns| ns.get("auth_grant"))
        .and_then(|v| v.as_str());
    if let Some(gid) = auth_grant {
        match crate::grants::token_grant_is_active(&state, &tenant, gid, now).await {
            Ok(true) => {}
            Ok(false) => return inactive().into_response(),
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "授权状态存储不可用,请重试")
                    .into_response()
            }
        }
    }

    let authorization_details = match verified.claims.get("authorization_details") {
        Some(details) => match crate::rar_delivery::parse_summary(details) {
            Ok(Some(summary)) => {
                let Some(grant_id) = auth_grant else {
                    return inactive().into_response();
                };
                let grant = match state.grants.get(&tenant, grant_id).await {
                    Ok(Some(grant)) if grant.is_usable(now).is_ok() => grant,
                    Ok(_) => return inactive().into_response(),
                    Err(_) => {
                        return (StatusCode::SERVICE_UNAVAILABLE, "授权状态存储不可用,请重试")
                            .into_response()
                    }
                };
                let Some(resource_grant) = grant.resource_grant(&aud) else {
                    return inactive().into_response();
                };
                if !crate::rar_delivery::matches(
                    &summary,
                    &aud,
                    &resource_grant.authorization_details,
                ) {
                    return inactive().into_response();
                }
                Some(serde_json::Value::Array(
                    resource_grant.authorization_details.clone(),
                ))
            }
            Ok(None) => Some(details.clone()),
            Err(()) => return inactive().into_response(),
        },
        None => None,
    };

    // 4. 组装 active 响应(RFC 7662 标准字段 + C8.7a 回带命名空间/act if present)。
    let c = &verified.claims;
    let mut out = serde_json::Map::new();
    out.insert("active".into(), serde_json::Value::Bool(true));
    // RFC 7662 可选 token_type(SDK 据此判定);本 AS access token 恒 Bearer。
    out.insert(
        "token_type".into(),
        serde_json::Value::String("Bearer".into()),
    );
    for key in [
        "sub",
        "aud",
        "iss",
        "exp",
        "iat",
        "nbf",
        "jti", // RFC 7662 标准字段(spec 011 增量 A:token 唯一标识,SDK/审计可关联)
        "client_id",
        "scope",
        "auth_time",
        "acr",
    ] {
        if let Some(v) = c.get(key) {
            out.insert(key.into(), v.clone());
        }
    }
    // C8.7a:回带命名空间对象(sub_type/auth_grant;actor_types if present)。
    if let Some(ns) = c.get(NAMESPACE) {
        out.insert(NAMESPACE.into(), ns.clone());
    }
    // C8.7a:act if present(P1 非委托 token 无 → 不编造)。
    if let Some(act) = c.get("act") {
        out.insert("act".into(), act.clone());
    }
    // C8.7a'(spec 010 §4.3):authorization_details(RAR)if present——**回带 if present、不编造**
    // (与 act 同款处理:P1 token 无 RAR → 不回带;RAR 绑 Grant 后随 token 携带则透出,使走
    // introspection 的 RS 与离线校验的 RS 拿到同一份 RAR 约束、能力对等)。走 introspection 的 RS
    // 拿到后交 SDK `enforce_rar` 执行(词汇表内约束拦截越界读,C8.5a)。
    if let Some(ad) = authorization_details {
        out.insert("authorization_details".into(), ad);
    }
    // C8.7b(spec 010 §5.3):`cnf`(DPoP sender-constraint,含 cnf.jkt)if present——**回带 if present、
    // 不编造**(与 act/authorization_details 同款)。AS P3 直接 grant(spec 010 §5.2)与 token-exchange 委托
    // token(spec 011 §7.2)均可能签 cnf;带 cnf 的 token 经此透出 cnf.jkt,使走 introspection 的 RS 校 DPoP
    // proof(SDK verify_dpop_proof,C8.9),与离线校验 RS 能力对等。无 cnf(bearer)→ 响应无 cnf。
    if let Some(cnf) = c.get("cnf") {
        out.insert("cnf".into(), cnf.clone());
    }
    Json(serde_json::Value::Object(out)).into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(introspect_handler))
}
