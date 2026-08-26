//! `POST /revoke`(RFC 7009)—— spec 011 C7.6a(P1)。
//!
//! **决策真相源:docs/DESIGN §5.1;CONFORMANCE C7.6a;RFC 7009。** 吊销单位 = refresh-token family
//! (P0/P1 授权记录以 refresh-family 为载体;Grant 单位吊销 = C7.6b,P2)。
//!
//! 契约(spec 011 收敛后):
//! - **请求**:`application/x-www-form-urlencoded`;`token`(REQUIRED)、`token_type_hint`(OPTIONAL,
//!   实现可忽略,不得改变结果)。
//! - **调用方认证**(RFC 7009 §2.1,与 `/token` 同):confidential client MUST 按注册方式认证;
//!   public(`none`)MUST 携 `client_id`。认证失败 → `invalid_client`(401)。**不留匿名可达吊销面**。
//! - **归属校验**:只能吊销**本 client 名下**的 family(family.client_id == 已认证 caller);不匹配
//!   当作未知 token(不吊销、不泄露)。
//! - **幂等 + 不泄露存在性**(RFC 7009 §2.2):无效/未知/已吊销/非本 client/access_token 输入 → 一律
//!   `200`;仅认证本身失败才 `invalid_client`。
//! - **access_token 输入**:P1 无 `jti→family` 反查,no-op 返 `200`(真正失效靠 refresh family 吊销 +
//!   access 自然过期;离线 RS 残留窗口 = access 剩余 TTL + verifier clock skew)。
//! - **宽限缓存**:family 吊销后按 `family_id` 删除全部缓存版本，避免宽限窗重放继续命中旧响应。

use axum::{
    extract::{rejection::FormRejection, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{ClientStore, GraceStore, RefreshStore};
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
pub struct RevokeRequest {
    /// 被吊销 token(RFC 7009;P1 受理 refresh token,access token 输入 no-op)。
    pub token: String,
    /// 可选 token_type_hint(`refresh_token`/`access_token`;实现可忽略,不得改变结果)。
    #[serde(default)]
    pub token_type_hint: Option<String>,
    /// 调用方 client_id(public client 走 form;confidential 也可带,与 Basic username 须一致)。
    #[serde(default)]
    pub client_id: Option<String>,
    /// client_secret_post 认证时的 secret(client_secret_basic 走 Authorization 头)。
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
}

/// `/revoke` 端点(C7.6a,RFC 7009)。
#[utoipa::path(
    post,
    path = "/revoke",
    tag = "revocation",
    request_body(content = RevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "已处理(幂等;RFC 7009——无效/未知 token 也 200,不泄露存在性)"),
        (status = 400, description = "请求缺少 token 或 form 编码非法(invalid_request)"),
        (status = 401, description = "调用方认证失败(invalid_client)")
    )
)]
pub async fn revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<RevokeRequest>, FormRejection>,
) -> impl IntoResponse {
    let Form(req) = match form {
        Ok(form) => form,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_request"})),
            )
                .into_response()
        }
    };
    // tenant 分区(spec 020 §2.3):caller/family 查询按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // 1. 调用方认证(RFC 7009 §2.1,与 /token 同口径)。caller_id 取 form client_id;
    //    若 Authorization: Basic 也带 username,两者 MUST 一致(防混淆);form 缺省时用 Basic username。
    let caller_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        &headers,
        req.client_assertion.as_deref(),
    ) {
        Err(_) => {
            return crate::token::invalid_client_response(
                &headers,
                StatusCode::UNAUTHORIZED,
                "Basic and form client_id do not match",
            )
        }
        Ok(Some(client_id)) => client_id,
        Ok(None) => {
            return crate::token::invalid_client_response(
                &headers,
                StatusCode::UNAUTHORIZED,
                "client authentication is required",
            )
        }
    };
    let caller = match state.clients.get(&tenant, &caller_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return crate::token::invalid_client_response(
                &headers,
                StatusCode::UNAUTHORIZED,
                "client authentication failed",
            )
        }
        Err(_) => {
            return crate::token::err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "client store unavailable",
            )
            .into_response()
        }
    };
    // 按注册的 token_endpoint_auth_method 认证(confidential 校 secret;public `none` 仅需 client_id
    // 存在即视为已"认证"到该 public 身份——RFC 7009 允许 public client 用 client_id)。
    let caller = match crate::client_auth::authenticate_loaded_snapshot(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Revocation,
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
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => crate::token::err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::ServerMisconfigured => crate::token::err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidRequest(_) => crate::token::err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidClient(_) => {
                    crate::token::invalid_client_response(
                        &headers,
                        StatusCode::UNAUTHORIZED,
                        error.description(),
                    )
                }
            }
        }
    };

    // 2. 定位 family 并做归属校验 + 吊销。任何"无法吊销"的情形(格式非法/未知/非本 client/access_token)
    //    一律走幂等 200,不泄露存在性(RFC 7009 §2.2)。
    if let Some((family_id, _ver)) = crate::refresh_flow::decode_refresh(&req.token) {
        if let Ok(Some(fam)) = state.refresh.get(&tenant, &family_id).await {
            // 归属:只能吊销本 client 名下的 family;不匹配当未知 token(不吊销、不泄露)。
            if fam.client_id == caller.client_id {
                // 吊销 family(立即失效;续期即被拒)+ 条件删宽限缓存(C3.5,否则窗内仍命中旧 token)。
                let _ = state.refresh.revoke(&tenant, &family_id).await;
                if let Some(grace) = &state.grace {
                    let _ = grace.delete_family(&family_id).await;
                }
            }
        }
    }
    // access_token / 非 refresh 格式 / 未知 / 非本 client:no-op。统一 200。
    StatusCode::OK.into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(revoke_handler))
}
