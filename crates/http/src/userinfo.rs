//! `GET /userinfo`(C2.11 audience 隔离):仅 `aud == <issuer>/userinfo` 的 token 可调。
//!
//! 验 Bearer access token(自己的 JWKS 公钥验签 + 时间校验),再用 `userinfo_allowed`(protocol/006)
//! 判 aud 隔离——`aud`=某 MCP RS 的 token 调 `/userinfo` MUST 被拒(401/403)。返回 `sub`
//! (P0 直接回 token 的 sub;pairwise 一致性规则以 §2.8 / spec 001 为权威,本层不派生)。

use agent_auth_discovery::derive_issuer;
use agent_auth_protocol::userinfo_allowed;
use agent_auth_token::claims::NAMESPACE;
use axum::{
    extract::{FromRequest, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::Signer;
use crate::state::AppState;
use crate::verify::{single_aud, verify_access_token};

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, credentials) = raw.split_once(' ')?;
    let token = credentials.trim();
    (scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty()).then(|| token.to_string())
}

fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    // issuer host(C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    crate::hostutil::issuer_host(headers)
}

#[derive(Deserialize, ToSchema)]
pub struct UserInfoRequest {
    pub access_token: String,
}

#[derive(Deserialize)]
struct UserInfoForm {
    access_token: Option<String>,
}

fn has_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
}

/// `/userinfo` 端点(C2.11)。
#[utoipa::path(
    get,
    path = "/userinfo",
    tag = "userinfo",
    responses(
        (status = 200, description = "userinfo(sub 等;仅 aud=<issuer>/userinfo 的 token 可调)"),
        (status = 401, description = "缺/无效 Bearer token"),
        (status = 403, description = "token aud 非 <issuer>/userinfo(aud 隔离,C2.11)")
    )
)]
pub async fn userinfo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    userinfo_response(&state, &headers, &token).await
}

#[utoipa::path(
    post,
    path = "/userinfo",
    tag = "userinfo",
    request_body(content = Option<UserInfoRequest>, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "userinfo(sub 等;仅 aud=<issuer>/userinfo 的 token 可调)"),
        (status = 400, description = "同时使用多种 bearer token 传递方式或 form 无效"),
        (status = 401, description = "缺/无效 Bearer token"),
        (status = 403, description = "token aud 非 <issuer>/userinfo(aud 隔离,C2.11)")
    )
)]
pub async fn userinfo_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> axum::response::Response {
    let header_token = bearer_token(&headers);
    let form_token = if has_form_content_type(&headers) {
        let raw = match axum::body::Bytes::from_request(request, &()).await {
            Ok(raw) => raw,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        match serde_urlencoded::from_bytes::<UserInfoForm>(&raw) {
            Ok(form) => form.access_token,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        None
    };
    let token = match (header_token, form_token) {
        (Some(_), Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    r#"Bearer error="invalid_request""#,
                )],
            )
                .into_response()
        }
        (Some(token), None) | (None, Some(token)) => token,
        (None, None) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    match userinfo_response(&state, &headers, &token).await {
        Ok(response) => response.into_response(),
        Err(status) => status.into_response(),
    }
}

async fn userinfo_response(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tenant =
        crate::tenant::tenant_or_400(state, headers).map_err(|_| StatusCode::BAD_REQUEST)?;
    let signer = state
        .tenant_keys
        .resolve(&tenant)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // 用自己的 JWKS 公钥验签,并强制 RFC 9068 access-token typ/claims 基线。
    let jwks_keys = signer
        .public_jwks()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let jwks: Vec<crate::jwks::Jwk> = jwks_keys.iter().map(crate::jwks::to_jwk).collect();

    let now = crate::token::current_unix_secs_pub();
    let verified = verify_access_token(token, &jwks, now).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // C2.11 aud 隔离:token 的单值 aud 必须 == <issuer>/userinfo。
    let issuer = host_from_headers(headers)
        .and_then(|h| derive_issuer(&h, &state.form).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let userinfo_resource = format!("{}/userinfo", issuer.as_str());
    let aud = single_aud(&verified.claims).ok_or(StatusCode::FORBIDDEN)?;
    if !userinfo_allowed(&aud, &userinfo_resource) {
        // aud = 某 MCP RS 的 token 调 /userinfo → 拒(C2.11)。
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(grant_id) = verified
        .claims
        .get(NAMESPACE)
        .and_then(|namespace| namespace.get("auth_grant"))
        .and_then(|value| value.as_str())
    {
        match crate::grants::token_grant_is_active(state, &tenant, grant_id, now).await {
            Ok(true) => {}
            Ok(false) => return Err(StatusCode::UNAUTHORIZED),
            Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    // 返回 userinfo(P0:sub;更多 claim 随 scope/consent,后续)。
    let sub = verified
        .claims
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(serde_json::json!({ "sub": sub })))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(userinfo_handler, userinfo_post_handler))
}
