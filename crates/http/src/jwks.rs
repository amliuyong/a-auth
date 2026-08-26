//! `/jwks.json`(C10.11a / C10.16):发布签名公钥集(双活结构,`kid`=JWK thumbprint)。
//!
//! 公钥由 `Signer::public_jwks` 提供(真机 = KMS GetPublicKey → SPKI DER → EC JWK;
//! 本地 = 进程内 P-256)。响应带显式 `Cache-Control: max-age`(C10.16 冻结默认 300s);
//! 公开只读(非匿名敏感面——JWKS 本就公开供 RS 验签)。

use agent_auth_infra_core::EcJwk;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::Signer;
use crate::state::AppState;

/// `/jwks.json` 的 `Cache-Control: max-age` 冻结默认值(秒,C10.16;CloudFront TTL 取同值)。
pub const JWKS_MAX_AGE_SECS: u32 = 300;

/// 单把 JWK(OpenAPI schema 用):EC(crv/x/y)与 RSA(n/e)共用一个结构,按 kty 填相应字段。
#[derive(Serialize, ToSchema)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub r#use: String,
    // EC 字段(kty=EC)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    // RSA 字段(kty=RSA)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

/// JWKS 文档(RFC 7517):`{ "keys": [ ... ] }`。
#[derive(Serialize, ToSchema)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

pub(crate) fn to_jwk(e: &EcJwk) -> Jwk {
    Jwk {
        kty: e.kty.to_string(),
        kid: e.kid.clone(),
        alg: e.alg.to_string(),
        r#use: e.r#use.to_string(),
        crv: Some(e.crv.to_string()),
        x: Some(e.x.clone()),
        y: Some(e.y.clone()),
        n: None,
        e: None,
    }
}

pub(crate) fn rsa_to_jwk(r: &agent_auth_infra_core::RsaJwk) -> Jwk {
    Jwk {
        kty: r.kty.to_string(),
        kid: r.kid.clone(),
        alg: r.alg.to_string(),
        r#use: r.r#use.to_string(),
        crv: None,
        x: None,
        y: None,
        n: Some(r.n.clone()),
        e: Some(r.e.clone()),
    }
}

/// JWKS 端点:多公钥双活,带冻结的 `Cache-Control: max-age`。
#[utoipa::path(
    get,
    path = "/jwks.json",
    tag = "discovery",
    responses(
        (status = 200, description = "签名公钥集(双活;kid=JWK thumbprint,C10.11a)", body = Jwks),
        (status = 503, description = "签名后端瞬时不可用")
    )
)]
pub async fn jwks_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let tenant =
        crate::tenant::tenant_or_400(&state, &headers).map_err(|_| StatusCode::BAD_REQUEST)?;
    let signer = state
        .tenant_keys
        .resolve(&tenant)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let ec_keys = signer
        .public_jwks()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // Ready snapshot is an atomic EC+RSA pair. Publishing only one algorithm
    // would create a partially trusted issuer, so either read failing is 503.
    let rsa_keys = signer
        .public_rsa_jwks()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut keys: Vec<Jwk> = ec_keys.iter().map(to_jwk).collect();
    keys.extend(rsa_keys.iter().map(rsa_to_jwk));
    let body = Jwks { keys };
    let headers = [(
        header::CACHE_CONTROL,
        format!("max-age={JWKS_MAX_AGE_SECS}"),
    )];
    Ok((headers, Json(body)))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(jwks_handler))
}
