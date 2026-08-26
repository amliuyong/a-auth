//! 发现面端点(C1):`/.well-known/openid-configuration` + `/.well-known/oauth-authorization-server`。
//!
//! 纯读、无状态、公开可达(discovery 本就公开;非匿名敏感面)。issuer 由请求 `Host` 头派生
//! (C1.6a,见 `agent_auth_discovery::derive`),metadata 由 `openid_configuration` /
//! `oauth_authorization_server` 生成(分阶段宣告、键序稳定)。本模块不重述任何 metadata 规则。

use agent_auth_discovery::{
    derive_issuer, oauth_authorization_server, openid_configuration, MetadataConfig,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

const DEPLOYMENT_COMMIT_HEADER: HeaderName =
    HeaderName::from_static("x-agent-auth-deployment-commit");

/// issuer host(C1.6a):优先 `X-Forwarded-Host`(CloudFront 统一入口透传)、回落 `Host`。
fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    crate::hostutil::issuer_host(headers)
}

/// 构造 metadata 配置(issuer 从 Host 派生 + state 的阶段/subject 类型)。
fn metadata_config(state: &AppState, headers: &HeaderMap) -> Result<MetadataConfig, StatusCode> {
    let host = host_from_headers(headers).ok_or(StatusCode::BAD_REQUEST)?;
    let issuer = derive_issuer(&host, &state.form).map_err(|_| StatusCode::BAD_REQUEST)?;
    let tenant = if state.tenant_partitioning {
        agent_auth_discovery::tenant_id_from(&host, &state.form)
            .map_err(|_| StatusCode::BAD_REQUEST)?
    } else {
        String::new()
    };
    Ok(MetadataConfig {
        issuer,
        subject_type: state.subject_type_for_tenant(&tenant),
        phase: state.phase,
        // CIBA ping/push 宣告随**运行时实际能力**(Phase≥P3 且 gate 开;spec 013 §4 M3)。
        ciba_ping_push_active: state.ciba_ping_push_active(),
        // X.509-mTLS 宣告随运行时能力(P3 且 feature 开 + SelfHosted;spec 012 §1.4/C5.7)。
        mtls_svid_enabled: state.mtls_svid_enabled,
        private_key_jwt_enabled: state.private_key_jwt_active(),
        ema_enabled: state.ema_active_for_tenant(&tenant),
        client_id_metadata_document_supported: state.cimd_active_for_tenant(&tenant),
    })
}

fn metadata_response(state: &AppState, body: serde_json::Value) -> Result<Response, StatusCode> {
    let deployment_commit = HeaderValue::from_str(&state.deployment_commit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [
            (DEPLOYMENT_COMMIT_HEADER, deployment_commit),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        Json(body),
    )
        .into_response())
}

/// OIDC discovery 文档(OpenID Connect Discovery)。
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "discovery",
    responses(
        (status = 200, description = "OIDC provider metadata(键序稳定的 JSON;字段分阶段宣告;CIMD 完整启用时含 client_id_metadata_document_supported=true,C1)", body = serde_json::Value,
            headers(
                ("x-agent-auth-deployment-commit" = String, description = "Full lowercase Git commit bound to the deployed Lambda artifacts"),
                ("cache-control" = String, description = "Requires caches to revalidate deployment provenance")
            )
        ),
        (status = 400, description = "Host 头缺失/非法或非本 issuer 的租户子域(C1.6a)")
    )
)]
pub async fn openid_configuration_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let cfg = metadata_config(&state, &headers)?;
    metadata_response(&state, openid_configuration(&cfg).to_json())
}

/// OAuth 2.0 Authorization Server Metadata(RFC 8414)。
#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    tag = "discovery",
    responses(
        (status = 200, description = "OAuth AS metadata(RFC 8414;字段分阶段宣告;CIMD 完整启用时含 client_id_metadata_document_supported=true,C1)", body = serde_json::Value,
            headers(
                ("x-agent-auth-deployment-commit" = String, description = "Full lowercase Git commit bound to the deployed Lambda artifacts"),
                ("cache-control" = String, description = "Requires caches to revalidate deployment provenance")
            )
        ),
        (status = 400, description = "Host 头缺失/非法或非本 issuer 的租户子域(C1.6a)")
    )
)]
pub async fn oauth_authorization_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let cfg = metadata_config(&state, &headers)?;
    metadata_response(&state, oauth_authorization_server(&cfg).to_json())
}

/// OpenID Shared Signals Framework 1.0 transmitter metadata.
#[utoipa::path(
    get,
    path = "/.well-known/ssf-configuration",
    tag = "discovery",
    responses(
        (status = 200, description = "Tenant-specific SSF transmitter metadata", body = serde_json::Value),
        (status = 400, description = "Host is not a valid issuer host")
    )
)]
pub async fn ssf_configuration_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let cfg = metadata_config(&state, &headers)?;
    let issuer = cfg.issuer.as_str().trim_end_matches('/');
    Ok(Json(serde_json::json!({
        "spec_version": "1_0",
        "issuer": cfg.issuer.as_str(),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "delivery_methods_supported": ["urn:ietf:rfc:8935"],
        "default_subjects": "ALL"
    })))
}

/// 发现面路由(OpenApiRouter:路由与 OpenAPI 同源)。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(openid_configuration_handler))
        .routes(routes!(oauth_authorization_server_handler))
        .routes(routes!(ssf_configuration_handler))
}
