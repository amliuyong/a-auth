//! PRM 生成端点(spec 010 C8.1,P1a 生成侧)—— **控制面工具**,非 issuer origin 数据面。
//!
//! **决策真相源:docs/DESIGN §6。** P1 默认投放方式 a:AS 只**生成** PRM JSON,交 RS 自挂在
//! **其自身 origin** 的 `/.well-known/oauth-protected-resource`。故本端点是 RS 运维取回自家
//! PRM JSON 的**控制面工具**(`GET /rs/prm?resource=<resource_id>`)——**绝不**在 AS issuer origin
//! 上提供 `/.well-known/oauth-protected-resource` 路由(违反"PRM 不在 AS origin"硬约束)。
//! 运行时按 Host 托管 + Host→租户绑定匹配属投放方式 b / C8.1b / P3(BYOD)。
//!
//! **调用方认证 + 归属校验(评审 Kiro H1)**:该端点要求调用方以其 introspection 凭证认证
//! (与 `/introspect` 同款:confidential client + `introspect_enabled`),且只放行 `resource` ∈
//! 该 caller 绑定的 `resource_ids`。这一并消除:① 未认证全表 Scan 的 DoS 放大(改为按 caller
//! 点查)、② 200-vs-404 对已注册 resource_id 的枚举。RS 只能取回**自己**的 PRM。
//!
//! resource 走 **query 参数**而非 path 段:资源标识是完整 URL(含 `://` 与 `/`),放 path 段
//! 会被 API Gateway/CloudFront 预解码 `%2F` 破坏路由(真机 e2e 实测);query 值不受影响。

use agent_auth_discovery::{build_prm, derive_issuer, issuer_for_tenant, PrmConfig};
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{ClientStore, DomainMapStore};
use crate::state::AppState;

fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    // issuer host(C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    crate::hostutil::issuer_host(headers)
}

#[derive(Deserialize, IntoParams)]
pub struct PrmQuery {
    /// 已注册 MCP RS 的资源标识(完整 URL);MUST ∈ 认证调用方绑定的 resource_ids。
    pub resource: String,
    /// 调用方 client_id(也可只放在 Authorization: Basic 里)。
    #[serde(default)]
    pub client_id: Option<String>,
    /// client_secret_post 认证时的 secret。
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct PrmForm {
    /// 已注册 MCP RS 的资源标识(完整 URL);MUST ∈ 认证调用方绑定的 resource_ids。
    pub resource: String,
    /// 可省略；private_key_jwt 从已验签 assertion 的 iss/sub 解析。
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
}

/// `GET /rs/prm?resource=<resource_id>`:认证的 RS 运维取回自家 PRM JSON(供自挂)。
#[utoipa::path(
    get,
    path = "/rs/prm",
    tag = "mcp",
    params(PrmQuery),
    responses(
        (status = 200, description = "生成的 PRM JSON(RFC 9728;供 RS 自挂在其自身 origin)"),
        (status = 401, description = "调用方认证失败 / 无 introspect 权限 / 该 resource 非本 caller 所属")
    )
)]
pub async fn prm_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PrmQuery>,
) -> impl IntoResponse {
    authenticated_prm(
        state,
        headers,
        q.resource,
        q.client_id,
        q.client_secret,
        None,
        None,
    )
    .await
}

/// `POST /rs/prm`:form 认证入口，供 private_key_jwt 使用而不把 assertion 放进 URL。
#[utoipa::path(
    post,
    path = "/rs/prm",
    tag = "mcp",
    request_body(content = PrmForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "生成的 PRM JSON(RFC 9728;供 RS 自挂在其自身 origin)"),
        (status = 401, description = "调用方认证失败 / 无 introspect 权限 / 该 resource 非本 caller 所属")
    )
)]
pub async fn prm_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PrmForm>,
) -> impl IntoResponse {
    authenticated_prm(
        state,
        headers,
        form.resource,
        form.client_id,
        form.client_secret,
        form.client_assertion_type,
        form.client_assertion,
    )
    .await
}

async fn authenticated_prm(
    state: AppState,
    headers: HeaderMap,
    resource: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
) -> Response {
    // 统一失败响应(不区分未知 client / 认证失败 / 无权限 / 非本 caller 资源,防枚举,评审 M1)。
    let deny = || (StatusCode::UNAUTHORIZED, "invalid_client").into_response();

    // issuer 从请求 Host 派生(PRM 的 authorization_servers 指向本 AS issuer)。
    let Some(issuer) =
        host_from_headers(&headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };

    // 调用方认证(与 /introspect 同款):按 client_id 点查(无全表 Scan)+ confidential + 权限门。
    let caller_id = match crate::client_auth::resolve_client_id_with_assertion(
        client_id.as_deref(),
        &headers,
        client_assertion.as_deref(),
    ) {
        Err(_) | Ok(None) => return deny(),
        Ok(Some(client_id)) => client_id,
    };
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let caller = match state.clients.get(&tenant, &caller_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return deny(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if !caller.is_confidential_auth_client() {
        return deny();
    }
    let caller = match crate::client_auth::authenticate_loaded_snapshot(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Prm,
        &caller,
        &headers,
        crate::client_auth::PresentedClientAuth::new(
            client_secret.as_deref(),
            client_assertion_type.as_deref(),
            client_assertion.as_deref(),
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
                _ => deny(),
            }
        }
    };
    if !caller.is_confidential_auth_client() {
        return deny();
    }
    if !caller.introspect_enabled {
        return deny();
    }
    // 归属校验:只能取回自己绑定的 resource 的 PRM(点查,无 Scan;消除枚举 + DoS 放大)。
    if !caller.resource_ids.iter().any(|r| r == &resource) {
        return deny();
    }

    let cfg = PrmConfig::new(resource, issuer.as_str());
    Json(build_prm(&cfg).to_json()).into_response()
}

// ============ BYOD 数据面 PRM 托管(投放方式 b,spec 010 §5.4 / C8.1b,P3)============
//
// RS 把自带域名 CNAME 到本系统 CloudFront,AS 在 **RS 自己域名的 origin** 上按入站 Host 托管 PRM。
// 与投放方式 a(上方 `/rs/prm?resource=` 控制面自挂工具)并存;此路由无 query、RFC 9728 well-known。
//
// **威胁模型(评审 H1/Q2)**:PRM 是 RFC 9728 **公开元数据**,不是秘密——200-vs-404 枚举是公开发现端点
// 固有 oracle(伪目标)。真威胁 = **跨租户 issuer 误导**(恶意租户登记不拥有的域名,把该域名 PRM 的
// authorization_servers 指向攻击者 issuer)。防线在**注册时**(域名归属 + 全局唯一 conditional-write);
// 返回的 issuer 从**存储绑定的 tenant_id 重建**(`issuer_for_tenant`),**绝不** `derive_issuer(inbound_host)`
// (评审 B3:BYOD host 派生要么 dead-on-arrival[NotATenantSubdomain],要么被"修"成 https://{host} = misdirection)。

/// `GET /.well-known/oauth-protected-resource`(无 query,RFC 9728):BYOD 数据面按入站 Host 托管 PRM。
///
/// 流程:BYOD 关 → 404(短路,触 store 前)。开 → 归一入站 Host → domain map 单次 GetItem(点查 O(1));
/// 命中 → PRM(resource=绑定的 resource_id、authorization_servers=**由绑定 tenant_id + form 重建**的 issuer);
/// 未命中(含 issuer 子域/控制面 host/未登记域)→ 404。**MUST NOT 调 tenant_or_400 / derive_issuer(host)**。
#[utoipa::path(
    get,
    path = "/.well-known/oauth-protected-resource",
    tag = "mcp",
    responses(
        (status = 200, description = "该 BYOD 域名的 PRM(RFC 9728;issuer 从存储绑定重建)"),
        (status = 404, description = "BYOD 未启用 / 该 Host 未登记(公开数据无枚举顾虑,防的是跨租户 misdirection)")
    )
)]
pub async fn well_known_prm_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let not_found = || (StatusCode::NOT_FOUND, "not found").into_response();

    // BYOD 未启用 → 触 store 前直接 404(短路,与"无此路由"同形,不给该路径加 store 往返;评审 H3)。
    if !state.byod_enabled {
        return not_found();
    }
    // 入站 Host(X-Forwarded-Host 优先,归一小写去端口)。缺失 → 404(无 Host 无从查绑定)。
    let Some(host) = crate::hostutil::issuer_host(&headers) else {
        return not_found();
    };
    // 查询期 issuer-origin 复检(评审 L1,纵深防配置漂移):若登记后运维改了 zone/configured_host,使某旧绑定
    // 的 host 现在成了 issuer origin(如后来 AGENT_AUTH_ZONE=acme.example 使已绑的 mcp.acme.example 变 *.zone
    // 子域),则该 host 的 well-known 会落在 issuer origin 上破 C8.1。此处 fail-closed 404,不服务该 PRM。
    if crate::admin::is_issuer_origin_host(&state.form, &host) {
        return not_found();
    }
    // 域名绑定点查(全局键,O(1) GetItem,无 Scan)。未命中 → 404;store 错 → 503。
    let binding = match state.domain_map.get(&host).await {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    // issuer 从**存储绑定的 tenant_id + form 重建**(SaaS=https://{tenant_id}.{zone}、SelfHosted=configured_host)。
    // 绝不 derive_issuer(host):BYOD host 非 tenant 子域,派生会 NotATenantSubdomain / 被误"修"成 misdirection。
    let Ok(issuer) = issuer_for_tenant(&state.form, &binding.tenant_id) else {
        // 绑定的 tenant_id 重建不出合法 issuer(理应不可达——登记时已校验)→ fail-closed 404,不产出畸形 PRM。
        return not_found();
    };
    let cfg = PrmConfig::new(binding.resource_id, issuer.as_str());
    Json(build_prm(&cfg).to_json()).into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(prm_handler, prm_post_handler))
        .routes(routes!(well_known_prm_handler))
}
