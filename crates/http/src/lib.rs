//! Agent Auth HTTP 面 —— 把纯逻辑 crate 接成真实端点(axum),utoipa 从代码派生 OpenAPI。
//!
//! **代码即契约**:请求/响应类型带 `#[derive(ToSchema)]`、路由带 `#[utoipa::path]`,
//! `openapi()` 编译期汇聚出 OpenAPI JSON(`export-openapi` bin 导出到 `openapi/openapi.json`,
//! CI 校验与代码一致)。协议决策一律回指 docs §N + C 编号,不在此重述(真相在纯逻辑 crate + docs)。
//!
//! 两形态同一套 handler:本地 axum server(`agent-auth-server` bin,开发/e2e)+ Lambda
//! (`lambda` feature,触发源 = **API Gateway**,绝不用 Lambda Function URL,见部署约定)。
//!
//! 当前进度:P0 端点分批接入,先 discovery(纯读、无状态,跑通代码→OpenAPI 链路)。

pub mod account_credentials;
pub mod account_sessions;
pub mod adapters;
pub mod admin;
pub mod admin_attribute_namespaces;
pub mod admin_credentials;
pub mod admin_federation_attributes;
pub mod admin_sso;
pub mod api_document;
mod assurance;
pub mod attribute_namespace;
pub mod authorize;
pub mod authz_gate;
pub mod authz_session;
pub mod ciba_flow;
pub mod cimd;
pub mod client_auth;
pub mod consent;
pub mod credential;
pub mod data_governance;
pub mod device_flow;
pub mod discovery;
pub mod dpop;
pub mod ema_flow;
pub mod end_session;
pub mod federation_attributes;
pub mod federation_flow;
pub mod governance;
mod governance_data;
pub mod governance_resources;
pub mod governance_worker;
pub mod grants;
pub mod hostutil;
pub mod introspect;
pub mod invitation;
mod jti_authority;
pub mod jwks;
mod local_identity;
pub mod login;
pub mod mtls;
pub mod origin_auth;
pub mod passkey_flow;
pub mod password_login;
pub mod policy_freshness;
mod poll_claim;
pub mod ports;
pub mod prm;
mod rar_delivery;
pub mod ratelimit_gate;
pub mod reclaim;
pub mod recompute;
pub mod recover;
pub mod refresh_flow;
pub mod region;
pub mod register;
pub mod revoke;
pub mod rs_attributes;
pub mod scim;
pub mod scim_groups;
pub mod security_event;
pub mod security_event_archive;
pub mod ssf;
pub mod ssf_admin;
pub mod ssf_worker;
pub mod state;
pub mod tenant;
mod tenant_admin;
pub mod tenant_key_provisioner;
pub mod tenant_keys;
pub mod token;
pub mod token_exchange;
pub mod user_gate;
pub mod user_lifecycle;
pub mod userinfo;
pub mod verify;
pub mod workload_flow;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

pub use state::AppState;
/// 当前 Unix 秒(测试/集成用;内部同 token::current_unix_secs_pub)。
pub fn current_unix_secs() -> i64 {
    token::current_unix_secs_pub()
}
// SubjectType 是 AppState.subject_type 的类型;re-export 便于调用方(如集成测试、控制面装配)
// 显式构造 pairwise/public 形态(spec 001 C2.11)。Phase 便于测试设阶段(如 P2 开 client_credentials)。
pub use agent_auth_discovery::{Phase, SubjectType};

/// 顶层 OpenAPI 文档定义(元信息;路径 schema 由各 handler 的 `#[utoipa::path]` 汇聚)。
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Agent Auth",
        description = "面向 agent 时代的 OAuth 2.1 / OIDC 授权服务器。协议决策真相源见 docs/DESIGN §N + CONFORMANCE C 编号。",
        version = "0.0.0"
    ),
    tags(
        (name = "discovery", description = "发现面:OIDC/OAuth metadata + JWKS(C1/C10.11a)"),
        (name = "authorize", description = "授权码签发:client-aware PKCE policy + authorize↔token 绑定(C4)"),
        (name = "token", description = "token 兑换:code flow + audience 选择 + 恒 ES256(C2/C10.15a)"),
        (name = "userinfo", description = "userinfo:aud 隔离,仅 aud=<issuer>/userinfo 可调(C2.11)"),
        (name = "dcr", description = "动态客户端注册:RFC 7591 三档准入(open / initial_access_token / software_statement,§3.2,C4)"),
        (name = "login", description = "magic-link 登录:发信防滥用 + login-CSRF 绑定(C9.1/C9.2)"),
        (name = "consent", description = "consent 同意:anti-CSRF + 会话 → 签发 code(C10.9)"),
        (name = "recovery", description = "账户恢复:一次性恢复码,验码→登入+吊销旧会话(C9.3)"),
        (name = "mcp", description = "MCP 集成:PRM 生成 + introspect(aud 隔离 + 回带命名空间/act,C8)"),
        (name = "sessions", description = "可观测授权会话状态机:GET /sessions(鉴权二选一,C6)"),
        (name = "logout", description = "RP-initiated logout:/end-session 清会话 + post_logout 精确匹配(C9.6)"),
        (name = "revocation", description = "token 吊销:RFC 7009 /revoke,吊销 refresh family(调用方认证 + 归属 + 幂等,C7.6a)"),
        (name = "device", description = "Device Authorization Grant:RFC 8628 /device_authorization + device_code 轮询(P2,C7b.4)"),
        (name = "ciba", description = "CIBA 异步授权:/bc-authorize + auth_req_id 轮询(P2,C7b.1–C7b.3)"),
        (name = "grants", description = "用户自助 Grant 管理:GET/DELETE /grants(会话鉴权,IDOR-safe,P2,C7.6b)"),
        (name = "account", description = "用户账户安全:登录会话列表与自助吊销(C12.5)"),
        (name = "admin", description = "Admin 控制台:仪表盘聚合 + client 管理(admin_token 超级权限,spec 025)"),
        (name = "data_governance", description = "Tenant-scoped privacy export, legal hold, erasure, and offboarding(C12.7)"),
        (name = "scim", description = "Tenant-scoped SCIM 2.0 Users lifecycle and Groups provisioning(C12.2/C12.3)")
    ),
    components(schemas(admin::ListUsersStatus))
)]
pub struct ApiDoc;

/// CORS 分类①②③(公开 GET / 协议 POST / open `/register`)——**不带浏览器凭证**的端点,
/// `Allow-Origin: *` 安全且必需(OAuth 2.0 Browser-Based Apps BCP:浏览器内 public client 从自有
/// origin fetch `/token` 等;PKCE/client_secret/device_code 靠协议内鉴权,不靠 cookie)。C10.10。
///
/// **绝不设 `Allow-Credentials: true`**(与 `*` 组合被浏览器禁止,且这些端点无 cookie)。
/// tower-http `CorsLayer` 自动处理 preflight `OPTIONS`(回 Allow-Methods/Allow-Headers/Max-Age)。
fn public_cors() -> tower_http::cors::CorsLayer {
    use axum::http::{header, Method};
    use tower_http::cors::{Any, CorsLayer};
    CorsLayer::new()
        .allow_origin(Any) // Access-Control-Allow-Origin: *
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    // 不 .allow_credentials(true):无 cookie 端点,且 credentials+`*` 浏览器禁止。
}

/// `/token` 独立路由(C3.4):部署时由专用 TokenFn 承载,与其他协议/管理端点的 IAM role 隔离。
fn token_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().merge(token::router())
}

/// **无 CORS 分组**(公开 GET + 非 token 协议 POST + open `/register`):挂 `public_cors()`。
/// 归此组的端点均**不读浏览器 cookie**,跨 origin fetch 用 `*` 安全(C10.10 分类①②③)。
fn cors_open_non_token_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        // ① 公开 GET(discovery/JWKS/PRM)。
        .merge(api_document::router())
        .merge(discovery::router())
        .merge(jwks::router())
        .merge(prm::router())
        // ② 非 token 协议 POST(不带浏览器 cookie:协议内鉴权)。
        .merge(userinfo::router())
        .merge(introspect::router())
        .merge(rs_attributes::router()) // GET /rs/attributes(spec 007,token-authed 读)
        .merge(revoke::router())
        .merge(device_flow::protocol_router()) // /device_authorization
        .merge(ciba_flow::protocol_router()) // /bc-authorize
        // ③ open 档 `POST /register`(无凭证注册;收紧档票据校验在 handler 内,preflight 无 cookie)。
        .merge(register::register_post_router())
}

/// **会话/导航分组**(带浏览器 cookie 的会话端点 + 浏览器导航):**不挂任何 CORS 层**(C10.10 分类④⑤)。
/// - 会话端点(magic-link/consent/grants/sessions/end-session/device 批准/bc-approve/admin/register 管理):
///   统一入口(issuer==origin,CloudFront 单域)下前端 SPA 与 AS 同源、同源请求不触发 CORS;
///   **不发 CORS 头 → 跨 origin credentialed 请求 preflight 失败 → 防 CSRF**。
/// - 浏览器导航(`/authorize`/`/login/callback`):顶层跳转、非 fetch,不适用 CORS。
fn cors_none_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .merge(authorize::router()) // ⑤ 浏览器导航
        .merge(login::router()) // magic-link(写 cookie)+ callback(导航)
        .merge(password_login::router()) // local password login + first-login change
        .merge(invitation::router()) // dedicated admin-issued onboarding invitations
        .merge(consent::router())
        .merge(recover::router())
        .merge(authz_session::router())
        .merge(end_session::router())
        .merge(federation_flow::router()) // GET /federation/callback(联邦回调,feature-gated)
        .merge(passkey_flow::router()) // /passkey/* 仪式(会话/pre-login,feature-gated)
        .merge(device_flow::approve_router()) // POST /device(会话鉴权)
        .merge(ciba_flow::approve_router()) // /bc-approve(会话鉴权)
        .merge(grants::router())
        .merge(account_credentials::router())
        .merge(account_sessions::router())
        .merge(scim::router())
        .merge(scim_groups::admin_router())
        .merge(admin_sso::router())
        .merge(ssf_admin::router())
        .merge(data_governance::router())
        .merge(admin_attribute_namespaces::router())
        .merge(admin_federation_attributes::router())
        .merge(admin::router())
        .merge(register::manage_router()) // RFC 7592 管理端点(Bearer,非浏览器 fetch)
}

/// 汇聚所有端点路由(OpenApiRouter 让路由与 OpenAPI 同源)。CORS 按 C10.10 分组:
/// 无凭证端点挂 `public_cors()`(`*`),会话/导航端点不挂(同源 + 防 CSRF)。
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(token_router().layer(public_cors()))
        .merge(cors_open_non_token_router().layer(public_cors()))
        .merge(cors_none_router())
}

/// Lambda 路由范围(C3.4)。`Full` 只供本地 server/测试/OpenAPI;部署 Lambda 必须显式选择
/// `Token` 或 `NonToken`,避免环境漏配时重新暴露单体路由。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteScope {
    Full,
    Token,
    NonToken,
}

impl RouteScope {
    pub fn from_deployment_env(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            Some("token") => Ok(Self::Token),
            Some("non_token") => Ok(Self::NonToken),
            Some(_) => Err("SCOPE must be token or non_token"),
            None => Err("SCOPE is required for deployed Lambda"),
        }
    }

    pub fn validate_runtime_environment(
        self,
        grace_table: Option<&str>,
        grace_kms_key: Option<&str>,
    ) -> Result<(), &'static str> {
        if self != Self::Full && grace_table.is_none_or(str::is_empty) {
            return Err("deployed HTTP scope requires GRACE_TABLE");
        }
        match self {
            Self::Token if grace_kms_key.is_none_or(str::is_empty) => {
                Err("token scope requires GRACE_KMS_KEY_ID")
            }
            Self::NonToken if grace_kms_key.is_some_and(|value| !value.is_empty()) => {
                Err("non-token scope must not receive GRACE_KMS_KEY_ID")
            }
            _ => Ok(()),
        }
    }
}

fn scoped_api_router(scope: RouteScope) -> OpenApiRouter<AppState> {
    match scope {
        RouteScope::Full => api_router(),
        RouteScope::Token => OpenApiRouter::with_openapi(ApiDoc::openapi())
            .merge(token_router().layer(public_cors())),
        RouteScope::NonToken => OpenApiRouter::with_openapi(ApiDoc::openapi())
            .merge(cors_open_non_token_router().layer(public_cors()))
            .merge(cors_none_router()),
    }
}

/// 组装指定范围的路由。所有范围复用相同 tenant/Region/origin-auth/mTLS middleware。
pub fn build_router_for_scope(
    state: AppState,
    scope: RouteScope,
) -> (axum::Router, utoipa::openapi::OpenApi) {
    let (router, api) = scoped_api_router(scope).split_for_parts();
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_attribute_namespaces::self_hosted_attribute_surface_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenant::tenant_readiness_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenant::tenant_mutation_gate_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            region::region_admission_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            origin_auth::saas_origin_auth_layer,
        ))
        .with_state(state);
    // mTLS 客户端证书接入(spec 012 §1.4 / C5.7):仅 `feature=lambda`(真机 API Gateway)挂中间件,把
    // requestContext 已验链证书翻译成 ClientCertPem 扩展。本地 server 无此层 → X.509 路径不激活(可测缝)。
    #[cfg(feature = "lambda")]
    let router = router.layer(axum::middleware::from_fn(mtls::client_cert_layer));
    (router, api)
}

/// 组装完整路由。仅供本地 server、测试与 OpenAPI 使用。
pub fn build_router(state: AppState) -> (axum::Router, utoipa::openapi::OpenApi) {
    build_router_for_scope(state, RouteScope::Full)
}

/// 仅生成 OpenAPI 文档(export-openapi bin 用;不建 server)。
pub fn openapi_doc() -> utoipa::openapi::OpenApi {
    let (_, api) = api_router().split_for_parts();
    api
}

#[cfg(test)]
mod tests {
    fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing section start: {start}"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("missing section end: {end}"))
            .0
    }

    fn without_line_comments(source: &str) -> String {
        source
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn c10_10_cors_router_partition_is_centralized() {
        let source = include_str!("lib.rs");
        let policy =
            without_line_comments(section(source, "fn public_cors()", "/// `/token` 独立路由"));
        assert!(policy.contains(".allow_origin(Any)"));
        assert!(policy.contains("Method::GET"));
        assert!(policy.contains("Method::POST"));
        assert!(policy.contains("Method::OPTIONS"));
        assert!(
            !policy.contains("allow_credentials"),
            "the wildcard CORS policy must never enable browser credentials"
        );

        let open = without_line_comments(section(
            source,
            "fn cors_open_non_token_router()",
            "/// **会话/导航分组**",
        ));
        let open_routes = [
            "api_document::router()",
            "discovery::router()",
            "jwks::router()",
            "prm::router()",
            "userinfo::router()",
            "introspect::router()",
            "rs_attributes::router()",
            "revoke::router()",
            "device_flow::protocol_router()",
            "ciba_flow::protocol_router()",
            "register::register_post_router()",
        ];
        assert_eq!(open.matches(".merge(").count(), open_routes.len());
        for route in open_routes {
            assert!(
                open.contains(&format!(".merge({route})")),
                "{route} must remain in the wildcard no-cookie group"
            );
        }

        let no_cors = without_line_comments(section(
            source,
            "fn cors_none_router()",
            "/// 汇聚所有端点路由",
        ));
        let no_cors_routes = [
            "authorize::router()",
            "login::router()",
            "password_login::router()",
            "invitation::router()",
            "consent::router()",
            "recover::router()",
            "authz_session::router()",
            "end_session::router()",
            "federation_flow::router()",
            "passkey_flow::router()",
            "device_flow::approve_router()",
            "ciba_flow::approve_router()",
            "grants::router()",
            "account_credentials::router()",
            "account_sessions::router()",
            "scim::router()",
            "scim_groups::admin_router()",
            "admin_sso::router()",
            "ssf_admin::router()",
            "data_governance::router()",
            "admin_attribute_namespaces::router()",
            "admin_federation_attributes::router()",
            "admin::router()",
            "register::manage_router()",
        ];
        assert_eq!(no_cors.matches(".merge(").count(), no_cors_routes.len());
        for route in no_cors_routes {
            assert!(
                no_cors.contains(&format!(".merge({route})")),
                "{route} must remain in the same-origin/no-CORS group"
            );
        }

        let assembled =
            without_line_comments(section(source, "fn api_router()", "/// Lambda 路由范围"));
        assert_eq!(assembled.matches(".merge(").count(), 3);
        assert!(assembled.contains(".merge(token_router().layer(public_cors()))"));
        assert!(assembled.contains(".merge(cors_open_non_token_router().layer(public_cors()))"));
        assert!(assembled.contains(".merge(cors_none_router())"));
    }
}
