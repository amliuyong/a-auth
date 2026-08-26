//! 数据面 tenant 分区(spec 020 §2.3,C10.19)——SaaS 多租户跨租户数据隔离。
//!
//! **机制**:每个 store 的物理分区键前缀 tenant(`tpk(tenant,key)`);tenant 由 handler 入口从入站
//! Host 派生一次、贯穿本请求所有 store 调用(D3)。**逐租户 CMK 是密码学隔离,本模块是数据面隔离**
//! ——二者叠加(见 DESIGN §8)。
//!
//! **feature-flag 全或无(评审 Kiro H2)**:`AppState.tenant_partitioning`(env
//! `AGENT_AUTH_ENABLE_TENANT_PARTITIONING`,默认 **false**)。
//! - **关(现网默认)**:handler 取 tenant = **空串** → `tpk("",key)=key`(无前缀)→ 与分区前**字节等价**,
//!   旧表旧数据零迁移、行为不变。**8 store 未全部分区前 MUST 保持关**(半迁移=新泄露面)。
//! - **开(SaaS 部署 / 全 store 就绪后)**:handler 取真 tenant(SelfHosted→`"default"`;Saas→子域标签),
//!   数据落 `{tenant}\x1f*` 分区;持久安全态表走新表集(D6,见 spec 020 §2.3-f)。
//!
//! **编码**:`\x1f`(US 分隔符,不可能出现在 tenant/key 内容里),复用已分区 store(jti)同一范式。

use crate::state::AppState;
use agent_auth_discovery::Form;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use std::future::Future;

const AUTHORITY_MUTATING_READ_ROUTES: &[&str] = &[
    "/account/credentials",
    "/account/sessions",
    "/admin/sso/callback",
    "/admin/sso/start",
    "/authorize",
    "/bc-approve/{auth_req_id}",
    "/consent/context",
    "/end-session",
    "/federation/callback",
    "/grants",
    "/grants/{grant_id}",
    "/login/callback",
    "/passkey/authenticate/begin",
    "/passkey/status",
    "/recovery/status",
    "/register/{client_id}",
    "/sessions",
    "/sessions/{session_id}",
];

const READ_ONLY_GET_ROUTES: &[&str] = &[
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/openid-configuration",
    "/.well-known/ssf-configuration",
    "/admin/attribute-namespaces",
    "/admin/clients",
    "/admin/clients/{client_id}",
    "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}",
    "/admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/evidence",
    "/admin/control/tenants",
    "/admin/control/tenants/{tenant_id}/keys",
    "/admin/data-governance/exports/{export_id}",
    "/admin/data-governance/jobs/{job_id}",
    "/admin/data-governance/jobs/{job_id}/evidence",
    "/admin/data-governance/policy",
    "/admin/data-governance/users/{user_id}/export",
    "/admin/federation/{tenant_id}",
    "/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings",
    "/admin/initial-access-tokens",
    "/admin/messages",
    "/admin/oidc",
    "/admin/overview",
    "/admin/scim/effective-role/{userId}",
    "/admin/scim/group-role-mappings",
    "/admin/security-events",
    "/admin/session",
    "/admin/ssf/streams",
    "/admin/ssf/streams/{stream_id}",
    "/admin/ssf/streams/{stream_id}/deliveries",
    "/admin/ssf/streams/{stream_id}/deliveries/{stream_revision}/{event_id}",
    "/admin/users",
    "/admin/users/{id}",
    "/admin/workload-trust/{tenant_id}",
    "/jwks.json",
    "/openapi.json",
    "/rs/attributes",
    "/rs/prm",
    "/scim/v2/Groups",
    "/scim/v2/Groups/{id}",
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/Users",
    "/scim/v2/Users/{id}",
    "/userinfo",
];

/// US 分隔符(tenant 与 key 之间)。tenant/key 内容均不含此字节。
pub const SEP: char = '\u{1f}';

/// tenant-scoped 物理分区键。**空 tenant → 原样返回 key**(flag 关时的透传,与分区前字节等价);
/// 非空 → `{tenant}\x1f{key}`。所有 core store 的 Dynamo pk / Memory 复合键统一走此编码。
pub fn tpk(tenant: &str, key: &str) -> String {
    if tenant.is_empty() {
        key.to_string()
    } else {
        format!("{tenant}{SEP}{key}")
    }
}

/// handler 取本请求的 tenant(D3:入口派生一次,贯穿全 store 调用)。
///
/// - **flag 关** → `Ok("")`(空 tenant,`tpk` 透传;现网默认,零迁移)。
/// - **flag 开** → `tenant_id_from(issuer_host, form)`;派生失败(控制面 Host/非租户子域/坏 Host)
///   → `Err(400)`(统一 fail-closed,评审 Kiro M3:禁各 handler 自定码/禁 panic)。
///
/// **绝不 fallback "default"**(flag 开时):控制面 Host 派生失败必须拒,不静默降级到 default 分区。
// Err = axum Response(全 crate handler 一致的错误载荷类型;同 workload_flow 的既有约定)。
#[allow(clippy::result_large_err)]
pub fn tenant_or_400(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, axum::response::Response> {
    if !state.tenant_partitioning {
        return Ok(String::new());
    }
    let host = crate::hostutil::issuer_host(headers).ok_or_else(bad_issuer)?;
    agent_auth_discovery::tenant_id_from(&host, &state.form).map_err(|_| bad_issuer())
}

pub async fn issuer_belongs_to_request_tenant(
    state: &AppState,
    headers: &HeaderMap,
    issuer: &str,
    actor: crate::security_event::SecurityActor,
) -> bool {
    let Some(host) = crate::hostutil::issuer_host(headers) else {
        return false;
    };
    let issuer_host = match &state.form {
        Form::SelfHosted { configured_host }
            if host
                .strip_prefix("mtls.")
                .is_some_and(|base| base == configured_host) =>
        {
            configured_host.as_str()
        }
        _ => host.as_str(),
    };
    if agent_auth_discovery::assert_iss_belongs_to_tenant(issuer, issuer_host, &state.form).is_ok()
    {
        return true;
    }
    let tenant = agent_auth_discovery::tenant_id_from(&host, &state.form)
        .unwrap_or_else(|_| "default".to_string());
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::issuer_boundary_denial(
                &tenant, actor, issuer,
            ),
        )
        .await;
    false
}

fn bad_issuer() -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "invalid_issuer",
            "error_description": "Host is not a valid tenant issuer"
        })),
    )
        .into_response()
}

/// SaaS admission gate. A syntactically valid tenant Host is not an active
/// issuer until the registry exposes a complete EC/RSA snapshot. Control-plane
/// and malformed Hosts continue to their own route-level rejection logic.
pub async fn tenant_readiness_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    if let Form::Saas { .. } = &state.form {
        if let Some(host) = crate::hostutil::issuer_host(request.headers()) {
            if let Ok(tenant_id) = agent_auth_discovery::tenant_id_from(&host, &state.form) {
                if !state.saas_tenants.iter().any(|tenant| tenant == &tenant_id) {
                    return (
                        StatusCode::NOT_FOUND,
                        axum::Json(serde_json::json!({
                            "error": "invalid_issuer",
                            "error_description": "Tenant issuer is not registered"
                        })),
                    )
                        .into_response();
                }
                if state.tenant_keys.resolve(&tenant_id).await.is_err() {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "temporarily_unavailable",
                            "error_description": "Tenant issuer is not ready"
                        })),
                    )
                        .into_response();
                }
            }
        }
    }
    next.run(request).await
}

/// Shared HTTP mutation fence for irreversible tenant offboarding. Governance
/// resume/status routes remain reachable after the freeze; every other
/// authority mutation fails closed. Background writers must apply the same
/// lifecycle revision in their own transactional fence.
pub async fn tenant_mutation_gate_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let is_governance_control = path.starts_with("/admin/data-governance/")
        || path.starts_with("/admin/control/data-governance/");
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    if is_governance_control
        || !request_requires_tenant_mutation_permit(request.method(), matched_path)
    {
        return next.run(request).await;
    }

    let logical_tenant = match &state.form {
        Form::SelfHosted { .. } => Some("default".to_string()),
        Form::Saas { .. } => crate::hostutil::issuer_host(request.headers())
            .and_then(|host| agent_auth_discovery::tenant_id_from(&host, &state.form).ok()),
    };
    let Some(logical_tenant) = logical_tenant else {
        return next.run(request).await;
    };

    use crate::ports::GovernanceStore;
    let now = crate::current_unix_secs();
    let permit = crate::governance::TenantMutationPermit {
        tenant_id: logical_tenant,
        permit_id: new_mutation_permit_id(),
        deadline: now.saturating_add(crate::governance::TENANT_MUTATION_PERMIT_LEASE_SECS),
    };
    let mut permit = match state
        .governance
        .acquire_tenant_mutation_permit(permit, now)
        .await
    {
        Ok(crate::governance::TenantMutationPermitAcquireOutcome::Acquired(permit)) => permit,
        Ok(crate::governance::TenantMutationPermitAcquireOutcome::Frozen {
            lifecycle_revision,
        }) => {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": "tenant_offboarding",
                    "error_description": "Tenant authority is frozen for offboarding",
                    "lifecycle_revision": lifecycle_revision
                })),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "Tenant mutation fence is unavailable"
                })),
            )
                .into_response()
        }
    };

    let response = {
        let request = next.run(request);
        tokio::pin!(request);
        loop {
            let renew = tokio::time::sleep(std::time::Duration::from_secs(
                crate::governance::TENANT_MUTATION_PERMIT_RENEW_SECS,
            ));
            tokio::pin!(renew);
            tokio::select! {
                response = &mut request => break response,
                () = &mut renew => {
                    let now = crate::current_unix_secs();
                    let deadline = now.saturating_add(
                        crate::governance::TENANT_MUTATION_PERMIT_LEASE_SECS,
                    );
                    match state
                        .governance
                        .renew_tenant_mutation_permit(&permit, now, deadline)
                        .await
                    {
                        Ok(true) => permit.deadline = deadline,
                        Ok(false) | Err(_) => {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                axum::Json(serde_json::json!({
                                    "error": "temporarily_unavailable",
                                    "error_description": "Tenant mutation authority expired"
                                })),
                            )
                                .into_response();
                        }
                    }
                }
            }
        }
    };
    if let Err(error) = state
        .governance
        .release_tenant_mutation_permit(permit, crate::current_unix_secs())
        .await
    {
        eprintln!("TENANT_MUTATION_PERMIT_RELEASE_FAILED error={error:?}");
    }
    response
}

fn request_requires_tenant_mutation_permit(method: &Method, matched_path: Option<&str>) -> bool {
    match *method {
        Method::GET | Method::HEAD => matched_path.is_some_and(|path| {
            AUTHORITY_MUTATING_READ_ROUTES.contains(&path) || !READ_ONLY_GET_ROUTES.contains(&path)
        }),
        Method::OPTIONS => false,
        _ => true,
    }
}

#[derive(Debug)]
pub(crate) enum TenantMutationFenceError {
    Frozen,
    AuthorityExpired,
    Store(crate::ports::StoreError),
}

impl std::fmt::Display for TenantMutationFenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frozen => formatter.write_str("tenant is frozen for offboarding"),
            Self::AuthorityExpired => formatter.write_str("mutation authority expired"),
            Self::Store(error) => write!(formatter, "mutation fence store error: {error:?}"),
        }
    }
}

/// Runs one background mutation under the same renewable permit used by HTTP
/// authority writes. On renewal failure the future is dropped immediately and
/// the old permit remains until its deadline to cover already-issued calls.
pub(crate) async fn with_tenant_mutation_permit<T, F>(
    state: &AppState,
    data_tenant: &str,
    operation: F,
) -> Result<T, TenantMutationFenceError>
where
    F: Future<Output = T>,
{
    use crate::ports::GovernanceStore;

    let logical_tenant = match &state.form {
        Form::SelfHosted { .. } => "default",
        Form::Saas { .. } if !data_tenant.is_empty() => data_tenant,
        Form::Saas { .. } => return Err(TenantMutationFenceError::Frozen),
    };
    let now = crate::current_unix_secs();
    let permit = crate::governance::TenantMutationPermit {
        tenant_id: logical_tenant.to_string(),
        permit_id: new_mutation_permit_id(),
        deadline: now.saturating_add(crate::governance::TENANT_MUTATION_PERMIT_LEASE_SECS),
    };
    let mut permit = match state
        .governance
        .acquire_tenant_mutation_permit(permit, now)
        .await
        .map_err(TenantMutationFenceError::Store)?
    {
        crate::governance::TenantMutationPermitAcquireOutcome::Acquired(permit) => permit,
        crate::governance::TenantMutationPermitAcquireOutcome::Frozen { .. } => {
            return Err(TenantMutationFenceError::Frozen);
        }
    };

    tokio::pin!(operation);
    let result = loop {
        let renew = tokio::time::sleep(std::time::Duration::from_secs(
            crate::governance::TENANT_MUTATION_PERMIT_RENEW_SECS,
        ));
        tokio::pin!(renew);
        tokio::select! {
            result = &mut operation => break result,
            () = &mut renew => {
                let now = crate::current_unix_secs();
                let deadline = now.saturating_add(
                    crate::governance::TENANT_MUTATION_PERMIT_LEASE_SECS,
                );
                match state
                    .governance
                    .renew_tenant_mutation_permit(&permit, now, deadline)
                    .await
                {
                    Ok(true) => permit.deadline = deadline,
                    Ok(false) | Err(_) => {
                        return Err(TenantMutationFenceError::AuthorityExpired);
                    }
                }
            }
        }
    };
    if let Err(error) = state
        .governance
        .release_tenant_mutation_permit(permit, crate::current_unix_secs())
        .await
    {
        eprintln!("BACKGROUND_MUTATION_PERMIT_RELEASE_FAILED error={error:?}");
    }
    Ok(result)
}

fn new_mutation_permit_id() -> String {
    let mut random = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::visit::Visit;

    #[derive(Default)]
    struct CallPaths(Vec<String>);

    impl<'ast> Visit<'ast> for CallPaths {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref() {
                self.0.push(
                    path.path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                );
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    fn function_call_paths(source: &str, function_name: &str) -> Vec<String> {
        let file = syn::parse_file(source).expect("reviewed Rust source must parse");
        let function = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == function_name => Some(function),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing function {function_name}"));
        let mut visitor = CallPaths::default();
        visitor.visit_block(&function.block);
        visitor.0
    }

    fn call_position(paths: &[String], suffix: &str) -> usize {
        paths
            .iter()
            .position(|path| path.ends_with(suffix))
            .unwrap_or_else(|| panic!("missing call ending in {suffix}: {paths:?}"))
    }

    fn assert_call_before(paths: &[String], first: &str, later: &str) {
        assert!(
            call_position(paths, first) < call_position(paths, later),
            "{first} must execute before {later}: {paths:?}"
        );
    }

    fn assert_calls(paths: &[String], expected: &[&str]) {
        for expected in expected {
            assert!(
                paths.iter().any(|path| path.ends_with(expected)),
                "missing call ending in {expected}: {paths:?}"
            );
        }
    }

    #[test]
    fn empty_tenant_passthrough_is_byte_identical() {
        // flag 关(空 tenant)= 分区前原始 key,零迁移。
        assert_eq!(tpk("", "client-abc"), "client-abc");
        assert_eq!(tpk("", "user:alice@example.com"), "user:alice@example.com");
    }

    #[test]
    fn nonempty_tenant_prefixes_with_us_separator() {
        assert_eq!(tpk("t1", "client-abc"), "t1\u{1f}client-abc");
        assert_eq!(tpk("default", "grant:x"), "default\u{1f}grant:x");
    }

    #[test]
    fn distinct_tenants_never_collide() {
        // 跨租户同一逻辑 key → 不同物理 key(隔离的根)。
        assert_ne!(tpk("t1", "user:a@x.com"), tpk("t2", "user:a@x.com"));
    }

    #[test]
    fn c10_22a_saas_issuance_call_sites_use_guarded_signers() {
        let tenant_paths = function_call_paths(
            include_str!("tenant.rs"),
            "issuer_belongs_to_request_tenant",
        );
        assert!(tenant_paths
            .iter()
            .any(|path| path.ends_with("assert_iss_belongs_to_tenant")));

        let guarded_access = function_call_paths(
            include_str!("token.rs"),
            "sign_tenant_access_token_with_delivery",
        );
        assert_call_before(
            &guarded_access,
            "issuer_belongs_to_request_tenant",
            "sign_access_token_with_delivery",
        );
        let guarded_id = function_call_paths(include_str!("token.rs"), "sign_tenant_id_token");
        assert_call_before(
            &guarded_id,
            "issuer_belongs_to_request_tenant",
            "sign_id_token",
        );
        let guarded_delegation = function_call_paths(
            include_str!("token.rs"),
            "sign_tenant_delegation_token_with_delivery",
        );
        assert_call_before(
            &guarded_delegation,
            "issuer_belongs_to_request_tenant",
            "sign_delegation_token_with_delivery",
        );
        let guarded_grant_ref =
            function_call_paths(include_str!("token.rs"), "sign_tenant_grant_ref");
        assert_call_before(
            &guarded_grant_ref,
            "issuer_belongs_to_request_tenant",
            "sign_grant_ref",
        );

        let code_paths = function_call_paths(include_str!("token.rs"), "token_handler_inner");
        assert_calls(
            &code_paths,
            &[
                "issuer_belongs_to_request_tenant",
                "sign_tenant_access_token_with_delivery",
                "sign_tenant_id_token",
            ],
        );

        let exchange_paths = function_call_paths(include_str!("token_exchange.rs"), "handle");
        assert_calls(
            &exchange_paths,
            &[
                "issuer_belongs_to_request_tenant",
                "sign_tenant_delegation_token_with_delivery",
            ],
        );

        let refresh_entry = function_call_paths(include_str!("refresh_flow.rs"), "handle");
        assert_call_before(&refresh_entry, "prepare_issuance", "issue_leased");
        let refresh_guard =
            function_call_paths(include_str!("refresh_flow.rs"), "prepare_issuance");
        assert!(refresh_guard
            .iter()
            .any(|path| path.ends_with("issuer_belongs_to_request_tenant")));
        let refresh_signer = function_call_paths(include_str!("refresh_flow.rs"), "issue_leased");
        assert_calls(&refresh_signer, &["sign_tenant_access_token_with_delivery"]);

        let workload_entry = function_call_paths(include_str!("workload_flow.rs"), "handle");
        assert_call_before(
            &workload_entry,
            "issuer_belongs_to_request_tenant",
            "try_handle_service",
        );
        assert_call_before(
            &workload_entry,
            "issuer_belongs_to_request_tenant",
            "issue_2lo",
        );
        let service_branch =
            function_call_paths(include_str!("workload_flow.rs"), "try_handle_service");
        assert!(
            service_branch
                .iter()
                .any(|path| path.ends_with("try_handle_loaded_service")),
            "service branch must reach authenticated service handling: {service_branch:?}"
        );
        let loaded_service_branch = function_call_paths(
            include_str!("workload_flow.rs"),
            "try_handle_loaded_service",
        );
        assert!(
            loaded_service_branch
                .iter()
                .any(|path| path.ends_with("issue_2lo")),
            "authenticated service branch must reach issue_2lo: {loaded_service_branch:?}"
        );
        let workload_signer = function_call_paths(include_str!("workload_flow.rs"), "issue_2lo");
        assert_calls(&workload_signer, &["sign_tenant_access_token"]);

        let device = function_call_paths(include_str!("device_flow.rs"), "issue_device_token");
        assert_calls(
            &device,
            &[
                "issuer_belongs_to_request_tenant",
                "sign_tenant_access_token",
            ],
        );

        let ciba = function_call_paths(include_str!("ciba_flow.rs"), "issue_ciba_token");
        assert_calls(
            &ciba,
            &[
                "issuer_belongs_to_request_tenant",
                "sign_tenant_access_token",
            ],
        );

        let ema = function_call_paths(include_str!("ema_flow.rs"), "handle");
        assert_calls(
            &ema,
            &[
                "issuer_belongs_to_request_tenant",
                "sign_tenant_access_token",
            ],
        );

        let grant_ref = function_call_paths(include_str!("grants.rs"), "mint_grant_ref");
        assert_calls(
            &grant_ref,
            &["issuer_belongs_to_request_tenant", "sign_tenant_grant_ref"],
        );
    }

    #[test]
    fn every_openapi_get_route_has_an_explicit_authority_classification() {
        use std::collections::BTreeSet;

        let document = serde_json::to_value(crate::openapi_doc()).unwrap();
        let actual = document["paths"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(path, item)| item.get("get").is_some().then_some(path.as_str()))
            .collect::<BTreeSet<_>>();
        let classified = AUTHORITY_MUTATING_READ_ROUTES
            .iter()
            .chain(READ_ONLY_GET_ROUTES)
            .copied()
            .collect::<BTreeSet<_>>();

        assert_eq!(actual, classified);
        assert!(AUTHORITY_MUTATING_READ_ROUTES
            .iter()
            .all(|path| !READ_ONLY_GET_ROUTES.contains(path)));
    }

    #[test]
    fn get_and_head_authority_writes_require_a_permit() {
        for method in [Method::GET, Method::HEAD] {
            for path in AUTHORITY_MUTATING_READ_ROUTES {
                assert!(
                    request_requires_tenant_mutation_permit(&method, Some(path)),
                    "{method} {path} must acquire a tenant mutation permit"
                );
            }
            for path in READ_ONLY_GET_ROUTES {
                assert!(
                    !request_requires_tenant_mutation_permit(&method, Some(path)),
                    "{method} {path} must remain read-only"
                );
            }
            assert!(request_requires_tenant_mutation_permit(
                &method,
                Some("/future-unclassified-route")
            ));
            assert!(!request_requires_tenant_mutation_permit(&method, None));
        }
    }
}
