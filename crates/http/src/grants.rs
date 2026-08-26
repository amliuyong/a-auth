//! 用户自助 Grant 管理(spec 011 §5.1 / FAPI Grant Management 风格,P2):
//! - `GET /grants`:列**当前登录用户**的全部 Grant(授权记录);
//! - `GET /grants/{grant_id}`:取单个(须属当前用户);
//! - `DELETE /grants/{grant_id}`:吊销(status→Revoked;须属当前用户)。
//!
//! **鉴权 = AS 登录会话**(magic-link 建的 `__Host-` session cookie;`login::current_session`)——不是
//! client 认证、不是 admin_token。**IDOR-safe**(C6 同源):list 只返 `grant.user_id == 当前 user`;
//! get/delete 先校归属,他人 grant_id 一律当"不存在"(404,不泄露存在性)。P2 端点门控。
//!
//! **CSRF**(评审 codex MEDIUM):DELETE 是 cookie-auth 状态变更。防护 = session cookie 的 **SameSite=Lax**
//! ——跨站 `fetch DELETE` 不带 Lax cookie、HTML form 也发不了 DELETE,故跨站 DELETE 到不了本端点(与
//! `/end-session` 同套防线)。**吊销级联**(C7.6b):DELETE 吊 Grant 后**级联吊销同 id 的 refresh family +
//! 删宽限缓存**——否则持旧 refresh 的 client 仍能 rotate,"一键吊销"失效。
//!
//! 决策真相源 docs §5.1(Grant + 用户吊销)/ spec 011 Task 1.5 + CONFORMANCE C7.6b。

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{GraceStore, GrantStore, RefreshStore};
use crate::state::AppState;

/// Shared online status check for access tokens carrying `auth_grant`.
/// Grant revocation, refresh-family revocation, and user lifecycle fences are all authoritative;
/// absence of both records preserves compatibility with device/2LO and legacy tokens.
pub(crate) async fn token_grant_is_active(
    state: &AppState,
    tenant: &str,
    grant_id: &str,
    now: i64,
) -> Result<bool, crate::ports::StoreError> {
    match state.grants.get(tenant, grant_id).await {
        Ok(Some(grant)) if grant.is_usable(now).is_err() => return Ok(false),
        Ok(Some(grant)) => {
            match crate::user_gate::require_active_user_epoch(
                state,
                tenant,
                &grant.user_id,
                grant.credential_epoch,
            )
            .await
            {
                Ok(()) => {}
                Err(crate::user_gate::UserGate::Blocked) => return Ok(false),
                Err(crate::user_gate::UserGate::Unavailable) => {
                    return Err(crate::ports::StoreError::Transient(
                        "user authority unavailable".into(),
                    ))
                }
                Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
            }
        }
        Ok(None) => {}
        Err(error) => return Err(error),
    }

    match state.refresh.get(tenant, grant_id).await {
        Ok(Some(family)) if family.revoked => Ok(false),
        Ok(Some(family)) => {
            match crate::user_gate::require_active_user_epoch(
                state,
                tenant,
                &family.user_id,
                family.credential_epoch,
            )
            .await
            {
                Ok(()) => Ok(true),
                Err(crate::user_gate::UserGate::Blocked) => Ok(false),
                Err(crate::user_gate::UserGate::Unavailable) => Err(
                    crate::ports::StoreError::Transient("user authority unavailable".into()),
                ),
                Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
            }
        }
        Ok(None) => Ok(true),
        Err(error) => Err(error),
    }
}

pub(crate) async fn revoke_with_audit(
    state: &AppState,
    tenant: &str,
    actor: crate::security_event::SecurityActor,
    grant_id: &str,
) -> bool {
    let result = revoke_with_audit_result(state, tenant, actor, grant_id).await;
    cleanup_reached_revoked_state(result)
}

pub(crate) async fn revoke_with_audit_result(
    state: &AppState,
    tenant: &str,
    actor: crate::security_event::SecurityActor,
    grant_id: &str,
) -> Result<bool, crate::ports::StoreError> {
    let result = state.grants.revoke(tenant, grant_id).await;
    audit_revoke_result(state, tenant, actor, grant_id, &result).await;
    result
}

async fn audit_revoke_result(
    state: &AppState,
    tenant: &str,
    actor: crate::security_event::SecurityActor,
    grant_id: &str,
    result: &Result<bool, crate::ports::StoreError>,
) {
    state
        .record_security_event(revoke_event_draft(tenant, actor, grant_id, result.is_ok()))
        .await;
}

pub(crate) fn revoke_event_draft(
    tenant: &str,
    actor: crate::security_event::SecurityActor,
    grant_id: &str,
    success: bool,
) -> crate::security_event::SecurityEventDraft {
    crate::security_event::SecurityEventDraft::grant(
        tenant,
        actor,
        grant_id,
        crate::security_event::GrantAction::Revoke,
        if success {
            crate::security_event::SecurityEventOutcome::Success
        } else {
            crate::security_event::SecurityEventOutcome::Failure
        },
    )
}

fn cleanup_reached_revoked_state(result: Result<bool, crate::ports::StoreError>) -> bool {
    // A concurrent lifecycle cleanup may already have removed the Grant.
    // Present-but-revoked and absent both satisfy this cleanup's invariant.
    result.is_ok()
}

/// Grant 对外视图(不泄露内部结构的多余字段;够用户识别 + 决定是否吊销)。
#[derive(Serialize, utoipa::ToSchema)]
pub struct GrantView {
    pub grant_id: String,
    pub client_id: String,
    /// 已授权的 RS + scopes(逐 resource)。
    pub resources: Vec<ResourceView>,
    pub status: String,
    pub expires_at: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ResourceView {
    pub resource: String,
    pub scopes: Vec<String>,
}

fn view(g: &agent_auth_grant::Grant) -> GrantView {
    GrantView {
        grant_id: g.grant_id.clone(),
        client_id: g.client_id.clone(),
        resources: g
            .per_resource
            .iter()
            .map(|r| ResourceView {
                resource: r.resource.clone(),
                scopes: r.scopes.clone(),
            })
            .collect(),
        status: match g.status {
            agent_auth_grant::GrantStatus::Active => "active",
            agent_auth_grant::GrantStatus::Revoked => "revoked",
            agent_auth_grant::GrantStatus::Expired => "expired",
        }
        .to_string(),
        expires_at: g.constraints.expires_at,
    }
}

/// 阶段门控 + 登录用户解析(未登录 → 401;阶段未到 → 404)。返回当前 user_id。
async fn require_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), axum::response::Response> {
    if !agent_auth_protocol::endpoint_available(state.phase, "/grants") {
        // 阶段未到:通用 404(不回显"这是 gated grants 端点",评审 LOW-1 不泄露端点存在)。
        return Err((StatusCode::NOT_FOUND, "").into_response());
    }
    // tenant 分区(spec 020 §2.3):Grant 按 tenant 隔离(list_by_user 跨租户碰撞防线,codex B1)。
    let tenant = crate::tenant::tenant_or_400(state, headers)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_issuer").into_response())?;
    match crate::login::current_session(state, headers).await {
        Some((_sid, user_id)) => Ok((tenant, user_id)),
        None => Err((StatusCode::UNAUTHORIZED, "需登录(无有效会话)").into_response()),
    }
}

/// `GET /grants`:列当前登录用户的全部 Grant。
#[utoipa::path(
    get, path = "/grants", tag = "grants",
    responses(
        (status = 200, description = "当前用户的 Grant 列表", body = [GrantView]),
        (status = 401, description = "未登录"),
        (status = 404, description = "grants 未在当前阶段启用")
    )
)]
pub async fn list_grants(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let (tenant, user_id) = match require_user(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let credential_epoch =
        match crate::user_gate::active_user_epoch(&state, &tenant, &user_id).await {
            Ok(epoch) => epoch,
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "用户状态不可用").into_response();
            }
        };
    match state.grants.list_by_user(&tenant, &user_id).await {
        Ok(gs) => Json(
            gs.iter()
                .filter(|grant| grant.credential_epoch == credential_epoch)
                .map(view)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(crate::ports::StoreError::Transient(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response(),
    }
}

/// `GET /grants/{grant_id}`:取单个(须属当前用户;他人的当不存在)。
#[utoipa::path(
    get, path = "/grants/{grant_id}", tag = "grants",
    params(("grant_id" = String, Path, description = "Grant id")),
    responses(
        (status = 200, description = "Grant 详情", body = GrantView),
        (status = 401, description = "未登录"),
        (status = 404, description = "不存在或非本人")
    )
)]
pub async fn get_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> impl IntoResponse {
    let (tenant, user_id) = match require_user(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let credential_epoch =
        match crate::user_gate::active_user_epoch(&state, &tenant, &user_id).await {
            Ok(epoch) => epoch,
            Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "用户状态不可用").into_response(),
        };
    match state.grants.get(&tenant, &grant_id).await {
        // **IDOR-safe**:非本人 grant 一律当不存在(404,不泄露存在性/归属)。
        Ok(Some(g)) if g.user_id == user_id && g.credential_epoch == credential_epoch => {
            Json(view(&g)).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, "不存在").into_response(),
        Err(crate::ports::StoreError::Transient(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response(),
    }
}

/// `DELETE /grants/{grant_id}`:吊销当前用户的 Grant(status→Revoked)。IDOR-safe:先校归属。
#[utoipa::path(
    delete, path = "/grants/{grant_id}", tag = "grants",
    params(("grant_id" = String, Path, description = "Grant id")),
    responses(
        (status = 204, description = "已吊销"),
        (status = 401, description = "未登录"),
        (status = 404, description = "不存在或非本人")
    )
)]
pub async fn revoke_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> impl IntoResponse {
    let (tenant, user_id) = match require_user(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // **先取 + 校归属**(IDOR-safe):他人/不存在的 grant_id → 404(不泄露、不吊销)。
    match state.grants.get(&tenant, &grant_id).await {
        Ok(Some(g)) if g.user_id == user_id => {
            // 归属确认 → 吊销 Grant(幂等:已 Revoked 再吊仍 204)。
            match revoke_with_audit_result(
                &state,
                &tenant,
                crate::security_event::SecurityActor::user(&user_id),
                &grant_id,
            )
            .await
            {
                Ok(_) => {}
                Err(crate::ports::StoreError::Transient(_)) => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response();
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response();
                }
            }
            // **级联吊销 refresh family + 删宽限缓存**(评审 codex HIGH / C7.6b):否则持旧 refresh token 的
            // client 在用户"一键吊销授权"后仍能 rotate 换新 access——吊销核心语义失效。Grant.grant_id ==
            // family_id(迁移不变式,token.rs),故直接按 grant_id 吊 family + 删缓存。两项必须独立尝试，
            // 任一失败都不得伪报 204；Grant revoke 与 cleanup 都幂等，调用方可重试完成清理。
            let refresh_result = state.refresh.revoke(&tenant, &grant_id).await;
            let grace_result = match &state.grace {
                Some(grace) => grace.delete_family(&grant_id).await,
                None => Ok(()),
            };
            if refresh_result.is_err() || grace_result.is_err() {
                let permanent =
                    matches!(&refresh_result, Err(crate::ports::StoreError::Permanent(_)))
                        || matches!(&grace_result, Err(crate::ports::StoreError::Permanent(_)));
                return if permanent {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Grant 已吊销，关联 refresh/grace 清理失败",
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Grant 已吊销，关联 refresh/grace 清理未完成，请重试",
                    )
                        .into_response()
                };
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(_) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::grant(
                    &tenant,
                    crate::security_event::SecurityActor::user(&user_id),
                    &grant_id,
                    crate::security_event::GrantAction::Deny,
                    crate::security_event::SecurityEventOutcome::Denied,
                ))
                .await;
            (StatusCode::NOT_FOUND, "不存在").into_response()
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::grant(
                    &tenant,
                    crate::security_event::SecurityActor::user(&user_id),
                    &grant_id,
                    crate::security_event::GrantAction::Revoke,
                    crate::security_event::SecurityEventOutcome::Failure,
                ))
                .await;
            (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response()
        }
        Err(_) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::grant(
                    &tenant,
                    crate::security_event::SecurityActor::user(&user_id),
                    &grant_id,
                    crate::security_event::GrantAction::Revoke,
                    crate::security_event::SecurityEventOutcome::Failure,
                ))
                .await;
            (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response()
        }
    }
}

/// `POST /grants/{grant_id}/refs` 请求体(spec 011 §4:铸 grant-ref)。
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct MintRefRequest {
    /// 绑定的发起 agent(workload client_id);MUST ∈ 该 Grant 的 actor_allowlist(SPIFFE 前缀通配)。
    pub bound_agent: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MintRefResponse {
    /// grant-ref(ES256 JWT,typ=grant-ref+jwt);token-exchange 以 `grant_ref` 参数出示。
    pub grant_ref: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

/// `POST /grants/{grant_id}/refs`(spec 011 §4,C7.1/C7.7,P2):**用户铸**跨 Grant 换发凭据 grant-ref。
/// 鉴权=登录会话(模型 A,拒 agent 自助铸);IDOR=grant.user_id==session.user_id;bound_agent MUST ∈
/// grant.actor_allowlist(actor_matches SPIFFE 通配,不允许铸双闸必拒的死 ref)。短时 ES256 JWT,无存储。
#[utoipa::path(
    post, path = "/grants/{grant_id}/refs", tag = "grants",
    params(("grant_id" = String, Path, description = "Grant id")),
    request_body = MintRefRequest,
    responses(
        (status = 201, description = "grant-ref 铸造成功", body = MintRefResponse),
        (status = 400, description = "bound_agent 不在 Grant actor_allowlist"),
        (status = 401, description = "未登录"),
        (status = 404, description = "Grant 不存在或非本人"),
        (status = 429, description = "铸造过于频繁")
    )
)]
pub async fn mint_grant_ref(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(req): Json<MintRefRequest>,
) -> impl IntoResponse {
    let (tenant, user_id) = match require_user(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // IDOR:先取 + 校归属(他人/不存在 → 404,不泄露)。
    let grant = match state.grants.get(&tenant, &grant_id).await {
        Ok(Some(g)) if g.user_id == user_id => g,
        Ok(_) => return (StatusCode::NOT_FOUND, "不存在").into_response(),
        Err(crate::ports::StoreError::Transient(_)) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response()
        }
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "存储错误").into_response(),
    };
    if crate::user_gate::require_active_user_epoch(
        &state,
        &tenant,
        &user_id,
        grant.credential_epoch,
    )
    .await
    .is_err()
    {
        return (StatusCode::NOT_FOUND, "Grant 不可用").into_response();
    }
    let now = crate::token::current_unix_secs_pub();
    // Grant 须可用(吊销/过期不铸)。
    if grant.is_usable(now).is_err() {
        return (StatusCode::NOT_FOUND, "Grant 不可用").into_response();
    }
    // bound_agent MUST ∈ actor_allowlist(actor_matches:SPIFFE 前缀通配,非字符串 contains)——
    // 不允许绑不在委托白名单的 agent(否则铸出受理侧双闸必拒的死 ref)。
    if !grant
        .constraints
        .actor_allowlist
        .iter()
        .any(|pat| agent_auth_grant::actor_matches(pat, &req.bound_agent))
    {
        return (
            StatusCode::BAD_REQUEST,
            "bound_agent 不在 Grant actor_allowlist(不铸死 ref)",
        )
            .into_response();
    }
    let Some(issuer) = crate::hostutil::issuer_host(&headers)
        .and_then(|h| agent_auth_discovery::derive_issuer(&h, &state.form).ok())
    else {
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };
    if !crate::tenant::issuer_belongs_to_request_tenant(
        &state,
        &headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::user(&user_id),
    )
    .await
    {
        return (StatusCode::BAD_REQUEST, "issuer does not belong to tenant").into_response();
    }
    // 节流(评审 codex/Kiro 一致 Low:不落存储但打 KMS Sign)。key=**per user+grant**,**不含 bound_agent**
    // ——否则 SPIFFE 通配 allowlist 下攻击者变换 bound_agent 随机后缀就每次落新桶、绕过限流狂打 KMS Sign。
    // 去掉 bound_agent 段后:同一 (user,grant) 的所有铸造共享一个桶,通配后缀无法再逃逸。fail-open。
    let rl_key = format!("grantref:{user_id}:{grant_id}");
    if crate::ratelimit_gate::grant_ref_mint_throttled(&state, &tenant, &rl_key).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "5")],
            "铸造过于频繁",
        )
            .into_response();
    }
    let tenant_signer = match crate::tenant_keys::signer_or_503(&state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return response,
    };
    match crate::token::sign_tenant_grant_ref(
        &state,
        &headers,
        tenant_signer.as_ref(),
        &grant_id,
        &req.bound_agent,
        issuer.as_str(),
        now,
        crate::security_event::SecurityActor::user(&user_id),
    )
    .await
    {
        Ok(jwt) => (
            StatusCode::CREATED,
            Json(MintRefResponse {
                grant_ref: jwt,
                token_type: "urn:agent-auth:params:token-type:grant-ref",
                expires_in: crate::token::GRANT_REF_TTL_SECS,
            }),
        )
            .into_response(),
        Err(crate::token::TokenSignError::Transient) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            "签名瞬时不可用,请重试",
        )
            .into_response(),
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            (StatusCode::BAD_REQUEST, "issuer does not belong to tenant").into_response()
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "签名失败").into_response()
        }
        Err(crate::token::TokenSignError::Permanent) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "签名失败").into_response()
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_grants))
        .routes(routes!(get_grant, revoke_grant))
        .routes(routes!(mint_grant_ref))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_event::{SecurityActor, SecurityEventOutcome, SecurityEventStore};

    #[tokio::test]
    async fn automatic_cleanup_revokes_the_grant_and_records_the_outcome() {
        let state = AppState::dev("localhost");
        let grant_id = "automatic-cleanup-grant";
        state
            .grants
            .put(
                "",
                agent_auth_grant::Grant {
                    grant_id: grant_id.to_string(),
                    user_id: "user:alice@example.com".to_string(),
                    client_id: "client".to_string(),
                    per_resource: vec![],
                    effective_per_resource: vec![],
                    effective_pv: 0,
                    allowed_ip_cidrs: vec![],
                    allowed_vpce: vec![],
                    credential_epoch: 0,
                    revision: 0,
                    constraints: agent_auth_grant::GrantConstraints {
                        max_act_chain: 1,
                        actor_allowlist: vec![],
                        expires_at: i64::MAX,
                    },
                    status: agent_auth_grant::GrantStatus::Active,
                },
            )
            .await
            .unwrap();

        assert!(
            revoke_with_audit(&state, "", SecurityActor::system("device-token"), grant_id,).await
        );
        assert_eq!(
            state
                .grants
                .get("", grant_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            agent_auth_grant::GrantStatus::Revoked
        );
        let events = state
            .security_events
            .list_by_tenant("default", 0, i64::MAX, 100)
            .await
            .unwrap();
        assert!(events.iter().any(|stored| {
            let event = serde_json::to_value(&stored.event).unwrap();
            stored.event.action == "grant.revoke"
                && stored.event.outcome == SecurityEventOutcome::Success
                && stored.event.correlation.grant_id.as_deref() == Some(grant_id)
                && event["actor"]["kind"] == "system"
                && event["actor"]["id"] == "device-token"
        }));
    }

    #[tokio::test]
    async fn automatic_cleanup_treats_an_absent_grant_as_idempotent_success() {
        let state = AppState::dev("localhost");
        assert!(
            revoke_with_audit(
                &state,
                "",
                SecurityActor::system("ciba-token"),
                "already-removed-grant",
            )
            .await
        );
        let events = state
            .security_events
            .list_by_tenant("default", 0, i64::MAX, 100)
            .await
            .unwrap();
        assert!(events.iter().any(|stored| {
            stored.event.action == "grant.revoke"
                && stored.event.outcome == SecurityEventOutcome::Success
        }));
    }

    #[test]
    fn automatic_cleanup_reports_only_store_errors_as_failure() {
        assert!(cleanup_reached_revoked_state(Ok(true)));
        assert!(cleanup_reached_revoked_state(Ok(false)));
        assert!(!cleanup_reached_revoked_state(Err(
            crate::ports::StoreError::Transient("unavailable".to_string())
        )));
    }
}
