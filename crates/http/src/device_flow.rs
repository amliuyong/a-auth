//! Device Authorization Grant(RFC 8628,spec 013 C7b.4):`POST /device_authorization` + `device_code` 轮询。
//!
//! 编排纯逻辑(agent_auth_ciba)+ DeviceStore,不重述规则:
//! - `/device_authorization`:铸 `device_code`(不透明,查库)+ `user_code`(短码,用户在另一设备输);
//!   下发 `verification_uri` / `interval` / `expires_in`。
//! - `/token` `grant_type=urn:ietf:params:oauth:grant-type:device_code`:`poll_decision`(C7b.4 矩阵:
//!   authorization_pending / slow_down / expired_token / access_denied / invalid_grant / IssueToken)。
//!   批准(status=approved + user_id 填)后签 3LO 形态 access token(sub=用户、sub_type=user)。
//!
//! 批准页(输 user_code + approve/deny)见 device 批准 handler(spec 013 §2b);此模块只做协议面。
//! 阶段:device_code grant + /device_authorization 均 P2(grant_accepted / endpoint_available 门控)。
//!
//! 决策真相源 docs §5.2 / spec 013 C7b.4 + CONFORMANCE C7b。

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::{Deserialize, Serialize};

use crate::poll_claim::{classify_poll_claim, PollClaimAction};
use crate::ports::{ClientStore, DeviceAuthGrant, DeviceStore};
use crate::state::AppState;
use crate::token::{err, sign_tenant_access_token, AccessTokenClaims, TokenResponse};
use agent_auth_ciba::{canonicalize_user_code, poll_decision, PollOutcome, PollStatus};
use agent_auth_discovery::derive_issuer;
use agent_auth_token::SubType;

/// device_code grant type(RFC 8628)。
pub(crate) const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// device 授权码有效期(秒;≤15min,docs §2.1)。
const DEVICE_CODE_TTL_SECS: i64 = 600;
/// 轮询间隔(秒)。
const DEVICE_POLL_INTERVAL: i64 = 5;

/// `POST /device_authorization` 请求(RFC 8628 §3.1)。
#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceAuthzRequest {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// 目标 RS(RFC 8707;可省)。
    #[serde(default)]
    pub resource: Option<String>,
}

/// `POST /device_authorization` 响应(RFC 8628 §3.2)。
#[derive(Serialize, utoipa::ToSchema)]
pub struct DeviceAuthzResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// 生成 user_code(8 位;字符集与 `agent_auth_ciba::user_code::USER_CODE_CHARSET` **一致**——评审 F5:
/// 生成集须 ⊆ 校验集,否则批准页 `is_valid_user_code_charset` 会误拒合法生成码)。
fn new_user_code() -> String {
    use rand::Rng;
    let charset = agent_auth_ciba::user_code::USER_CODE_CHARSET.as_bytes();
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

/// `POST /device_authorization`(RFC 8628 §3.1;spec 013 C7b.4)。
#[utoipa::path(
    post, path = "/device_authorization", tag = "device",
    request_body(content = DeviceAuthzRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "device_code + user_code(RFC 8628)", body = DeviceAuthzResponse),
        (status = 400, description = "invalid_request / 未知 client"),
        (status = 404, description = "device flow 未在当前阶段启用")
    )
)]
pub async fn device_authorization_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceAuthzRequest>,
) -> impl IntoResponse {
    // 阶段门控(C1.2:/device_authorization 是 P2 端点)。
    if !agent_auth_protocol::endpoint_available(state.phase, "/device_authorization") {
        return (StatusCode::NOT_FOUND, "device flow 未在当前阶段启用").into_response();
    }
    let Some(issuer) =
        crate::hostutil::issuer_host(&headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response();
    };
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // client 必须存在,且**须 public**——评审 codex/Kiro HIGH:device flow 无 client 认证(轮询只凭
    // client_id 字符串),若放行 confidential/workload,攻击者知其 client_id 即可冒发 device flow 拿该
    // client 名下用户 token。用**规范判定** `client_type()==Public`(与 authorize.rs 的 is_workload 拒
    // 同源):既拒 confidential(须 client 认证,P2 未实现),也拒 workload(机器身份不走用户 3LO,即便
    // auth_method=none 也不放行)。fail-closed。
    match state.clients.get(&tenant, &req.client_id).await {
        Ok(Some(c)) => {
            use agent_auth_workload::ClientType;
            // tombstone 闸(spec 005 §9.3,C10.5):回收中的 client 拒发起 device 授权。
            if c.is_tombstoned() {
                return err(StatusCode::BAD_REQUEST, "invalid_client", "client 已回收")
                    .into_response();
            }
            if c.client_type() != ClientType::Public {
                // unauthorized_client(RFC 6749 §5.2):已知 client 无权用该 grant 类型(与 authorize.rs
                // 对 workload 3LO 的拒绝同码,评审 Kiro LOW-2)。非 invalid_client(那是认证失败语义)。
                return err(
                    StatusCode::BAD_REQUEST,
                    "unauthorized_client",
                    "device flow 仅限 public client;confidential 须 client 认证(未实现)、workload 不走用户授权",
                )
                .into_response();
            }
        }
        Ok(None) => {
            return err(StatusCode::BAD_REQUEST, "invalid_client", "未知 client").into_response()
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response()
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response()
        }
    }

    // 铸码节流(spec 013 Task 2b.3 / 评审 F6):按 client_id 限 device_code 铸造频率,防狂铸撑爆 DeviceTable
    // (现仅 TTL 限生命周期、不限突发)。device flow client 是 public(自称 client_id),此为粗兜底——攻击者
    // 轮换 client_id 归 per-IP/WAF 层管(§3.2);此闸挡单 client_id 存储膨胀。复用 per-client 令牌桶。fail-open。
    if let Some(resp) = crate::ratelimit_gate::check(&state, &tenant, &req.client_id).await {
        return resp;
    }

    let now = crate::token::current_unix_secs_pub();
    let device_code = crate::token::new_jti(&state); // 复用 CSPRNG 不透明串
    let user_code = new_user_code();
    let scope: Vec<String> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let resources: Vec<String> = req.resource.iter().cloned().collect();

    let grant = DeviceAuthGrant {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: req.client_id.clone(),
        user_id: None, // 批准页填
        authz_session_id: None,
        scope,
        resources,
        interval: DEVICE_POLL_INTERVAL,
        last_poll_at: None,
        expires_at: now + DEVICE_CODE_TTL_SECS,
        status: "pending".to_string(),
        consumed: false,
        password_credential_version: None,
    };
    if state.device.put(&tenant, grant).await.is_err() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "存储瞬时不可用",
        )
        .into_response();
    }
    // 主动投影(spec 004 §3.3 / C6.5):device 发起 = AwaitingUserCode(等用户在另一端输码)。哈希 device_code 作键。
    crate::authz_session::emit_flow_projection(
        &state,
        &device_code,
        agent_auth_ciba::CibaState::AwaitingUserCode,
    )
    .await;

    // verification_uri 指向**前端批准页** `/approve`(用户在浏览器打开、输 user_code),不是 API 的
    // `POST /device`(那是页面提交的动作)。统一入口下 issuer = 前端同域(CloudFront),`/approve` 走
    // SPA behavior→S3;页/动作分离与 /consent↔/consent/decision 一致(spec 025 / 013 §2b)。
    let verification_uri = format!("{}/approve", issuer.as_str());
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    Json(DeviceAuthzResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_TTL_SECS,
        interval: DEVICE_POLL_INTERVAL,
    })
    .into_response()
}

/// `/token` 的 `grant_type=device_code` 轮询(RFC 8628 §3.4;spec 013 C7b.4)。
/// `req` 复用 TokenRequest(device_code 走其 `device_code` 字段;client_id 归属校验)。
pub async fn handle_token(
    state: &AppState,
    headers: &HeaderMap,
    req: &crate::token::TokenRequest,
) -> axum::response::Response {
    handle_token_with_clock(state, headers, req, &crate::token::current_unix_secs_pub).await
}

async fn handle_token_with_clock<N>(
    state: &AppState,
    headers: &HeaderMap,
    req: &crate::token::TokenRequest,
    now_fn: &N,
) -> axum::response::Response
where
    N: Fn() -> i64 + ?Sized,
{
    let Some(device_code) = req.device_code.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "缺 device_code").into_response();
    };
    if !state.region.owns_id(device_code) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code belongs to another Region",
        )
        .into_response();
    }
    let Some(client_id) = req.client_id.as_deref() else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "缺 client_id").into_response();
    };
    // tenant 分区(spec 020 §2.3):client/user gate 按 tenant 隔离(device_code 本身高熵不透明,不分区)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let grant = match state.device.get(&tenant, device_code).await {
        Ok(Some(g)) => g,
        // 未知 device_code → invalid_grant(不泄露)。
        Ok(None) => {
            return err(StatusCode::BAD_REQUEST, "invalid_grant", "device_code 无效")
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
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response()
        }
    };

    let now = now_fn();
    let status = match grant.status.as_str() {
        "approved" => PollStatus::Approved,
        "denied" => PollStatus::Denied,
        _ => PollStatus::Pending,
    };
    let outcome = poll_decision(
        grant.client_id == client_id, // 归属:presented client_id == 记录 client_id
        grant.consumed,
        grant.expires_at,
        now,
        grant.last_poll_at,
        grant.interval,
        status,
    );

    // C10.7:device poll 的 form client_id 仍是调用方自报值。只有 artifact 归属验证通过后，
    // 才能用记录中的权威 client_id 消费聚合桶；且必须位于 claim_poll 前，429 不推进轮询槽位。
    if outcome != PollOutcome::InvalidGrant {
        if let Some(response) = crate::ratelimit_gate::check(state, &tenant, &grant.client_id).await
        {
            return response;
        }
    }

    // 原子占用轮询槽位(除非 InvalidGrant——那不推进节流状态)。条件写绑定本次读到的
    // last_poll_at,两个并发 poll 只有一个可继续;过期仍按 poll_decision 的更高优先级返回。
    if outcome != PollOutcome::InvalidGrant {
        match classify_poll_claim(
            outcome,
            state
                .device
                .claim_poll(&tenant, device_code, grant.last_poll_at, now)
                .await,
        ) {
            PollClaimAction::Proceed => {}
            PollClaimAction::SlowDown => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "slow_down",
                    "轮询频率超过 interval",
                )
                .into_response()
            }
            PollClaimAction::TemporarilyUnavailable => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response()
            }
            PollClaimAction::ServerError => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response()
            }
        }
    }

    match outcome {
        PollOutcome::IssueToken => {
            // 已批准 + user_id 填(批准页填);缺 user_id 视为异常 → invalid_grant。
            let Some(user_id) = grant.user_id.clone() else {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "已批准但缺 user_id",
                )
                .into_response();
            };
            // tombstone 闸(spec 005 §9.3,C10.5):poll 签发前**不 reload client**(只比对 client_id 串),
            // 故此处补一次 client tombstone 读——回收中的 client 拒签出 device token(仅签发分支读,不放大每次 poll)。
            match state.clients.get(&tenant, client_id).await {
                Ok(Some(c)) if c.is_tombstoned() => {
                    return err(StatusCode::BAD_REQUEST, "invalid_client", "client 已回收")
                        .into_response()
                }
                Ok(_) => {}
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "存储瞬时不可用",
                    )
                    .into_response()
                }
            }
            // active-user gate(spec 003 §1.4):签发前查 user status——disable/tombstone 后拒签
            // device token(**在 consume 之前**,查询失败/被禁均不 consume,防绕过/防误烧 device_code)。
            // 所有人类 user:* 主体统一过 status gate(含联邦 canonical-user)。
            match crate::user_gate::require_active_user(state, &tenant, &user_id).await {
                crate::user_gate::UserGate::Allowed => {}
                crate::user_gate::UserGate::Blocked => {
                    return err(StatusCode::BAD_REQUEST, "access_denied", "account disabled")
                        .into_response()
                }
                crate::user_gate::UserGate::Unavailable => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "user status 查询失败",
                    )
                    .into_response()
                }
            }
            match crate::user_gate::require_password_authority_version(
                state,
                &tenant,
                &user_id,
                grant.password_credential_version,
            )
            .await
            {
                crate::user_gate::PasswordGate::Allowed => {}
                crate::user_gate::PasswordGate::ChangeRequired => {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "password authority changed after approval",
                    )
                    .into_response()
                }
                crate::user_gate::PasswordGate::Unavailable => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "password authority 查询失败",
                    )
                    .into_response()
                }
            }
            // **先原子消费**(评审 codex/Kiro HIGH F1:device_code 一次性须原子,否则写失败/并发可
            // 重放签出第二个 token)。CAS consumed:false→true;仅赢家(true)继续签,输家(false)判重放。
            let commit_now = now_fn();
            match state.device.consume(&tenant, device_code, commit_now).await {
                Ok(true) => {} // 赢得独占,继续签发
                Ok(false) => {
                    if agent_auth_infra_core::lifecycle::shortlived_is_expired(
                        commit_now,
                        grant.expires_at,
                    ) {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "expired_token",
                            "device_code 已过期",
                        )
                        .into_response();
                    }
                    // 已被消费(重放/并发落败)→ invalid_grant,不签。
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code 已使用",
                    )
                    .into_response();
                }
                Err(crate::ports::StoreError::Transient(_)) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "存储瞬时不可用",
                    )
                    .into_response();
                }
                Err(_) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "存储错误",
                    )
                    .into_response();
                }
            }
            // DPoP 绑定(spec 010 §5.2):有 proof → jkt 写 cnf.jkt;无 → bearer;失败/重放 → 拒 +
            // **释放消费**(bad proof 不应烧掉 device_code,client 修正后可重试)。issuer 由 issue 内派生,
            // 此处用同口径 host→issuer 求 htu。取 client 的 require_dpop(评审 H2:device 也 MUST 尊重,不硬编码
            // false)。**fail-closed(评审复核):store 错误/client 缺失 → 拒 + 释放消费**——不把读失败静默
            // 降级为 require_dpop=false(否则 require_dpop client 在读抖动窗口拿到 bearer,H2 同类绕过)。
            let require_dpop = match state.clients.get(&tenant, &grant.client_id).await {
                Ok(Some(c)) => c.require_dpop,
                Ok(None) => {
                    // client 不存在(理论不该:发起时校过)→ fail-closed 拒 + 释放消费。
                    let _ = state
                        .device
                        .release_consume(&tenant, device_code, now_fn())
                        .await;
                    return err(StatusCode::BAD_REQUEST, "invalid_client", "未知 client")
                        .into_response();
                }
                Err(_) => {
                    let _ = state
                        .device
                        .release_consume(&tenant, device_code, now_fn())
                        .await;
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "存储瞬时不可用",
                    )
                    .into_response();
                }
            };
            let dpop_jkt = match crate::hostutil::issuer_host(headers)
                .and_then(|h| derive_issuer(&h, &state.form).ok())
            {
                Some(iss) => {
                    match crate::dpop::resolve_dpop_binding(
                        state,
                        headers,
                        &tenant,
                        iss.as_str(),
                        require_dpop,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(resp) => {
                            let _ = state
                                .device
                                .release_consume(&tenant, device_code, now_fn())
                                .await;
                            return resp;
                        }
                    }
                }
                None => None,
            };
            let resp =
                issue_device_token(state, headers, &grant, &user_id, dpop_jkt.as_deref(), now)
                    .await;
            // 签名瞬时失败(503):释放消费标记,让客户端可重试(否则该 device_code 被永久烧掉)。
            // **字段级** release_consume(只 consumed→false),不整对象写(评审 codex F1 二轮:整对象
            // 写会用旧快照踩掉并发批准/last_poll_at)。
            if resp.1.is_err() {
                let _ = state
                    .device
                    .release_consume(&tenant, device_code, now_fn())
                    .await;
            } else {
                // 签发成功 → 记 client 最后使用日(spec 005 §9.2,C10.5)+ 主动投影 Complete(C6.5)。
                crate::token::touch_client_last_used(state, &tenant, client_id, now).await;
                crate::authz_session::emit_flow_projection(
                    state,
                    device_code,
                    agent_auth_ciba::CibaState::Complete,
                )
                .await;
            }
            resp.0
        }
        other => {
            let code = other.error_code().unwrap_or("invalid_grant");
            // RFC 8628:轮询错误用 400 + 标准 error code(slow_down/authorization_pending 亦 400)。
            err(StatusCode::BAD_REQUEST, code, "device 轮询").into_response()
        }
    }
}

/// 签 device 批准后的 3LO access token(sub=用户、sub_type=user)。返回 (响应, 是否成功签发)。
#[allow(clippy::too_many_arguments)]
async fn issue_device_token(
    state: &AppState,
    headers: &HeaderMap,
    grant: &DeviceAuthGrant,
    user_id: &str,
    cnf_jkt: Option<&str>, // DPoP 绑定(spec 010 §5.2);None=bearer
    now: i64,
) -> (axum::response::Response, Result<(), ()>) {
    // tenant 分区(spec 020 §2.3):Grant 落库按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return (resp, Err(())),
    };
    let credential_epoch = match crate::user_gate::active_user_epoch(state, &tenant, user_id).await
    {
        Ok(epoch) => epoch,
        Err(crate::user_gate::UserGate::Blocked) => {
            return (
                err(StatusCode::BAD_REQUEST, "invalid_grant", "account disabled").into_response(),
                Err(()),
            )
        }
        Err(_) => {
            return (
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "user status 查询失败",
                )
                .into_response(),
                Err(()),
            )
        }
    };
    let issuer = match crate::hostutil::issuer_host(headers)
        .and_then(|h| derive_issuer(&h, &state.form).ok())
    {
        Some(i) => i,
        None => {
            return (
                err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response(),
                Err(()),
            )
        }
    };
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("device-token"),
    )
    .await
    {
        return (
            err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "issuer does not belong to tenant",
            )
            .into_response(),
            Err(()),
        );
    }
    // aud:device grant 的单值 resource(有则)否则 /userinfo。scope=授权集合。
    let aud = match grant.resources.first() {
        Some(r) => r.clone(),
        None => format!("{}/userinfo", issuer.as_str()),
    };
    // sub:按形态派生(pairwise 用 aud sector;public=user_id)。
    let mode = crate::token::subject_mode(state.subject_type_for_tenant(&tenant));
    let sub = agent_auth_token::derive_user_sub(mode, &state.server_secret, user_id, &aud);
    let scope_str = grant.scope.join(" ");
    let jti = crate::token::new_jti(state);
    // Grant 接入(spec 011 §5.1 / 013;device 同 3LO,DESIGN §5.1)。grant_id **签名前生成**(作 auth_grant
    // claim,令 token 可经 /grants 列/吊销 + introspect 反映吊销);Grant **签名成功后落库**(评审 MEDIUM 时序:
    // 防签名 503 重试造孤儿 Grant)。有效期=access TTL(评审 MEDIUM:device 无 refresh 续期,Grant 不宜挂 30 天
    // 僵尸)。actor_allowlist=[](评审 LOW:纯 3LO 无委托源,不用 migration_constraints 的 [client_id])。
    let grant_id = crate::refresh_flow::new_family_id(state);
    if let Some(response) = crate::ratelimit_gate::kms_sign_tenant_gate(state, &tenant).await {
        return (response, Err(()));
    }
    if let Some(response) = crate::ratelimit_gate::kms_sign_gate(state).await {
        return (response, Err(()));
    }
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => return (response, Err(())),
    };
    let jwt = match sign_tenant_access_token(
        state,
        headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: issuer.as_str(),
            sub: &sub,
            aud: &aud,
            client_id: &grant.client_id,
            scope: &scope_str,
            jti: &jti,
            auth_grant: &grant_id, // 稳定 grant_id(introspect/`/grants` 据此定位吊销)
            sub_type: SubType::User, // device flow = 3LO 用户
            authorization_details: &[], // device flow 暂不接受 RAR 参数(spec 010 §4 仅 code flow 发行)
            cnf_jkt,
            auth_time: None,
            acr: None,
            now,
        },
        crate::security_event::SecurityActor::system("device-token"),
    )
    .await
    {
        Ok(j) => j,
        Err(crate::token::TokenSignError::Transient) => {
            return (
                crate::token::err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "签名瞬时失败,请重试",
                    1,
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            return (
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            return (
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "issuer does not belong to tenant",
                )
                .into_response(),
                Err(()),
            )
        }
        Err(crate::token::TokenSignError::Permanent) => {
            return (
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "签名失败",
                )
                .into_response(),
                Err(()),
            )
        }
    };
    // Grant 落库(签名成功后)。**fail-closed**(评审 HIGH:device 无 family/refresh 兜底,建 Grant 失败
    // 则 token 天生不可吊销/introspect 恒 active → 绝不签出;调用方 release_consume 后可重试,重生 grant_id)。
    let mut device_grant = agent_auth_grant::Grant {
        grant_id: grant_id.clone(),
        user_id: user_id.to_string(),
        client_id: grant.client_id.clone(),
        per_resource: grant
            .resources
            .iter()
            .map(|r| agent_auth_grant::ResourceGrant {
                resource: r.clone(),
                scopes: grant.scope.clone(),
                authorization_details: vec![],
            })
            .collect(),
        // effective/pv/ip/revision:flag 关默认空(spec 005 §7);flag 开由 apply_policy_to_grant 填(T7.5)。
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch,
        revision: 0,
        constraints: agent_auth_grant::GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![], // 纯 3LO,不授委托(空集 fail-closed)
            expires_at: now + crate::token::ACCESS_TTL, // 与 token 同生共死(无 refresh 续期)
        },
        status: agent_auth_grant::GrantStatus::Active,
    };
    // T7.5:flag 开则 Cedar 预判收窄 effective + 打 pv 戳。fail-closed 分档(补强 ⑯):Transient(工件缺失/坏/
    // store 瞬时)→ 503 可重试;Denied(有可评估单元被策略全 deny)→ 403 access_denied 永久拒(重试无用)。flag 关 no-op。
    if let Err(e) =
        crate::authz_gate::apply_policy_to_grant(state, &tenant, &mut device_grant).await
    {
        eprintln!("[authz] device Grant 策略预判失败(fail-closed):{e}");
        let resp = match e {
            crate::authz_gate::ApplyPolicyError::Denied(_) => {
                state
                    .record_security_event(crate::security_event::SecurityEventDraft::grant(
                        &tenant,
                        crate::security_event::SecurityActor::user(user_id),
                        &grant_id,
                        crate::security_event::GrantAction::Deny,
                        crate::security_event::SecurityEventOutcome::Denied,
                    ))
                    .await;
                err(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "授权被策略拒绝(policy denies requested access)",
                )
            }
            crate::authz_gate::ApplyPolicyError::Transient(_) => err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "授权策略暂不可用,请重试",
            ),
        };
        return (resp.into_response(), Err(()));
    }
    if !matches!(
        state
            .put_grant_for_client(&tenant, device_grant, true)
            .await,
        Ok(true)
    ) {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::grant(
                &tenant,
                crate::security_event::SecurityActor::user(user_id),
                &grant_id,
                crate::security_event::GrantAction::Create,
                crate::security_event::SecurityEventOutcome::Failure,
            ))
            .await;
        return (
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "授权记录落库失败,请重试",
            )
            .into_response(),
            Err(()), // 调用方据此 release_consume,客户端重试重生 grant_id
        );
    }
    state
        .record_security_event(crate::security_event::SecurityEventDraft::grant(
            &tenant,
            crate::security_event::SecurityActor::user(user_id),
            &grant_id,
            crate::security_event::GrantAction::Create,
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;
    match crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        user_id,
        grant.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        authority => {
            let cleanup_ok = crate::grants::revoke_with_audit(
                state,
                &tenant,
                crate::security_event::SecurityActor::system("device-token"),
                &grant_id,
            )
            .await;
            let response = match (authority, cleanup_ok) {
                (crate::user_gate::PasswordGate::ChangeRequired, true) => err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "password authority changed during token issuance",
                ),
                _ => err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "password authority verification failed",
                ),
            };
            return (response.into_response(), Err(()));
        }
    }
    if crate::user_gate::require_active_user_epoch(state, &tenant, user_id, credential_epoch)
        .await
        .is_err()
    {
        crate::grants::revoke_with_audit(
            state,
            &tenant,
            crate::security_event::SecurityActor::system("device-token"),
            &grant_id,
        )
        .await;
        return (
            err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "user lifecycle changed during token issuance",
            )
            .into_response(),
            Err(()),
        );
    }
    (
        Json(TokenResponse {
            access_token: jwt,
            token_type: crate::token::token_type_for(cnf_jkt),
            expires_in: crate::token::ACCESS_TTL,
            scope: (!scope_str.is_empty()).then_some(scope_str),
            refresh_token: None, // device flow P2 先不发 refresh(简化;后续可补)
            id_token: None,
            resource: None,
        })
        .into_response(),
        Ok(()),
    )
}

/// device 批准动作(spec 013 §2b):按 user_code 定位 + 校当前登录 user + approve/deny。
/// 供批准页 handler 调用(此处提供纯装配便于测试;真页面在后续增量)。
pub async fn approve_by_user_code(
    state: &AppState,
    tenant: &str,
    user_code_input: &str,
    approving_user_id: &str,
    approve: bool,
) -> Result<(), &'static str> {
    approve_by_user_code_with_clock(
        state,
        tenant,
        user_code_input,
        approving_user_id,
        approve,
        &crate::token::current_unix_secs_pub,
    )
    .await
}

async fn approve_by_user_code_with_clock<N>(
    state: &AppState,
    tenant: &str,
    user_code_input: &str,
    approving_user_id: &str,
    approve: bool,
    now_fn: &N,
) -> Result<(), &'static str>
where
    N: Fn() -> i64 + ?Sized,
{
    let canon = canonicalize_user_code(user_code_input);
    // user_code 在**本租户分区**内查(评审 codex Medium:8 位短码跨租户碰撞,MUST tenant-scope)。
    let Some(grant) = state
        .device
        .get_by_user_code(tenant, &canon)
        .await
        .map_err(|_| "store")?
    else {
        return Err("unknown user_code");
    };
    if !state.region.owns_id(&grant.device_code) {
        return Err("wrong Region activation");
    }
    let now = now_fn();
    if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, grant.expires_at) {
        return Err("expired");
    }
    if grant.status != "pending" {
        return Err("already decided");
    }
    let password_credential_version = if approve {
        crate::user_gate::password_authority_snapshot(state, tenant, approving_user_id)
            .await
            .map_err(|gate| match gate {
                crate::user_gate::PasswordGate::ChangeRequired => "password change required",
                _ => "store",
            })?
    } else {
        None
    };
    // **原子** CAS(评审 codex F1 二轮):不读改整对象写回(旧快照会重开已消费的 device_code),
    // 而是条件写 status:pending→(approved|denied) + 填 user_id,绝不触碰 consumed/last_poll_at。
    // decide 返 false = 期间已被并发决定(TOCTOU 落败)→ already decided。
    let commit_now = now_fn();
    match state
        .device
        .decide(
            tenant,
            &grant.device_code,
            approving_user_id,
            password_credential_version,
            approve,
            commit_now,
        )
        .await
        .map_err(|_| "store")?
    {
        true => {
            // 主动投影(spec 004 §3.3 / C6.5):批准→ApprovedAwaitingPoll;拒→Denied。哈希 device_code 作键。
            let st = if approve {
                agent_auth_ciba::CibaState::ApprovedAwaitingPoll
            } else {
                agent_auth_ciba::CibaState::Denied
            };
            crate::authz_session::emit_flow_projection(state, &grant.device_code, st).await;
            if !approve {
                let operation_id =
                    crate::authz_session::flow_credential_fingerprint(state, &grant.device_code);
                state
                    .record_security_event(crate::security_event::SecurityEventDraft::grant_denial(
                        tenant,
                        crate::security_event::SecurityActor::user(approving_user_id),
                        &grant.client_id,
                        &operation_id,
                    ))
                    .await;
            }
            Ok(())
        }
        false
            if agent_auth_infra_core::lifecycle::shortlived_is_expired(
                commit_now,
                grant.expires_at,
            ) =>
        {
            Err("expired")
        }
        false => Err("already decided"),
    }
}

/// device 批准动作请求体(用户在浏览器输入 user_code + approve/deny)。
#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceApproveRequest {
    /// 用户在另一设备看到的短码(规范化前原样,内部 canonicalize)。
    pub user_code: String,
    pub approve: bool,
}

/// `POST /device`(spec 013 §2b):**已登录用户**输入 user_code 批准/拒绝 device 授权。
/// 批准者 = 当前登录 user;approve 后其 user_id 填入 grant(device grant token 的 sub 源)。
/// **不做 IDOR 归属校**(device grant 建档时无 user_id,由批准者认领)——但**须已登录**(防匿名批准),
/// 且 user_code 高熵短命一次性(user_code→device_code 主防线是 device_code 128-bit;user_code 尝试限流
/// 见 2b.3 backlog)。CSRF 靠 session cookie SameSite=Lax。
#[utoipa::path(
    post, path = "/device", tag = "device",
    request_body(content = DeviceApproveRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 204, description = "已批准/拒绝"),
        (status = 401, description = "未登录"),
        (status = 404, description = "user_code 无效/不可批准")
    )
)]
pub async fn device_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<DeviceApproveRequest>,
) -> axum::response::Response {
    let user = match require_login(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // tenant 分区(spec 020 §2.3,评审 codex Medium):user_code 在本租户内定位,绝不跨租户批准
    // 他租户 device 请求(flag 关=空 tenant;控制面 Host→400)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // user_code **尝试限流**(spec 013 Task 2b.3,防爆破枚举):按批准者(登录 user)令牌桶限提交频率。
    // user_code 是 8 位短码(user_code::USER_CODE_CHARSET 20 字符 → 20^8 空间),device_code 128-bit 是主
    // 防线,但 user_code 提交面须限爆破。正常批准仅 1-2 次提交,桶容量 5/补充 0.1/s 足够;枚举脚本被挡。
    // 键 `devcode-attempt:{user}` 与其它桶隔离。fail-open(anti-abuse 优先可用性)。
    if crate::ratelimit_gate::user_code_attempt_throttled(&state, &tenant, &user).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "10".to_string())],
            "尝试过于频繁,请稍候(防 user_code 爆破,2b.3)",
        )
            .into_response();
    }
    match approve_by_user_code(&state, &tenant, &body.user_code, &user, body.approve).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        // unknown/expired/already decided 一律 404(不泄露具体原因)。
        Err(_) => (StatusCode::NOT_FOUND, "user_code 无效或不可批准").into_response(),
    }
}

/// 批准端点登录鉴权(P2 门控 + 会话)。返回当前登录 user_id。
async fn require_login(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, axum::response::Response> {
    if !agent_auth_protocol::endpoint_available(state.phase, "/device_authorization") {
        return Err((StatusCode::NOT_FOUND, "").into_response());
    }
    match crate::login::current_session(state, headers).await {
        Some((_sid, user_id)) => Ok(user_id),
        None => Err((StatusCode::UNAUTHORIZED, "需登录(无有效会话)").into_response()),
    }
}

pub fn router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::router::OpenApiRouter;
    OpenApiRouter::new()
        .merge(protocol_router())
        .merge(approve_router())
}

/// 协议 POST 端点(`/device_authorization`):device flow client 铸码,**不带浏览器 cookie**
/// (靠 client_id + 后续 device_code 轮询),CORS 分类②(`Allow-Origin: *`,C10.10)。
pub fn protocol_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::{router::OpenApiRouter, routes};
    OpenApiRouter::new().routes(routes!(device_authorization_handler))
}

/// 批准端点(`POST /device`):**登录会话 cookie 鉴权**(current_session),CORS 分类④会话端点
/// (不发 CORS 头、拒跨域,防 CSRF;统一入口下前端同源,C10.10)。
pub fn approve_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::{router::OpenApiRouter, routes};
    OpenApiRouter::new().routes(routes!(device_approve))
}

#[cfg(test)]
mod tests {
    use super::{approve_by_user_code_with_clock, handle_token_with_clock, DEVICE_CODE_GRANT};
    use crate::ports::{DeviceAuthGrant, DeviceStore};
    use crate::{AppState, Phase};
    use axum::body::to_bytes;
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn device_request(device_code: &str, client_id: &str) -> crate::token::TokenRequest {
        crate::token::TokenRequest {
            grant_type: DEVICE_CODE_GRANT.into(),
            code: None,
            code_verifier: None,
            redirect_uri: None,
            client_id: Some(client_id.into()),
            client_secret: None,
            resource: None,
            refresh_token: None,
            scope: None,
            client_assertion: None,
            client_assertion_type: None,
            assertion: None,
            authorization_details: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            device_code: Some(device_code.into()),
            auth_req_id: None,
            grant_ref: None,
        }
    }

    #[tokio::test]
    async fn token_commit_resamples_expiry_after_async_gates() {
        let mut state = AppState::dev("localhost");
        state.phase = Phase::P2;
        state
            .seed_dev_client("device-client", "http://127.0.0.1/cb", None)
            .await;
        state
            .device
            .put(
                "",
                DeviceAuthGrant {
                    device_code: "device-at-expiry".into(),
                    user_code: "EXPIRY01".into(),
                    client_id: "device-client".into(),
                    user_id: Some("alice".into()),
                    authz_session_id: None,
                    scope: vec!["openid".into()],
                    resources: vec![],
                    interval: 5,
                    last_poll_at: None,
                    expires_at: 1_000,
                    status: "approved".into(),
                    consumed: false,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
        let calls = AtomicUsize::new(0);
        let clock = || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                999
            } else {
                1_000
            }
        };

        let response = handle_token_with_clock(
            &state,
            &headers,
            &device_request("device-at-expiry", "device-client"),
            &clock,
        )
        .await;
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "expired_token");
        assert!(
            !state
                .device
                .get("", "device-at-expiry")
                .await
                .unwrap()
                .unwrap()
                .consumed
        );
    }

    #[tokio::test]
    async fn approval_commit_resamples_expiry_after_async_gates() {
        let state = AppState::dev("localhost");
        state
            .device
            .put(
                "",
                DeviceAuthGrant {
                    device_code: "device-approval-at-expiry".into(),
                    user_code: "EXPIRY02".into(),
                    client_id: "device-client".into(),
                    user_id: None,
                    authz_session_id: None,
                    scope: vec!["openid".into()],
                    resources: vec![],
                    interval: 5,
                    last_poll_at: None,
                    expires_at: 1_000,
                    status: "pending".into(),
                    consumed: false,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        let calls = AtomicUsize::new(0);
        let clock = || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                999
            } else {
                1_000
            }
        };

        let result =
            approve_by_user_code_with_clock(&state, "", "EXPIRY02", "alice", true, &clock).await;
        let grant = state
            .device
            .get("", "device-approval-at-expiry")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result, Err("expired"));
        assert_eq!(grant.status, "pending");
        assert_eq!(grant.user_id, None);
        assert_eq!(grant.password_credential_version, None);
        assert!(!grant.consumed);
    }
}
