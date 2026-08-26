//! `POST /token` 的 `refresh_token` grant(C3:rotation + 复用检测 + 下采样)。
//!
//! 编排 token crate 的 `RefreshFamily` 语义 + RefreshStore 的原子 rotation:
//! - 解析 refresh token → family_id + presented_version;
//! - `RefreshFamily::consume(presented)`:呈现当前版本 → Rotated(签新 access + 新 refresh、版本+1);
//!   呈现旧版本 → ReuseDetectedRevokeFamily(全链吊销,C3.1);已吊销 → AlreadyRevoked;
//! - 下采样(C3.6):refresh 可带 `resource` 收窄到授权集合内某单值;rotation **保整个集合**;
//! - access token 恒 ES256、aud 单元素(复用 token.rs 的 delivery-aware signer)。
//!
//! 复用检测的库侧原子性靠 `RefreshStore::rotate`(条件写 CAS):仅当版本匹配才推进;不匹配 =
//! 被并发轮换过或呈现旧值 → 按复用处理(吊销 family)。宽限窗(C3.2)指纹判定属 spec 001,P0 从简。

use std::future::Future;

use agent_auth_protocol::{
    select_audience, AudienceSelection, AuthorizePhase, AuthorizedResources, ClientRegistration,
};
use agent_auth_token::{
    fingerprint, ConsumeOutcome, GraceIdentity, GraceRequest, RefreshFamily, SubType,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

use crate::ports::{
    ClientStore, GraceStore, GrantStore, JtiStore, RefreshLeaseAcquire, RefreshStore,
};
use crate::state::AppState;
use crate::token::{
    err, host_from_headers, invalid_client_response, AccessTokenClaims, TokenRequest,
    TokenResponse, ACCESS_TTL,
};
use agent_auth_discovery::derive_issuer;

const GRANT_BACKED_RAR_FAMILY_MARKER: &str = "gbr1~";
const REFRESH_LEASE_TTL_SECS: i64 = 30;

/// 生成新 family_id(CSPRNG)。
pub fn new_family_id(state: &AppState) -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    state.region.issue_id(URL_SAFE_NO_PAD.encode(b))
}

pub(crate) fn new_grant_backed_rar_family_id(state: &AppState) -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    state.region.issue_id(format!(
        "{GRANT_BACKED_RAR_FAMILY_MARKER}{}",
        URL_SAFE_NO_PAD.encode(b)
    ))
}

pub(crate) fn requires_grant_backed_rar(family_id: &str) -> bool {
    family_id
        .split('_')
        .any(|segment| segment.starts_with(GRANT_BACKED_RAR_FAMILY_MARKER))
}

/// refresh token 编码:`family_id.version`(不透明给客户端;服务端解析出 family+version)。
pub fn encode_refresh(family_id: &str, version: u64) -> String {
    format!("{family_id}.{version}")
}

/// 解析 refresh token → (family_id, version)。
pub(crate) fn decode_refresh(token: &str) -> Option<(String, u64)> {
    let (fam, ver) = token.rsplit_once('.')?;
    let v: u64 = ver.parse().ok()?;
    (!fam.is_empty()).then(|| (fam.to_string(), v))
}

struct PreparedRefresh {
    family_id: String,
    presented_version: u64,
}

enum PrepareError {
    MissingToken,
    InvalidToken,
    WrongRegion,
}

impl PrepareError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::MissingToken => err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺 refresh_token",
            ),
            Self::InvalidToken => err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 格式非法",
            ),
            Self::WrongRegion => err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token belongs to another Region",
            ),
        }
        .into_response()
    }
}

fn prepare(state: &AppState, req: &TokenRequest) -> Result<PreparedRefresh, PrepareError> {
    let Some(refresh) = req.refresh_token.as_deref() else {
        return Err(PrepareError::MissingToken);
    };
    let Some((family_id, presented_version)) = decode_refresh(refresh) else {
        return Err(PrepareError::InvalidToken);
    };
    if !state.region.owns_id(&family_id) {
        return Err(PrepareError::WrongRegion);
    }
    Ok(PreparedRefresh {
        family_id,
        presented_version,
    })
}

/// 处理 refresh_token grant。
///
/// Keep parsing and Region ownership validation outside the async state
/// machine, then pass owned context through bounded async stages. AWS adapter
/// variants otherwise make the monolithic poll path deep enough to exhaust
/// Rust's default test-thread stack.
pub fn handle<'a>(
    state: &'a AppState,
    headers: &'a HeaderMap,
    req: &'a TokenRequest,
) -> impl Future<Output = axum::response::Response> + 'a {
    let prepared = prepare(state, req);
    async move {
        let PreparedRefresh {
            family_id,
            presented_version,
        } = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return error.into_response(),
        };
        let authenticated =
            match load_authenticated(state, headers, req, family_id, presented_version).await {
                Ok(authenticated) => authenticated,
                Err(response) => return *response,
            };
        let gated = match run_account_gates(state, headers, authenticated).await {
            Ok(gated) => gated,
            Err(response) => return *response,
        };
        let validated = match prepare_issuance(state, headers, req, gated).await {
            Ok(validated) => validated,
            Err(response) => return *response,
        };
        let leased = match acquire_validated(state, validated).await {
            Ok(leased) => leased,
            Err(response) => return *response,
        };
        issue_leased(state, leased).await
    }
}

struct AuthenticatedRefresh {
    tenant: String,
    family_id: String,
    presented_version: u64,
    fam_rec: crate::ports::RefreshFamilyRecord,
    client: crate::ports::ClientRecord,
    presented_client_id: String,
}

type RefreshStageResult<T> = Result<T, Box<Response>>;

fn reject<T>(response: Response) -> RefreshStageResult<T> {
    Err(Box::new(response))
}

#[derive(Clone, Copy)]
enum ReuseCleanupError {
    Transient,
    Permanent,
}

fn classify_cleanup_error(
    current: Option<ReuseCleanupError>,
    error: crate::ports::StoreError,
) -> Option<ReuseCleanupError> {
    match (current, error) {
        (_, crate::ports::StoreError::Permanent(_)) => Some(ReuseCleanupError::Permanent),
        (Some(ReuseCleanupError::Permanent), _) => Some(ReuseCleanupError::Permanent),
        (_, crate::ports::StoreError::Transient(_)) => Some(ReuseCleanupError::Transient),
    }
}

async fn revoke_family_and_delete_grace(
    state: &AppState,
    tenant: &str,
    family_id: &str,
) -> Result<(), ReuseCleanupError> {
    let mut failure = None;
    if let Err(error) = state.refresh.revoke(tenant, family_id).await {
        failure = classify_cleanup_error(failure, error);
    }
    if let Some(grace) = &state.grace {
        if let Err(error) = grace.delete_family(family_id).await {
            failure = classify_cleanup_error(failure, error);
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn reuse_cleanup_failure(error: ReuseCleanupError) -> Response {
    match error {
        ReuseCleanupError::Transient => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "refresh family 吊销或宽限缓存清理暂时失败,请重试",
        ),
        ReuseCleanupError::Permanent => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "refresh family 吊销或宽限缓存清理失败",
        ),
    }
    .into_response()
}

async fn load_authenticated(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    family_id: String,
    presented_version: u64,
) -> RefreshStageResult<AuthenticatedRefresh> {
    // tenant 分区(spec 020 §2.3):从入站 Host 派生,贯穿 refresh/client/grant 全链(flag 关=空)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return Err(Box::new(resp)),
    };

    // 取 family。
    let fam_rec = match state.refresh.get(&tenant, &family_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Err(Box::new(
                err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh 无效").into_response(),
            ))
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return Err(Box::new(
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                )
                .into_response(),
            ))
        }
        Err(_) => {
            return Err(Box::new(
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response(),
            ))
        }
    };

    // RFC 6749 §6:Basic username、form client_id 或 assertion 均可呈现 client 身份；
    // 多处同时存在时须一致。先认证该呈现身份，再比较 family owner，避免把一个已认证
    // client 对其他 client refresh token 的使用错误映射成 invalid_client。
    let presented_client_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        headers,
        req.client_assertion.as_deref(),
    ) {
        Ok(Some(client_id)) => client_id,
        Err(_) => {
            return Err(Box::new(invalid_client_response(
                headers,
                StatusCode::UNAUTHORIZED,
                "client identity sources do not match",
            )));
        }
        Ok(None) => {
            return Err(Box::new(invalid_client_response(
                headers,
                StatusCode::UNAUTHORIZED,
                "refresh grant 缺 client_id",
            )));
        }
    };
    let is_family_owner = presented_client_id == fam_rec.client_id;

    // 客户端认证策略继承首签 authority。CIMD family 永远使用 code-bound 快照；
    // 预注册/DCR family 继续强读 ClientStore，使控制面生命周期变更即时生效。
    let client = if is_family_owner {
        match fam_rec.cimd_snapshot.as_ref() {
            Some(snapshot) if snapshot.client_id == fam_rec.client_id => {
                snapshot.as_client_record()
            }
            Some(_) => {
                return Err(Box::new(
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "refresh family client metadata is inconsistent",
                    )
                    .into_response(),
                ))
            }
            None => match state.clients.get(&tenant, &presented_client_id).await {
                Ok(Some(client)) => client,
                Ok(None) => {
                    return Err(Box::new(invalid_client_response(
                        headers,
                        StatusCode::BAD_REQUEST,
                        "unknown client",
                    )))
                }
                Err(crate::ports::StoreError::Transient(_)) => {
                    return Err(Box::new(
                        err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "client store unavailable",
                        )
                        .into_response(),
                    ))
                }
                Err(_) => {
                    return Err(Box::new(
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "client store error",
                        )
                        .into_response(),
                    ))
                }
            },
        }
    } else {
        match state.clients.get(&tenant, &presented_client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return Err(Box::new(invalid_client_response(
                    headers,
                    StatusCode::BAD_REQUEST,
                    "unknown client",
                )))
            }
            Err(crate::ports::StoreError::Transient(_)) => {
                return Err(Box::new(
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "client store unavailable",
                    )
                    .into_response(),
                ))
            }
            Err(_) => {
                return Err(Box::new(
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "client store error",
                    )
                    .into_response(),
                ))
            }
        }
    };
    // tombstone 闸(spec 005 §9.3,C10.5):回收中的 client 拒 refresh 换新 access。
    if client.is_tombstoned() {
        return Err(Box::new(invalid_client_response(
            headers,
            StatusCode::BAD_REQUEST,
            "client 已回收",
        )));
    }
    let audit_identifier = if is_family_owner {
        fam_rec
            .cimd_snapshot
            .as_ref()
            .map(crate::cimd::CimdClientSnapshot::audit_identifier)
            .unwrap_or_else(|| client.client_id.clone())
    } else {
        client.client_id.clone()
    };
    let client = match crate::client_auth::authenticate_loaded_snapshot_with_audit_identifier(
        state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Token,
        &client,
        headers,
        crate::client_auth::PresentedClientAuth::new(
            req.client_secret.as_deref(),
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
        ),
        &audit_identifier,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            let response = match error {
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::ServerMisconfigured => err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidRequest(_) => err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    error.description(),
                )
                .into_response(),
                crate::client_auth::ClientAuthError::InvalidClient(_) => {
                    invalid_client_response(headers, StatusCode::UNAUTHORIZED, error.description())
                }
            };
            return Err(Box::new(response));
        }
    };
    if !is_family_owner {
        if presented_version < fam_rec.current_version {
            if let Err(error) = revoke_family_and_delete_grace(state, &tenant, &family_id).await {
                return Err(Box::new(reuse_cleanup_failure(error)));
            }
        }
        return Err(Box::new(
            err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token was not issued to the authenticated client",
            )
            .into_response(),
        ));
    }

    Ok(AuthenticatedRefresh {
        tenant,
        family_id,
        presented_version,
        fam_rec,
        client,
        presented_client_id,
    })
}

struct ValidatedRefresh {
    headers: HeaderMap,
    tenant: String,
    family_id: String,
    presented_version: u64,
    fam_rec: crate::ports::RefreshFamilyRecord,
    now: i64,
    source_grant: Option<agent_auth_grant::Grant>,
    issuer: String,
    aud: String,
    access_sub: String,
    granted_scopes: Vec<String>,
    cnf_jkt: Option<String>,
    req_fp: [u8; 32],
    req_identity: GraceIdentity,
}

struct GatedRefresh {
    tenant: String,
    family_id: String,
    presented_version: u64,
    fam_rec: crate::ports::RefreshFamilyRecord,
    client: crate::ports::ClientRecord,
    presented_client_id: String,
    now: i64,
    source_grant: Option<agent_auth_grant::Grant>,
}

async fn run_account_gates(
    state: &AppState,
    headers: &HeaderMap,
    authenticated: AuthenticatedRefresh,
) -> RefreshStageResult<GatedRefresh> {
    let AuthenticatedRefresh {
        tenant,
        family_id,
        presented_version,
        fam_rec,
        client,
        presented_client_id,
    } = authenticated;

    // per-client 应用层限流(C10.7 / spec 005 §3.1):**认证后**按 `fam_rec.client_id`(不可伪造——client
    // 已过 verify_client_auth,或 public client 绑定 family)限流。评审 HIGH#2:限流键必须是认证后主体,
    // 不用未认证 form client_id(防打他人桶 DoS 放大)。
    // fail-open:store 未配/瞬时错误→放行(anti-abuse 优先可用性,非安全闸;与 CIBA 节流 C7b.6 一致)。
    if let Some(resp) = crate::ratelimit_gate::check(state, &tenant, &fam_rec.client_id).await {
        return reject(resp);
    }

    let now = crate::token::current_unix_secs_pub();

    // **Grant status 联查(spec 020 §5.3 / C11.2,codex+Kiro 双评审收敛)**:refresh 校验 MUST 不只看
    // 本地 refresh 表 `fam_rec.revoked`,还要**联查身份表 Grant 的最新 status**(双源 AND,与 token-exchange
    // 同口径)。价值(**单区域即成立**,非纯 P3):①`/grants` DELETE 在 cleanup 失败时返回可重试错误，
    // 但 Grant 状态写与 family 标记之间仍存在短窗——联查 Grant 独立堵住该窗;②Grant 有效期
    // (constraints.expires_at)refresh 无独立闸,联查是唯一执行点;③admin/策略引擎
    // 直改 Grant.status 的兜底。多区域(P3)只是让此联查跨区成立(Grant 表 Global Tables 复制 + 复制延迟窗)。
    // 兼容:有 grant_id(=family_id,迁移不变式)→ 联查 `is_usable`,不 usable 拒;无 Grant(老 family/
    // Grant 创建失败)→ 回退只看 fam.revoked(不因无 Grant 拒,后向兼容)。联查瞬时失败 → **fail-closed 503**
    // (与 token-exchange 一致:口径统一防 downgrade 面;Grant 吊销 MUST NOT 因 store 抖动被绕过)。
    // 置于 consume/CAS **之前**(read gate:503/拒不改任何状态,client 可安全重试)。
    // 捕获 Grant 供后续 RAR 透传(spec 010 §4:refresh 换发的新 token MUST 带源 Grant 该 resource 的
    // authorization_details,否则续期静默剥离 RAR = 比源 Grant 权限更宽 = 扩权,违反 DESIGN §5.2:510)。
    let grant_backed_rar_required = requires_grant_backed_rar(&family_id);
    let source_grant: Option<agent_auth_grant::Grant> =
        match state.grants.get(&tenant, &family_id).await {
            Ok(Some(grant)) => {
                if grant.is_usable(now).is_err() {
                    return reject(
                        err(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "源 Grant 已吊销或过期",
                        )
                        .into_response(),
                    );
                }
                Some(grant)
            }
            Ok(None) if grant_backed_rar_required => {
                return reject(
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Grant-backed refresh family 缺少权威 Grant",
                    )
                    .into_response(),
                )
            }
            Ok(None) => None, // 无 Grant:老 family / Grant 创建失败 → 回退 fam.revoked(后向兼容)
            Err(crate::ports::StoreError::Transient(_)) => {
                // 联查瞬时失败 fail-closed(不放过可能已吊销的 Grant;refresh 503 可重试、不改状态)。
                return reject(
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "Grant 状态存储瞬时不可用,请重试",
                    )
                    .into_response(),
                );
            }
            Err(_) if grant_backed_rar_required => {
                return reject(
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "Grant-backed refresh family 无法读取权威 Grant",
                    )
                    .into_response(),
                )
            }
            Err(_) => None, // 永久错误:旧 family 降级为无 Grant(后向兼容)
        };

    // T7.4 热路径 fail-safe 闸(C10.17):源 Grant 若 policy stale → 503 拒(不续超策略 token);ip/vpc 不匹配
    // → access_denied。置于 consume/rotate **之前**(read-gate:503/拒不改状态可重试)。flag 关 no-op;零 Cedar。
    // 无 Grant(老 family 回退)不 gate。refresh 换发经 source_grant.resource_grant 读 effective_view(T2 已迁)。
    if let Some(g) = &source_grant {
        if let Err(resp) =
            crate::policy_freshness::stale_gate(state, &tenant, g, headers, now).await
        {
            return reject(resp);
        }
    }

    // **active-user gate(评审 codex High,spec 003 §1.4)**:refresh 是"签用户 token"入口——disable/
    // tombstone 后 MUST 拒续期。级联 `revoke_by_user` 已标 family.revoked,但**状态置位在级联之前**:
    // 若级联失败(→503,admin 未重试)则 status=Disabled 而 family 仍活,只靠 fam.revoked 会漏——gate
    // 是独立第二道闸(与 Grant 联查同为 read-gate,置 consume/rotate 之前:被禁/查询失败 fail-closed
    // 不改任何状态,client 可重试)。人类 user:* 均 gate,含联邦 canonical-user。
    match crate::user_gate::require_active_user_epoch(
        state,
        &tenant,
        &fam_rec.user_id,
        fam_rec.credential_epoch,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::user_gate::UserGate::Blocked) => {
            return reject(
                err(StatusCode::BAD_REQUEST, "invalid_grant", "account disabled").into_response(),
            )
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            return reject(
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "user status 查询失败",
                )
                .into_response(),
            )
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    }
    match crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        &fam_rec.user_id,
        fam_rec.password_credential_version,
    )
    .await
    {
        crate::user_gate::PasswordGate::Allowed => {}
        crate::user_gate::PasswordGate::ChangeRequired => {
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "password change required",
                )
                .into_response(),
            )
        }
        crate::user_gate::PasswordGate::Unavailable => {
            return reject(
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "password credential 查询失败",
                )
                .into_response(),
            )
        }
    }

    Ok(GatedRefresh {
        tenant,
        family_id,
        presented_version,
        fam_rec,
        client,
        presented_client_id,
        now,
        source_grant,
    })
}

async fn prepare_issuance(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    gated: GatedRefresh,
) -> RefreshStageResult<ValidatedRefresh> {
    let GatedRefresh {
        tenant,
        family_id,
        presented_version,
        fam_rec,
        client,
        presented_client_id,
        now,
        source_grant,
    } = gated;

    // issuer + audience 选择(C2.8/C3.6 下采样)—— **前移到 consume/rotate 之前**(评审 High,spec 006 §3.4):
    // per-resource scope 收窄须是 read-gate(拒不改状态),而它依赖 aud;select_audience/derive_issuer 纯只读,
    // 前移安全。此处算出的 issuer/aud/authorized 供下方 scope 闸 + 后续签名复用(不再在 rotate 后重算)。
    let issuer = match host_from_headers(headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    {
        Some(i) => i,
        None => {
            return reject(
                err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response(),
            )
        }
    };
    // C10.22a 跨租户防伪造闸(spec 020;纵深 + 回归护栏,当前结构恒成立)。见 token.rs 同注。
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("refresh-token"),
    )
    .await
    {
        return reject(
            err(StatusCode::BAD_REQUEST, "invalid_request", "iss 不属本租户").into_response(),
        );
    }
    let authorized =
        AuthorizedResources::from_authorize(&fam_rec.resources, AuthorizePhase::P1Plus)
            .unwrap_or_else(|_| {
                AuthorizedResources::from_authorize(&[], AuthorizePhase::P1Plus).unwrap()
            });
    let reg = ClientRegistration {
        default_resource: client.default_resource.clone(),
    };
    let token_resources: Vec<String> = req.resource.iter().cloned().collect();
    let aud = match select_audience(&token_resources, &authorized, &reg) {
        Ok(AudienceSelection::Resource(r)) => r,
        Ok(AudienceSelection::UserinfoFallback) => format!("{}/userinfo", issuer.as_str()),
        Err(_) => {
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    "resource 不属授权集合",
                )
                .into_response(),
            )
        }
    };
    let userinfo_aud = format!("{}/userinfo", issuer.as_str());
    if requires_grant_backed_rar(&family_id)
        && source_grant
            .as_ref()
            .and_then(|grant| grant.resource_grant(&aud))
            .is_none()
    {
        return reject(
            err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Grant-backed refresh family 的目标 resource 已不再授权",
            )
            .into_response(),
        );
    }

    // scope 下采样(RFC 6749 §6 / DESIGN §1:156)——**read gate,置于 consume/rotate 之前**(评审:
    // 超集 scope 是纯拒、MUST NOT 改任何状态,否则会先 rotate 掉版本再拒、令合法 refresh 失效)。
    // 带 `scope` → 签发 = 授权集 ∩ 请求(逐个 ⊆,超出拒 invalid_scope);不带 → 继承授权集。
    // **授权源(spec 006 §3.4,O1 修复,C10.17)**:
    // - aud=<issuer>/userinfo,或无源 Grant,或源 Grant 未策略评估(effective_pv==0)→ **扁平 `fam_rec.scope`**
    //   (字节等价现网;userinfo scope 如 openid/profile 在 family.scope、不在 per_resource)。
    // - aud=真 RS 且源 Grant 已评估(effective_pv≥1)→ **该 aud 的 effective scopes**(经 Cedar 收窄)。
    //   effective_view 该 aud 返 None 须回 consent 层 `consent_grant(aud)` **三态消歧**(评审 Blocker):
    //   consent 空 scope+无 RAR=RS 默认权限→签空 scope 不拒;consent 有 scope/RAR 被 effective 丢弃=真 deny→invalid_scope;
    //   consent 无此条目→invalid_target。**绝不回退扁平全集**。
    // **C3.6 铁律**:只收窄本次 token scope claim,family.scope + Grant per_resource(consent)都不动。
    let req_scopes_for_issue: Vec<String> = match req.scope.as_deref() {
        Some(s) => s.split_whitespace().map(str::to_string).collect(),
        None => Vec::new(),
    };
    // 判据(评审 Medium #3 修正):按 **aud 是否属该 Grant 的 consent 集**(`consent_grant(aud).is_some()`),
    // **不用** `aud != userinfo_aud` 字符串判——后者会把**显式绑定** `resource=<issuer>/userinfo`(该 aud 在
    // per_resource、可被策略收窄)误路由到扁平、重开 O1 泄漏。用 membership:显式绑定的 userinfo → per-resource;
    // 回落 userinfo(未绑定、不在 per_resource)→ consent_grant None → 扁平(family.scope 含 openid/profile)。
    // 加 `state.authz_enabled` 闸(评审 Info,严格字节等价):flag 关时即便某 Grant 残留 effective_pv≥1
    // (历史开过又关)也走扁平,不按上次策略收窄——"关 flag = 完全回退现网"无意外。
    let use_per_resource = state.authz_enabled
        && source_grant
            .as_ref()
            .is_some_and(|g| g.effective_pv >= 1 && g.consent_grant(&aud).is_some());
    let granted_scopes = if use_per_resource {
        // aud ∈ consent 集(由 use_per_resource 保证)且已策略评估:授权源 = 该 aud 的 **effective** scopes;
        // effective 命中 → 用它;effective 无(evaluate 丢弃)→ 回 consent 消歧(空 scope+无 RAR=RS 默认权限
        // 签空 scope 不拒;consent 有 scope 被丢弃=真 deny → invalid_scope)。consent 命中已由判据保证,故无
        // "consent 也无"分支(那会被判据路由到扁平)。
        let g = source_grant.as_ref().unwrap();
        let authorized_for_aud: Vec<String> = match g.resource_grant(&aud) {
            Some(rg) => rg.scopes.clone(), // effective 命中(策略允许的 scopes)
            None => {
                // effective 丢弃该 aud。consent 必有(判据保证)。空 scope+无 RAR=RS 默认权限;否则=真 deny。
                let cg = g
                    .consent_grant(&aud)
                    .expect("use_per_resource 已保证 consent_grant(aud) 命中");
                if cg.scopes.is_empty() && cg.authorization_details.is_empty() {
                    Vec::new() // RS 默认权限 → 签空 scope(等价现网,不拒)
                } else {
                    return reject(
                        err(
                            StatusCode::BAD_REQUEST,
                            "invalid_scope",
                            "该 resource 的授权被当前策略拒绝(policy denies all scopes for target)",
                        )
                        .into_response(),
                    );
                }
            }
        };
        match agent_auth_grant::narrow_flat_scope(&authorized_for_aud, &req_scopes_for_issue) {
            Ok(s) => s,
            Err(_) => {
                return reject(
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "请求 scope 超出该 resource 生效授权(不内联补授权,RFC 6749 §6)",
                    )
                    .into_response(),
                )
            }
        }
    } else {
        // 扁平回退(userinfo / 无源 Grant / 未评估):字节等价现网。
        match agent_auth_grant::narrow_flat_scope(&fam_rec.scope, &req_scopes_for_issue) {
            Ok(s) => s,
            Err(_) => {
                return reject(
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "请求 scope 超出授权集(不内联补授权,RFC 6749 §6)",
                    )
                    .into_response(),
                )
            }
        }
    };

    // DPoP 绑定延续(spec 010 §5.2/B1,RFC 9449 §5)——**read gate,置于 consume/rotate 之前**(同 scope
    // 闸:缺/错 proof 是纯拒、MUST NOT 改状态,否则会先 rotate 掉版本再拒 → 后续合法重试被误判复用吊销)。
    // 有 proof → 得 jkt;失败/重放 → 拒。htu 用派生可信 issuer 的 token endpoint。
    let dpop_issuer =
        match host_from_headers(headers).and_then(|h| derive_issuer(&h, &state.form).ok()) {
            Some(i) => i,
            None => {
                return reject(
                    err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response(),
                )
            }
        };
    let presented_jkt = match crate::dpop::resolve_dpop_binding(
        state,
        headers,
        &tenant,
        dpop_issuer.as_str(),
        client.require_dpop,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return reject(resp),
    };
    // **绑定闸**:DPoP-bound family(dpop_jkt=Some)MUST 出示匹配 jkt 的 proof,缺/不匹配拒不降级 bearer;
    // 非 DPoP family(None)不要求 proof(后向兼容;若此时带了 proof 则新 token 绑其 jkt,但不改 family)。
    let cnf_jkt: Option<String> = match &fam_rec.dpop_jkt {
        Some(bound) => match &presented_jkt {
            Some(j) if j == bound => Some(j.clone()),
            _ if presented_version < fam_rec.current_version => {
                if let Err(error) = revoke_family_and_delete_grace(state, &tenant, &family_id).await
                {
                    return reject(reuse_cleanup_failure(error));
                }
                return reject(
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "refresh 复用检测:DPoP identity 不匹配,family 已吊销",
                    )
                    .into_response(),
                );
            }
            _ => {
                return reject(
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_dpop_proof",
                        "DPoP-bound refresh 须出示匹配 jkt 的 proof(缺失/不匹配拒,不降级 bearer)",
                    )
                    .into_response(),
                )
            }
        },
        None => presented_jkt.clone(),
    };

    // 宽限窗请求指纹 + 独立身份维度(C3.2)。**请求侧**绑定(评审 codex HIGH-3/HIGH-4):
    // scope 只取**请求实际携带**的 scope；缺省保持空串，不能回落 family scope，
    // 否则“省略 scope”和“显式完整 scope”会错误折叠成同一指纹。
    // client_id 取**呈现**的 client_id(Basic 优先,否则 form;已由 verify_client_auth 校过=fam_rec.client_id)。
    // resource=本次下采样目标;code_challenge 取 family 持久化的 PKCE 授权源
    // (legacy/non-PKCE family 缺失时为空);dpop_jkt=本次绑定的 cnf_jkt
    // (评审 L1:宽限窗身份维度须区分 proof key/无 proof——DPoP-bound refresh 的缓存不与 bearer/异 key 混淆;
    // 虽绑定闸已挡 DPoP-bound family 的错 proof,填此维度使缓存契约"client_id+dpop_jkt+fingerprint 全一致"完整)。
    let req_scopes: Vec<String> = match req.scope.as_deref() {
        Some(s) => s.split_whitespace().map(str::to_string).collect(),
        None => Vec::new(),
    };
    let req_fp = fingerprint(
        &state.server_secret,
        &GraceRequest {
            grant_type: "refresh_token".to_string(),
            scopes: req_scopes,
            resource: req.resource.clone().unwrap_or_default(),
            code_challenge: fam_rec.pkce_code_challenge.clone().unwrap_or_default(),
        },
    );
    let req_identity = GraceIdentity {
        client_id: presented_client_id,
        dpop_jkt: cnf_jkt.clone(),
    };
    let mode = crate::token::subject_mode(state.subject_type_for_tenant(&tenant));
    let access_sub = if aud == userinfo_aud {
        match mode {
            agent_auth_token::SubjectMode::Public => fam_rec.user_id.clone(),
            agent_auth_token::SubjectMode::Pairwise => match client.oidc_sector() {
                Some(sector) => {
                    agent_auth_token::pairwise_sub(&state.server_secret, &fam_rec.user_id, &sector)
                }
                None => {
                    return reject(
                        err(
                            StatusCode::BAD_REQUEST,
                            "invalid_client",
                            "pairwise 下无法确定 OIDC sector(多 redirect host 须 sector_identifier_uri)",
                        )
                        .into_response(),
                    )
                }
            },
        }
    } else {
        agent_auth_token::derive_user_sub(mode, &state.server_secret, &fam_rec.user_id, &aud)
    };

    Ok(ValidatedRefresh {
        headers: headers.clone(),
        tenant,
        family_id,
        presented_version,
        fam_rec,
        now,
        source_grant,
        issuer: issuer.as_str().to_string(),
        aud,
        access_sub,
        granted_scopes,
        cnf_jkt,
        req_fp,
        req_identity,
    })
}

async fn read_current_grace<S, N>(
    grace: &S,
    family_id: &str,
    version: u64,
    now: N,
) -> Result<Option<crate::ports::GraceCacheEntry>, ()>
where
    S: crate::ports::GraceStore + ?Sized,
    N: FnOnce() -> i64,
{
    let entry = grace.get(family_id, version).await;
    let observed_at = now();
    match entry {
        Ok(Some(entry))
            if agent_auth_infra_core::lifecycle::shortlived_is_valid(
                observed_at,
                entry.expires_at,
            ) =>
        {
            Ok(Some(entry))
        }
        Ok(Some(_)) | Ok(None) => Ok(None),
        Err(crate::ports::StoreError::Transient(_)) => Err(()),
        Err(_) => Ok(None),
    }
}

// 宽限窗探查(C3.2):查 (family, presented_version) 缓存,窗内 + 全维度一致 → 返回该重放响应。
// 瞬时错误(KMS/DDB 节流)MUST 冒泡成 503(评审 Kiro F2:不得吞成不可逆吊销)。
// 返回:Ok(Some(resp))=命中重放;Ok(None)=未命中(按复用处理);Err(())=瞬时错误(上层返 503)。
async fn probe_grace(
    state: &AppState,
    family_id: &str,
    version: u64,
    req_fp: &[u8; 32],
    req_identity: &GraceIdentity,
) -> Result<Option<TokenResponse>, ()> {
    let Some(grace) = &state.grace else {
        return Ok(None); // 宽限窗关闭 → fail-closed(按复用)
    };
    let Some(entry) = read_current_grace(
        grace.as_ref(),
        family_id,
        version,
        crate::token::current_unix_secs_pub,
    )
    .await?
    else {
        return Ok(None);
    };
    let decision = agent_auth_token::decide(
        &entry.fingerprint,
        &GraceIdentity {
            client_id: entry.client_id.clone(),
            dpop_jkt: entry.dpop_jkt.clone(),
        },
        req_fp,
        req_identity,
    );
    if decision == agent_auth_token::GraceDecision::ReturnCached {
        // token_type 须与新签发路径一致(评审 codex/Kiro:DPoP-bound family 的 grace 重放不能返 Bearer,
        // 否则 client 按 Authorization: Bearer 用 cnf-bound token → RS 拒)。entry.dpop_jkt 已与本次请求
        // 呈现的 proof jkt 经 decide 校一致(维度匹配才 ReturnCached),故按它派生 token_type。
        let tt = crate::token::token_type_for(entry.dpop_jkt.as_deref());
        let r = entry.response;
        Ok(Some(TokenResponse {
            access_token: r.access_token,
            token_type: tt,
            expires_in: r.expires_in,
            scope: r.scope,
            refresh_token: Some(r.refresh_token),
            id_token: r.id_token,
            resource: None,
        }))
    } else {
        Ok(None) // 窗外 / 维度不符 → 按复用
    }
}

struct LeasedRefresh {
    validated: ValidatedRefresh,
    lease_owner: String,
    lease_expires_at: i64,
    new_version: u64,
}

async fn acquire_validated(
    state: &AppState,
    validated: ValidatedRefresh,
) -> RefreshStageResult<LeasedRefresh> {
    let tenant = &validated.tenant;
    let family_id = &validated.family_id;
    let presented_version = validated.presented_version;
    let fam_rec = &validated.fam_rec;
    let req_fp = &validated.req_fp;
    let req_identity = &validated.req_identity;

    // 用 token crate 的 RefreshFamily 判定 consume 结局(纯逻辑)。
    let mut family = RefreshFamily {
        family_id: fam_rec.family_id.clone(),
        current_version: fam_rec.current_version,
        revoked: fam_rec.revoked,
    };
    match family.consume(presented_version) {
        ConsumeOutcome::ReuseDetectedRevokeFamily => {
            // 呈现非当前版本:先看宽限窗(C3.2)——窗内全维度一致的合法重试返回缓存的同一组结果,
            // 不吊销、不再签;瞬时错误 → 503(不吊销);未命中 → 复用检测 → 全链吊销 + 删缓存(C3.5)。
            match probe_grace(state, family_id, presented_version, req_fp, req_identity).await {
                Ok(Some(resp)) => return reject(Json(resp).into_response()),
                Err(()) => {
                    return reject(
                        err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "宽限窗存储瞬时不可用,请重试",
                        )
                        .into_response(),
                    )
                }
                Ok(None) => {}
            }
            if let Err(error) = revoke_family_and_delete_grace(state, tenant, family_id).await {
                return reject(reuse_cleanup_failure(error));
            }
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh 复用检测:family 已吊销",
                )
                .into_response(),
            );
        }
        ConsumeOutcome::AlreadyRevoked => {
            if let Err(error) = revoke_family_and_delete_grace(state, tenant, family_id).await {
                return reject(reuse_cleanup_failure(error));
            }
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh family 已吊销",
                )
                .into_response(),
            );
        }
        ConsumeOutcome::Rotated { .. } => {}
    }

    let lease_owner = crate::token::new_jti(state);
    let lease_now = crate::token::current_unix_secs_pub();
    let lease_expires_at = lease_now.saturating_add(REFRESH_LEASE_TTL_SECS);
    match state
        .refresh
        .acquire_lease(
            tenant,
            family_id,
            presented_version,
            &lease_owner,
            lease_now,
            lease_expires_at,
        )
        .await
    {
        Ok(RefreshLeaseAcquire::Acquired) => {}
        Ok(RefreshLeaseAcquire::Locked { retry_after_secs }) => {
            return reject(
                crate::token::err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "refresh signing is already in progress",
                    retry_after_secs,
                )
                .into_response(),
            )
        }
        Ok(RefreshLeaseAcquire::VersionMismatch) => {
            // The strong read used for validation raced a completed finalize.
            // Re-probe the transactionally written grace result before asking
            // the client to retry; do not revoke from this stale-read branch.
            match probe_grace(state, family_id, presented_version, req_fp, req_identity).await {
                Ok(Some(resp)) => return reject(Json(resp).into_response()),
                Err(()) => {
                    return reject(
                        err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "宽限窗存储瞬时不可用,请重试",
                        )
                        .into_response(),
                    )
                }
                Ok(None) => {
                    return reject(
                        crate::token::err_retry_after(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "并发续期争用,请重试",
                            1,
                        )
                        .into_response(),
                    );
                }
            }
        }
        Ok(RefreshLeaseAcquire::Revoked) => {
            if let Err(error) = revoke_family_and_delete_grace(state, tenant, family_id).await {
                return reject(reuse_cleanup_failure(error));
            }
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh family 已吊销",
                )
                .into_response(),
            );
        }
        Ok(RefreshLeaseAcquire::NotFound) => {
            return reject(
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh family 不存在",
                )
                .into_response(),
            )
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return reject(
                crate::token::err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "存储瞬时不可用",
                    1,
                )
                .into_response(),
            )
        }
        Err(_) => {
            return reject(
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "存储错误",
                )
                .into_response(),
            )
        }
    }
    let new_version = presented_version + 1;
    Ok(LeasedRefresh {
        validated,
        lease_owner,
        lease_expires_at,
        new_version,
    })
}

fn lease_retry_after(lease_expires_at: i64) -> u64 {
    lease_expires_at
        .saturating_sub(crate::token::current_unix_secs_pub())
        .max(1) as u64
}

async fn release_refresh_lease(
    state: &AppState,
    tenant: &str,
    family_id: &str,
    presented_version: u64,
    lease_owner: &str,
) -> bool {
    matches!(
        state
            .refresh
            .release_lease(tenant, family_id, presented_version, lease_owner)
            .await,
        Ok(true)
    )
}

async fn issue_leased(state: &AppState, leased: LeasedRefresh) -> Response {
    let LeasedRefresh {
        validated:
            ValidatedRefresh {
                headers,
                tenant,
                family_id,
                presented_version,
                fam_rec,
                now,
                source_grant,
                issuer,
                aud,
                access_sub,
                granted_scopes,
                cnf_jkt,
                req_fp,
                req_identity,
            },
        lease_owner,
        lease_expires_at,
        new_version,
    } = leased;

    // Issuer, audience, subject, authorization and DPoP semantics were all
    // validated before the lease was acquired. From here to signing, every
    // rejection must release this owner without advancing the family.

    // RAR 透传(spec 010 §4 / DESIGN §5.2:510 委托⊆源 Grant):从源 Grant 取本次 aud(resource)的
    // authorization_details,签入新 token。**禁止静默剥离**——无源 Grant(老 family)则无 RAR(后向兼容:
    // 老 token 本无 RAR)。取 Grant 该 resource 条目的 RAR(Grant 是 RAR 权威源,per_resource 已按 locations 归属)。
    let rar_for_aud: Vec<serde_json::Value> = source_grant
        .as_ref()
        .and_then(|g| g.resource_grant(&aud))
        .map(|rg| rg.authorization_details.clone())
        .unwrap_or_default();
    let scope_str = granted_scopes.join(" ");
    let access_jti = crate::token::new_jti(state);
    if let Some(response) = crate::ratelimit_gate::kms_sign_tenant_gate(state, &tenant).await {
        if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner).await
        {
            return response;
        }
        return crate::token::err_retry_after(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "refresh lease release failed; retry after the lease expires",
            lease_retry_after(lease_expires_at),
        )
        .into_response();
    }
    if let Some(response) = crate::ratelimit_gate::kms_sign_gate(state).await {
        if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner).await
        {
            return response;
        }
        return crate::token::err_retry_after(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "refresh lease release failed; retry after the lease expires",
            lease_retry_after(lease_expires_at),
        )
        .into_response();
    }
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, &tenant).await {
        Ok(signer) => signer,
        Err(response) => {
            if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner)
                .await
            {
                return response;
            }
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "refresh lease release failed; retry after the lease expires",
                lease_retry_after(lease_expires_at),
            )
            .into_response();
        }
    };
    let jwt = match crate::token::sign_tenant_access_token_with_delivery(
        state,
        &headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: issuer.as_str(),
            sub: &access_sub,
            aud: &aud,
            client_id: &fam_rec.client_id,
            scope: &scope_str,
            jti: &access_jti,
            auth_grant: &family_id,  // family 引用(稳定;比 code 更合适)
            sub_type: SubType::User, // refresh 承接 3LO
            authorization_details: &rar_for_aud,
            cnf_jkt: cnf_jkt.as_deref(),
            auth_time: fam_rec.auth_time,
            acr: fam_rec.acr.as_deref(),
            now,
        },
        state.phase.at_least(agent_auth_discovery::Phase::P3) && source_grant.is_some(),
        crate::security_event::SecurityActor::system("refresh-token"),
    )
    .await
    {
        Ok(signed) => signed.token,
        // No family state has advanced yet. Pre-finalize failures release this
        // owner's lease, so the same refresh handle remains safely retryable.
        Err(crate::token::TokenSignError::TooLarge) => {
            if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner)
                .await
            {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
                )
                .into_response();
            }
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "refresh lease release failed; retry after the lease expires",
                lease_retry_after(lease_expires_at),
            )
            .into_response();
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner)
                .await
            {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "issuer does not belong to tenant",
                )
                .into_response();
            }
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "refresh lease release failed; retry after the lease expires",
                lease_retry_after(lease_expires_at),
            )
            .into_response();
        }
        Err(crate::token::TokenSignError::Transient) => {
            let released =
                release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner)
                    .await;
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "签名瞬时失败(KMS throttle),请退避重试",
                if released {
                    1
                } else {
                    lease_retry_after(lease_expires_at)
                },
            )
            .into_response();
        }
        Err(crate::token::TokenSignError::Permanent) => {
            if release_refresh_lease(state, &tenant, &family_id, presented_version, &lease_owner)
                .await
            {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "签名失败",
                )
                .into_response();
            }
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "refresh lease release failed; retry after the lease expires",
                lease_retry_after(lease_expires_at),
            )
            .into_response();
        }
    };

    let new_refresh = encode_refresh(&family_id, new_version);
    let resp_scope = (!scope_str.is_empty()).then_some(scope_str);
    let finalize_now = crate::token::current_unix_secs_pub();
    let grace_entry = state.grace.as_ref().map(|_| crate::ports::GraceCacheEntry {
        family_id: family_id.clone(),
        version: presented_version,
        fingerprint: req_fp,
        client_id: req_identity.client_id.clone(),
        dpop_jkt: req_identity.dpop_jkt.clone(),
        response: crate::ports::GraceCachedResponse {
            access_token: jwt.clone(),
            refresh_token: new_refresh.clone(),
            id_token: None,
            scope: resp_scope.clone(),
            expires_in: ACCESS_TTL,
        },
        expires_at: finalize_now + state.grace_window_secs,
    });
    match state
        .refresh
        .finalize_rotation_with_grace(
            state.grace.as_deref(),
            &tenant,
            &family_id,
            presented_version,
            &lease_owner,
            finalize_now,
            grace_entry,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return crate::token::err_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "refresh finalize failed; retry after the signing lease expires",
                lease_retry_after(lease_expires_at),
            )
            .into_response()
        }
    }

    // spec 011 C7.8:落新 access token 的 jti→{user_id, family_id, grant_id} 映射(承接 3LO;可作 subject_token)。
    // **grant_id 仅当 Grant 确实存在时才写**:老 pre-migration family / Grant 创建失败的 token
    // 仍可正常 refresh，但不具备 token-exchange 委托授权源；缺指针时 token-exchange fail-closed。
    // tenant 从 issuer 派生;失败不阻断。
    if let Some(jti_store) = &state.jti_store {
        let grant_id = match state.grants.get(&tenant, &family_id).await {
            Ok(Some(_)) => Some(family_id.clone()), // Grant 存在(code flow 创建时 grant_id=family_id)
            _ => None,                              // 无 Grant / 存储错误 → 退回 family 前身路径
        };
        let _ = jti_store
            .put(crate::ports::JtiRecord {
                jti: access_jti.clone(),
                // jti tenant(codex M1):本请求派生 tenant;空(flag 关)沿用 "default" 后向兼容。
                tenant_id: if tenant.is_empty() {
                    "default".to_string()
                } else {
                    tenant.clone()
                },
                user_id: fam_rec.user_id.clone(),
                family_id: Some(family_id.clone()),
                grant_id,
                expires_at: now + ACCESS_TTL,
            })
            .await;
    }

    // 记预注册 client 最后使用日；CIMD identity 没有 ClientStore 行。
    if fam_rec.cimd_snapshot.is_none() {
        crate::token::touch_client_last_used(state, &tenant, &fam_rec.client_id, now).await;
    }

    // Close the reset race after signing, family rotation, JTI persistence, and
    // grace-cache creation. PasswordStore uses a strongly consistent read in
    // AWS, so a completed reset cannot return a newly issued token. Revoke the
    // rotated family and remove every cached response before suppressing it.
    // Keep this as the final awaited operation on the successful response path.
    let post_issue_authority = crate::user_gate::require_password_authority_version(
        state,
        &tenant,
        &fam_rec.user_id,
        fam_rec.password_credential_version,
    )
    .await;
    let post_issue_epoch = crate::user_gate::require_active_user_epoch(
        state,
        &tenant,
        &fam_rec.user_id,
        fam_rec.credential_epoch,
    )
    .await;
    if post_issue_authority != crate::user_gate::PasswordGate::Allowed || post_issue_epoch.is_err()
    {
        let mut cleanup_ok = state.refresh.revoke(&tenant, &family_id).await.is_ok();
        if let Some(grace) = &state.grace {
            cleanup_ok &= grace.delete_family(&family_id).await.is_ok();
        }
        return match (post_issue_authority, post_issue_epoch, cleanup_ok) {
            (crate::user_gate::PasswordGate::ChangeRequired, _, true) => err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "password authority changed during refresh issuance",
            )
            .into_response(),
            (crate::user_gate::PasswordGate::Allowed, Err(_), true) => err(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "user lifecycle changed during refresh issuance",
            )
            .into_response(),
            _ => err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "password authority verification or cleanup failed",
            )
            .into_response(),
        };
    }

    Json(TokenResponse {
        access_token: jwt,
        token_type: crate::token::token_type_for(cnf_jkt.as_deref()),
        expires_in: ACCESS_TTL,
        scope: resp_scope,
        refresh_token: Some(new_refresh),
        id_token: None,
        resource: None,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{GraceCacheEntry, GraceCachedResponse, GraceStore, StoreError};
    use std::sync::atomic::{AtomicI64, Ordering};

    struct AdvancingGraceStore<'a> {
        now: &'a AtomicI64,
        entry: GraceCacheEntry,
    }

    impl GraceStore for AdvancingGraceStore<'_> {
        async fn put(&self, _entry: GraceCacheEntry) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get(
            &self,
            _family_id: &str,
            _version: u64,
        ) -> Result<Option<GraceCacheEntry>, StoreError> {
            self.now.store(1_000, Ordering::SeqCst);
            Ok(Some(self.entry.clone()))
        }

        async fn delete_family(&self, _family_id: &str) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn refresh_encode_decode_roundtrip() {
        let t = encode_refresh("fam-abc", 3);
        assert_eq!(decode_refresh(&t), Some(("fam-abc".to_string(), 3)));
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(decode_refresh("noversion"), None);
        assert_eq!(decode_refresh(".5"), None);
        assert_eq!(decode_refresh("fam.notanumber"), None);
    }

    // family_id 可含 '.'(base64url 不含 '.',但防御性):rsplit 取最后一段为 version。
    #[test]
    fn decode_uses_last_dot() {
        assert_eq!(decode_refresh("a.b.7"), Some(("a.b".to_string(), 7)));
    }

    #[tokio::test]
    async fn grace_probe_samples_time_after_store_read() {
        let now = AtomicI64::new(999);
        let store = AdvancingGraceStore {
            now: &now,
            entry: GraceCacheEntry {
                family_id: "family-1".into(),
                version: 7,
                fingerprint: [1; 32],
                client_id: "client-1".into(),
                dpop_jkt: None,
                response: GraceCachedResponse {
                    access_token: "access".into(),
                    refresh_token: "refresh".into(),
                    id_token: None,
                    scope: Some("openid".into()),
                    expires_in: 300,
                },
                expires_at: 1_000,
            },
        };

        let result = read_current_grace(&store, "family-1", 7, || now.load(Ordering::SeqCst))
            .await
            .unwrap();

        assert!(result.is_none());
    }
}
