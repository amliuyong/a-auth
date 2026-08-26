//! `POST /token` 的 `grant_type=client_credentials`(2LO)。
//!
//! 编排纯逻辑 crate(`agent_auth_workload`),不重述规则:
//! - 预注册 confidential service 复用标准 client auth registry(Basic/Post/private_key_jwt),签
//!   `sub_type=service`。
//! - JWKS 本地验签(`verify_rs256`,jwt_rs256.rs)——公钥**只来自管理面登记的 `jwks_uri`**,绝不取 JWT
//!   header 的 `jku`/`x5u`(防 key confusion,评审收敛)。
//! - OIDC claim 决策(`authorize_oidc`,oidc.rs:aud=本AS 硬校验 / exp / iss+sub 匹配信任绑定)+ 本层补
//!   nbf / ±skew / 最长寿命上限(评审 M4)。
//! - workload 信任绑定映射 → `WorkloadIdentity{client_id,...}`；据 client_id load ClientRecord
//!   确认 `client_type==workload`，不能降级成普通 client。
//! - 2LO token 形态(spec 001 §2.8):`sub`=client_id、`sub_type=agent|service`、
//!   `auth_grant="client_credentials"`、**无 pairwise / act / grant_id / auth_time**；
//!   **不发 refresh / id_token**(评审 M2)。
//!
//! **SigV4/STS**(`aws_sigv4_caller_identity`,C5.2/5.3/5.4):前校组合门、一次性 replay 缓存(C5.3②,
//! HMAC(secret,签名段)key)、熔断器、StsCaller 端口转发、caller ARN→client_id 映射全接线
//! (`authenticate_workload_sigv4`)。真机 = HttpStsCaller(reqwest→真 STS,超时 2s)+ ReplayStore(JtiTable);
//! dev/测试 = 内存 mock。准入 fail-closed(无 SigV4 trust binding 认证不了)。
//!
//! **SPIFFE JWT-SVID**(`spiffe_jwt_svid`,spec 012 §1.4/C5.7,`authenticate_workload_spiffe`):同 `jwt-bearer`
//! wire type,按未验签 `sub` 是否合法 SPIFFE ID 消歧;信任锚 = 从 `sub` 解出的 trust domain(**绝不用 iss**),
//! 用该 trust bundle JWKS 本地验签(ES256/RS256,alg pin);aud 硬校验 + 共享时间前置 → authorize_spiffe_jwt。
//! **X.509-SVID/mTLS**(`spiffe_svid_mtls`,P3 SelfHosted):独立 API Gateway mTLS 域名完成握手验链,
//! 本层只消费 requestContext 注入的已验链叶子证书,从唯一 SPIFFE URI SAN 映射 client_id。
//!
//! 决策真相源 docs §3.1(workload 三机制、aud 硬定向)、§2/§2.8(2LO 形态)、spec 012 C5。

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::ports::{
    ClientRecord, ClientStore, JwksFetcher, ReplayStore, StsCaller, WorkloadTrustStore,
};
use crate::state::AppState;
use crate::token::{err, AccessTokenClaims, TokenRequest, TokenResponse, ACCESS_TTL};
use agent_auth_discovery::derive_issuer;
use agent_auth_token::SubType;
use agent_auth_workload::{authorize_oidc, verify_rs256, OidcAuthError, TrustMechanism};

/// 标准 RFC 7523 client_assertion type(workload_oidc_jwt 用它;auth_method 才叫 workload_oidc_jwt)。
pub(crate) const JWT_BEARER_ASSERTION: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// SigV4/STS 路径的自定义 client_assertion type(spec 012 C5.2;assertion=JSON 编码的 SigV4Assertion)。
pub(crate) const SIGV4_ASSERTION: &str =
    "urn:agent-auth:params:oauth:client-assertion-type:aws-sigv4";
/// SigV4 audience 绑定头(对标 Vault `X-Vault-AWS-IAM-Server-ID`;MUST 在 SignedHeaders 内,C5.2)。
const SIGV4_AUDIENCE_HEADER: &str = "x-agent-auth-audience";

/// 平台 token 最长寿命上限(评审 M4):拒绝 exp-iat 过长的平台 token(缩小重放价值,免强制 jti)。
const MAX_PLATFORM_TOKEN_LIFETIME: i64 = 3600; // 1h
/// 时钟 skew 余量(C10.6;与 workload replay 一致)。
const CLOCK_SKEW_SECS: i64 = 30;
const OIDC_AUDIENCE_ERROR_DESCRIPTION: &str =
    "platform token audience must equal this authorization server; configure the platform audience or use SigV4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TwoLoSubjectKind {
    Agent,
    Service,
}

impl TwoLoSubjectKind {
    const fn sub_type(self) -> SubType {
        match self {
            Self::Agent => SubType::Agent,
            Self::Service => SubType::Service,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AuthenticatedTwoLoSubject<'a> {
    client_id: &'a str,
    kind: TwoLoSubjectKind,
    client_snapshot: Option<&'a ClientRecord>,
}

impl<'a> AuthenticatedTwoLoSubject<'a> {
    const fn agent(client_id: &'a str) -> Self {
        Self {
            client_id,
            kind: TwoLoSubjectKind::Agent,
            client_snapshot: None,
        }
    }

    fn service(client: &'a ClientRecord) -> Self {
        Self {
            client_id: client.client_id.as_str(),
            kind: TwoLoSubjectKind::Service,
            client_snapshot: Some(client),
        }
    }
}

async fn audit_workload_rejection(
    state: &AppState,
    tenant: &str,
    client_id: Option<&str>,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::workload_authentication(
                tenant, client_id, outcome,
            ),
        )
        .await;
    response
}

async fn audit_verified_2lo_rejection(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    subject_kind: TwoLoSubjectKind,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    let draft = match subject_kind {
        TwoLoSubjectKind::Agent => {
            crate::security_event::SecurityEventDraft::workload_authentication(
                tenant,
                Some(client_id),
                outcome,
            )
        }
        TwoLoSubjectKind::Service => {
            crate::security_event::SecurityEventDraft::service_authentication(
                tenant, client_id, outcome,
            )
        }
    };
    state.record_security_event(draft).await;
    response
}

async fn audit_2lo_issuance_rejection(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    subject_kind: TwoLoSubjectKind,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    let draft = match subject_kind {
        TwoLoSubjectKind::Agent => {
            crate::security_event::SecurityEventDraft::workload_token_issuance(
                tenant, client_id, outcome,
            )
        }
        TwoLoSubjectKind::Service => {
            crate::security_event::SecurityEventDraft::service_token_issuance(
                tenant, client_id, outcome,
            )
        }
    };
    state.record_security_event(draft).await;
    response
}

fn client_auth_error_response(
    headers: &HeaderMap,
    error: crate::client_auth::ClientAuthError,
) -> Response {
    match error {
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
            crate::token::invalid_client_response(
                headers,
                StatusCode::UNAUTHORIZED,
                error.description(),
            )
        }
    }
}

async fn try_handle_service(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    as_issuer: &str,
    tenant: &str,
) -> Option<Response> {
    let secret_credential_present =
        headers.contains_key(axum::http::header::AUTHORIZATION) || req.client_secret.is_some();
    let presented_client_id = req
        .client_id
        .clone()
        .or_else(|| crate::client_auth::basic_client_id(headers));
    let service_assertion = match req.client_assertion_type.as_deref() {
        Some(JWT_BEARER_ASSERTION) | None => req.client_assertion.as_deref(),
        Some(_) if !secret_credential_present => return None,
        Some(_) => None,
    };
    let client_id = match crate::client_auth::resolve_client_id_with_assertion(
        req.client_id.as_deref(),
        headers,
        service_assertion,
    ) {
        Ok(Some(client_id)) => client_id,
        Ok(None) if secret_credential_present => {
            return Some(crate::token::invalid_client_response(
                headers,
                StatusCode::UNAUTHORIZED,
                "client credentials are malformed",
            ))
        }
        Ok(None) => return None,
        Err(error) => {
            if let Some(client_id) = presented_client_id.as_deref() {
                match state.clients.get(tenant, client_id).await {
                    Ok(Some(client)) if client.is_workload() => return None,
                    Ok(Some(_)) => {
                        return Some(
                            audit_verified_2lo_rejection(
                                state,
                                tenant,
                                client_id,
                                TwoLoSubjectKind::Service,
                                client_auth_error_response(headers, error),
                            )
                            .await,
                        )
                    }
                    Ok(None) => {}
                    Err(crate::ports::StoreError::Transient(_)) => {
                        return Some(
                            audit_verified_2lo_rejection(
                                state,
                                tenant,
                                client_id,
                                TwoLoSubjectKind::Service,
                                err(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "temporarily_unavailable",
                                    "client store temporarily unavailable",
                                )
                                .into_response(),
                            )
                            .await,
                        )
                    }
                    Err(_) => {
                        return Some(
                            audit_verified_2lo_rejection(
                                state,
                                tenant,
                                client_id,
                                TwoLoSubjectKind::Service,
                                err(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "server_error",
                                    "client store error",
                                )
                                .into_response(),
                            )
                            .await,
                        )
                    }
                }
            }
            if secret_credential_present {
                return Some(client_auth_error_response(headers, error));
            }
            // An assertion-only request with no resolvable registered client identity still
            // belongs to the managed workload dispatcher. In particular, a copied PEM
            // certificate must fail as workload authentication, not be claimed as malformed
            // private_key_jwt service authentication.
            return None;
        }
    };

    let client = match state.clients.get(tenant, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) if !secret_credential_present && req.client_assertion.is_some() => {
            // OIDC workload assertions may legitimately have iss == sub, the same unverified
            // shape as private_key_jwt. Only a registered client selects the service path.
            return None;
        }
        Ok(None) => {
            return Some(
                audit_verified_2lo_rejection(
                    state,
                    tenant,
                    &client_id,
                    TwoLoSubjectKind::Service,
                    crate::token::invalid_client_response(
                        headers,
                        StatusCode::UNAUTHORIZED,
                        "unknown client",
                    ),
                )
                .await,
            )
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            return Some(
                audit_verified_2lo_rejection(
                    state,
                    tenant,
                    &client_id,
                    TwoLoSubjectKind::Service,
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "client store temporarily unavailable",
                    )
                    .into_response(),
                )
                .await,
            )
        }
        Err(_) => {
            return Some(
                audit_verified_2lo_rejection(
                    state,
                    tenant,
                    &client_id,
                    TwoLoSubjectKind::Service,
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "client store error",
                    )
                    .into_response(),
                )
                .await,
            )
        }
    };

    try_handle_loaded_service(
        state,
        headers,
        req,
        as_issuer,
        tenant,
        client,
        secret_credential_present,
    )
    .await
}

async fn try_handle_loaded_service(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    as_issuer: &str,
    tenant: &str,
    client: ClientRecord,
    secret_credential_present: bool,
) -> Option<Response> {
    let client_id = client.client_id.clone();
    if client.is_workload() {
        if secret_credential_present {
            return Some(
                audit_workload_rejection(
                    state,
                    tenant,
                    Some(&client_id),
                    crate::token::invalid_client_response(
                        headers,
                        StatusCode::UNAUTHORIZED,
                        "workload clients require platform identity authentication",
                    ),
                )
                .await,
            );
        }
        return None;
    }
    if !client.is_confidential_auth_client() {
        return Some(
            audit_verified_2lo_rejection(
                state,
                tenant,
                &client_id,
                TwoLoSubjectKind::Service,
                crate::token::invalid_client_response(
                    headers,
                    StatusCode::UNAUTHORIZED,
                    "client_credentials requires a confidential or workload client",
                ),
            )
            .await,
        );
    }
    let client = match crate::client_auth::authenticate_loaded_snapshot(
        state,
        tenant,
        crate::client_auth::ClientAuthEndpoint::Token,
        &client,
        headers,
        crate::client_auth::PresentedClientAuth::new(
            req.client_secret.as_deref(),
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
        ),
    )
    .await
    {
        Ok(client) => client,
        Err(error) => return Some(client_auth_error_response(headers, error)),
    };
    if !client.is_confidential_auth_client() {
        return Some(
            audit_verified_2lo_rejection(
                state,
                tenant,
                &client_id,
                TwoLoSubjectKind::Service,
                crate::token::invalid_client_response(
                    headers,
                    StatusCode::UNAUTHORIZED,
                    "authenticated client is not a confidential service",
                ),
            )
            .await,
        );
    }
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::service_authentication(
                tenant,
                &client_id,
                crate::security_event::SecurityEventOutcome::Success,
            ),
        )
        .await;
    if client.allowed_resources.is_empty() {
        return Some(
            audit_2lo_issuance_rejection(
                state,
                tenant,
                &client_id,
                TwoLoSubjectKind::Service,
                err(
                    StatusCode::BAD_REQUEST,
                    "unauthorized_client",
                    "client is not registered for client_credentials",
                )
                .into_response(),
            )
            .await,
        );
    }

    Some(
        issue_2lo(
            state,
            headers,
            req,
            as_issuer,
            tenant,
            AuthenticatedTwoLoSubject::service(&client),
        )
        .await,
    )
}

/// 处理 `grant_type=client_credentials`(2LO)。显式配置 2LO resource policy 的 confidential
/// client 走 service 路径；其余请求按受管 workload 身份机制分派。
pub async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
) -> axum::response::Response {
    // issuer(本 AS,用于 aud 硬校验)+ tenant 派生(评审 H4:从 issuer/Host 派生,绝不客户端提供)。
    let Some(issuer) =
        crate::hostutil::issuer_host(headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    else {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "Host 非法").into_response();
    };
    // C10.22a 跨租户防伪造闸(spec 020;纵深 + 回归护栏,当前结构恒成立)。见 token.rs 同注。
    if !crate::tenant::issuer_belongs_to_request_tenant(
        state,
        headers,
        issuer.as_str(),
        crate::security_event::SecurityActor::system("workload-token"),
    )
    .await
    {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "iss 不属本租户").into_response();
    }
    let as_issuer = issuer.as_str();
    // tenant 分区(spec 020 §2.3,codex M1):从入站 Host 派生;store 物理键用 `tenant`(空=透传),
    // jti 反查 tenant_id 空时沿用 "default"(后向兼容)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let tenant_id = if tenant.is_empty() {
        "default".to_string()
    } else {
        tenant.clone()
    };

    if let Some(response) = try_handle_service(state, headers, req, as_issuer, &tenant).await {
        return response;
    }

    // 认证机制分派(auth_method):workload_oidc_jwt(平台 OIDC JWT,本地验签)
    // 或 aws_sigv4_caller_identity(预签名 GetCallerIdentity,前校 + 转发 STS)。产出统一 WorkloadIdentity。
    let identity = match (
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
    ) {
        // jwt-bearer assertion:workload_oidc_jwt(平台 OIDC JWT)**或** spiffe_jwt_svid(JWT-SVID)——
        // 二者同 wire assertion_type,按未验签 `sub` 消歧:合法 SPIFFE ID(spiffe://+非空 trust domain)→
        // SPIFFE 路径(按 sub-trust-domain 选绑定),否则 → OIDC 路径(按 iss 选绑定)。真信任在各自验签后。
        // (OIDC 平台 sub 如 `repo:acme/...` 绝非 spiffe://;SPIFFE sub 恒 spiffe://,消歧无歧义。)
        (Some(a), Some(t)) if t == JWT_BEARER_ASSERTION => {
            // 消歧按 `sub` 是否 **`spiffe://` scheme 前缀**(评审 codex H2 fail-closed):凡带 spiffe:// 前缀
            // 一律走 SPIFFE 路径——即便 trust domain 畸形(空/含端口)也**不回落 OIDC**(在 SPIFFE 路径
            // fail-closed 拒),杜绝"畸形 SPIFFE ID 逃逸到 OIDC 路径"。无 spiffe:// 前缀 → OIDC(OIDC 路径
            // 另有纵深:见到 spiffe:// sub 直接拒)。
            let is_spiffe = peek_kid_iss_sub(a)
                .and_then(|(_, _, sub)| sub)
                .is_some_and(|s| s.starts_with("spiffe://"));
            let auth = if is_spiffe {
                authenticate_workload_spiffe(state, a, as_issuer, &tenant_id).await
            } else {
                authenticate_workload_oidc(state, a, as_issuer, &tenant_id).await
            };
            match auth {
                Ok(id) => id,
                Err(resp) => return audit_workload_rejection(state, &tenant, None, resp).await,
            }
        }
        // aws_sigv4_caller_identity:assertion=JSON 编码的 SigV4Assertion(预签名 GetCallerIdentity)。
        (Some(a), Some(t)) if t == SIGV4_ASSERTION => {
            match authenticate_workload_sigv4(state, a, as_issuer, &tenant_id).await {
                Ok(id) => id,
                Err(resp) => return audit_workload_rejection(state, &tenant, None, resp).await,
            }
        }
        _ => {
            // service 注册认证与受管 workload 身份均未匹配时 fail closed。
            return audit_workload_rejection(
                state,
                &tenant,
                None,
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "client_credentials requires registered service authentication or a supported workload identity",
                )
                .into_response(),
            )
            .await;
        }
    };

    if req
        .client_id
        .as_deref()
        .is_some_and(|client_id| client_id != identity.client_id)
    {
        return audit_workload_rejection(
            state,
            &tenant,
            Some(&identity.client_id),
            crate::token::invalid_client_response(
                headers,
                StatusCode::UNAUTHORIZED,
                "client_id does not match the authenticated workload identity",
            ),
        )
        .await;
    }

    // 认证已产出 WorkloadIdentity;共享 2LO 签发尾(client lookup → 校验 → aud/scope → DPoP → 签发)。
    issue_2lo(
        state,
        headers,
        req,
        as_issuer,
        &tenant,
        AuthenticatedTwoLoSubject::agent(&identity.client_id),
    )
    .await
}

/// X.509-SVID / mTLS 专用前导(spec 012 §1.4 / C5.7,P3)——**不复用 `handle()` 的 Host 派生**(评审 B2:
/// mTLS 域名 `mtls.<host>` 经 `derive_issuer` 必 HostMismatch 400)。仅 SelfHosted 可达(token handler 已按
/// `mtls_svid_enabled`[from_env_aws 已 SelfHosted 门控] gate)。身份来自**连接层已验链证书**(评审 H1 排他:
/// 忽略 body client_assertion)。`as_issuer` = 配置域 issuer;`tenant`="";`tenant_id`="default"。
pub async fn handle_x509(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    client_cert_pem: &str,
) -> axum::response::Response {
    // as_issuer 从**配置域**派生(SelfHosted 的 configured_host),**绝不** derive_issuer(mtls_host)(评审 B2)。
    let Some(issuer) = crate::hostutil::self_hosted_issuer(&state.form) else {
        // 仅 SelfHosted 可达(mtls_svid_enabled 已门控);Saas 到此 = fail-closed。
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "X.509-mTLS 仅 SelfHosted 形态可用",
        )
        .into_response();
    };
    let as_issuer = issuer.as_str();
    // SelfHosted 单租户:store 物理分区 tenant=""(透传)、jti 反查 tenant_id="default"。
    let tenant = String::new();
    let tenant_id = "default".to_string();

    // 从已验链叶子证书取唯一 SPIFFE ID(SAN URI;0/多 URI / 非 spiffe / 畸形 → fail-closed)。
    let svid = match agent_auth_workload::spiffe_id_from_leaf_pem(client_cert_pem) {
        Ok(s) => s,
        Err(_) => {
            return audit_workload_rejection(
                state,
                &tenant,
                None,
                err(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端证书无唯一 SPIFFE ID(SAN URI)",
                )
                .into_response(),
            )
            .await
        }
    };
    // 纵深 validity 复核(API Gateway 握手已校,此为纵深;字符串已解成 Unix 秒)。
    let now = crate::token::current_unix_secs_pub();
    if now + CLOCK_SKEW_SECS < svid.not_before || now - CLOCK_SKEW_SECS > svid.not_after {
        return audit_workload_rejection(
            state,
            &tenant,
            None,
            err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端证书不在有效期内",
            )
            .into_response(),
        )
        .await;
    }
    // 匹配 SpiffeX509 信任绑定(trust domain 锚 + pattern;tenant 隔离)→ WorkloadIdentity。
    let bindings = match state.workload_trust.list_by_tenant(&tenant_id).await {
        Ok(entries) => trust_bindings(entries),
        Err(_) => {
            return audit_workload_rejection(
                state,
                &tenant,
                None,
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "信任绑定存储暂不可用",
                )
                .into_response(),
            )
            .await
        }
    };
    let identity =
        match agent_auth_workload::match_spiffe_x509(&bindings, &tenant_id, &svid.spiffe_id) {
            Ok(id) => id,
            Err(_) => {
                return audit_workload_rejection(
                    state,
                    &tenant,
                    None,
                    err(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "无匹配的 X.509-SVID 信任绑定",
                    )
                    .into_response(),
                )
                .await
            }
        };
    issue_2lo(
        state,
        headers,
        req,
        as_issuer,
        &tenant,
        AuthenticatedTwoLoSubject::agent(&identity.client_id),
    )
    .await
}

/// 2LO 签发共享尾(OIDC / SigV4 / SPIFFE-JWT / X.509 认证后共用):client lookup → workload/tombstone 校验
/// → 限流/背压闸 → aud(∈allowed_resources)→ scope(⊆allowed_scopes)→ DPoP 绑定 → 签 access token。
async fn issue_2lo(
    state: &AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
    as_issuer: &str,
    tenant: &str,
    subject: AuthenticatedTwoLoSubject<'_>,
) -> axum::response::Response {
    let client_id = subject.client_id;
    let subject_kind = subject.kind;
    // 7. workload 据认证后的 client_id 读取一次 ClientRecord；service 复用刚完成 client auth 的
    // 同一注册快照，避免凭据按旧版本认证、授权策略却从新版本读取的 TOCTOU。
    // **用 `tenant`(store 物理分区,flag 关=空)非 `tenant_id`(jti 反查用,空时="default")**——
    // client 落在 tenant 分区,不是 jti 的 "default" 命名(codex M1 两者语义不同,别混用)。
    let client = if let Some(client) = subject.client_snapshot {
        client.clone()
    } else {
        match state.clients.get(tenant, client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return audit_verified_2lo_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "映射 client 不存在",
                    )
                    .into_response(),
                )
                .await
            }
            Err(crate::ports::StoreError::Transient(_)) => {
                return audit_verified_2lo_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "存储瞬时不可用",
                    )
                    .into_response(),
                )
                .await
            }
            Err(_) => {
                return audit_verified_2lo_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "存储错误",
                    )
                    .into_response(),
                )
                .await
            }
        }
    };
    // tombstone 闸(spec 005 §9.3,C10.5):回收中的 2LO client 拒绝签发。
    if client.is_tombstoned() {
        return audit_verified_2lo_rejection(
            state,
            tenant,
            client_id,
            subject_kind,
            err(StatusCode::BAD_REQUEST, "invalid_client", "client 已回收").into_response(),
        )
        .await;
    }
    let type_matches = match subject_kind {
        TwoLoSubjectKind::Agent => client.is_workload(),
        TwoLoSubjectKind::Service => client.is_confidential_auth_client(),
    };
    if !type_matches {
        return audit_verified_2lo_rejection(
            state,
            tenant,
            client_id,
            subject_kind,
            err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client type does not match the authenticated 2LO subject",
            )
            .into_response(),
        )
        .await;
    }

    // per-client 限流(C10.7 / spec 005 §3.1):**认证后**按 `client_id`。workload 已过
    // 平台身份认证与信任绑定，service 已过注册认证，均不可由请求方任意伪造。fail-open。
    if let Some(resp) = crate::ratelimit_gate::check(state, tenant, client_id).await {
        return audit_2lo_issuance_rejection(state, tenant, client_id, subject_kind, resp).await;
    }
    // 逐租户 ECC Sign 公平闸(spec 020 §3.1 / C10.14):全局闸之前(默认关字节等价)。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_tenant_gate(state, tenant).await {
        return audit_2lo_issuance_rejection(state, tenant, client_id, subject_kind, resp).await;
    }
    // 全局 KMS Sign 前置并发闸(spec 005 §1.4 / C10.2;默认关)。2LO 无 code lease,超额直接 503 退避。
    if let Some(resp) = crate::ratelimit_gate::kms_sign_gate(state).await {
        return audit_2lo_issuance_rejection(state, tenant, client_id, subject_kind, resp).await;
    }

    // 8. 2LO audience(评审 H2:不复用 select_audience;请求 resource ∈ allowed_resources)。
    let aud = match req.resource.as_deref() {
        Some(r) => {
            if !client.allowed_resources.iter().any(|a| a == r) {
                return audit_2lo_issuance_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_target",
                        "resource 不在该 2LO client 的 allowed_resources",
                    )
                    .into_response(),
                )
                .await;
            }
            r.to_string()
        }
        None => match client.allowed_resources.as_slice() {
            [single] => single.clone(),
            _ => {
                return audit_2lo_issuance_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_target",
                        "省略 resource 但 allowed_resources 非唯一(须显式指定)",
                    )
                    .into_response(),
                )
                .await
            }
        },
    };

    // 9. scope(C7.5:请求 scope 恒 ⊆ allowed_scopes)。**fail-closed**(评审 codex HIGH/Kiro:空 allowed_scopes
    //    不再"不限",而是无 scope 可授——请求任何 scope 都拒;与 allowed_resources 对称)。
    let scope_str = match req.scope.as_deref() {
        Some(s) => {
            let allowed: std::collections::HashSet<&str> =
                client.allowed_scopes.iter().map(String::as_str).collect();
            // 空集合 allowed → 任何非空请求 scope 都不在其中 → 拒(fail-closed)。
            if s.split_whitespace().any(|sc| !allowed.contains(sc)) {
                return audit_2lo_issuance_rejection(
                    state,
                    tenant,
                    client_id,
                    subject_kind,
                    err(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "请求 scope 超出该 2LO client 的 allowed_scopes(空 allowed_scopes = 不授任何 scope)",
                    )
                    .into_response(),
                )
                .await;
            }
            s.to_string()
        }
        // 省略 scope:授予该 2LO client 注册的全部 allowed_scopes(可为空)。
        None => client.allowed_scopes.join(" "),
    };

    // DPoP 绑定(spec 010 §5.2):2LO 也可 sender-constrained(RFC 9449 允许 client_credentials + DPoP)。
    // 有 proof → cnf.jkt;无 → bearer;失败/重放 → 拒(不降级)。
    let dpop_jkt = match crate::dpop::resolve_dpop_binding(
        state,
        headers,
        tenant,
        as_issuer,
        client.require_dpop,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => {
            return audit_2lo_issuance_rejection(state, tenant, client_id, subject_kind, resp).await
        }
    };

    // 10. 签 2LO token:sub=client_id、sub_type=agent|service、
    // auth_grant="client_credentials"、无 pairwise/act/grant_id/auth_time。
    // 2LO **不落 jti→user_id 映射**(无 user_id、不可作 subject_token,评审 Kiro/codex);jti claim 仍有(审计/关联)。
    let now = crate::token::current_unix_secs_pub();
    let tenant_signer = match crate::tenant_keys::signer_or_503(state, tenant).await {
        Ok(signer) => signer,
        Err(response) => {
            return audit_2lo_issuance_rejection(state, tenant, client_id, subject_kind, response)
                .await
        }
    };
    let jwt = match crate::token::sign_tenant_access_token(
        state,
        headers,
        tenant_signer.as_ref(),
        &AccessTokenClaims {
            issuer: as_issuer,
            sub: client_id, // 2LO:sub=client_id(不做 pairwise,§2.8)
            aud: &aud,
            client_id,
            scope: &scope_str,
            jti: &crate::token::new_jti(state),
            auth_grant: "client_credentials",
            sub_type: subject_kind.sub_type(),
            authorization_details: &[], // 2LO client_credentials 无 RAR(无用户授权,spec 010 §4 仅 3LO code flow)
            cnf_jkt: dpop_jkt.as_deref(),
            auth_time: None,
            acr: None,
            now,
        },
        crate::security_event::SecurityActor::system("workload-token"),
    )
    .await
    {
        Ok(j) => j,
        Err(crate::token::TokenSignError::Transient) => {
            // 签名瞬时失败(KMS throttle)→ 503 + Retry-After(C10.2 退避重试)。
            return audit_2lo_issuance_rejection(
                state,
                tenant,
                client_id,
                subject_kind,
                crate::token::err_retry_after(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "签名瞬时失败(KMS throttle),请退避重试",
                    1,
                )
                .into_response(),
            )
            .await;
        }
        Err(crate::token::TokenSignError::TooLarge) => {
            return audit_2lo_issuance_rejection(
                state,
                tenant,
                client_id,
                subject_kind,
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    crate::token::TOKEN_TOO_LARGE_ERROR_DESCRIPTION,
                )
                .into_response(),
            )
            .await
        }
        Err(crate::token::TokenSignError::IssuerMismatch) => {
            return audit_2lo_issuance_rejection(
                state,
                tenant,
                client_id,
                subject_kind,
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "issuer does not belong to tenant",
                )
                .into_response(),
            )
            .await
        }
        Err(crate::token::TokenSignError::Permanent) => {
            return audit_2lo_issuance_rejection(
                state,
                tenant,
                client_id,
                subject_kind,
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "签名失败",
                )
                .into_response(),
            )
            .await
        }
    };

    // 记 client 最后使用日(spec 005 §9.2,C10.5;2LO client 无 refresh/session,last_used 是**唯一**存活
    // 信号——评审强调此路径最须准确追踪,否则活跃 2LO client 被误回收)。
    crate::token::touch_client_last_used(state, tenant, client_id, now).await;
    let audit = match subject_kind {
        TwoLoSubjectKind::Agent => {
            crate::security_event::SecurityEventDraft::workload_authentication(
                tenant,
                Some(client_id),
                crate::security_event::SecurityEventOutcome::Success,
            )
        }
        TwoLoSubjectKind::Service => {
            crate::security_event::SecurityEventDraft::service_token_issuance(
                tenant,
                client_id,
                crate::security_event::SecurityEventOutcome::Success,
            )
        }
    };
    state.record_security_event(audit).await;
    // 2LO 不发 refresh(RFC 6749 §4.4.3 SHOULD NOT)、不发 id_token(评审 M2)。
    Json(TokenResponse {
        access_token: jwt,
        token_type: crate::token::token_type_for(dpop_jkt.as_deref()),
        expires_in: ACCESS_TTL,
        scope: (!scope_str.is_empty()).then_some(scope_str),
        refresh_token: None,
        id_token: None,
        resource: None,
    })
    .into_response()
}

/// 按 `kid` 从平台 JWKS 选一把 key(kid 命中;无 kid 则仅当单 key 时取它)。缓存未命中时 force-refresh 一次。
async fn select_platform_key(
    state: &AppState,
    jwks_uri: &str,
    unverified_kid: Option<&str>,
) -> Result<crate::ports::PlatformJwk, axum::response::Response> {
    let unavailable = || {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "平台 JWKS 暂不可用",
        )
        .into_response()
    };
    let select = |keys: &[crate::ports::PlatformJwk]| -> Option<crate::ports::PlatformJwk> {
        match unverified_kid {
            Some(kid) => keys.iter().find(|k| k.kid.as_deref() == Some(kid)).cloned(),
            None if keys.len() == 1 => keys.first().cloned(),
            None => None,
        }
    };
    let cached = state
        .jwks_fetcher
        .fetch(jwks_uri)
        .await
        .map_err(|_| unavailable())?;
    if let Some(k) = select(&cached) {
        return Ok(k);
    }
    // 缓存未命中(轮换)→ force-refresh 一次(限一次,防重取风暴)。
    let fresh = state
        .jwks_fetcher
        .fetch_fresh(jwks_uri)
        .await
        .map_err(|_| unavailable())?;
    select(&fresh).ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "平台 JWKS 无匹配 kid(force-refresh 后仍无)",
        )
        .into_response()
    })
}

/// 用一把平台 JWK **按 kty/alg 选验签器**验 compact JWT(spec 012 §1.4-pre.4:alg pin 防混淆)。
/// EC(kty=EC 或 alg=ES256)→ ES256(x/y);RSA(kty=RSA/None 且非 ES256)→ RS256(n/e)。
/// 返回已验签 claims;失败一律 `invalid_client`(不泄露细节)。
// Err=axum Response(本 crate 统一惯例:HTTP 层 helper 直接返可 IntoResponse 的错误,不 box——与
// authenticate_workload_* 等同款;此处 Ok 类型小故触发 lint,allow 保持一致而非引入 box 不一致)。
#[allow(clippy::result_large_err)]
fn verify_with_platform_key(
    assertion: &str,
    key: &crate::ports::PlatformJwk,
    unverified_kid: Option<&str>,
) -> Result<serde_json::Value, axum::response::Response> {
    let reject = || err(StatusCode::UNAUTHORIZED, "invalid_client", "断言验签失败").into_response();
    // **混合字段 fail-closed(评审 codex M1)**:一把 JWK 同时带 RSA(n/e)与 EC(x/y)字段是畸形/歧义
    // 的——kty 判定可能被诱导走错验签器。同时含二者一律拒(绝不猜)。
    let has_rsa = !key.n.is_empty() || !key.e.is_empty();
    let has_ec = key.x.is_some() || key.y.is_some();
    if has_rsa && has_ec {
        return Err(reject());
    }
    // kty/alg 判定:EC(kty=EC 或 alg=ES256 或有 x/y)走 ES256;否则 RS256。绝不交叉(alg 混淆防线)。
    let is_ec = key.kty.as_deref() == Some("EC") || key.alg.as_deref() == Some("ES256") || has_ec;
    if is_ec {
        // EC 分派下若 alg 明确声称 RS256 / 或带 RSA 字段 → 矛盾,拒(纵深)。
        if key.alg.as_deref() == Some("RS256") || has_rsa {
            return Err(reject());
        }
        let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
            return Err(reject()); // 声称 EC 却无 x/y
        };
        let v = agent_auth_workload::verify_es256(assertion, x, y, unverified_kid)
            .map_err(|_| reject())?;
        Ok(v.claims)
    } else {
        // RSA 分派下若 alg 明确声称 ES256 → 矛盾,拒。
        if key.alg.as_deref() == Some("ES256") {
            return Err(reject());
        }
        let v = verify_rs256(assertion, &key.n, &key.e, unverified_kid).map_err(|_| reject())?;
        Ok(v.claims)
    }
}

/// 已验签平台 token 的**共享时间前置**(spec 012 §1.4:OIDC/SPIFFE 复用,防漂移):nbf 未生效拒、
/// iat 必需、最长寿命上限拒长命。`now` 未并入 skew(内部对 nbf 加 skew)。
// Err=axum Response(本 crate 统一惯例;Ok=() 故触发 lint,allow 保持一致不引入 box 不一致)。
#[allow(clippy::result_large_err)]
fn check_platform_time_claims(
    claims: &serde_json::Value,
    now: i64,
) -> Result<i64, axum::response::Response> {
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now + CLOCK_SKEW_SECS {
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "断言 nbf 未生效",
            )
            .into_response());
        }
    }
    let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "断言缺 iat(无从界定寿命,拒)",
        )
        .into_response());
    };
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(iat);
    if exp - iat > MAX_PLATFORM_TOKEN_LIFETIME {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "断言寿命过长(拒长命平台 token)",
        )
        .into_response());
    }
    Ok(iat)
}

/// SPIFFE JWT-SVID 认证核心(spec 012 §1.4,C5.7):assertion(JWT-SVID)→ 按 sub 解 trust domain 选绑定
/// → 该 trust bundle JWKS 本地验签(ES256/RS256,alg pin)→ 共享时间前置 → authorize_spiffe_jwt。
/// **信任锚 = 从 sub 解出的 trust domain,绝不用 iss**(评审 High)。
pub(crate) async fn authenticate_workload_spiffe(
    state: &AppState,
    assertion: &str,
    as_issuer: &str,
    tenant_id: &str,
) -> Result<agent_auth_workload::WorkloadIdentity, axum::response::Response> {
    use agent_auth_workload::{
        authorize_spiffe_jwt, spiffe_id_matches, spiffe_trust_domain, SpiffeAuthError,
    };
    let bad = || err(StatusCode::BAD_REQUEST, "invalid_client", "断言非合法 JWT").into_response();
    let (unverified_kid, _iss, unverified_sub) = peek_kid_iss_sub(assertion).ok_or_else(bad)?;
    // sub 须为合法 SPIFFE ID(未验签,仅用于**选绑定**;真信任在验签 + authorize_spiffe_jwt)。
    let sub = unverified_sub.ok_or_else(|| {
        err(StatusCode::UNAUTHORIZED, "invalid_client", "SVID 缺 sub").into_response()
    })?;
    let td = spiffe_trust_domain(&sub).ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "sub 非合法 SPIFFE ID(无 spiffe:// / 空 trust domain)",
        )
        .into_response()
    })?;
    // typ 防混淆(spec 012 §1.4,MUST NOT 接受 at+jwt):`at+jwt` 是本 AS access token 专用 typ;JWT-SVID
    // header typ 应为 JWT/JOSE。若断言 typ=at+jwt(大小写不敏感),拒(不当作 SVID;纵深于 bundle-key 隔离之上)。
    if peek_header_typ_lower(assertion).as_deref() == Some("at+jwt") {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "SVID header typ=at+jwt(本 AS access token 专用),拒(防 token 混淆)",
        )
        .into_response());
    }
    let bindings = list_bindings(state, tenant_id).await?;
    // 未验签 sub 仅用于候选缩小；必须恰好一条 tenant + trust-domain + 完整 ID pattern 候选。
    // 多候选时绝不按存储顺序取第一条，否则 client 映射与验签 bundle 都会变成非确定行为。
    let candidates: Vec<_> = bindings
        .iter()
        .filter(|binding| {
            binding.tenant_id == tenant_id
                && matches!(
                    &binding.mechanism,
                    TrustMechanism::SpiffeJwt {
                        trust_domain,
                        spiffe_id_pattern,
                        ..
                    } if trust_domain == td && spiffe_id_matches(spiffe_id_pattern, &sub)
                )
        })
        .cloned()
        .collect();
    let candidate = match candidates.as_slice() {
        [candidate] => candidate.clone(),
        [] => {
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "无匹配 SPIFFE workload 信任绑定(trust domain/pattern)",
            )
            .into_response())
        }
        _ => {
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "多条 SPIFFE workload 信任绑定同时命中(拒绝非确定映射)",
            )
            .into_response())
        }
    };
    let TrustMechanism::SpiffeJwt { jwks_uri, .. } = &candidate.mechanism else {
        unreachable!("SPIFFE candidate filtering preserves the mechanism");
    };
    let key = select_platform_key(state, jwks_uri, unverified_kid.as_deref()).await?;
    let claims = verify_with_platform_key(assertion, &key, unverified_kid.as_deref())?;
    let now = crate::token::current_unix_secs_pub();
    let issued_at = check_platform_time_claims(&claims, now)?;
    if !state.region.accepts_external_issued_at(issued_at) {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "SVID predates this Region activation",
        )
        .into_response());
    }
    match authorize_spiffe_jwt(
        &claims,
        as_issuer,
        now - CLOCK_SKEW_SECS,
        std::slice::from_ref(&candidate),
        tenant_id,
    ) {
        Ok(id) => Ok(id),
        Err(SpiffeAuthError::AudNotThisAs) => Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "SVID aud 非本 AS(绝不放宽)",
        )
        .into_response()),
        Err(SpiffeAuthError::Expired) => {
            Err(err(StatusCode::UNAUTHORIZED, "invalid_client", "SVID 已过期").into_response())
        }
        Err(_) => Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "SVID 无匹配信任绑定或缺 claim",
        )
        .into_response()),
    }
}

/// 列该 tenant 的 workload 信任绑定(OIDC/SPIFFE 共用;存储错误映射响应)。
async fn list_bindings(
    state: &AppState,
    tenant_id: &str,
) -> Result<Vec<agent_auth_workload::TrustBinding>, axum::response::Response> {
    match state.workload_trust.list_by_tenant(tenant_id).await {
        Ok(entries) => Ok(trust_bindings(entries)),
        Err(crate::ports::StoreError::Transient(_)) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "存储瞬时不可用",
        )
        .into_response()),
        Err(_) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "存储错误",
        )
        .into_response()),
    }
}

fn trust_bindings(
    entries: Vec<crate::ports::WorkloadTrustEntry>,
) -> Vec<agent_auth_workload::TrustBinding> {
    entries.into_iter().map(|entry| entry.binding).collect()
}

/// workload_oidc_jwt 认证核心(2LO 与 token-exchange actor 共用):assertion → 验签 → OIDC 决策 → WorkloadIdentity。
/// 步骤 1-6(见 handle 原注释):未验签取 iss 选信任绑定拿 jwks_uri(绝不取 jku/x5u)→ 按 kid 选 key
/// (轮换 force-refresh 一次)→ 验签 → nbf/skew/最长寿命 → authorize_oidc(aud=本AS/exp/iss+sub 匹配)。
pub(crate) async fn authenticate_workload_oidc(
    state: &AppState,
    assertion: &str,
    as_issuer: &str,
    tenant_id: &str,
) -> Result<agent_auth_workload::WorkloadIdentity, axum::response::Response> {
    let Some((unverified_kid, unverified_iss)) = peek_kid_iss(assertion) else {
        return Err(
            err(StatusCode::BAD_REQUEST, "invalid_client", "断言非合法 JWT").into_response(),
        );
    };
    let bindings = list_bindings(state, tenant_id).await?;
    let Some(jwks_uri) = bindings.iter().find_map(|b| match &b.mechanism {
        TrustMechanism::Oidc {
            platform_issuer,
            jwks_uri,
            ..
        } if *platform_issuer == unverified_iss => Some(jwks_uri.clone()),
        _ => None,
    }) else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "无匹配 workload 信任绑定",
        )
        .into_response());
    };
    let key = select_platform_key(state, &jwks_uri, unverified_kid.as_deref()).await?;
    // 验签(按 kty/alg 选 ES256/RS256;平台多 RS256,但支持 EC 平台,alg pin 防混淆)。
    let claims = verify_with_platform_key(assertion, &key, unverified_kid.as_deref())?;
    let now = crate::token::current_unix_secs_pub();
    let issued_at = check_platform_time_claims(&claims, now)?;
    if !state.region.accepts_external_issued_at(issued_at) {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "workload assertion predates this Region activation",
        )
        .into_response());
    }
    match authorize_oidc(
        &claims,
        as_issuer,
        now - CLOCK_SKEW_SECS,
        &bindings,
        tenant_id,
    ) {
        Ok(id) => Ok(id),
        Err(OidcAuthError::AudNotThisAs) => Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            OIDC_AUDIENCE_ERROR_DESCRIPTION,
        )
        .into_response()),
        Err(OidcAuthError::Expired) => {
            Err(err(StatusCode::UNAUTHORIZED, "invalid_client", "断言已过期").into_response())
        }
        Err(_) => Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "无匹配信任绑定或缺 claim",
        )
        .into_response()),
    }
}

/// SigV4/STS 认证核心(spec 012 C5.2/C5.3/C5.4):assertion(JSON 编码 SigV4Assertion)→ 前校组合门
/// (audience 被签名 + TTL + host allowlist)→ 熔断器 gate → 转发 STS(sts_caller)→ 解析 caller ARN →
/// `match_sigv4` 映射 client_id → WorkloadIdentity。
///
/// **fail-closed**:`sts_caller=None`(SigV4 未启用)→ 拒;前校任一门失败 → 拒(不转发,省 STS 配额);
/// 熔断打开 → 快速 503;STS 拒(签名无效)→ 拒;STS 瞬时失败 → 熔断计数 + 503。
/// replay 一次性缓存(C5.3②)在有 replay-store 时接线(P2 IO;当前 mock/真机未落 replay 表则不做,
/// 靠短 TTL 限重放窗——记 backlog)。
async fn authenticate_workload_sigv4(
    state: &AppState,
    assertion_json: &str,
    as_issuer: &str,
    tenant_id: &str,
) -> Result<agent_auth_workload::WorkloadIdentity, axum::response::Response> {
    use agent_auth_workload::{match_sigv4, validate_sigv4_pre_sts, Decision, SigV4Assertion};

    // sts_caller=None → SigV4 路径未启用,fail-closed 拒。
    let Some(sts) = state.sts_caller.as_ref() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "aws_sigv4_caller_identity 未在本部署启用(fail-closed)",
        )
        .into_response());
    };
    // 解析 assertion JSON → SigV4Assertion。
    let Ok(mut assertion) = serde_json::from_str::<SigV4Assertion>(assertion_json) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "SigV4 client_assertion 非合法 SigV4Assertion JSON",
        )
        .into_response());
    };
    // **头名归一小写**(评审 LOW,互操作):前校/解析全按小写键查(authorization/x-amz-date/audience 头)。
    // SigV4 规范 canonical case 是首字母大写(Authorization/Host),客户端若原样发会被前校误拒。
    // 归一后既容错又不放松安全(值不变、SignedHeaders 本就小写)。
    assertion.headers = assertion
        .headers
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    // 前校组合门(C5.2/C5.3:audience 被签名+值=本AS / TTL / host allowlist / signature 段)。
    let now = crate::token::current_unix_secs_pub();
    let validated = match validate_sigv4_pre_sts(&assertion, SIGV4_AUDIENCE_HEADER, as_issuer, now)
    {
        Ok(v) => v,
        Err(_reason) => {
            // 前校失败一律 invalid_client(不泄露具体门,避免探测)。
            return Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "SigV4 前校失败(audience 未签名/值不符 / 超 TTL / STS host 不合法)",
            )
            .into_response());
        }
    };
    if !state.region.accepts_external_issued_at(validated.issued_at) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "SigV4 assertion predates this Region activation",
        )
        .into_response());
    }
    // **一次性 replay 缓存**(C5.3②):key=HMAC(server_secret, 签名段);窗内重放拒。有 replay_store 才做
    // (None 退化到靠短 TTL 限窗)。**在转发 STS 前** check-and-set,省重放请求的 STS 外呼。
    if let Some(rs) = state.replay_store.as_ref() {
        let key = agent_auth_authn::authz_session::session_token_hash(
            &state.server_secret,
            &validated.signature,
        );
        // TTL = 预签名 TTL 窗上限(60+30 skew);窗过后同签名不再有效、缓存可 GC。
        let replay_exp = now + agent_auth_workload::SIGV4_MAX_AGE_SECS + 30;
        match rs.check_and_set(tenant_id, &key, replay_exp).await {
            Ok(true) => {} // 首次,接受
            Ok(false) => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "SigV4 预签名请求重放(一次性缓存命中)",
                )
                .into_response());
            }
            Err(_) => {
                // replay 存储错误 → fail-closed 拒(不冒险放行可能的重放)。
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "replay 缓存暂不可用",
                )
                .into_response());
            }
        }
    }
    // 熔断器 gate(C5.4):打开期快速失败(503),不外呼。
    {
        let mut cb = state.sts_circuit.lock().await;
        if cb.on_request(now) == Decision::Reject {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "STS 依赖熔断中,请稍后重试",
            )
            .into_response());
        }
    }
    // 转发 STS(前校已过)。据结果推进熔断状态。
    let sts_result = sts.get_caller_identity(&assertion).await;
    let identity_opt = match sts_result {
        Ok(opt) => {
            state.sts_circuit.lock().await.on_success();
            opt
        }
        Err(crate::ports::StoreError::Transient(_)) => {
            state.sts_circuit.lock().await.on_failure(now);
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "STS 瞬时不可用",
            )
            .into_response());
        }
        Err(_) => {
            // 非瞬时 STS/存储错误:**仍计熔断失败**(评审 codex+Kiro MEDIUM:否则 HalfOpen 探针遇
            // Permanent 既不 on_success 也不 on_failure → probe_in_flight 永久卡死 → SigV4 路径永久 503)。
            // 任何已放行(含 half-open 探针)的 STS 调用 MUST 有确定状态迁移;Permanent 也是依赖侧问题,
            // on_failure(reopen/计数)安全且释放探针。返 500(区别于 Transient 的 503,便于归因)。
            state.sts_circuit.lock().await.on_failure(now);
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "STS 调用错误",
            )
            .into_response());
        }
    };
    // STS 拒(签名无效 / 响应不可解析)→ Ok(None) → 认证失败。
    let Some(caller) = identity_opt else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "STS 未验证通过该 SigV4 断言",
        )
        .into_response());
    };
    // 信任绑定映射(caller ARN + account → client_id)。
    let bindings = match state.workload_trust.list_by_tenant(tenant_id).await {
        Ok(entries) => trust_bindings(entries),
        Err(crate::ports::StoreError::Transient(_)) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "存储瞬时不可用",
            )
            .into_response())
        }
        Err(_) => {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "存储错误",
            )
            .into_response())
        }
    };
    match match_sigv4(&bindings, tenant_id, &caller.account, &caller.arn) {
        Ok(id) => Ok(id),
        Err(_) => Err(err(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "caller ARN 无匹配 workload 信任绑定",
        )
        .into_response()),
    }
}

/// token-exchange 的**发起 actor 身份**(spec 011 C7.2):复用 workload_oidc_jwt 认证 `actor_token`。
/// actor = **已认证 workload**,不是客户端自称、不是裸 RS-bound access token(评审:token 转用面)。
/// 须 `actor_token_type = jwt-bearer`(平台 OIDC JWT);其它类型(含标准 access_token)P1 拒。
pub(crate) async fn authenticate_actor(
    state: &AppState,
    _headers: &HeaderMap,
    req: &TokenRequest,
    as_issuer: &str,
    tenant_id: &str,
) -> Result<agent_auth_workload::WorkloadIdentity, axum::response::Response> {
    let (Some(actor_token), Some(actor_type)) =
        (req.actor_token.as_deref(), req.actor_token_type.as_deref())
    else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token-exchange 缺 actor_token / actor_token_type(actor 须为已认证 workload)",
        )
        .into_response());
    };
    if actor_type != JWT_BEARER_ASSERTION {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "actor_token_type 仅支持 jwt-bearer(平台 OIDC JWT);标准 access_token 作 actor 未支持(防 token 转用)",
        )
        .into_response());
    }
    authenticate_workload_oidc(state, actor_token, as_issuer, tenant_id).await
}

// `tenant_from_issuer` 已退役(spec 020 §2.3):tenant 一律经 `crate::tenant::tenant_or_400(headers, form)`
// 从入站 Host 派生(codex M1:替代硬编码 "default"),不再有单独的 issuer→tenant helper。

/// 未验签地窥探 JWT 的 header.kid + payload.iss(仅用于选信任绑定;验签前不信任任何 claim)。
fn peek_kid_iss(jwt: &str) -> Option<(Option<String>, String)> {
    let (kid, iss, _sub) = peek_kid_iss_sub(jwt)?;
    let iss = iss?; // OIDC 路径 iss 必需
    Some((kid, iss))
}

/// 未验签窥探 JWT `header.typ`,**规范化为小写**(仅用于 SPIFFE 路径拒 `at+jwt` 混淆;验签前只读 header)。
/// typ 是媒体类型,**大小写不敏感**(RFC 7515 §4.1.9);故小写归一比对,防 `AT+JWT`/`At+Jwt` 绕过(评审
/// codex/Kiro H1)。非字符串(数组/对象)→ None(调用方按"是否 ==at+jwt"判,None 不等于 at+jwt)。
fn peek_header_typ_lower(jwt: &str) -> Option<String> {
    let h = jwt.split('.').next()?;
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    header
        .get("typ")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase())
}

/// 未验签窥探 `header.kid` + `payload.iss` + `payload.sub`(仅用于**选信任绑定**;验签前不信任任何 claim,
/// spec 012 §1.4:SPIFFE 路径按 sub 解 trust domain 选绑定,故须 sub)。iss/sub 各可缺(返 None)。
fn peek_kid_iss_sub(jwt: &str) -> Option<(Option<String>, Option<String>, Option<String>)> {
    let mut parts = jwt.split('.');
    let (h, p) = (parts.next()?, parts.next()?);
    parts.next()?; // 必须有签名段
    if parts.next().is_some() {
        return None; // 多于 3 段非法
    }
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    let kid = header.get("kid").and_then(|v| v.as_str()).map(String::from);
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(String::from);
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(String::from);
    Some((kid, iss, sub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ClientStore, Signer};
    use base64::engine::general_purpose::STANDARD;

    fn service_request(resource: &str, scope: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "client_credentials".into(),
            code: None,
            code_verifier: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            resource: Some(resource.into()),
            refresh_token: None,
            scope: Some(scope.into()),
            client_assertion: None,
            client_assertion_type: None,
            assertion: None,
            authorization_details: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            device_code: None,
            auth_req_id: None,
            grant_ref: None,
        }
    }

    async fn assert_legacy_migration_uses_persisted_policy(cas_loses: bool) {
        const HOST: &str = "auth.example.com";
        const OLD_RS: &str = "https://old-policy.example.com";
        const NEW_RS: &str = "https://new-policy.example.com";

        let state = AppState::dev(HOST);
        let stale = ClientRecord {
            client_id: "legacy-service".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("old-secret".into()),
            client_type: Some("confidential".into()),
            allowed_resources: vec![OLD_RS.into()],
            allowed_scopes: vec!["old:scope".into()],
            ..Default::default()
        };
        let now = crate::token::current_unix_secs_pub();
        let mut current = stale.clone();
        let presented_secret = if cas_loses {
            current.client_secret = None;
            current.client_secret_credentials = crate::credential::CredentialSet {
                current: Some(crate::credential::new_credential_record(
                    &state.server_secret,
                    crate::credential::CredentialKind::ClientSecret,
                    "",
                    "cred-current".into(),
                    current.client_id.clone(),
                    "new-secret",
                    now - 1,
                    now + 3600,
                    "test".into(),
                    None,
                )),
                version: 1,
                ..Default::default()
            };
            "new-secret"
        } else {
            "old-secret"
        };
        current.allowed_resources = vec![NEW_RS.into()];
        current.allowed_scopes = vec!["new:scope".into()];
        state.clients.put("", current).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, HOST.parse().unwrap());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("legacy-service:{presented_secret}"))
            )
            .parse()
            .unwrap(),
        );
        let response = try_handle_loaded_service(
            &state,
            &headers,
            &service_request(NEW_RS, "new:scope"),
            "https://auth.example.com",
            "",
            stale,
            true,
        )
        .await
        .expect("a registered service request is always handled");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let signer = state.tenant_keys.resolve("").await.unwrap();
        let jwks = signer
            .public_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::to_jwk)
            .collect::<Vec<_>>();
        let verified = crate::verify::verify_access_token(access_token, &jwks, now).unwrap();
        assert_eq!(verified.claims["aud"], serde_json::json!([NEW_RS]));
        assert_eq!(verified.claims["scope"], "new:scope");
        assert_eq!(verified.claims["sub"], "legacy-service");
        assert_eq!(
            verified.claims["https://a-auth.com/c"]["sub_type"],
            "service"
        );
    }

    #[tokio::test]
    async fn legacy_migration_issues_service_tokens_from_persisted_authenticated_policy_snapshots()
    {
        assert_legacy_migration_uses_persisted_policy(false).await;
        assert_legacy_migration_uses_persisted_policy(true).await;
        assert_legacy_migration_rejects_tombstone_cas_winner().await;
    }

    async fn assert_legacy_migration_rejects_tombstone_cas_winner() {
        const HOST: &str = "auth.example.com";
        const RS: &str = "https://service.example.com";

        let state = AppState::dev(HOST);
        let stale = ClientRecord {
            client_id: "legacy-service".into(),
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("old-secret".into()),
            client_type: Some("confidential".into()),
            allowed_resources: vec![RS.into()],
            allowed_scopes: vec!["service:read".into()],
            ..Default::default()
        };
        let mut tombstone = stale.clone();
        tombstone.tombstoned_at = Some(crate::token::current_unix_secs_pub());
        state.clients.put("", tombstone).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, HOST.parse().unwrap());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode("legacy-service:old-secret"))
                .parse()
                .unwrap(),
        );
        let response = try_handle_loaded_service(
            &state,
            &headers,
            &service_request(RS, "service:read"),
            "https://auth.example.com",
            "",
            stale,
            true,
        )
        .await
        .expect("a registered service request is always handled");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "invalid_client");
        assert!(body.get("access_token").is_none());
    }
}
