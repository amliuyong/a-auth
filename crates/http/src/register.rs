//! `POST /register`(C4 DCR,RFC 7591):动态客户端注册。
//!
//! P0:`open` 档(显式 opt-in 的公开注册)——匿名请求走 per-IP 桶；显式携带有效
//! `initial_access_token` 时走票据自身的 tenant-scoped 配额。两条路径都铸造 `client_id` +
//! `registration_access_token`,存 client 记录,返回注册响应(含 `registration_client_uri`)。
//!
//! ⚠️ 准入档默认随形态(自部署 open / SaaS 收紧,权威在 DESIGN §3.2);本 P0 端点默认要求
//! `AppState.dcr_mode`(§3.2 三档)分流:`Open` 无凭证放行，也接受受控 IAT，但显式无效 IAT 不降级匿名；
//! `InitialAccessToken` 须带有效 Bearer 票据；`SoftwareStatement` P0 显式拒(501)。**open 是显式 opt-in,
//! MUST NOT 匿名绕过收紧档**。RFC 7592 管理端点凭 `registration_access_token`(与 initial access token 域隔离)。
//! PKCE 分级策略、redirect 精确匹配等准入规则见 spec 002;本 handler 只做注册铸造 + 落库。

use agent_auth_client::{match_redirect, MatchResult, RedirectMode};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::admin::{
    apply_patch, apply_put, bearer, downgrade_error, finalize_update, hash_eq, reg_token_hash,
    view, ClientPatch, ClientUpdated, ClientView, UpdateOutcome,
};
use crate::ports::{
    ClientRecord, ClientStore, InitialAccessTokenStore, RateLimitStore, RegisteredClientJwks,
};
use crate::state::AppState;

/// DCR 请求(RFC 7591 metadata 子集,P0)。
#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// 客户端 redirect_uris(至少一个;PKCE code flow 必需)。
    pub redirect_uris: Vec<String>,
    /// OIDC application type. Missing values default to `web`.
    #[serde(default)]
    pub application_type: Option<String>,
    /// 认证方式(缺省 none=public+PKCE)。
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7591 inline public keys. Mutually exclusive with jwks_uri.
    #[serde(default)]
    pub jwks: Option<RegisteredClientJwks>,
    /// RFC 7591 protected remote key set. Mutually exclusive with jwks.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// private_key_jwt assertion algorithm pin (RS256 or ES256).
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// 省略 resource 时的默认绑定(C2.8;可选)。
    pub default_resource: Option<String>,
    /// RP-initiated logout 的允许回跳集合(spec 003 C9.6;可选,缺省空)。
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// id_token 签名算法(OIDC DCR;可选,缺省 RS256)。仅接受 RS256/ES256(spec 001 C2.7)。
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    /// CIBA token 投递模式(OIDC CIBA Core §10.2;可选,缺省 poll)。`ping`/`push` 时 MUST confidential
    /// + 提供合法 notification endpoint,且需 ping/push 能力已上线(Phase≥P3+gate),否则拒(spec 013 §4)。
    #[serde(default)]
    pub backchannel_token_delivery_mode: Option<String>,
    /// CIBA ping/push 的回调通知端点(OIDC CIBA Core §10.2;ping/push 时 MUST 提供且过 SSRF 结构校验)。
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    /// require DPoP(spec 010 §5.2/C8.7b;可选,缺省 false)。true = 该 client 的 `/token` MUST 带合法
    /// DPoP proof(缺 proof 拒),防中间件丢头/漏配把期望 sender-constrained 的 client 静默签成 bearer。
    #[serde(default)]
    pub require_dpop: Option<bool>,
    /// Redirect matching mode. Missing/`exact` is the default. `prefix` is
    /// restricted to confidential clients whose redirect hosts are explicitly
    /// allowlisted by deployment configuration.
    #[serde(default)]
    pub redirect_mode: Option<String>,
}

/// DCR 响应(RFC 7591 §3.2.1,P0 子集)。
#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    pub client_id: String,
    /// 管理端点(C4.3,GET/PUT/PATCH/DELETE /register/{id})凭此 Bearer 访问。
    pub registration_access_token: String,
    pub registration_client_uri: String,
    pub redirect_uris: Vec<String>,
    pub application_type: String,
    pub token_endpoint_auth_method: String,
    pub require_dpop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<RegisteredClientJwks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// RFC 7591 §3.2.1:绝对 Unix 时间；仅 secret auth client 返回。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterError {
    pub error: String,
    pub error_description: String,
}

pub(crate) fn rand_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn err(status: StatusCode, code: &str, desc: &str) -> (StatusCode, Json<RegisterError>) {
    (
        status,
        Json(RegisterError {
            error: code.to_string(),
            error_description: desc.to_string(),
        }),
    )
}

pub(crate) fn normalize_application_type(
    value: Option<&str>,
) -> Result<&'static str, &'static str> {
    match value.unwrap_or("web") {
        "native" => Ok("native"),
        "web" => Ok("web"),
        _ => Err("application_type 仅支持 native 或 web"),
    }
}

fn is_reverse_domain_private_use_scheme(scheme: &str) -> bool {
    let labels = scheme.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

pub(crate) fn validate_application_redirects(
    application_type: &str,
    redirect_uris: &[String],
) -> Result<(), &'static str> {
    for uri in redirect_uris {
        if !matches!(
            match_redirect(&RedirectMode::Exact, uri, uri),
            MatchResult::Allow
        ) {
            return Err("redirect_uri 非法(canonicalize 失败)");
        }
        let parsed = url::Url::parse(uri).map_err(|_| "redirect_uri 不是合法绝对 URI")?;
        match application_type {
            "web" => {
                if parsed.scheme() != "https" {
                    return Err("web application redirect_uri 必须使用 HTTPS");
                }
                let non_public = match parsed.host() {
                    Some(url::Host::Domain(host)) => {
                        let host = host.trim_end_matches('.');
                        host.eq_ignore_ascii_case("localhost")
                            || host
                                .to_ascii_lowercase()
                                .strip_suffix(".localhost")
                                .is_some()
                    }
                    Some(url::Host::Ipv4(ip)) => {
                        agent_auth_ciba::ip_is_blocked(&std::net::IpAddr::V4(ip))
                    }
                    Some(url::Host::Ipv6(ip)) => {
                        agent_auth_ciba::ip_is_blocked(&std::net::IpAddr::V6(ip))
                    }
                    None => return Err("web application redirect_uri 必须包含 host"),
                };
                if non_public {
                    return Err("web application redirect_uri 必须使用公网 HTTPS host");
                }
            }
            "native" => match parsed.scheme() {
                "http" => {
                    let local = match parsed.host() {
                        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
                        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
                        Some(url::Host::Domain(_)) | None => false,
                    };
                    if !local {
                        return Err("native HTTP redirect_uri 仅允许 127.0.0.1 或 [::1]");
                    }
                }
                "https" => {
                    return Err("native redirect_uri 仅允许 private-use scheme 或 HTTP loopback")
                }
                scheme if is_reverse_domain_private_use_scheme(scheme) => {}
                _ => {
                    return Err(
                        "native private-use redirect_uri scheme 必须使用 reverse-domain 形式",
                    )
                }
            },
            _ => return Err("application_type 仅支持 native 或 web"),
        }
    }
    Ok(())
}

pub(crate) fn registered_redirect_matches(
    client: &ClientRecord,
    inbound: &str,
) -> Result<bool, &'static str> {
    for registered in &client.redirect_uris {
        let mode = match client.redirect_mode.as_deref() {
            None | Some("exact") => {
                let native_loopback = client.application_type() == "native"
                    && url::Url::parse(registered)
                        .ok()
                        .is_some_and(|redirect| redirect.scheme() == "http");
                if native_loopback {
                    RedirectMode::Loopback
                } else {
                    RedirectMode::Exact
                }
            }
            Some("loopback") => RedirectMode::Loopback,
            Some("prefix")
                if client.client_type() == agent_auth_workload::ClientType::Confidential =>
            {
                RedirectMode::Prefix
            }
            Some("prefix") => return Err("redirect prefix 模式仅授 confidential 客户端"),
            Some(_) => return Err("未知 redirect_mode"),
        };
        if matches!(
            match_redirect(&mode, registered, inbound),
            MatchResult::Allow
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn validate_redirect_policy(
    state: &AppState,
    tenant: &str,
    client: &ClientRecord,
) -> Result<(), &'static str> {
    match client.redirect_mode.as_deref() {
        None | Some("exact") => Ok(()),
        Some("loopback") if client.application_type() == "native" => Ok(()),
        Some("loopback") => Err("redirect loopback 模式仅授 native 客户端"),
        Some("prefix") => {
            if client.client_type() != agent_auth_workload::ClientType::Confidential {
                return Err("redirect prefix 模式仅授 confidential 客户端");
            }
            if client.application_type() != "web" {
                return Err("redirect prefix 模式仅授 web 客户端");
            }
            let allowed = state.redirect_prefix_allowed_hosts_for_tenant(tenant);
            if allowed.is_empty() {
                return Err("redirect prefix host allowlist 未配置");
            }
            for redirect in &client.redirect_uris {
                let parsed = url::Url::parse(redirect).map_err(|_| "redirect prefix URI 非法")?;
                let host = parsed
                    .host_str()
                    .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                    .ok_or("redirect prefix URI 缺少 host")?;
                if parsed.scheme() != "https"
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                    || !parsed.path().ends_with("/*")
                {
                    return Err("redirect prefix URI 必须是以 /* 结尾的 HTTPS URL");
                }
                if !allowed.contains(&host) {
                    return Err("redirect prefix host 不在部署 allowlist");
                }
            }
            Ok(())
        }
        Some(_) => Err("未知 redirect_mode"),
    }
}

enum IatAuthError {
    Invalid,
    RateLimited(i64),
    Unavailable,
}

fn split_initial_access_token(token: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = token.split_once('.')?;
    if !token_id.starts_with("iat_")
        || token_id.len() > 128
        || secret.is_empty()
        || secret.len() > 256
    {
        return None;
    }
    Some((token_id, secret))
}

async fn authorize_initial_access_token(
    state: &AppState,
    tenant: &str,
    presented: &str,
    now: i64,
) -> Result<crate::credential::InitialAccessTokenRecord, IatAuthError> {
    let (token_id, secret) = split_initial_access_token(presented).ok_or(IatAuthError::Invalid)?;
    let regional_id = token_id.strip_prefix("iat_").ok_or(IatAuthError::Invalid)?;
    if !state.region.owns_id(regional_id) {
        return Err(IatAuthError::Invalid);
    }
    let record = state
        .initial_access_tokens
        .get(tenant, token_id)
        .await
        .map_err(|_| IatAuthError::Unavailable)?
        .ok_or(IatAuthError::Invalid)?;
    if !record.is_authorized_for("dcr:register", now)
        || !record.verify(&state.server_secret, tenant, secret)
    {
        return Err(IatAuthError::Invalid);
    }

    let rate_limit = state.rate_limit.as_ref().ok_or(IatAuthError::Unavailable)?;
    let capacity = f64::from(record.rate_limit_per_minute);
    let decision = rate_limit
        .try_consume(
            &format!("iat:{tenant}:{token_id}"),
            now,
            capacity,
            capacity / 60.0,
            1.0,
        )
        .await
        .map_err(|_| IatAuthError::Unavailable)?;
    if !decision.allowed {
        return Err(IatAuthError::RateLimited(
            decision.retry_after_secs.unwrap_or(60).max(1),
        ));
    }
    Ok(record)
}

fn initial_access_token_error_response(error: IatAuthError) -> axum::response::Response {
    match error {
        IatAuthError::RateLimited(retry_after) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
            Json(RegisterError {
                error: "temporarily_unavailable".to_string(),
                error_description: "initial access token rate limit exceeded".to_string(),
            }),
        )
            .into_response(),
        IatAuthError::Unavailable => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "initial access token dependency unavailable",
        )
        .into_response(),
        IatAuthError::Invalid => (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\"",
            )],
            Json(RegisterError {
                error: "invalid_token".to_string(),
                error_description: "缺/无效 initial access token(Authorization: Bearer)"
                    .to_string(),
            }),
        )
            .into_response(),
    }
}

async fn authorize_initial_access_token_header(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    now: i64,
) -> Result<crate::credential::InitialAccessTokenRecord, axum::response::Response> {
    let token = bearer(headers)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| initial_access_token_error_response(IatAuthError::Invalid))?;
    authorize_initial_access_token(state, tenant, &token, now)
        .await
        .map_err(initial_access_token_error_response)
}

/// `POST /register`(§3.2 三档:open / initial_access_token / software_statement)。
#[utoipa::path(
    post,
    path = "/register",
    tag = "dcr",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "注册成功(RFC 7591;含 client_id + registration_access_token)", body = RegisterResponse),
        (status = 400, description = "invalid_redirect_uri / invalid_client_metadata", body = RegisterError),
        (status = 401, description = "强制 IAT 档缺/无效票据，或 open 档显式携带无效 IAT", body = RegisterError),
        (status = 501, description = "software_statement 档 P0 未实现(fail-closed)", body = RegisterError)
    )
)]
pub async fn register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // tenant 分区(spec 020 §2.3):注册的 client 落本租户分区(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let issuer = match crate::hostutil::issuer_host(&headers)
        .and_then(|host| agent_auth_discovery::derive_issuer(&host, &state.form).ok())
    {
        Some(issuer) => issuer,
        None => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Host is not a valid issuer host",
            )
            .into_response()
        }
    };
    // 准入门(§3.2/C4.3 三档,互斥)。状态码语义(评审 Kiro F6):
    //   Open → 匿名请求走 IP 桶，显式 IAT 走票据桶且缺/错票拒；InitialAccessToken → 强制 IAT；
    //   SoftwareStatement → 501(P0 未实现)。元数据非法在下方各 4xx(400)。
    // (无 403:三档互斥,不存在"open 关了又不是另两档"的态;旧 dcr_open 布尔的 403 路径已随枚举迁移移除。)
    let now = crate::token::current_unix_secs_pub();
    let mut matched_iat: Option<crate::credential::InitialAccessTokenRecord> = None;
    match state.dcr_mode {
        crate::state::DcrMode::Open => {
            if headers.contains_key(axum::http::header::AUTHORIZATION) {
                matched_iat =
                    match authorize_initial_access_token_header(&state, &tenant, &headers, now)
                        .await
                    {
                        Ok(record) => Some(record),
                        Err(response) => return response,
                    };
            } else {
                // 无凭证放行(自部署内网可信 / SaaS 显式开),但 **per-IP 注册洪水粗兜底**(C10.8 §3.2):
                // open 档匿名注册无票据闸,须防批量脚本洪水铸 client(存储膨胀 + 未验证标识滥用)。IP 取
                // X-Forwarded-For 首段(CloudFront/API GW 注入)。有效 IAT 走独立票据桶,不叠匿名 IP 桶。
                let client_ip = headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown");
                if crate::ratelimit_gate::register_ip_throttled(&state, &tenant, client_ip).await {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(axum::http::header::RETRY_AFTER, "5".to_string())],
                        Json(RegisterError {
                            error: "temporarily_unavailable".to_string(),
                            error_description: "注册请求过于频繁,请稍候重试(per-IP 洪水防护,C10.8)"
                                .to_string(),
                        }),
                    )
                        .into_response();
                }
                match crate::ratelimit_gate::register_global_quota(&state, &tenant).await {
                    Ok(decision) if decision.allowed => {}
                    Ok(decision) => {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            [(
                                axum::http::header::RETRY_AFTER,
                                decision.retry_after_secs.unwrap_or(1).max(1).to_string(),
                            )],
                            Json(RegisterError {
                                error: "temporarily_unavailable".to_string(),
                                error_description: "匿名注册全局配额已耗尽,请稍候重试(C10.8)"
                                    .to_string(),
                            }),
                        )
                            .into_response();
                    }
                    Err(_) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [(axum::http::header::RETRY_AFTER, "1".to_string())],
                            Json(RegisterError {
                                error: "temporarily_unavailable".to_string(),
                                error_description: "匿名注册全局配额依赖不可用(C10.8)".to_string(),
                            }),
                        )
                            .into_response();
                    }
                }
            }
        }
        crate::state::DcrMode::InitialAccessToken => {
            // MUST 带 Authorization: Bearer <iat>;按 token id 定位 tenant 记录后校验 verifier 与策略。
            matched_iat =
                match authorize_initial_access_token_header(&state, &tenant, &headers, now).await {
                    Ok(record) => Some(record),
                    Err(response) => return response,
                };
        }
        crate::state::DcrMode::SoftwareStatement => {
            // P0 未实现(RFC 7591 §3.1.1 签名声明验签 + issuer 信任锚)→ 显式拒(fail-closed,评审确认)。
            return err(
                StatusCode::NOT_IMPLEMENTED,
                "invalid_software_statement",
                "software_statement 档 P0 未实现(需 P1 补签名声明验签 + issuer 信任锚)",
            )
            .into_response();
        }
    }

    // redirect_uris 必需且非空。
    if req.redirect_uris.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris 不能为空",
        )
        .into_response();
    }
    let application_type = match normalize_application_type(req.application_type.as_deref()) {
        Ok(application_type) => application_type,
        Err(message) => {
            return err(StatusCode::BAD_REQUEST, "invalid_client_metadata", message).into_response()
        }
    };
    if let Err(message) = validate_application_redirects(application_type, &req.redirect_uris) {
        return err(StatusCode::BAD_REQUEST, "invalid_redirect_uri", message).into_response();
    }

    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".to_string());
    // 只接受 capability registry 当前可执行的 registered-client 方法。
    let Some(auth_capability) = state.registered_client_auth_method(&auth_method) else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "token_endpoint_auth_method 尚未实现或未知",
        )
        .into_response();
    };
    let (client_secret_credentials, secret_echo, client_secret_expires_at) =
        if auth_capability.requires_secret() {
            let sec = rand_token(32);
            let expires_at = now
                .checked_add(crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
                .expect("bounded client secret TTL");
            let record = crate::credential::new_credential_record(
                &state.server_secret,
                crate::credential::CredentialKind::ClientSecret,
                &tenant,
                format!("cred_{}", rand_token(12)),
                String::new(), // filled after client_id generation
                &sec,
                now,
                expires_at,
                "pending:dcr".into(),
                None,
            );
            (
                crate::credential::CredentialSet {
                    current: Some(record),
                    version: 1,
                    ..Default::default()
                },
                Some(sec),
                Some(expires_at),
            )
        } else {
            (crate::credential::CredentialSet::default(), None, None)
        };
    let key_config = match crate::client_auth::validate_registration_key_config(
        &auth_method,
        req.jwks.clone(),
        req.jwks_uri.clone(),
        req.token_endpoint_auth_signing_alg.clone(),
    ) {
        Ok(config) => config,
        Err(message) => {
            return err(StatusCode::BAD_REQUEST, "invalid_client_metadata", message).into_response()
        }
    };

    // id_token 签名 alg 白名单(spec 001 C2.7:仅 discovery 宣告的 RS256/ES256;缺省 None→RS256)。
    if let Some(alg) = &req.id_token_signed_response_alg {
        if alg != "RS256" && alg != "ES256" {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "id_token_signed_response_alg 仅支持 RS256/ES256",
            )
            .into_response();
        }
    }

    // CIBA 投递模式(spec 013 §4,C7b.5,OIDC CIBA Core §10.2):缺省 poll(后向兼容)。
    // ping/push MUST:①能力已上线(Phase≥P3+gate,否则拒——不接受未上线声明);②client confidential
    //(auth_method != none;push 直投 token / ping 通知取,匿名 public 无法安全接收);③endpoint 提供且过
    // SSRF 结构校验(https/端口/非字面私网,投递前再 DNS 复校)。标准字段语义见 OIDC CIBA Core §10.2。
    let (delivery_mode, notification_endpoint) = match req
        .backchannel_token_delivery_mode
        .as_deref()
    {
        None | Some("poll") => (None, None), // 缺省 poll:不落 delivery_mode(向后兼容旧记录)
        Some(mode @ ("ping" | "push")) => {
            if !state.ciba_ping_push_active() {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "ping/push 投递模式当前未启用(需 Phase≥P3 且开启 ping/push 能力)",
                )
                .into_response();
            }
            // confidential 强制(H3):auth_method != none。
            if auth_method == "none" {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "ping/push 投递要求 confidential 客户端认证(token_endpoint_auth_method 不能为 none)",
                )
                .into_response();
            }
            // **push + require_dpop 不兼容(评审 codex/Kiro)**:push 是 AS 主动投递完整 token(无客户端
            // 请求 → 无 DPoP proof 可绑),require_dpop=true 却期望 sender-constrained → 组合矛盾会静默签出
            // bearer 绕过 require_dpop。注册即拒(ping 仍可:ping 通知后 client 走 /token 取,可带 proof)。
            if mode == "push" && req.require_dpop.unwrap_or(false) {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "push 投递与 require_dpop 不兼容(push 无客户端请求可绑 DPoP proof;改用 ping 或去掉 require_dpop)",
                )
                .into_response();
            }
            // notification endpoint MUST 提供 + 过 SSRF 结构校验(https/端口/非字面私网 IP)。
            let Some(ep) = req.backchannel_client_notification_endpoint.as_deref() else {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "ping/push 投递 MUST 提供 backchannel_client_notification_endpoint",
                )
                .into_response();
            };
            if let Err(e) = agent_auth_ciba::validate_endpoint_url(ep, None) {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    &format!("notification endpoint 非法(SSRF fail-closed): {e:?}"),
                )
                .into_response();
            }
            (Some(mode.to_string()), Some(ep.to_string()))
        }
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "backchannel_token_delivery_mode 仅支持 poll/ping/push",
            )
            .into_response();
        }
    };

    // OIDC sector(C2.11/§2.8):从 redirect_uris 归一(全同 host→该 host;多 host/含非归一 URI→None)。
    let oidc_sector_identifier = match validated_oidc_sector(
        state.subject_type_for_tenant(&tenant),
        &req.redirect_uris,
    ) {
        Ok(sector) => sector,
        Err(()) => return err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "pairwise 部署:多 redirect host 须提供 sector_identifier_uri(否则 OIDC sub 不可确定)",
        )
        .into_response(),
    };

    let client_id = format!("c_{}", rand_token(16));
    let audit_identity = matched_iat
        .as_ref()
        .map(|record| format!("iat:{}", record.token_id))
        .unwrap_or_else(|| "dcr:open".to_string());
    let mut client_secret_credentials = client_secret_credentials;
    if let Some(current) = client_secret_credentials.current.as_mut() {
        current.owner = client_id.clone();
        current.audit_identity = audit_identity.clone();
        current.verifier = crate::credential::credential_verifier(
            &state.server_secret,
            crate::credential::CredentialKind::ClientSecret,
            &tenant,
            &client_id,
            secret_echo.as_deref().expect("secret exists"),
        );
    }
    let reg_token = rand_token(32);
    let reg_token_expires_at = now
        .checked_add(crate::credential::DEFAULT_REGISTRATION_TOKEN_TTL_SECS)
        .expect("bounded registration token TTL");
    let registration_token_credentials = crate::credential::CredentialSet {
        current: Some(crate::credential::new_credential_record(
            &state.server_secret,
            crate::credential::CredentialKind::RegistrationAccessToken,
            &tenant,
            format!("cred_{}", rand_token(12)),
            client_id.clone(),
            &reg_token,
            now,
            reg_token_expires_at,
            audit_identity.clone(),
            None,
        )),
        version: 1,
        ..Default::default()
    };
    let record = ClientRecord {
        client_id: client_id.clone(),
        redirect_uris: req.redirect_uris.clone(),
        application_type: Some(application_type.to_string()),
        token_endpoint_auth_method: auth_method.clone(),
        client_secret: None,
        client_secret_credentials,
        jwks: key_config.jwks.clone(),
        jwks_uri: key_config.jwks_uri.clone(),
        token_endpoint_auth_signing_alg: key_config.signing_alg.clone(),
        default_resource: req.default_resource.clone(),
        // DCR 注册的普通 client 默认无 introspect 权限;MCP RS 的 introspect 凭证由控制面
        // 注册单独授予(spec 010 C8.6,非公开 DCR 路径)。
        introspect_enabled: false,
        resource_ids: vec![],
        // post_logout_redirect_uris:DCR 请求可带(RFC 7591 未标准化此字段,P1 从 req 取,缺省空)。
        post_logout_redirect_uris: req.post_logout_redirect_uris.clone().unwrap_or_default(),
        // C4.3:存 reg_token 的 HMAC 哈希,/register/{id} 管理端点据此校验 Bearer(spec 025)。
        reg_token_hash: None,
        registration_token_credentials,
        client_type: None,
        id_token_signed_response_alg: req.id_token_signed_response_alg.clone(),
        // OIDC sector(C2.11/§2.8):注册时从 redirect_uris 归一持久化(上文已算 + pairwise 下 None 已拒)。
        oidc_sector_identifier,
        // DCR 注册的普通 client 非 workload,不做 2LO(C7.5:2LO 策略仅管理面登记 workload 时设)。
        allowed_resources: vec![],
        allowed_scopes: vec![],
        redirect_mode: req.redirect_mode.clone(),
        // 回收元数据(spec 005 §9,C10.5):注册即记 created_at(审计 + never-used 边界);未使用/未 tombstone。
        created_at: now,
        last_used_day: None,
        authority_revision: 0,
        tombstoned_at: None,
        // CIBA 投递模式(spec 013 §4;已在上文校验:ping/push 须 confidential + 合法 endpoint + 能力上线)。
        backchannel_token_delivery_mode: delivery_mode,
        backchannel_client_notification_endpoint: notification_endpoint,
        // require DPoP(spec 010 §5.2):client 注册可声明;缺省 false(opt-in)。
        require_dpop: req.require_dpop.unwrap_or(false),
        prm_domains: vec![],
    };
    if let Err(message) = validate_redirect_policy(&state, &tenant, &record) {
        return err(StatusCode::BAD_REQUEST, "invalid_client_metadata", message).into_response();
    }
    if let Some(iat) = &matched_iat {
        if iat.one_time {
            // Reserve the one-time authorization before the client write so concurrent requests
            // cannot create two clients. A later client-store error intentionally burns the token:
            // DynamoDB write errors can be ambiguous (the PutItem may have committed), so
            // compensating by reactivating the token could violate at-most-once registration.
            match state
                .initial_access_tokens
                .consume_once(&tenant, &iat.token_id, iat.version, now)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return err(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "initial access token was already consumed or revoked",
                    )
                    .into_response()
                }
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "initial access token dependency unavailable",
                    )
                    .into_response()
                }
            }
        }
    }
    let client_secret_credential_id = record
        .client_secret_credentials
        .current
        .as_ref()
        .map(|credential| credential.credential_id.clone());
    let registration_credential_id = record
        .registration_token_credentials
        .current
        .as_ref()
        .map(|credential| credential.credential_id.clone())
        .expect("DCR always issues a registration access token");
    if state.clients.put(&tenant, record).await.is_err() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "存储瞬时不可用",
        )
        .into_response();
    }
    if let Some(credential_id) = client_secret_credential_id.as_deref() {
        tokio::join!(
            audit_client_lifecycle(
                &state,
                &tenant,
                &audit_identity,
                &client_id,
                "client.create",
            ),
            audit_client_credential(
                &state,
                &tenant,
                &audit_identity,
                &client_id,
                credential_id,
                "credential.client_secret.create",
            ),
            audit_client_credential(
                &state,
                &tenant,
                &audit_identity,
                &client_id,
                &registration_credential_id,
                "credential.registration_access_token.create",
            ),
        );
    } else {
        tokio::join!(
            audit_client_lifecycle(
                &state,
                &tenant,
                &audit_identity,
                &client_id,
                "client.create",
            ),
            audit_client_credential(
                &state,
                &tenant,
                &audit_identity,
                &client_id,
                &registration_credential_id,
                "credential.registration_access_token.create",
            ),
        );
    }

    let reg_client_uri = format!(
        "{}/register/{client_id}",
        issuer.as_str().trim_end_matches('/')
    );
    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            registration_access_token: reg_token,
            registration_client_uri: reg_client_uri,
            redirect_uris: req.redirect_uris,
            application_type: application_type.to_string(),
            token_endpoint_auth_method: auth_method,
            require_dpop: req.require_dpop.unwrap_or(false),
            redirect_mode: req.redirect_mode,
            jwks: key_config.jwks,
            jwks_uri: key_config.jwks_uri,
            token_endpoint_auth_signing_alg: key_config.signing_alg,
            client_secret: secret_echo,
            client_secret_expires_at,
        }),
    )
        .into_response()
}

pub(crate) fn validated_oidc_sector(
    subject_type: agent_auth_discovery::SubjectType,
    redirect_uris: &[String],
) -> Result<Option<String>, ()> {
    let sector = agent_auth_token::oidc_sector_from_redirect_hosts(redirect_uris);
    if subject_type == agent_auth_discovery::SubjectType::Pairwise && sector.is_none() {
        Err(())
    } else {
        Ok(sector)
    }
}

// ------- RFC 7592 客户端配置管理端点(C4.3,spec 025 自助域)-------
//
// 双鉴权域(spec 025 Purpose):这里凭 `registration_access_token`(每 client 独立),**不接受 admin_token**;
// admin 超级权限走 `/admin/clients/*`(admin.rs)。两域互不代替。
//
// 鉴权 = 取 client 记录 → 校验 tenant/client 分域的 registration token current/next verifier。
// legacy reg_token_hash 命中后以 CAS 懒迁移到有到期时间的 credential set；新记录不写该字段。

/// 校验 `Authorization: Bearer <registration_access_token>` 是否属于该 client。
/// client 无有效 registration token credential → 一律拒(fail-closed,不可自助管理)。
async fn reg_auth_identity(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    mut client: ClientRecord,
) -> Result<Option<(String, ClientRecord)>, crate::ports::StoreError> {
    let Some(tok) = bearer(headers) else {
        return Ok(None);
    };
    let now = crate::token::current_unix_secs_pub();
    if let Some(record) = client.registration_token_credentials.verify(
        &state.server_secret,
        crate::credential::CredentialKind::RegistrationAccessToken,
        tenant,
        &tok,
        now,
    ) {
        return Ok(Some((
            format!("registration-token:{}", record.credential_id),
            client,
        )));
    }
    let Some(verifier) = client
        .reg_token_hash
        .as_deref()
        .filter(|expected| hash_eq(&reg_token_hash(&state.server_secret, &tok), expected))
    else {
        return Ok(None);
    };
    let credentials = crate::credential::CredentialSet {
        current: Some(crate::credential::CredentialRecord {
            credential_id: format!("cred_{}", rand_token(12)),
            owner: client.client_id.clone(),
            verifier: verifier.to_string(),
            verifier_version: crate::credential::VerifierVersion::LegacyRegistrationTokenV0,
            created_at: if client.created_at > 0 {
                client.created_at
            } else {
                now
            },
            expires_at: now
                .checked_add(crate::credential::DEFAULT_REGISTRATION_TOKEN_TTL_SECS)
                .ok_or_else(|| {
                    crate::ports::StoreError::Permanent(
                        "legacy registration-token migration expiry overflow".into(),
                    )
                })?,
            status: crate::credential::CredentialStatus::Active,
            audit_identity: "system:lazy-legacy-migration".into(),
            rotation_request_id: None,
        }),
        version: client
            .registration_token_credentials
            .version
            .saturating_add(1),
        ..Default::default()
    };
    let stored = state
        .clients
        .replace_credential_set(
            tenant,
            &client.client_id,
            crate::credential::CredentialKind::RegistrationAccessToken,
            client.registration_token_credentials.version,
            credentials.clone(),
        )
        .await?;
    if stored {
        let credential_id = credentials
            .current
            .as_ref()
            .expect("migration creates current credential")
            .credential_id
            .clone();
        client.reg_token_hash = None;
        client.registration_token_credentials = credentials;
        return Ok(Some((
            format!("registration-token:{credential_id}"),
            client,
        )));
    }

    let Some(refreshed) = state.clients.get(tenant, &client.client_id).await? else {
        return Ok(None);
    };
    let credential_id = refreshed
        .registration_token_credentials
        .verify(
            &state.server_secret,
            crate::credential::CredentialKind::RegistrationAccessToken,
            tenant,
            &tok,
            now,
        )
        .map(|record| record.credential_id.clone());
    Ok(credential_id
        .map(|credential_id| (format!("registration-token:{credential_id}"), refreshed)))
}

/// RFC 7592 PUT 全量更新体:白名单元数据(全替换语义,缺省即清空/置默认)。
#[derive(Deserialize, ToSchema)]
pub struct ClientPut {
    pub redirect_uris: Vec<String>,
    /// OIDC application type. PUT omission resets to the `web` default.
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// PUT omission resets the DPoP policy to its optional/default state.
    #[serde(default)]
    pub require_dpop: bool,
    #[serde(default)]
    pub jwks: Option<RegisteredClientJwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub default_resource: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub redirect_mode: Option<String>,
    /// 降级确认(C4.7):朝更弱方向变更需带 true。
    #[serde(default)]
    pub confirm_downgrade: bool,
}

/// `GET /register/{client_id}`(RFC 7592):读回自己的注册元数据(reg_token;不回 secret)。
#[utoipa::path(get, path = "/register/{client_id}", tag = "dcr",
    params(("client_id" = String, Path)),
    responses((status = 200, description = "client 元数据", body = ClientView), (status = 401), (status = 404)))]
pub async fn get_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let client = match state.clients.get(&tenant, &client_id).await {
        Ok(Some(c)) => c,
        // spec 025:不存在返 404(DCR client_id 高熵随机,不可枚举,无需 anti-enumeration);token 不符才 401。
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    let (_, client) = match reg_auth_identity(&state, &tenant, &headers, client).await {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid_token").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    Json(view(&client)).into_response()
}

/// `DELETE /register/{client_id}`(RFC 7592):自助注销；先建立 client tombstone 写屏障，
/// 再级联吊销 refresh family、物理删除 Grants 和 client(reg_token)。
#[utoipa::path(delete, path = "/register/{client_id}", tag = "dcr",
    params(("client_id" = String, Path)),
    responses((status = 204, description = "已注销"), (status = 401)))]
pub async fn delete_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let client = match state.clients.get(&tenant, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    let (audit_identity, client) = match reg_auth_identity(&state, &tenant, &headers, client).await
    {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid_token").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if state
        .delete_registered_client_authority(&tenant, &client)
        .await
        .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "client deletion did not converge",
        )
            .into_response();
    }
    audit_client_lifecycle(
        &state,
        &tenant,
        &audit_identity,
        &client_id,
        "client.delete",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `PATCH /register/{client_id}`(RFC 7592 部分更新):白名单字段 + 降级确认 + secret 调谐(reg_token)。
#[utoipa::path(patch, path = "/register/{client_id}", tag = "dcr",
    params(("client_id" = String, Path)), request_body = ClientPatch,
    responses((status = 200, description = "已更新(auth_method 切换时回显新 secret 一次)", body = ClientUpdated), (status = 400), (status = 401)))]
pub async fn patch_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(p): Json<ClientPatch>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let old = match state.clients.get(&tenant, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    let (audit_identity, old) = match reg_auth_identity(&state, &tenant, &headers, old).await {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid_token").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if p.has_conflicting_key_sources() {
        return (
            StatusCode::BAD_REQUEST,
            "jwks and jwks_uri are mutually exclusive",
        )
            .into_response();
    }
    let updated = apply_patch(old.clone(), &p);
    finalize_and_put(
        &state,
        &tenant,
        &old,
        updated,
        p.confirm_downgrade,
        &audit_identity,
    )
    .await
}

/// `PUT /register/{client_id}`(RFC 7592 全量替换):白名单元数据全替换 + 降级确认 + secret 调谐(reg_token)。
#[utoipa::path(put, path = "/register/{client_id}", tag = "dcr",
    params(("client_id" = String, Path)), request_body = ClientPut,
    responses((status = 200, description = "已替换(auth_method 切换时回显新 secret 一次)", body = ClientUpdated), (status = 400), (status = 401)))]
pub async fn put_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(p): Json<ClientPut>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let old = match state.clients.get(&tenant, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    let (audit_identity, old) = match reg_auth_identity(&state, &tenant, &headers, old).await {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid_token").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    if p.redirect_uris.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris 不能为空",
        )
        .into_response();
    }
    let updated = apply_put(old.clone(), &p);
    finalize_and_put(
        &state,
        &tenant,
        &old,
        updated,
        p.confirm_downgrade,
        &audit_identity,
    )
    .await
}

/// RFC 7592 PATCH/PUT 收尾:校 auth_method 白名单 + 降级确认 + secret 调谐 → 落库(admin.rs 同口径)。
async fn finalize_and_put(
    state: &AppState,
    tenant: &str,
    old: &ClientRecord,
    updated: ClientRecord,
    confirm_downgrade: bool,
    audit_identity: &str,
) -> axum::response::Response {
    let credential_context = crate::admin::CredentialIssueContext {
        server_secret: &state.server_secret,
        tenant,
        audit_identity,
        now: crate::token::current_unix_secs_pub(),
    };
    match finalize_update(
        old,
        updated,
        confirm_downgrade,
        state.private_key_jwt_active(),
        &credential_context,
    ) {
        UpdateOutcome::UnknownMethod => (
            StatusCode::BAD_REQUEST,
            "unknown token_endpoint_auth_method",
        )
            .into_response(),
        UpdateOutcome::UnsupportedMethod => (
            StatusCode::BAD_REQUEST,
            "unsupported token_endpoint_auth_method",
        )
            .into_response(),
        UpdateOutcome::InvalidKeyConfig => err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "invalid private_key_jwt key metadata",
        )
        .into_response(),
        UpdateOutcome::InvalidApplicationMetadata(message) => {
            err(StatusCode::BAD_REQUEST, "invalid_client_metadata", message).into_response()
        }
        UpdateOutcome::DowngradeUnconfirmed(fields) => downgrade_error(fields),
        UpdateOutcome::InvalidDeliveryCombo => err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "ping/push 投递要求 confidential 客户端(token_endpoint_auth_method 不能为 none)",
        )
        .into_response(),
        UpdateOutcome::InvalidDpopDeliveryCombo => err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "push 投递与 require_dpop 不兼容(push 无客户端请求可绑定 DPoP proof)",
        )
        .into_response(),
        UpdateOutcome::Ok(rec, secret) => {
            if let Err(message) = validate_redirect_policy(state, tenant, &rec) {
                return err(StatusCode::BAD_REQUEST, "invalid_client_metadata", message)
                    .into_response();
            }
            // pairwise 部署:更新后 redirect_uris 变成多 host(sector 不可确定)→ 拒(评审 F1,与注册同口径)。
            if state.subject_type_for_tenant(tenant) == agent_auth_discovery::SubjectType::Pairwise
                && rec.oidc_sector_identifier.is_none()
            {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "pairwise 部署:多 redirect host 须提供 sector_identifier_uri(OIDC sub 不可确定)",
                )
                .into_response();
            }
            match state
                .clients
                .put_if_credential_versions(
                    tenant,
                    (*rec).clone(),
                    old.client_secret_credentials.version,
                    old.registration_token_credentials.version,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return (StatusCode::CONFLICT, "credential version conflict").into_response()
                }
                Err(_) => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
                }
            }
            audit_client_lifecycle(
                state,
                tenant,
                audit_identity,
                &rec.client_id,
                "client.update",
            )
            .await;
            if secret.is_some() {
                if let Some(credential) = rec
                    .client_secret_credentials
                    .next
                    .as_ref()
                    .or(rec.client_secret_credentials.current.as_ref())
                {
                    audit_client_credential(
                        state,
                        tenant,
                        audit_identity,
                        &rec.client_id,
                        &credential.credential_id,
                        "credential.client_secret.create",
                    )
                    .await;
                }
            }
            Json(ClientUpdated {
                client_secret: secret,
                view: view(&rec),
            })
            .into_response()
        }
    }
}

async fn audit_client_lifecycle(
    state: &AppState,
    tenant: &str,
    audit_identity: &str,
    client_id: &str,
    action: &'static str,
) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::client(audit_identity),
                Some(crate::security_event::SecuritySubject::client(client_id)),
                crate::security_event::SecurityEventCategory::Administration,
                action,
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(client_id.to_string()),
                ..Default::default()
            }),
        )
        .await;
}

async fn audit_client_credential(
    state: &AppState,
    tenant: &str,
    audit_identity: &str,
    client_id: &str,
    credential_id: &str,
    action: &'static str,
) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::client(audit_identity),
                Some(crate::security_event::SecuritySubject::credential(
                    credential_id,
                )),
                crate::security_event::SecurityEventCategory::KeySecret,
                action,
                crate::security_event::SecurityEventOutcome::Success,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(client_id.to_string()),
                credential_id: Some(credential_id.to_string()),
                ..Default::default()
            }),
        )
        .await;
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .merge(register_post_router())
        .merge(manage_router())
}

/// `POST /register`(DCR RFC 7591):`open` 档无凭证注册,**不带浏览器 cookie**。CORS 分类③
/// (open 档 `Allow-Origin: *`;收紧档虽需 Bearer 票据,但 preflight 不带 cookie、`*` 仍安全,
/// 票据校验在 handler 内)。build_router 对本组挂许可 CORS。
pub fn register_post_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(register_handler))
}

/// RFC 7592 管理端点(`GET/PUT/PATCH/DELETE /register/{id}`):凭 `registration_access_token`(Bearer)
/// 访问,通常由工具/SDK(非浏览器 fetch)调用。CORS 分类④(不发 CORS 头,浏览器跨域无法调;
/// Bearer token 泄露的滥用面收窄——不给浏览器内任意 origin 兑换能力)。build_router 不对本组挂 CORS。
pub fn manage_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(
        get_registration,
        put_registration,
        patch_registration,
        delete_registration
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn application_type_defaults_to_web_and_rejects_unknown_values() {
        assert_eq!(normalize_application_type(None), Ok("web"));
        assert_eq!(normalize_application_type(Some("native")), Ok("native"));
        assert!(normalize_application_type(Some("desktop")).is_err());
    }

    #[test]
    fn web_redirects_require_non_loopback_https() {
        assert!(validate_application_redirects(
            "web",
            &uris(&["https://app.example.com/callback"])
        )
        .is_ok());
        for invalid in [
            "http://app.example.com/callback",
            "https://localhost/callback",
            "https://app.localhost/callback",
            "https://localhost./callback",
            "https://app.localhost./callback",
            "https://127.0.0.1/callback",
            "https://[::1]/callback",
            "https://10.0.0.1/callback",
            "https://169.254.169.254/callback",
            "https://192.0.2.1/callback",
        ] {
            assert!(
                validate_application_redirects("web", &uris(&[invalid])).is_err(),
                "{invalid} must be rejected for web clients"
            );
        }
    }

    #[test]
    fn native_redirects_allow_private_use_and_http_loopback_only() {
        for valid in [
            "com.example.app:/oauth2/callback",
            "com.example.app://callback/oauth2",
            "http://127.0.0.1:49152/callback",
            "http://[::1]:49152/callback",
        ] {
            assert!(
                validate_application_redirects("native", &uris(&[valid])).is_ok(),
                "{valid} must be accepted for native clients"
            );
        }
        for invalid in [
            "http://app.example.com/callback",
            "http://localhost/callback",
            "https://app.example.com/callback",
            "https://localhost/callback",
            "myapp:/oauth2/callback",
            "javascript:/alert",
            "data:/text",
            "file:///tmp/callback",
            "ftp://app.example.com/callback",
        ] {
            assert!(
                validate_application_redirects("native", &uris(&[invalid])).is_err(),
                "{invalid} must be rejected for native clients"
            );
        }
    }

    #[test]
    fn registered_native_loopback_ignores_only_the_ephemeral_port() {
        let loopback = ClientRecord {
            redirect_uris: uris(&["http://127.0.0.1:49152/oauth/callback"]),
            application_type: Some("native".to_string()),
            token_endpoint_auth_method: "none".to_string(),
            ..Default::default()
        };
        assert_eq!(
            registered_redirect_matches(&loopback, "http://127.0.0.1:54321/oauth/callback"),
            Ok(true)
        );
        assert_eq!(
            registered_redirect_matches(&loopback, "http://127.0.0.1:54321/other"),
            Ok(false)
        );
        assert_eq!(
            registered_redirect_matches(&loopback, "http://[::1]:54321/oauth/callback"),
            Ok(false)
        );

        let private_use = ClientRecord {
            redirect_uris: uris(&["com.example.app:/oauth/callback"]),
            application_type: Some("native".to_string()),
            token_endpoint_auth_method: "none".to_string(),
            ..Default::default()
        };
        assert_eq!(
            registered_redirect_matches(&private_use, "com.example.app:/oauth/callback"),
            Ok(true)
        );
        assert_eq!(
            registered_redirect_matches(&private_use, "com.example.app:/other"),
            Ok(false)
        );
    }
}
