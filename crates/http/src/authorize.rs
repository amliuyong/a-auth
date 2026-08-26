//! `GET|POST /authorize`(C4.1 PKCE / C1.7 state echo / authorize↔token 绑定):授权码签发。
//!
//! P0 最小实现:按 client policy 校验 PKCE(S256 only)、redirect_uri 属注册集合精确匹配、落地授权码(绑定
//! client/redirect/challenge/resource 集合,写 CodeStore),回跳 redirect_uri?code=..&state=..。
//!
//! ⚠️ **真人登录 + consent 页**(magic-link/会话 cookie/同意授权 UI,spec 003/005 §4)尚未接入:
//! 本 P0 版为跑通 code flow 端到端做**自动授权**(用请求带的 `login_user` 充当已认证用户)——
//! 仅用于本地/e2e 验证签发链路,**MUST NOT 上真实身份**(真身份前置 P0.5 恢复 gate,见 spec 003)。
//! 接入真实登录/consent 后本 handler 的"自动授权"分支 MUST 移除。

use agent_auth_client::{check_authorize, match_redirect, MatchResult, PkceCheck, RedirectMode};
use agent_auth_discovery::{derive_issuer, echo_state};
use axum::{
    extract::{RawForm, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    AuthzSessionStore, ClientRecord, CodeIssueOutcome, CodeRecord, GrantStore, RefreshStore,
    SessionRecord, Signer,
};
use crate::state::AppState;

fn host_from_headers(headers: &HeaderMap) -> Option<String> {
    // issuer host(C1.6a):优先 X-Forwarded-Host(CloudFront 统一入口透传)、回落 Host。
    crate::hostutil::issuer_host(headers)
}

/// authorization code 有效期(秒;短命项 ≤ 数分钟,§2.1)。
const CODE_TTL_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationCodePolicyError {
    Workload,
    MissingChallenge,
    NotS256,
}

/// Shared authorization-code admission policy for direct authorize, consent,
/// and PAR. Only ClientStore-backed confidential clients with a currently
/// executable non-none auth method may omit both PKCE parameters.
pub(crate) fn check_authorization_code_policy(
    state: &AppState,
    source: &crate::cimd::ClientSource,
    client: &ClientRecord,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> Result<(), AuthorizationCodePolicyError> {
    if client.is_workload() {
        return Err(AuthorizationCodePolicyError::Workload);
    }

    match check_authorize(code_challenge, code_challenge_method) {
        PkceCheck::Ok => Ok(()),
        PkceCheck::MissingChallenge
            if matches!(source, crate::cimd::ClientSource::Registered)
                && code_challenge.is_none()
                && code_challenge_method.is_none()
                && state.allows_authorization_code_without_pkce(client) =>
        {
            Ok(())
        }
        PkceCheck::MissingChallenge => Err(AuthorizationCodePolicyError::MissingChallenge),
        PkceCheck::NotS256 => Err(AuthorizationCodePolicyError::NotS256),
    }
}

/// `GET|POST /authorize` 参数(RFC 6749 + PKCE 子集)。
#[derive(Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    // ⚠️ **不在此解析 `resource`**:serde_urlencoded 遇重复 `resource=`(多 resource,P1+ C2.5b)会
    // "duplicate field" 反序列化失败 → Query extractor 在 handler 前就 400,多 resource 永不可达。
    // 故 resource **全从 raw_query 手解**(见 handler resource_params),支持单/多值。
    /// OIDC `nonce`(C2.9):带则透传进 code、签 id_token 时 echo。
    pub nonce: Option<String>,
    /// OIDC ID Token hint. It is verified against this issuer and client before
    /// being used to select the active browser subject.
    pub id_token_hint: Option<String>,
    /// ⚠️ P0 e2e 占位:充当"已认证用户"。真实登录接入后移除。
    pub login_user: Option<String>,
    /// OIDC `prompt`(C9.5a):`none`(不弹登录,无会话返 login_required)/`login`(强制重认证)。
    pub prompt: Option<String>,
    /// OIDC `max_age`(C9.5a):会话 `auth_time` 超此秒数则强制重认证。
    pub max_age: Option<i64>,
    /// OIDC/RFC 9470 assurance preference list. Only Agent Auth canonical values are supported.
    pub acr_values: Option<String>,
    /// 上游 IdP 联邦提示(spec 003 §4):无本地会话时若带此且联邦启用 → 重定向到该上游 IdP 登录。
    pub idp_hint: Option<String>,
}

#[derive(Deserialize)]
struct ParClientAuthParams {
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

/// 生成授权码:**CSPRNG 32 字节随机**的不透明串(不可预测、不可逆、不含任何请求内容)。
/// 授权码是"查库随机串",绑定关系存在 CodeRecord 里(非编码进 code 本身)——防枚举/预消费/信息泄露。
fn make_code(state: &AppState) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    state.region.issue_id(URL_SAFE_NO_PAD.encode(bytes))
}

/// percent-encode(RFC 3986 保留字 + 非 unreserved 一律编码)——回调 URL 拼 state/iss 时防注入
/// (评审:state 含 `&code=x` 会注入额外回调参数)。unreserved = A-Za-z0-9-._~。
pub(crate) fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Append OAuth response parameters without discarding an existing redirect
/// query. The redirect URI has already passed the registered-client matcher,
/// but parsing remains fallible so callers can fail closed if that invariant
/// changes.
pub(crate) fn oauth_response_url(
    redirect_uri: &str,
    params: &[(&str, &str)],
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(redirect_uri)?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in params {
            query.append_pair(name, value);
        }
    }
    Ok(url.into())
}

/// 把 authorize 上下文拼成 query(供重定向前端 /login 或 /consent 续流;各值 percent-encode)。
/// `resources` 单独传(不在 AuthorizeParams 里,支持多值 C2.5b):**逐个** append `resource=`,
/// 保留完整集合到续流 query(前端回来后 token 侧再收窄)。
fn authorize_context_query(
    p: &AuthorizeParams,
    resources: &[String],
    rar_json: &str,
    cimd_digest: Option<&str>,
    cimd_binding: Option<&str>,
) -> String {
    let mut q = format!(
        "response_type=code&client_id={}&redirect_uri={}",
        pct_encode(&p.client_id),
        pct_encode(&p.redirect_uri)
    );
    if let Some(cc) = &p.code_challenge {
        q.push_str(&format!(
            "&code_challenge={}&code_challenge_method=S256",
            pct_encode(cc)
        ));
    }
    if let Some(s) = &p.scope {
        q.push_str(&format!("&scope={}", pct_encode(s)));
    }
    if let Some(st) = &p.state {
        q.push_str(&format!("&state={}", pct_encode(st)));
    }
    // 多 resource:逐个 append(保留完整集合;单值时等价原行为)。
    for r in resources {
        q.push_str(&format!("&resource={}", pct_encode(r)));
    }
    if let Some(n) = &p.nonce {
        q.push_str(&format!("&nonce={}", pct_encode(n)));
    }
    if let Some(id_token_hint) = &p.id_token_hint {
        q.push_str(&format!("&id_token_hint={}", pct_encode(id_token_hint)));
    }
    if let Some(acr_values) = &p.acr_values {
        q.push_str(&format!("&acr_values={}", pct_encode(acr_values)));
    }
    if let Some(max_age) = p.max_age.filter(|value| *value > 0) {
        q.push_str(&format!("&max_age={max_age}"));
    }
    if let Some(idp_hint) = &p.idp_hint {
        q.push_str(&format!("&idp_hint={}", pct_encode(idp_hint)));
    }
    // RAR(spec 010 §4):已准入校验的 authorization_details JSON 透传给 /consent(用户同意后落 Grant)。
    if !rar_json.is_empty() {
        q.push_str(&format!("&authorization_details={}", pct_encode(rar_json)));
    }
    if let Some(digest) = cimd_digest {
        q.push_str(&format!("&cimd_digest={}", pct_encode(digest)));
    }
    if let Some(binding) = cimd_binding {
        q.push_str(&format!("&cimd_binding={}", pct_encode(binding)));
    }
    q
}

/// 在 authorize 上下文 query 上追加授权会话 id(spec 004:会话在 authorize 受理时创建,
/// id 随重定向链 authorize→login→consent 透传,consent 迁移同一条会话而非新建)。
fn context_query_with_session(
    p: &AuthorizeParams,
    resources: &[String],
    rar_json: &str,
    authz_session_id: &str,
    cimd_digest: Option<&str>,
    cimd_binding: Option<&str>,
) -> String {
    format!(
        "{}&authz_session_id={}",
        authorize_context_query(p, resources, rar_json, cimd_digest, cimd_binding),
        pct_encode(authz_session_id)
    )
}

/// 未登录 → 重定向前端 /login(带 authorize 上下文,登录后经 /consent 续流)。
fn redirect_to_login(
    browser_origin: &str,
    p: &AuthorizeParams,
    resources: &[String],
    rar_json: &str,
    sid: &str,
    cimd_digest: Option<&str>,
    cimd_binding: Option<&str>,
) -> Redirect {
    Redirect::to(&format!(
        "{}/login?{}",
        browser_origin,
        context_query_with_session(p, resources, rar_json, sid, cimd_digest, cimd_binding,)
    ))
}

/// 已登录 → 重定向前端 /consent(用户同意后 POST /consent 才签 code;修 consent bypass)。
fn redirect_to_consent(
    browser_origin: &str,
    p: &AuthorizeParams,
    resources: &[String],
    rar_json: &str,
    sid: &str,
    cimd_digest: Option<&str>,
    cimd_binding: Option<&str>,
) -> Redirect {
    Redirect::to(&format!(
        "{}/consent?{}",
        browser_origin,
        context_query_with_session(p, resources, rar_json, sid, cimd_digest, cimd_binding,)
    ))
}

/// OIDC 错误回跳到 client 的 redirect_uri(如 `prompt=none` 无会话 → `error=login_required`,C9.5a)。
/// error/state/iss 均 percent-encode(C1.7 防注入)。
fn redirect_error(p: &AuthorizeParams, error: &str, issuer: &str) -> Redirect {
    let mut params = vec![("error", error), ("iss", issuer)];
    if let Some(state) = p.state.as_deref() {
        params.push(("state", state));
    }
    let url = oauth_response_url(&p.redirect_uri, &params)
        .expect("matched redirect URI must remain parseable");
    Redirect::to(&url)
}

/// OIDC `prompt` 是**空格分隔的值列表**(OIDC Core §3.1.2.1)。解析结果。
struct PromptSet {
    none: bool,
    login: bool,
    /// `none` 与其它值组合是非法的(spec:none 不可与他值同现)。
    invalid: bool,
}

#[derive(Default)]
struct CimdContinuationParams {
    authz_session_id: Option<String>,
    digest: Option<String>,
    binding: Option<String>,
}

fn parse_cimd_continuation(raw_query: Option<&str>) -> Result<CimdContinuationParams, ()> {
    let mut continuation = CimdContinuationParams::default();
    for (key, value) in url::form_urlencoded::parse(raw_query.unwrap_or("").as_bytes()) {
        let slot = match key.as_ref() {
            "authz_session_id" => &mut continuation.authz_session_id,
            "cimd_digest" => &mut continuation.digest,
            "cimd_binding" => &mut continuation.binding,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(());
        }
    }
    Ok(continuation)
}

fn parse_prompt(prompt: Option<&str>) -> PromptSet {
    let Some(p) = prompt else {
        return PromptSet {
            none: false,
            login: false,
            invalid: false,
        };
    };
    let vals: Vec<&str> = p.split_whitespace().collect();
    let none = vals.contains(&"none");
    let login = vals.contains(&"login");
    // none 与任何其它值组合 → 非法(OIDC)。
    let invalid = none && vals.len() > 1;
    PromptSet {
        none,
        login,
        invalid,
    }
}

async fn verified_hint_subject(
    state: &AppState,
    tenant: &str,
    issuer: &str,
    client_id: &str,
    hint: &str,
    now: i64,
) -> Result<String, axum::response::Response> {
    let signer = crate::tenant_keys::signer_or_503(state, tenant).await?;
    let ec_keys = signer.public_jwks().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization signing keys unavailable",
        )
            .into_response()
    })?;
    let rsa_keys = signer.public_rsa_jwks().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization signing keys unavailable",
        )
            .into_response()
    })?;
    let mut jwks: Vec<crate::jwks::Jwk> = ec_keys.iter().map(crate::jwks::to_jwk).collect();
    jwks.extend(rsa_keys.iter().map(crate::jwks::rsa_to_jwk));
    crate::verify::verify_authorization_id_token_hint(hint, &jwks, issuer, client_id, now)
        .ok()
        .and_then(|verified| {
            verified
                .claims
                .get("sub")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid_request").into_response())
}

fn oidc_subject_for_user(
    state: &AppState,
    tenant: &str,
    client: &ClientRecord,
    user_id: &str,
) -> Option<String> {
    match crate::token::subject_mode(state.subject_type_for_tenant(tenant)) {
        agent_auth_token::SubjectMode::Public => Some(user_id.to_string()),
        agent_auth_token::SubjectMode::Pairwise => client
            .oidc_sector()
            .map(|sector| agent_auth_token::pairwise_sub(&state.server_secret, user_id, &sector)),
    }
}

fn values_are_subset(requested: &[String], authorized: &[String]) -> bool {
    requested
        .iter()
        .all(|value| authorized.iter().any(|item| item == value))
}

fn resources_are_covered_by_consent(requested: &[String], authorized: &[String]) -> bool {
    // An empty resource list selects the client's implicit/default OIDC target;
    // it is not a subset request for every explicitly authorized resource set.
    (!requested.is_empty() || authorized.is_empty()) && values_are_subset(requested, authorized)
}

async fn has_reusable_consent(
    state: &AppState,
    headers: &HeaderMap,
    tenant: &str,
    client_id: &str,
    session: &SessionRecord,
    requested_resources: &[String],
    requested_scopes: &[String],
    now: i64,
) -> Result<bool, axum::response::Response> {
    let grants = state
        .grants
        .list_by_user(tenant, &session.user_id)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization state unavailable",
            )
                .into_response()
        })?;
    let mut policy_error = None;
    for grant in grants {
        if grant.client_id != client_id
            || grant.user_id != session.user_id
            || grant.credential_epoch != session.credential_epoch
            || grant.is_usable(now).is_err()
        {
            continue;
        }
        let family = match state.refresh.get(tenant, &grant.grant_id).await {
            Ok(Some(family)) => family,
            Ok(None) => continue,
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization state unavailable",
                )
                    .into_response())
            }
        };
        if family.revoked
            || family.client_id != client_id
            || family.user_id != session.user_id
            || family.credential_epoch != session.credential_epoch
            || !resources_are_covered_by_consent(requested_resources, &family.resources)
            || !values_are_subset(requested_scopes, &family.scope)
        {
            continue;
        }
        match crate::user_gate::require_password_authority_version(
            state,
            tenant,
            &session.user_id,
            family.password_credential_version,
        )
        .await
        {
            crate::user_gate::PasswordGate::Allowed => {}
            crate::user_gate::PasswordGate::ChangeRequired => continue,
            crate::user_gate::PasswordGate::Unavailable => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password authority unavailable",
                )
                    .into_response())
            }
        }
        if !grant.per_resource.is_empty() {
            if let Err(response) =
                crate::policy_freshness::stale_gate(state, tenant, &grant, headers, now).await
            {
                policy_error = Some(response);
                continue;
            }
            if requested_resources.iter().any(|resource| {
                grant.resource_grant(resource).is_none_or(|resource_grant| {
                    !values_are_subset(requested_scopes, &resource_grant.scopes)
                })
            }) {
                continue;
            }
        }
        return Ok(true);
    }
    if let Some(response) = policy_error {
        return Err(response);
    }
    Ok(false)
}

async fn issue_silent_authorization_code(
    state: &AppState,
    tenant: &str,
    issuer: &str,
    p: &AuthorizeParams,
    resources: Vec<String>,
    session: SessionRecord,
    cimd_snapshot: Option<crate::cimd::CimdClientSnapshot>,
    authz_session_id: String,
    now: i64,
) -> axum::response::Response {
    let password_credential_version = match crate::user_gate::password_authority_snapshot(
        state,
        tenant,
        &session.user_id,
    )
    .await
    {
        Ok(version) => version,
        Err(crate::user_gate::PasswordGate::ChangeRequired) => {
            return redirect_error(p, "access_denied", issuer).into_response()
        }
        Err(crate::user_gate::PasswordGate::Unavailable) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "password authority unavailable",
            )
                .into_response()
        }
        Err(crate::user_gate::PasswordGate::Allowed) => unreachable!(),
    };
    if !crate::authz_session::bind_user(state, tenant, &authz_session_id, &session.user_id).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization session unavailable",
        )
            .into_response();
    }
    match crate::authz_session::try_transition(
        state,
        tenant,
        &authz_session_id,
        agent_auth_authn::authz_session::AuthzState::CodeIssuedAwaitingExchange,
        None,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: stale authorization session",
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization session unavailable",
            )
                .into_response()
        }
    }

    let code = make_code(state);
    let record = CodeRecord {
        code: code.clone(),
        client_id: p.client_id.clone(),
        cimd_snapshot,
        redirect_uri: p.redirect_uri.clone(),
        code_challenge: p.code_challenge.clone().unwrap_or_default(),
        resources,
        user_id: session.user_id.clone(),
        scope: p
            .scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .map(String::from)
            .collect(),
        expires_at: now + CODE_TTL_SECS,
        authz_session_id: Some(authz_session_id),
        nonce: p.nonce.clone(),
        auth_time: session.auth_time,
        authorization_details: Vec::new(),
        acr: Some(crate::assurance::session_class(&session).acr().to_string()),
        amr: session.amr,
        credential_epoch: Some(session.credential_epoch),
        password_credential_version,
    };
    match state
        .codes
        .put_authorized(&state.users, tenant, record, session.credential_epoch)
        .await
    {
        Ok(CodeIssueOutcome::Stored) => {}
        Ok(CodeIssueOutcome::AuthorityChanged) => {
            return redirect_error(p, "access_denied", issuer).into_response()
        }
        Ok(CodeIssueOutcome::CodeExists) | Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization code unavailable",
            )
                .into_response()
        }
    }

    let state_param = echo_state(p.state.as_deref());
    let mut params = vec![("code", code.as_str()), ("iss", issuer)];
    if let Some(state_param) = state_param.as_deref() {
        params.push(("state", state_param));
    }
    match oauth_response_url(&p.redirect_uri, &params) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "validated redirect URI became invalid",
        )
            .into_response(),
    }
}

/// `/authorize` 端点(P0 code flow;response_type=code only)。
#[utoipa::path(
    get,
    path = "/authorize",
    tag = "authorize",
    params(AuthorizeParams),
    responses(
        (status = 302, description = "回跳 redirect_uri?code=..&state=.. (授权成功)"),
        (status = 400, description = "invalid_request / unsupported_response_type / PKCE 缺失")
    )
)]
pub async fn authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> axum::response::Response {
    authorize_encoded(&state, &headers, raw_query).await
}

/// `POST /authorize` form transport. The raw form is preserved so repeated
/// parameters such as RFC 8707 `resource` retain the same semantics as GET.
#[utoipa::path(
    post,
    path = "/authorize",
    tag = "authorize",
    request_body(content = AuthorizeParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "回跳 redirect_uri?code=..&state=.. (授权成功)"),
        (status = 400, description = "invalid_request / unsupported_response_type / PKCE 缺失")
    )
)]
pub async fn authorize_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawForm(body): RawForm,
) -> axum::response::Response {
    let raw = match String::from_utf8(body.to_vec()) {
        Ok(raw) => raw,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: form 非 UTF-8").into_response()
        }
    };
    authorize_encoded(&state, &headers, Some(raw)).await
}

async fn authorize_encoded(
    state: &AppState,
    headers: &HeaderMap,
    raw_query: Option<String>,
) -> axum::response::Response {
    let q = raw_query.clone().unwrap_or_default();
    // PAR(RFC 9126,§7bis):**在 AuthorizeParams 提取前**探 request_uri(否则三必填字段致 request_uri-only
    // 请求过不了 Query extractor,评审 Kiro H1)。合法 PAR request_uri 先分流并忽略全部外层附加参数。
    match raw_single_parameter(&q, "request_uri") {
        Ok(Some(request_uri))
            if state.phase.at_least(agent_auth_discovery::Phase::P3)
                && request_uri.starts_with(PAR_URN_PREFIX) =>
        {
            return authorize_via_par(&state, &headers, &request_uri).await;
        }
        Ok(Some(_)) => {
            return authorization_protocol_error(state, headers, &q, "request_uri_not_supported")
                .await
        }
        Err(()) => {
            return authorization_protocol_error(state, headers, &q, "invalid_request").await
        }
        Ok(None) => {}
    }

    match raw_single_parameter(&q, "request") {
        Ok(Some(_)) => {
            return authorization_protocol_error(state, headers, &q, "request_not_supported").await
        }
        Err(()) => {
            return authorization_protocol_error(state, headers, &q, "invalid_request").await
        }
        Ok(None) => {}
    }

    if matches!(raw_single_parameter(&q, "response_type"), Ok(None)) {
        return authorization_protocol_error(state, headers, &q, "invalid_request").await;
    }

    // 常规:从 query 解析 AuthorizeParams(request_uri-only 之外,字段齐全)。
    let p: AuthorizeParams = match serde_urlencoded::from_str(&q) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: 参数解析失败").into_response()
        }
    };
    run_authorize(&state, &headers, raw_query, p).await
}

fn raw_single_parameter(raw: &str, expected: &str) -> Result<Option<String>, ()> {
    let mut value = None;
    for (key, item) in url::form_urlencoded::parse(raw.as_bytes()) {
        if key == expected && value.replace(item.into_owned()).is_some() {
            return Err(());
        }
    }
    Ok(value)
}

async fn authorization_protocol_error(
    state: &AppState,
    headers: &HeaderMap,
    raw: &str,
    error: &str,
) -> axum::response::Response {
    match trusted_authorization_error_redirect(state, headers, raw, error).await {
        Some(redirect) => redirect.into_response(),
        None => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn trusted_authorization_error_redirect(
    state: &AppState,
    headers: &HeaderMap,
    raw: &str,
    error: &str,
) -> Option<Redirect> {
    let client_id = raw_single_parameter(raw, "client_id").ok()??;
    let tenant = crate::tenant::tenant_or_400(state, headers).ok()?;
    let resolved = crate::cimd::resolve_client(state, &tenant, &client_id)
        .await
        .ok()?;
    if resolved.client.is_tombstoned() {
        return None;
    }

    let redirect_uri = match raw_single_parameter(raw, "redirect_uri").ok()? {
        Some(redirect_uri) => redirect_uri,
        None if resolved.client.redirect_uris.len() == 1 => {
            resolved.client.redirect_uris[0].clone()
        }
        None => return None,
    };
    let registered = match &resolved.source {
        crate::cimd::ClientSource::Registered => {
            crate::register::validate_application_redirects(
                resolved.client.application_type(),
                std::slice::from_ref(&redirect_uri),
            )
            .is_ok()
                && crate::register::registered_redirect_matches(&resolved.client, &redirect_uri)
                    .ok()?
        }
        crate::cimd::ClientSource::Cimd => resolved.client.redirect_uris.iter().any(|registered| {
            matches!(
                match_redirect(&RedirectMode::Exact, registered, &redirect_uri),
                MatchResult::Allow
            )
        }),
    };
    if !registered {
        return None;
    }

    let issuer =
        host_from_headers(headers).and_then(|host| derive_issuer(&host, &state.form).ok())?;
    let state_param = raw_single_parameter(raw, "state").ok()?;
    let mut params = vec![("error", error), ("iss", issuer.as_str())];
    if let Some(state_param) = state_param.as_deref() {
        params.push(("state", state_param));
    }
    let location = oauth_response_url(&redirect_uri, &params).ok()?;
    Some(Redirect::to(&location))
}

/// authorize 处理核心(spec 006;从 authorize_handler 抽出解耦 extractor,供直连 + PAR 两入口复用,§7bis)。
/// `raw_query` = 有效授权参数串(直连=HTTP query;PAR=存储的 raw_params);`p` = 由该串解析的 AuthorizeParams。
async fn run_authorize(
    state: &AppState,
    headers: &HeaderMap,
    raw_query: Option<String>,
    mut p: AuthorizeParams,
) -> axum::response::Response {
    // 只支持 code(implicit/hybrid 永久不存在,006)。
    if p.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported_response_type").into_response();
    }

    // 多 resource 处理(C2.5b/C2.8 / 006 4.2/6.1):`Query<AuthorizeParams>` 的 `resource: Option<String>`
    // 只取末个,无法察觉重复 `resource=`;故从**原始 query** 解析所有 `resource=`(逐 kv 解码**键**再比对,
    // 评审 M3:防 `res%6furce=` 编码键绕过计数),交 protocol 层按**部署阶段**判定:
    // - P0:>1 即拒(MultiResourceRejectedP0,单 resource 绑定);
    // - P1+:允许多 resource 集合写入 code,token 侧收窄到单值(select_audience,C2.5b)。
    // resource 值 percent-decode(存 CodeRecord 用解码后的规范值,与 token 侧比对一致)。
    let resource_params: Vec<String> = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| crate::consent::pct_decode(k) == "resource")
        .map(|(_, v)| crate::consent::pct_decode(v))
        .filter(|v| !v.is_empty())
        .collect();
    let authorize_phase = if state.phase.at_least(agent_auth_discovery::Phase::P1) {
        agent_auth_protocol::AuthorizePhase::P1Plus
    } else {
        agent_auth_protocol::AuthorizePhase::P0
    };
    let authorized_resources = match agent_auth_protocol::AuthorizedResources::from_authorize(
        &resource_params,
        authorize_phase,
    ) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_target: P0 单次 authorize 只允许单个 resource(见 C2.8);多 resource 属 P1+",
            )
                .into_response();
        }
    };

    // RAR 发行(RFC 9396 authorization_details;spec 010 §4 / C8.5a):从原始 query 取(JSON 参数,
    // Query extractor 不解嵌套 JSON),percent-decode → 解析数组 → **准入校验**(type∈词汇表 + 字段∈词汇表
    // + 值格式,grant::rar::validate_admission)。**phase 门控**:P0/P1 拒(fail-closed——静默忽略会让
    // 客户端以为拿到细粒度收窄实则 token 更宽,危险);P2+ 接受。空/无参 → 无 RAR(继续)。
    let authorization_details: Vec<serde_json::Value> = match raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| crate::consent::pct_decode(k) == "authorization_details")
        .map(|(_, v)| crate::consent::pct_decode(v))
    {
        Some(raw) if !raw.is_empty() => {
            if !state.phase.at_least(agent_auth_discovery::Phase::P2) {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_request: authorization_details(RAR)属 P2,当前阶段不支持",
                )
                    .into_response();
            }
            let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "invalid_authorization_details: 非合法 JSON",
                    )
                        .into_response()
                }
            };
            // 准入 + **locations 越界校验**(评审 codex HIGH:带 locations 的 RAR MUST 命中授权 resource
            // 集,否则落空 → SDK 视缺失 RAR 为 scope 放行 = 签出比 RAR 请求更宽的 token)。
            if let Err(e) =
                agent_auth_grant::rar::validate_admission_for_resources(&parsed, &resource_params)
            {
                // 准入不合规(未知 type/未知约束字段/值格式/超量/locations 越界)→ invalid_authorization_details。
                let _ = e;
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_authorization_details: 未通过内建词汇表准入校验(type/字段/格式/locations 越界)",
                )
                    .into_response();
            }
            parsed.as_array().cloned().unwrap_or_default()
        }
        _ => Vec::new(),
    };
    // 已准入校验的 RAR 规范 JSON 串(透传 /login→/consent 链;空=无 RAR)。重新序列化(而非透传原始
    // percent-decode 串)确保规范形态 + 已被 serde 解析过,不夹带畸形。
    let rar_json: String = if authorization_details.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&authorization_details).unwrap_or_default()
    };

    // issuer 派生(C1.6a)——用于授权响应 iss(C1.4 RFC 9207 mix-up 防护)。
    let issuer = match host_from_headers(headers).and_then(|h| derive_issuer(&h, &state.form).ok())
    {
        Some(i) => i,
        None => return (StatusCode::BAD_REQUEST, "invalid_request: Host 非法").into_response(),
    };
    // tenant 分区(spec 020 §2.3):client/code/user 按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Some(browser_origin) = crate::hostutil::browser_origin(state, headers) else {
        return (StatusCode::BAD_REQUEST, "invalid browser origin").into_response();
    };

    // 客户端存在 + redirect_uri 属注册集合精确匹配(C4.5)。
    let resolved_client = match crate::cimd::resolve_client(state, &tenant, &p.client_id).await {
        Ok(client) => client,
        Err(
            crate::cimd::ResolveClientError::Unknown | crate::cimd::ResolveClientError::Invalid(_),
        ) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: 未知或非法 client",
            )
                .into_response()
        }
        Err(crate::cimd::ResolveClientError::TemporarilyUnavailable) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "client metadata 暂时不可用",
            )
                .into_response()
        }
        Err(crate::cimd::ResolveClientError::Store) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "client store error").into_response()
        }
    };
    let audit_client_id = resolved_client.audit_identifier();
    let cimd_digest = resolved_client.cimd_digest();
    let continuation = match parse_cimd_continuation(raw_query.as_deref()) {
        Ok(continuation) => continuation,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: duplicate authorization continuation",
            )
                .into_response()
        }
    };
    let now = crate::token::current_unix_secs_pub();
    let resumed_cimd_session = match resolved_client.cimd_snapshot.as_ref() {
        Some(snapshot) => match (
            continuation.authz_session_id.as_deref(),
            continuation.digest.as_deref(),
            continuation.binding.as_deref(),
        ) {
            (None, None, None) => None,
            (Some(session_id), Some(digest), Some(binding))
                if !session_id.is_empty()
                    && !digest.is_empty()
                    && !binding.is_empty()
                    && digest == snapshot.digest()
                    && crate::cimd::verify_continuation_binding(
                        &state.server_secret,
                        session_id,
                        &p.client_id,
                        digest,
                        binding,
                    ) =>
            {
                use crate::ports::AuthzSessionStore;
                match state.authz_sessions.get(&tenant, session_id).await {
                    Ok(Some(record))
                        if record.expires_at > now
                            && record.client_id == audit_client_id
                            && matches!(
                                agent_auth_authn::authz_session::AuthzState::parse(&record.state),
                                Some(
                                    agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication
                                        | agent_auth_authn::authz_session::AuthzState::PendingConsent
                                )
                            ) =>
                    {
                        Some(session_id.to_string())
                    }
                    Ok(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "invalid_request: stale CIMD authorization continuation",
                        )
                            .into_response()
                    }
                    Err(_) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "authorization continuation unavailable",
                        )
                            .into_response()
                    }
                }
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_request: invalid CIMD authorization continuation",
                )
                    .into_response()
            }
        },
        None => {
            if continuation.digest.is_some() || continuation.binding.is_some() {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid_request: unexpected CIMD authorization continuation",
                )
                    .into_response();
            }
            None
        }
    };
    let enforce_application_type = matches!(
        &resolved_client.source,
        crate::cimd::ClientSource::Registered
    );
    let client_source = resolved_client.source;
    let cimd_snapshot = resolved_client.cimd_snapshot;
    let client = resolved_client.client;
    // tombstone 闸(spec 005 §9.3,C10.5):回收中的 client MUST NOT 建新 code/session。
    if client.is_tombstoned() {
        return (StatusCode::BAD_REQUEST, "invalid_request: client 已回收").into_response();
    }
    // C4.1/C5.6: apply the shared client-source, client-type, and PKCE policy.
    match check_authorization_code_policy(
        state,
        &client_source,
        &client,
        p.code_challenge.as_deref(),
        p.code_challenge_method.as_deref(),
    ) {
        Ok(()) => {}
        Err(AuthorizationCodePolicyError::Workload) => {
            return (
                StatusCode::BAD_REQUEST,
                "unauthorized_client: workload clients cannot use authorization_code flow",
            )
                .into_response()
        }
        Err(AuthorizationCodePolicyError::MissingChallenge) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: 缺 code_challenge",
            )
                .into_response()
        }
        Err(AuthorizationCodePolicyError::NotS256) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: code_challenge_method 须 S256",
            )
                .into_response()
        }
    }
    if enforce_application_type
        && crate::register::validate_application_redirects(
            client.application_type(),
            std::slice::from_ref(&p.redirect_uri),
        )
        .is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request: redirect_uri 不符合 application_type 策略",
        )
            .into_response();
    }
    // Registered native loopback callbacks accept an ephemeral inbound port;
    // CIMD callbacks remain exact because the verified document is the policy.
    let matched = if enforce_application_type {
        match crate::register::registered_redirect_matches(&client, &p.redirect_uri) {
            Ok(matched) => matched,
            Err(message) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid_request: {message}"),
                )
                    .into_response()
            }
        }
    } else {
        client.redirect_uris.iter().any(|registered| {
            matches!(
                match_redirect(&RedirectMode::Exact, registered, &p.redirect_uri),
                MatchResult::Allow
            )
        })
    };
    if !matched {
        // redirect_uri 非法时 MUST NOT 回跳(防开放重定向),直接 400。
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request: redirect_uri 未注册",
        )
            .into_response();
    }

    // ⚠️ authorize **永不直接签 code**(修评审 CRITICAL:有会话直接签会跳过用户 consent 同意,
    // 违反 DESIGN §4)。三态:
    // ① 有 AS 会话(已登录)→ 重定向到前端 /consent,由用户同意后 POST /consent 才签 code;
    // ② 无会话但 allow_login_placeholder + login_user → **仅 e2e 快捷**(dev-only,gated):
    //    直接签 code(等价"已登录且已同意"的测试捷径,注释钉死;生产 allow_login_placeholder=false);
    // ③ 都没有 → 重定向前端 /login(带 authorize 上下文)。
    // spec 004(评审 H2):authorize **受理时即创建授权会话**,据登录态选初始态
    // (已登录→pending_consent,未登录→pending_user_authentication),id 随重定向链透传,
    // consent 迁移同一条会话而非新建 —— 让 created/pending_* 成为真实流的可观测态,非死代码。
    // C9.5a:prompt 是空格分隔值列表;none 与他值组合非法(OIDC)。
    let prompt = parse_prompt(p.prompt.as_deref());
    if prompt.invalid {
        return redirect_error(&p, "invalid_request", issuer.as_str()).into_response();
    }
    let requirement = match crate::assurance::resolve_requirement(
        &state.assurance_policy,
        p.acr_values.as_deref(),
        &authorization_details,
        p.max_age,
    ) {
        Ok(requirement) => requirement,
        Err(crate::assurance::RequirementError::UnsupportedAcrValues) => {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                    &tenant,
                    None,
                    &audit_client_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                ))
                .await;
            return redirect_error(&p, "unmet_authentication_requirements", issuer.as_str())
                .into_response();
        }
        Err(crate::assurance::RequirementError::InvalidMaxAge) => {
            return redirect_error(&p, "invalid_request", issuer.as_str()).into_response()
        }
    };
    if requirement.step_up {
        p.acr_values = Some(requirement.class.acr().to_string());
        p.max_age = requirement.max_age_secs;
    }

    // Use the full session evidence for both class and freshness. `prompt=login`
    // always forces a new event, but is intentionally not copied into the
    // browser continuation query to avoid a reauthentication loop.
    let session = crate::login::current_session_full(state, headers).await;
    let hint_subject = match p.id_token_hint.as_deref() {
        Some(hint) => {
            match verified_hint_subject(state, &tenant, issuer.as_str(), &p.client_id, hint, now)
                .await
            {
                Ok(subject) => Some(subject),
                Err(response) if response.status() == StatusCode::BAD_REQUEST => {
                    return redirect_error(&p, "invalid_request", issuer.as_str()).into_response()
                }
                Err(response) => return response,
            }
        }
        None => None,
    };
    let hint_matches_session = match (hint_subject.as_deref(), session.as_ref()) {
        (Some(subject), Some(session)) => {
            oidc_subject_for_user(state, &tenant, &client, &session.user_id).as_deref()
                == Some(subject)
        }
        (Some(_), None) => false,
        (None, _) => true,
    };
    let fresh = hint_matches_session
        && !prompt.login
        && crate::assurance::session_satisfies(requirement, session.as_ref(), now);

    // prompt=none 且不满足新鲜会话 → OIDC login_required(不静默弹登录,C9.5a)。
    if prompt.none && !fresh {
        if requirement.step_up {
            state
                .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                    &tenant,
                    session.as_ref().map(|session| session.user_id.as_str()),
                    &audit_client_id,
                    crate::security_event::SecurityEventOutcome::Denied,
                ))
                .await;
        }
        let error = if !hint_matches_session {
            "login_required"
        } else if requirement.step_up && session.is_some() {
            "unmet_authentication_requirements"
        } else {
            "login_required"
        };
        return redirect_error(&p, error, issuer.as_str()).into_response();
    }

    if prompt.none {
        let session = session
            .clone()
            .expect("fresh prompt=none authorization requires an active session");
        if !authorization_details.is_empty() {
            return redirect_error(&p, "consent_required", issuer.as_str()).into_response();
        }
        let requested_scopes: Vec<String> = p
            .scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .map(String::from)
            .collect();
        match has_reusable_consent(
            state,
            headers,
            &tenant,
            &p.client_id,
            &session,
            &resource_params,
            &requested_scopes,
            now,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return redirect_error(&p, "consent_required", issuer.as_str()).into_response()
            }
            Err(response) => return response,
        }

        let authz_session_id = match resumed_cimd_session {
            Some(session_id) => {
                let current = state.authz_sessions.get(&tenant, &session_id).await;
                match current {
                    Ok(Some(record))
                        if record.state
                            == agent_auth_authn::authz_session::AuthzState::PendingConsent
                                .as_str() => {}
                    Ok(Some(record))
                        if record.state
                            == agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication
                                .as_str() =>
                    {
                        match crate::authz_session::try_transition(
                            state,
                            &tenant,
                            &session_id,
                            agent_auth_authn::authz_session::AuthzState::PendingConsent,
                            None,
                        )
                        .await
                        {
                            Ok(true) => {}
                            _ => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    "invalid_request: stale authorization session",
                                )
                                    .into_response()
                            }
                        }
                    }
                    _ => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "invalid_request: stale authorization session",
                        )
                            .into_response()
                    }
                }
                session_id
            }
            None => match crate::authz_session::create_session(
                state,
                &tenant,
                &audit_client_id,
                agent_auth_authn::authz_session::AuthzState::PendingConsent,
                now,
            )
            .await
            {
                Some((session_id, _)) => session_id,
                None => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "authorization session unavailable",
                    )
                        .into_response()
                }
            },
        };
        return issue_silent_authorization_code(
            state,
            &tenant,
            issuer.as_str(),
            &p,
            resource_params,
            session,
            cimd_snapshot,
            authz_session_id,
            now,
        )
        .await;
    }

    // spec 004(评审 H2):authorize **受理时即创建授权会话**,据登录态选初始态
    // (fresh→pending_consent,须重认证→pending_user_authentication),id 随重定向链透传。
    let initial = if fresh {
        agent_auth_authn::authz_session::AuthzState::PendingConsent
    } else {
        agent_auth_authn::authz_session::AuthzState::PendingUserAuthentication
    };
    let resumed_cimd = resumed_cimd_session.is_some();
    let authz_sid = match resumed_cimd_session {
        Some(session_id) => session_id,
        None => match crate::authz_session::create_session(
            state,
            &tenant,
            &audit_client_id,
            initial,
            now,
        )
        .await
        {
            Some((session_id, _)) => session_id,
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization session unavailable",
                )
                    .into_response()
            }
        },
    };
    let continuation_sid = authz_sid.as_str();
    let cimd_binding = cimd_digest.as_deref().map(|digest| {
        crate::cimd::continuation_binding(
            &state.server_secret,
            continuation_sid,
            &p.client_id,
            digest,
        )
    });

    if fresh {
        if resumed_cimd {
            crate::authz_session::transition(
                state,
                &tenant,
                &authz_sid,
                agent_auth_authn::authz_session::AuthzState::PendingConsent,
                None,
            )
            .await;
        }
        // 新鲜会话 → 去 consent 同意页(consent 后端签 code)。prompt=login/max_age 超时时 fresh=false,
        // 会落到下方 login 分支强制重认证。
        return redirect_to_consent(
            &browser_origin,
            &p,
            &resource_params,
            &rar_json,
            &authz_sid,
            cimd_digest.as_deref(),
            cimd_binding.as_deref(),
        )
        .into_response();
    }
    let placeholder_user = if state.allow_login_placeholder {
        p.login_user.as_deref().filter(|s| !s.is_empty())
    } else {
        None
    };
    let Some(user) = placeholder_user else {
        // 未登录 + 带 idp_hint + 联邦启用 → 重定向到上游 IdP(spec 003 §4);原 authorize query 作
        // 下游续跑上下文(callback 成功后带 session 回跳本 /authorize 续流发码,F1)。回落:联邦关/config
        // 缺/tenant 不定 → start 返 None → 走本地登录(不报错、不泄露)。
        if let Some(hint) = p.idp_hint.as_deref().filter(|s| !s.is_empty()) {
            let continuation = context_query_with_session(
                &p,
                &resource_params,
                &rar_json,
                &authz_sid,
                cimd_digest.as_deref(),
                cimd_binding.as_deref(),
            );
            if let Some(resp) = crate::federation_flow::start(
                state,
                headers,
                hint,
                &continuation,
                requirement.max_age_secs,
                prompt.login
                    || requirement.step_up
                    || requirement.max_age_secs == Some(0)
                    || session.is_some(),
            )
            .await
            {
                return resp;
            }
        }
        // 未登录 → 前端登录页(登录后经 /consent 续流)。
        return redirect_to_login(
            &browser_origin,
            &p,
            &resource_params,
            &rar_json,
            &authz_sid,
            cimd_digest.as_deref(),
            cimd_binding.as_deref(),
        )
        .into_response();
    };

    // —— 仅 dev/e2e 占位快捷:直接签 code(生产不可达)——
    // The placeholder is not an authentication method and can never satisfy a
    // strong/RAR step-up, even in local tests.
    if requirement.step_up {
        state
            .record_security_event(crate::security_event::SecurityEventDraft::step_up(
                &tenant,
                None,
                &audit_client_id,
                crate::security_event::SecurityEventOutcome::Denied,
            ))
            .await;
        return redirect_error(&p, "unmet_authentication_requirements", issuer.as_str())
            .into_response();
    }
    // **active-user gate(评审 codex Medium,spec 003 §1.4"发 code")**:占位快捷也发 code,故发码前
    // 复查 status(与 consent 发码对称)。dev-only 路径,`is_local_email_user` 天然跳过非 `user:` 占位。
    let credential_epoch = match crate::user_gate::active_user_epoch(state, &tenant, user).await {
        Ok(epoch) => epoch,
        Err(crate::user_gate::UserGate::Blocked) => {
            return redirect_error(&p, "access_denied", issuer.as_str()).into_response()
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "user status 查询失败").into_response()
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    };
    let password_credential_version =
        match crate::user_gate::password_authority_snapshot(state, &tenant, user).await {
            Ok(version) => version,
            Err(crate::user_gate::PasswordGate::ChangeRequired) => {
                return redirect_error(&p, "access_denied", issuer.as_str()).into_response()
            }
            Err(crate::user_gate::PasswordGate::Unavailable) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "password authority 查询失败",
                )
                    .into_response()
            }
            Err(crate::user_gate::PasswordGate::Allowed) => unreachable!(),
        };
    // resource 集合 = 从原始 query 解析的**全部** resource(P0 单值/P1+ 多值,已过 from_authorize 校验),
    // 写 CodeRecord;token 侧按 select_audience 收窄到单值(C2.5b)。取代旧的单值 `p.resource`。
    let resources: Vec<String> = resource_params.clone();
    let _ = &authorized_resources; // 校验用(from_authorize),值已在 resource_params
    let scope: Vec<String> = p
        .scope
        .as_deref()
        .unwrap_or("openid")
        .split_whitespace()
        .map(String::from)
        .collect();
    let code = make_code(state); // CSPRNG 随机码;多区域模式加区域属主前缀
                                 // spec 004:占位快捷等价"已登录+已同意",推进上方已建的会话
                                 // pending_user_authentication → pending_consent → code_issued_awaiting_exchange。
    use agent_auth_authn::authz_session::AuthzState;
    if !crate::authz_session::bind_user(state, &tenant, &authz_sid, user).await {
        return redirect_error(&p, "access_denied", issuer.as_str()).into_response();
    }
    crate::authz_session::transition(state, &tenant, &authz_sid, AuthzState::PendingConsent, None)
        .await;
    let record = CodeRecord {
        code: code.clone(),
        client_id: p.client_id.clone(),
        cimd_snapshot,
        redirect_uri: p.redirect_uri.clone(),
        code_challenge: p.code_challenge.clone().unwrap_or_default(),
        resources,
        user_id: user.to_string(),
        scope,
        expires_at: now + CODE_TTL_SECS,
        authz_session_id: Some(authz_sid.clone()),
        nonce: p.nonce.clone(),
        auth_time: now, // 占位登录:受理时刻即"登录时刻"(真实登录接入后用会话 auth_time)
        authorization_details: authorization_details.clone(), // RAR(已准入校验;dev 快捷直接落 code)
        // dev 占位登录:无上游 acr;amr 视作占位(login_user 快捷,非真实认证)。
        acr: None,
        amr: Vec::new(),
        credential_epoch: Some(credential_epoch),
        password_credential_version,
    };
    match state
        .codes
        .put_authorized(&state.users, &tenant, record, credential_epoch)
        .await
    {
        Ok(CodeIssueOutcome::Stored) => {}
        Ok(CodeIssueOutcome::AuthorityChanged) => {
            return redirect_error(&p, "access_denied", issuer.as_str()).into_response();
        }
        Ok(CodeIssueOutcome::CodeExists) | Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response();
        }
    }
    crate::authz_session::transition(
        state,
        &tenant,
        &authz_sid,
        AuthzState::CodeIssuedAwaitingExchange,
        None,
    )
    .await;

    // 回跳:code + iss(C1.4 RFC 9207 mix-up 防护)+ state 逐字节 echo(C1.7,percent-encode 防注入)。
    let state_param = echo_state(p.state.as_deref());
    let mut params = vec![("code", code.as_str()), ("iss", issuer.as_str())];
    if let Some(state_param) = state_param.as_deref() {
        params.push(("state", state_param));
    }
    let url = match oauth_response_url(&p.redirect_uri, &params) {
        Ok(url) => url,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "validated redirect URI became invalid",
            )
                .into_response()
        }
    };
    Redirect::to(&url).into_response()
}

// ============ PAR(RFC 9126,spec 006 §7.3,P3)============

/// PAR request_uri TTL(秒;短命 ≤90s,§2.1)。
const PAR_TTL_SECS: i64 = 90;
/// request_uri URN 前缀(RFC 9126 §2.2)。
const PAR_URN_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// authorize 的 PAR 分支:consume request_uri(过期/已用拒)→ 用存储 raw_params 走 run_authorize
/// (**忽略请求其余全部 query**,含 client_id,RFC 9126 §4)。
async fn authorize_via_par(
    state: &AppState,
    headers: &HeaderMap,
    request_uri: &str,
) -> axum::response::Response {
    use crate::ports::ParStore;
    let Some(opaque) = request_uri.strip_prefix(PAR_URN_PREFIX) else {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request_uri: request_uri 格式非法",
        )
            .into_response();
    };
    if !state.region.owns_id(opaque) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request_uri: request_uri 属于其他区域",
        )
            .into_response();
    }
    let tenant = match crate::tenant::tenant_or_400(state, headers) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let now = crate::token::current_unix_secs_pub();
    let rec = match state.par.consume(&tenant, request_uri, now).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // 不存在/已消费/过期 → RFC 9126:invalid_request_uri。
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request_uri: request_uri 无效/已用/过期",
            )
                .into_response();
        }
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response(),
    };
    // 用存储的授权参数(权威),忽略本次请求 query 其余参数。
    let p: AuthorizeParams = match serde_urlencoded::from_str(&rec.raw_params) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: PAR 参数损坏").into_response()
        }
    };
    // 绑定:存储的 client_id 权威(PAR 存的即提交者);run_authorize 内按 p.client_id 查 client。
    // (p 由 rec.raw_params 解析,其 client_id 就是 PAR 提交时的 client_id,天然绑定。)
    run_authorize(state, headers, Some(rec.raw_params), p).await
}

/// `POST /par`(RFC 9126,P3):推送授权请求 → 存一次性 request_uri。confidential 过 client 认证;
/// public 无认证并强制 PKCE。**校验段复用 run_authorize 前置策略**(此处做基本校验:
/// response_type/client_id/redirect_uri/PKCE policy + client 存在 + 认证);存储前**剔除认证参数**(H3)。
#[utoipa::path(post, path = "/par", tag = "authorize",
    responses((status = 201), (status = 400), (status = 401), (status = 404)))]
pub async fn par_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(_rq): RawQuery,
    body: String,
) -> impl IntoResponse {
    // 阶段门控(C1.2):仅 P3+ 可达。
    if !state.phase.at_least(agent_auth_discovery::Phase::P3) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    // 解析授权参数(form body,与 authorize query 同格式)。
    let p: AuthorizeParams = match serde_urlencoded::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: 参数解析失败").into_response()
        }
    };
    let auth: ParClientAuthParams = match serde_urlencoded::from_str(&body) {
        Ok(auth) => auth,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: 参数解析失败").into_response()
        }
    };
    // 基本校验(RFC 9126 §2.2:以与 authorize 相同方式校验)。
    if p.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported_response_type").into_response();
    }
    if p.redirect_uri.is_empty() || p.client_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "invalid_request: 缺 client_id/redirect_uri",
        )
            .into_response();
    }
    // tenant 分区(spec 020 §2.3):client 查询按 tenant 隔离(flag 关=空 tenant)。
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // 取 client + 认证(confidential 过 verify_client_auth;public/none 无 secret 放行,靠 PKCE)。
    let resolved_client = match crate::cimd::resolve_client(&state, &tenant, &p.client_id).await {
        Ok(resolved) => resolved,
        Err(
            crate::cimd::ResolveClientError::Unknown | crate::cimd::ResolveClientError::Invalid(_),
        ) => {
            return (
                StatusCode::UNAUTHORIZED,
                "invalid_client: 未知或非法 client",
            )
                .into_response()
        }
        Err(crate::cimd::ResolveClientError::TemporarilyUnavailable) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "client metadata 暂时不可用",
            )
                .into_response()
        }
        Err(crate::cimd::ResolveClientError::Store) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "client store error").into_response()
        }
    };
    let audit_client_id = resolved_client.audit_identifier();
    let client_source = resolved_client.source;
    let client = resolved_client.client;
    if client.is_tombstoned() {
        return (StatusCode::UNAUTHORIZED, "invalid_client: client 已回收").into_response();
    }
    let client = match crate::client_auth::authenticate_loaded_snapshot_with_audit_identifier(
        &state,
        &tenant,
        crate::client_auth::ClientAuthEndpoint::Par,
        &client,
        &headers,
        crate::client_auth::PresentedClientAuth::new(
            auth.client_secret.as_deref(),
            auth.client_assertion_type.as_deref(),
            auth.client_assertion.as_deref(),
        ),
        &audit_client_id,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            return match error {
                crate::client_auth::ClientAuthError::TemporarilyUnavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::ServerMisconfigured => {
                    (StatusCode::INTERNAL_SERVER_ERROR, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::InvalidRequest(_) => {
                    (StatusCode::BAD_REQUEST, error.description()).into_response()
                }
                crate::client_auth::ClientAuthError::InvalidClient(_) => (
                    StatusCode::UNAUTHORIZED,
                    format!("invalid_client: {}", error.description()),
                )
                    .into_response(),
            }
        }
    };
    match check_authorization_code_policy(
        &state,
        &client_source,
        &client,
        p.code_challenge.as_deref(),
        p.code_challenge_method.as_deref(),
    ) {
        Ok(()) => {}
        Err(AuthorizationCodePolicyError::Workload) => {
            return (
                StatusCode::BAD_REQUEST,
                "unauthorized_client: workload clients cannot use authorization_code flow",
            )
                .into_response()
        }
        Err(AuthorizationCodePolicyError::MissingChallenge) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: 缺 code_challenge(PKCE)",
            )
                .into_response()
        }
        Err(AuthorizationCodePolicyError::NotS256) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid_request: code_challenge_method 须 S256",
            )
                .into_response()
        }
    }
    // 存储前**剔除认证参数**(H3:client_secret/client_assertion* 绝不落库明文)——重建只含授权参数的串。
    let cleaned: String = form_urlencoded_strip_auth(&body);
    let request_uri = format!("{PAR_URN_PREFIX}{}", make_code(&state)); // opaque = CSPRNG 32B(L1)
    let now = crate::token::current_unix_secs_pub();
    use crate::ports::ParStore;
    if state
        .par
        .put(
            &tenant,
            crate::ports::ParRecord {
                request_uri: request_uri.clone(),
                client_id: p.client_id.clone(),
                raw_params: cleaned,
                expires_at: now + PAR_TTL_SECS,
            },
        )
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "存储瞬时不可用").into_response();
    }
    // RFC 9126 §2.2:201 + {request_uri, expires_in}。session_token 不在此返回(§7.3 M3,载体职责延 §4)。
    (
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "request_uri": request_uri,
            "expires_in": PAR_TTL_SECS,
        })),
    )
        .into_response()
}

/// 从 form-encoded 串剔除认证参数(client_secret/client_assertion/client_assertion_type),保留授权参数。
/// H3:PAR 存储绝不含明文凭证。逐 kv 解码键判定,重编码保留项(与 authorize 解析口径一致)。
fn form_urlencoded_strip_auth(body: &str) -> String {
    body.split('&')
        .filter(|kv| {
            let k = kv.split_once('=').map(|(k, _)| k).unwrap_or(kv);
            let dk = crate::consent::pct_decode(k);
            dk != "client_secret" && dk != "client_assertion" && dk != "client_assertion_type"
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(authorize_handler))
        .routes(routes!(authorize_post_handler))
        .routes(routes!(par_handler))
}
