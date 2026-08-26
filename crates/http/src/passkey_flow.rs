//! WebAuthn passkey 登录仪式 HTTP 面(spec 003 §3,C9.4)。注册/认证仪式 + 会话鉴权状态端点。
//! **feature-gated**(`state.passkey_enabled`,F10 同 federation):默认关时全 404——尤其
//! authenticate/finish 签发全 AS 会话(amr=["webauthn","hwk"]),e2e 全绿前不暴露不完整主认证面。
//!
//! 纯判定逻辑在 authn::passkey(`verify_attestation_none` 注册 / `verify_assertion` 认证,均已 UT);
//! 本模块只做 IO 编排:challenge 生命周期(begin 存、finish 一次性 consume)+ 存储 + 会话。全 fail-closed。
//!
//! **仪式 vs 会话**:register 须**已登录会话**(passkey 绑当前 user_id;不能匿名注册他人)。
//! authenticate 是 pre-login(它就是登录):P1 用 `login_hint`(email)定位候选凭证(usernameless 留后)。
//!
//! 决策真相源:docs/DESIGN §7(rp_id 逐租户)/ §8;CONFORMANCE C9.4;评审 Kiro(UV/gate/challenge 绑定)。

use agent_auth_authn::passkey::{
    rp_id_from_issuer_host, verify_assertion, verify_attestation_none, AssertionExpectations,
    AssertionInput, PasskeyCredential, RegistrationExpectations,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    PasskeyCeremony, PasskeyChallenge, PasskeyChallengeStore, PasskeyRegistrationOutcome,
    PasskeyStore, SessionRecord, SessionStore, StoreError, UsersStore,
};
use crate::state::AppState;

const SESSION_COOKIE: &str = "__Host-agent_auth_session";
const SESSION_TTL_SECS: i64 = 3600;
const CHALLENGE_TTL_SECS: i64 = 300; // 仪式 challenge 短命窗 ≤5min
const REQUIRE_UV: bool = true; // 无密码主因子 MUST UV(评审 Kiro High)

fn now_secs() -> i64 {
    crate::token::current_unix_secs_pub()
}

fn rand_challenge() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

fn passkey_gate(state: &AppState) -> Option<axum::response::Response> {
    if !state.passkey_enabled {
        return Some((StatusCode::NOT_FOUND, "passkey not enabled").into_response());
    }
    if matches!(state.form, agent_auth_discovery::Form::Saas { .. }) && !state.tenant_partitioning {
        return Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "passkey tenant isolation unavailable",
            )
                .into_response(),
        );
    }
    None
}

/// WebAuthn RP + 浏览器 origin。统一复用浏览器交互 origin 口径。
pub(crate) fn rp_id_and_origin(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    if matches!(state.form, agent_auth_discovery::Form::Saas { .. }) && !state.tenant_partitioning {
        return None;
    }
    let origin = crate::hostutil::browser_origin(state, headers)?;
    let uri: axum::http::Uri = origin.parse().ok()?;
    let host = uri.authority()?.host();
    Some((rp_id_from_issuer_host(host), origin))
}

fn challenge_matches(
    challenge: &PasskeyChallenge,
    ceremony: PasskeyCeremony,
    tenant: &str,
    rp_id: &str,
    origin: &str,
) -> bool {
    challenge.ceremony == ceremony
        && challenge.tenant == tenant
        && challenge.rp_id == rp_id
        && challenge.origin == origin
}

async fn passkey_snapshot_is_authoritative(
    state: &AppState,
    tenant: &str,
    expected: &PasskeyCredential,
    expected_sign_count: u32,
) -> Result<bool, StoreError> {
    Ok(state
        .passkeys
        .get(tenant, &expected.credential_id)
        .await?
        .is_some_and(|current| {
            current.user_id == expected.user_id
                && current.rp_id == expected.rp_id
                && current.public_key_sec1 == expected.public_key_sec1
                && current.created_at == expected.created_at
                && current.sign_count == expected_sign_count
        }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PasskeyStatusResponse {
    pub configured: bool,
    pub count: usize,
}

/// `GET /passkey/status`(会话鉴权):返回当前用户的 passkey 配置摘要。
#[utoipa::path(get, path = "/passkey/status", tag = "logout",
    responses(
        (status = 200, body = PasskeyStatusResponse),
        (status = 401),
        (status = 404),
        (status = 503)
    ))]
pub async fn passkey_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(response) = passkey_gate(&state) {
        return response;
    }
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some((_session_id, user_id)) = crate::login::current_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    let credentials = match state.passkeys.list_by_user(&tenant, &user_id).await {
        Ok(credentials) => credentials,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
    };
    Json(PasskeyStatusResponse {
        configured: !credentials.is_empty(),
        count: credentials.len(),
    })
    .into_response()
}

// ---- register(须已登录会话)----

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisterBeginResponse {
    /// PublicKeyCredentialCreationOptions 子集(前端喂 navigator.credentials.create)。
    pub rp_id: String,
    pub user_id: String,
    pub challenge: String,
    /// 已注册凭证 id 列表(excludeCredentials:防同 authenticator 重复注册)。
    pub exclude_credentials: Vec<String>,
    /// pubKeyCredParams:仅 ES256(-7)。
    pub alg: i64,
    /// userVerification 要求(MUST required,评审 Kiro)。
    pub user_verification: &'static str,
}

/// `POST /passkey/register/begin`(会话鉴权):下发 challenge(绑当前 user_id)+ 注册选项。
#[utoipa::path(post, path = "/passkey/register/begin", tag = "logout",
    responses(
        (status = 200, body = RegisterBeginResponse),
        (status = 401),
        (status = 403, description = "需要最近五分钟内重新认证"),
        (status = 404),
        (status = 503)
    ))]
pub async fn register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(response) = passkey_gate(&state) {
        return response;
    }
    let (tenant, session) = match crate::account_credentials::require_fresh_session(
        &state,
        &headers,
        "register_begin",
        "passkey",
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let user_id = session.user_id.clone();
    let Some((rp_id, _origin)) = rp_id_and_origin(&state, &headers) else {
        audit_registration(&state, &tenant, &user_id, "denied").await;
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };
    let challenge = state.region.issue_base64_id(rand_challenge());
    // challenge 绑当前会话 user_id(评审 Kiro:防 A 会话 challenge 铸凭证到 B)。
    if state
        .passkey_challenges
        .put(PasskeyChallenge {
            challenge_b64url: challenge.clone(),
            tenant: tenant.clone(),
            user_id: Some(user_id.clone()),
            ceremony: PasskeyCeremony::Registration,
            rp_id: rp_id.clone(),
            origin: _origin,
            expires_at: now_secs() + CHALLENGE_TTL_SECS,
        })
        .await
        .is_err()
    {
        audit_registration(&state, &tenant, &user_id, "failed").await;
        return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
    }
    let exclude: Vec<String> = state
        .passkeys
        .list_by_user(&tenant, &user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.credential_id)
        .collect();
    Json(RegisterBeginResponse {
        rp_id,
        user_id,
        challenge,
        exclude_credentials: exclude,
        alg: -7,
        user_verification: "required",
    })
    .into_response()
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterFinishRequest {
    /// challenge(begin 下发的;定位 + 一次性 consume)。
    pub challenge: String,
    /// clientDataJSON(base64url)。
    pub client_data_json: String,
    /// attestationObject(base64url,CBOR)。
    pub attestation_object: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisterFinishResponse {
    pub registered: bool,
}

async fn audit_registration(state: &AppState, tenant: &str, user_id: &str, result: &'static str) {
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::UserCredentialOperation {
                action: "register",
                tenant,
                actor: user_id,
                kind: "passkey",
                target: "new",
                result,
            },
        )
        .await;
}

async fn audit_authentication(
    state: &AppState,
    tenant: &str,
    user_id: Option<&str>,
    credential_id: Option<&str>,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    let mut draft = crate::security_event::SecurityEventDraft::authentication(
        tenant,
        user_id,
        crate::security_event::AuthenticationMethod::Passkey,
        outcome,
    );
    if let Some(credential_id) = credential_id {
        draft = draft.correlated(crate::security_event::SecurityEventCorrelation {
            credential_id: Some(credential_id.to_string()),
            ..Default::default()
        });
    }
    state.record_security_event(draft).await;
}

/// `POST /passkey/register/finish`(会话鉴权):consume challenge → verify_attestation_none → 存凭证。
#[utoipa::path(post, path = "/passkey/register/finish", tag = "logout",
    responses(
        (status = 200, body = RegisterFinishResponse),
        (status = 400),
        (status = 401),
        (status = 403, description = "需要最近五分钟内重新认证"),
        (status = 404),
        (status = 409, description = "会话或账户权限在注册期间发生变化"),
        (status = 503)
    ))]
pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterFinishRequest>,
) -> impl IntoResponse {
    if let Some(response) = passkey_gate(&state) {
        return response;
    }
    let (tenant, session) = match crate::account_credentials::require_fresh_session(
        &state,
        &headers,
        "register_finish",
        "passkey",
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let user_id = session.user_id.clone();
    let Some((rp_id, origin)) = rp_id_and_origin(&state, &headers) else {
        audit_registration(&state, &tenant, &user_id, "denied").await;
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };
    if !state.region.owns_base64_id(&req.challenge) {
        audit_registration(&state, &tenant, &user_id, "denied").await;
        return (StatusCode::BAD_REQUEST, "invalid or expired challenge").into_response();
    }
    // consume challenge(一次性)+ 校绑定 user_id == 当前会话(防跨会话铸凭证)。
    let ch = match state
        .passkey_challenges
        .consume(&tenant, &req.challenge)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            audit_registration(&state, &tenant, &user_id, "denied").await;
            return (StatusCode::BAD_REQUEST, "invalid or expired challenge").into_response();
        }
        Err(_) => {
            audit_registration(&state, &tenant, &user_id, "failed").await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    if ch.user_id.as_deref() != Some(user_id.as_str())
        || !challenge_matches(&ch, PasskeyCeremony::Registration, &tenant, &rp_id, &origin)
    {
        audit_registration(&state, &tenant, &user_id, "denied").await;
        return (
            StatusCode::BAD_REQUEST,
            "challenge not bound to this ceremony",
        )
            .into_response();
    }
    let (Ok(cdj), Ok(att)) = (
        URL_SAFE_NO_PAD.decode(&req.client_data_json),
        URL_SAFE_NO_PAD.decode(&req.attestation_object),
    ) else {
        audit_registration(&state, &tenant, &user_id, "denied").await;
        return (StatusCode::BAD_REQUEST, "bad base64").into_response();
    };
    let reg = match verify_attestation_none(
        &cdj,
        &att,
        &RegistrationExpectations {
            rp_id: &rp_id,
            challenge_b64url: &req.challenge,
            origin: &origin,
            require_uv: REQUIRE_UV,
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            audit_registration(&state, &tenant, &user_id, "denied").await;
            return (
                StatusCode::BAD_REQUEST,
                format!("attestation invalid: {e:?}"),
            )
                .into_response();
        }
    };
    // 存凭证(条件写唯一;已存在 credentialId → 拒,防覆盖)。
    let now = now_secs();
    let cred = PasskeyCredential {
        credential_id: reg.credential_id,
        user_id: user_id.clone(),
        rp_id,
        public_key_sec1: reg.public_key_sec1,
        sign_count: reg.sign_count,
        name: "Passkey".to_string(),
        created_at: now,
    };
    match state
        .passkeys
        .put_new_authorized(&state.users, &state.sessions, &tenant, &session, cred, now)
        .await
    {
        Ok(PasskeyRegistrationOutcome::Created) => {
            audit_registration(&state, &tenant, &user_id, "success").await;
            Json(RegisterFinishResponse { registered: true }).into_response()
        }
        Ok(PasskeyRegistrationOutcome::CredentialExists) => {
            audit_registration(&state, &tenant, &user_id, "already_exists").await;
            (StatusCode::BAD_REQUEST, "credential already exists").into_response()
        }
        Ok(PasskeyRegistrationOutcome::AuthorityChanged) => {
            audit_registration(&state, &tenant, &user_id, "conflict").await;
            (
                StatusCode::CONFLICT,
                "session authority changed during registration",
            )
                .into_response()
        }
        Err(_) => {
            audit_registration(&state, &tenant, &user_id, "failed").await;
            (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response()
        }
    }
}

// ---- authenticate(pre-login;P1 用 login_hint 定位 user)----

#[derive(Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
pub struct AuthBeginQuery {
    /// 用户 email(P1 定位候选凭证;usernameless[discoverable]留后)。
    pub login_hint: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthBeginResponse {
    pub rp_id: String,
    pub challenge: String,
    /// allowCredentials:该 user 的 credentialId 列表(前端喂 navigator.credentials.get)。
    pub allow_credentials: Vec<String>,
    pub user_verification: &'static str,
}

/// `GET /passkey/authenticate/begin?login_hint=`:下发 challenge(不绑会话)+ allowCredentials。
#[utoipa::path(get, path = "/passkey/authenticate/begin", tag = "logout",
    params(("login_hint" = String, Query)),
    responses((status = 200, body = AuthBeginResponse), (status = 404)))]
pub async fn authenticate_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuthBeginQuery>,
) -> impl IntoResponse {
    if let Some(response) = passkey_gate(&state) {
        return response;
    }
    let Some((rp_id, _origin)) = rp_id_and_origin(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let challenge = state.region.issue_base64_id(rand_challenge());
    // 认证 challenge:pre-login,不绑会话(user_id=None)——只按 challenge 值一次性(评审 Kiro)。
    if state
        .passkey_challenges
        .put(PasskeyChallenge {
            challenge_b64url: challenge.clone(),
            tenant: tenant.clone(),
            user_id: None,
            ceremony: PasskeyCeremony::Authentication,
            rp_id: rp_id.clone(),
            origin: _origin,
            expires_at: now_secs() + CHALLENGE_TTL_SECS,
        })
        .await
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
    }
    // login_hint(email)→ user_id(users 表;未注册返空 allowCredentials,不泄露"用户是否存在")。
    let norm = q.login_hint.trim().to_lowercase();
    let allow: Vec<String> = match state.users.get_by_email(&tenant, &norm).await {
        Ok(Some(u)) => state
            .passkeys
            .list_by_user(&tenant, &u.user_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.credential_id)
            .collect(),
        _ => vec![], // 未注册/查不到 → 空(不泄露)
    };
    Json(AuthBeginResponse {
        rp_id,
        challenge,
        allow_credentials: allow,
        user_verification: "required",
    })
    .into_response()
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AuthFinishRequest {
    pub challenge: String,
    /// 使用的 credentialId(base64url)。
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthFinishResponse {
    pub authenticated: bool,
}

/// `POST /passkey/authenticate/finish`:consume challenge → verify_assertion → signCount CAS → 建会话。
#[utoipa::path(post, path = "/passkey/authenticate/finish", tag = "logout",
    responses((status = 200, body = AuthFinishResponse), (status = 400), (status = 404)))]
pub async fn authenticate_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuthFinishRequest>,
) -> impl IntoResponse {
    if let Some(response) = passkey_gate(&state) {
        return response;
    }
    let Some((rp_id, origin)) = rp_id_and_origin(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "bad host").into_response();
    };
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !state.region.owns_base64_id(&req.challenge) {
        return (StatusCode::BAD_REQUEST, "invalid or expired challenge").into_response();
    }
    // consume challenge(一次性,防重放)。
    let challenge = match state
        .passkey_challenges
        .consume(&tenant, &req.challenge)
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            audit_authentication(
                &state,
                &tenant,
                None,
                None,
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "invalid or expired challenge").into_response();
        }
        Err(_) => {
            audit_authentication(
                &state,
                &tenant,
                None,
                None,
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    if !challenge_matches(
        &challenge,
        PasskeyCeremony::Authentication,
        &tenant,
        &rp_id,
        &origin,
    ) || challenge.user_id.is_some()
    {
        audit_authentication(
            &state,
            &tenant,
            None,
            None,
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            "challenge not bound to this ceremony",
        )
            .into_response();
    }
    // 取凭证。
    let cred = match state.passkeys.get(&tenant, &req.credential_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            audit_authentication(
                &state,
                &tenant,
                None,
                Some(&req.credential_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "unknown credential").into_response();
        }
        Err(_) => {
            audit_authentication(
                &state,
                &tenant,
                None,
                Some(&req.credential_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    };
    let (Ok(cdj), Ok(ad), Ok(sig)) = (
        URL_SAFE_NO_PAD.decode(&req.client_data_json),
        URL_SAFE_NO_PAD.decode(&req.authenticator_data),
        URL_SAFE_NO_PAD.decode(&req.signature),
    ) else {
        audit_authentication(
            &state,
            &tenant,
            Some(&cred.user_id),
            Some(&cred.credential_id),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (StatusCode::BAD_REQUEST, "bad base64").into_response();
    };
    let new_count = match verify_assertion(
        &cred,
        &AssertionExpectations {
            rp_id: &rp_id,
            challenge_b64url: &req.challenge,
            origin: &origin,
            require_uv: REQUIRE_UV,
        },
        &AssertionInput {
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            audit_authentication(
                &state,
                &tenant,
                Some(&cred.user_id),
                Some(&cred.credential_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, format!("assertion invalid: {e:?}")).into_response();
        }
    };
    // signCount CAS 回写(防克隆;竞态/回退拒认证)。
    match state
        .passkeys
        .update_sign_count(&tenant, &cred.credential_id, new_count, cred.sign_count)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            audit_authentication(
                &state,
                &tenant,
                Some(&cred.user_id),
                Some(&cred.credential_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::BAD_REQUEST, "sign count race / clone").into_response();
        }
        Err(_) => {
            audit_authentication(
                &state,
                &tenant,
                Some(&cred.user_id),
                Some(&cred.credential_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
    }
    // Existing passkeys must remain bound to a canonical user. The pre-JIT
    // missing-user exception is not valid for credential-backed login.
    let credential_epoch = match crate::user_gate::active_existing_canonical_user_epoch(
        &state,
        &tenant,
        &cred.user_id,
    )
    .await
    {
        Ok(epoch) => epoch,
        Err(crate::user_gate::UserGate::Blocked) => {
            audit_authentication(
                &state,
                &tenant,
                Some(&cred.user_id),
                Some(&cred.credential_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            return (StatusCode::FORBIDDEN, "account disabled").into_response();
        }
        Err(crate::user_gate::UserGate::Unavailable) => {
            audit_authentication(
                &state,
                &tenant,
                Some(&cred.user_id),
                Some(&cred.credential_id),
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
        }
        Err(crate::user_gate::UserGate::Allowed) => unreachable!(),
    };
    // 建 AS 会话(登入;amr=["webauthn","hwk"] 透传进 token,复用 acr/amr 链)。
    let session_id = state.region.issue_id(rand_challenge());
    let user_id = cred.user_id.clone();
    let login_at = now_secs();
    if state
        .sessions
        .create(
            &tenant,
            SessionRecord {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                credential_epoch,
                auth_time: login_at,
                created_at: login_at,
                last_used_at: login_at,
                device: crate::login::session_device(&headers),
                expires_at: login_at + SESSION_TTL_SECS,
                acr: Some(
                    agent_auth_authn::assurance::AssuranceClass::Strong
                        .acr()
                        .to_string(),
                ),
                amr: vec!["webauthn".to_string(), "hwk".to_string()],
            },
        )
        .await
        .is_err()
    {
        audit_authentication(
            &state,
            &tenant,
            Some(&user_id),
            Some(&cred.credential_id),
            crate::security_event::SecurityEventOutcome::Failure,
        )
        .await;
        return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
    }
    let passkey_is_authoritative =
        match passkey_snapshot_is_authoritative(&state, &tenant, &cred, new_count).await {
            Ok(authoritative) => authoritative,
            Err(_) => {
                let _ = state.sessions.delete(&tenant, &session_id).await;
                audit_authentication(
                    &state,
                    &tenant,
                    Some(&user_id),
                    Some(&cred.credential_id),
                    crate::security_event::SecurityEventOutcome::Failure,
                )
                .await;
                return (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response();
            }
        };
    if !passkey_is_authoritative {
        let _ = state.sessions.delete(&tenant, &session_id).await;
        audit_authentication(
            &state,
            &tenant,
            Some(&user_id),
            Some(&cred.credential_id),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            "credential changed during authentication",
        )
            .into_response();
    }
    if let Some(error) = crate::user_gate::session_authority_error(
        crate::user_gate::validate_existing_session_authority(
            &state,
            &tenant,
            &session_id,
            &user_id,
        )
        .await,
    ) {
        audit_authentication(
            &state,
            &tenant,
            Some(&user_id),
            Some(&cred.credential_id),
            crate::security_event::SecurityEventOutcome::Denied,
        )
        .await;
        return error.into_response();
    }
    crate::user_gate::touch_last_login(&state, &tenant, &user_id, login_at).await;
    audit_authentication(
        &state,
        &tenant,
        Some(&user_id),
        Some(&cred.credential_id),
        crate::security_event::SecurityEventOutcome::Success,
    )
    .await;
    (
        [(
            header::SET_COOKIE,
            set_cookie(SESSION_COOKIE, &session_id, SESSION_TTL_SECS),
        )],
        Json(AuthFinishResponse {
            authenticated: true,
        }),
    )
        .into_response()
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(passkey_status))
        .routes(routes!(register_begin))
        .routes(routes!(register_finish))
        .routes(routes!(authenticate_begin))
        .routes(routes!(authenticate_finish))
}

#[cfg(test)]
mod tests {
    use super::{challenge_matches, passkey_snapshot_is_authoritative};
    use crate::ports::{PasskeyCeremony, PasskeyChallenge, PasskeyStore};

    fn challenge() -> PasskeyChallenge {
        PasskeyChallenge {
            challenge_b64url: "challenge".to_string(),
            tenant: "t1".to_string(),
            user_id: None,
            ceremony: PasskeyCeremony::Authentication,
            rp_id: "t1.example.com".to_string(),
            origin: "https://t1.example.com".to_string(),
            expires_at: i64::MAX,
        }
    }

    #[test]
    fn challenge_context_requires_exact_ceremony_tenant_rp_and_origin() {
        let challenge = challenge();
        assert!(challenge_matches(
            &challenge,
            PasskeyCeremony::Authentication,
            "t1",
            "t1.example.com",
            "https://t1.example.com"
        ));
        assert!(!challenge_matches(
            &challenge,
            PasskeyCeremony::Registration,
            "t1",
            "t1.example.com",
            "https://t1.example.com"
        ));
        assert!(!challenge_matches(
            &challenge,
            PasskeyCeremony::Authentication,
            "t2",
            "t1.example.com",
            "https://t1.example.com"
        ));
        assert!(!challenge_matches(
            &challenge,
            PasskeyCeremony::Authentication,
            "t1",
            "t2.example.com",
            "https://t1.example.com"
        ));
        assert!(!challenge_matches(
            &challenge,
            PasskeyCeremony::Authentication,
            "t1",
            "t1.example.com",
            "https://t2.example.com"
        ));
    }

    #[tokio::test]
    async fn deleted_passkey_snapshot_cannot_authorize_a_new_session() {
        let state = crate::AppState::dev("localhost");
        let passkey = agent_auth_authn::passkey::PasskeyCredential {
            credential_id: "deleted-during-authentication".to_string(),
            user_id: "user:alice@example.com".to_string(),
            rp_id: "localhost".to_string(),
            public_key_sec1: vec![4; 65],
            sign_count: 2,
            name: "Security key".to_string(),
            created_at: 123,
        };
        assert!(state.passkeys.put_new("", passkey.clone()).await.unwrap());
        assert!(passkey_snapshot_is_authoritative(&state, "", &passkey, 2)
            .await
            .unwrap());
        assert!(state
            .passkeys
            .delete_owned("", &passkey.user_id, &passkey.credential_id)
            .await
            .unwrap());
        assert!(!passkey_snapshot_is_authoritative(&state, "", &passkey, 2)
            .await
            .unwrap());
    }
}
