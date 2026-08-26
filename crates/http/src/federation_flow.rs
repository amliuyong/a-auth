//! 上游 OIDC 联邦登录往返(spec 003 §4,C9.5b)——AS 作上游 IdP 的 RP(Authorization Code + PKCE)。
//!
//! **功能开关**(F10):仅 `state.federation_enabled` 时生效;否则 `start` 忽略(回落本地登录)、
//! `callback` 返 404——e2e 全绿前默认关,不暴露不完整登录面。
//!
//! 两腿:
//! - `start`(由 `/authorize?idp_hint=<idp>` 在**无本地会话**时触发):按 (tenant, idp) 取 config →
//!   生成 state/nonce/PKCE → stash flow(含 **original_authz_request** 供 F1 续跑)→ 重定向上游 authorize。
//! - `callback`(`GET /federation/callback?code=&state=`):consume flow(一次性防重放)→ SecretResolver
//!   取 secret → exchange_code → JwksFetcher 验签(信任锚绑 config.jwks_uri)→ **verify_upstream_id_token_claims**
//!   (F9:iss/aud/azp/nonce/exp/nbf/iat)→ resolve_upstream_context(tenant+issuer 纵深)→ federated_user_id
//!   (复合键)→ 建本地会话 → **重定向回 `/authorize`(带原下游 query + session cookie)续跑发码回原 client**(F1)。
//!   上游返 `?error=` → 回跳原下游 redirect_uri 透传标准 OAuth error(F5)。全 fail-closed。
//!
//! 决策真相源:docs/DESIGN §7;CONFORMANCE C9.5b;逐租户隔离 C10.19。纯判定逻辑在 authn::federation。

use agent_auth_authn::assurance::{
    authentication_is_fresh, normalize_auth_time, requested_class, AssuranceClass, STRONG_ACR,
};
use agent_auth_authn::federation::{
    federated_user_id, resolve_upstream_context, verify_upstream_id_token_claims, FederationError,
    IdTokenClaimError, IdTokenExpectations,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{
    FederationConfigStore, FederationFlowState, FederationFlowStore, JwksFetcher, SecretResolver,
    SessionRecord, SessionStore, UpstreamTokenExchangeRequest, UpstreamTokenExchanger, UsersStore,
};
use crate::state::AppState;

const SESSION_COOKIE: &str = "__Host-agent_auth_session";
const SESSION_TTL_SECS: i64 = 3600;
const FLOW_TTL_SECS: i64 = 600; // 联邦往返短命窗 ≤10min
const CLOCK_SKEW_SECS: i64 = 60;

fn now_secs() -> i64 {
    crate::token::current_unix_secs_pub()
}

fn rand_b64(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

async fn audit_federation_rejection(
    state: &AppState,
    tenant: &str,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant,
            None,
            crate::security_event::AuthenticationMethod::Federation,
            outcome,
        ))
        .await;
    response
}

async fn audit_verified_federation_rejection(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    response: Response,
) -> Response {
    let outcome = if response.status().is_server_error() {
        crate::security_event::SecurityEventOutcome::Failure
    } else {
        crate::security_event::SecurityEventOutcome::Denied
    };
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant,
            Some(user_id),
            crate::security_event::AuthenticationMethod::Federation,
            outcome,
        ))
        .await;
    response
}

fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

/// tenant 派生(与签发侧同口径):SelfHosted 固定 "default";SaaS 按 Host 派生(spec 020)。
fn tenant_from_host(state: &AppState, headers: &HeaderMap) -> Option<String> {
    match &state.form {
        agent_auth_discovery::Form::SelfHosted { .. } => Some("default".to_string()),
        agent_auth_discovery::Form::Saas { .. } => {
            let host = crate::hostutil::issuer_host(headers)?;
            agent_auth_discovery::tenant_id_from(&host, &state.form).ok()
        }
    }
}

async fn audit_federation_callback_rejection(
    state: &AppState,
    headers: &HeaderMap,
    response: Response,
) -> Response {
    let Some(tenant) = tenant_from_host(state, headers) else {
        return response;
    };
    audit_federation_rejection(state, &tenant, response).await
}

async fn audit_federation_issuer_boundary(state: &AppState, tenant: &str, denied_issuer: &str) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::issuer_boundary_denial(
                tenant,
                crate::security_event::SecurityActor::system("federation"),
                denied_issuer,
            ),
        )
        .await;
}

async fn audit_federation_tenant_boundary(state: &AppState, tenant: &str, denied_tenant: &str) {
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::tenant_boundary_denial(
                tenant,
                crate::security_event::SecurityActor::system("federation"),
                denied_tenant,
            ),
        )
        .await;
}

/// **联邦 start**(由 authorize 的 idp_hint 分支在无本地会话时调):重定向到上游 IdP。
/// `original_authz_request` = 原下游 `/authorize` 的完整 query(callback 成功后续跑发码回原 client)。
/// 失败(功能关/config 缺/tenant 不定)→ 回落:返回 None,调用方走本地登录(不报错、不泄露)。
pub async fn start(
    state: &AppState,
    headers: &HeaderMap,
    idp_hint: &str,
    original_authz_request: &str,
    required_max_age_secs: Option<i64>,
    force_reauthentication: bool,
) -> Option<Response> {
    if !state.federation_enabled {
        return None; // 功能关 → 回落本地登录
    }
    let tenant = tenant_from_host(state, headers)?;
    let config = state
        .federation_config
        .get(&tenant, idp_hint)
        .await
        .ok()??;
    let oidc = config.oidc.as_ref()?; // 无 OIDC 参数(SAML/残缺)→ 回落
    let requires_strong =
        requested_class(query_param(original_authz_request, "acr_values").as_deref())
            .ok()
            .flatten()
            == Some(AssuranceClass::Strong);
    if requires_strong && config.strong_acr_values.is_empty() {
        return None;
    }
    // 生成 RP 侧 state/nonce/PKCE。
    let flow_state = state.region.issue_id(rand_b64(24));
    let nonce = rand_b64(24);
    let code_verifier = rand_b64(48);
    let challenge = agent_auth_client::s256_challenge(&code_verifier);
    let browser_origin = crate::hostutil::browser_origin(state, headers)?;
    let redirect_uri = format!("{browser_origin}/federation/callback");
    // stash flow(含下游续跑上下文)。
    let put = state
        .federation_flow
        .put(FederationFlowState {
            state: flow_state.clone(),
            nonce: nonce.clone(),
            code_verifier,
            tenant_id: tenant,
            upstream_idp_id: idp_hint.to_string(),
            original_authz_request: original_authz_request.to_string(),
            required_max_age_secs,
            expires_at: now_secs() + FLOW_TTL_SECS,
        })
        .await;
    if put.is_err() {
        return None; // 存储不可用 → 回落本地登录(不卡死)
    }
    // 重定向上游 authorize(scope/state/nonce/PKCE;redirect_uri=本 AS callback)。
    let scope = if oidc.scopes.is_empty() {
        "openid".to_string()
    } else {
        oidc.scopes.join(" ")
    };
    let mut url = format!(
        "{ep}?response_type=code&client_id={cid}&redirect_uri={ru}&scope={sc}&state={st}&nonce={nc}&code_challenge={ch}&code_challenge_method=S256",
        ep = oidc.authorization_endpoint,
        cid = urlencoding(&oidc.client_id),
        ru = urlencoding(&redirect_uri),
        sc = urlencoding(&scope),
        st = urlencoding(&flow_state),
        nc = urlencoding(&nonce),
        ch = urlencoding(&challenge),
    );
    if requires_strong {
        url.push_str("&acr_values=");
        url.push_str(&urlencoding(&config.strong_acr_values.join(" ")));
    }
    if let Some(max_age) = required_max_age_secs {
        url.push_str("&max_age=");
        url.push_str(&max_age.to_string());
    }
    if force_reauthentication {
        url.push_str("&prompt=login");
    }
    Some(Redirect::to(&url).into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /federation/callback`:上游回调 → 换 token → 验签 → 建会话 → 续跑下游 authorize 发码。
#[utoipa::path(get, path = "/federation/callback", tag = "logout",
    responses(
        (status = 303, description = "登录成功,续跑下游 authorize / 或透传上游 error 回下游"),
        (status = 400, description = "state 无效 / 验签失败 / claims 校验失败"),
        (status = 404, description = "联邦功能未启用")))]
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if !state.federation_enabled {
        return (StatusCode::NOT_FOUND, "federation not enabled").into_response();
    }
    // state 必带(CSRF/flow 定位)。
    let Some(flow_state) = q.state.as_deref().filter(|s| !s.is_empty()) else {
        return audit_federation_callback_rejection(
            &state,
            &headers,
            (StatusCode::BAD_REQUEST, "missing state").into_response(),
        )
        .await;
    };
    if !state.region.owns_id(flow_state) {
        return audit_federation_callback_rejection(
            &state,
            &headers,
            (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
        )
        .await;
    }
    // consume flow(一次性:取出即删,防 state 重放)。
    let flow = match state.federation_flow.consume(flow_state).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return audit_federation_callback_rejection(
                &state,
                &headers,
                (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
            )
            .await
        }
        Err(_) => {
            return audit_federation_callback_rejection(
                &state,
                &headers,
                (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
            )
            .await
        }
    };
    if let Some(callback_tenant) = tenant_from_host(&state, &headers) {
        if callback_tenant != flow.tenant_id {
            audit_federation_tenant_boundary(&state, &callback_tenant, &flow.tenant_id).await;
            return (StatusCode::BAD_REQUEST, "tenant mismatch").into_response();
        }
    }

    // 上游返 error → 回跳原下游 redirect_uri 透传标准 OAuth error(F5);无法定 redirect 则 400。
    if let Some(err) = q.error.as_deref().filter(|s| !s.is_empty()) {
        return audit_federation_rejection(
            &state,
            &flow.tenant_id,
            redirect_downstream_error(
                &flow.original_authz_request,
                err,
                q.error_description.as_deref(),
            ),
        )
        .await;
    }
    let Some(code) = q.code.as_deref().filter(|s| !s.is_empty()) else {
        return audit_federation_rejection(
            &state,
            &flow.tenant_id,
            (StatusCode::BAD_REQUEST, "missing code").into_response(),
        )
        .await;
    };

    // 取回 config(复合键;flow 里记了 tenant+idp)。
    let config = match state
        .federation_config
        .get(&flow.tenant_id, &flow.upstream_idp_id)
        .await
    {
        Ok(Some(c)) => c,
        _ => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::BAD_REQUEST, "unknown upstream config").into_response(),
            )
            .await
        }
    };
    let Some(oidc) = config.oidc.as_ref() else {
        return audit_federation_rejection(
            &state,
            &flow.tenant_id,
            (StatusCode::BAD_REQUEST, "config missing oidc params").into_response(),
        )
        .await;
    };

    // 解析 client_secret(引用名→明文;明文只在本栈存活)。
    let secret = match state.secret_resolver.resolve(&oidc.client_secret_ref).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::SERVICE_UNAVAILABLE, "secret unresolved").into_response(),
            )
            .await
        }
        Err(_) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::SERVICE_UNAVAILABLE, "secret store unavailable").into_response(),
            )
            .await
        }
    };
    let Some(browser_origin) = crate::hostutil::browser_origin(&state, &headers) else {
        return audit_federation_rejection(
            &state,
            &flow.tenant_id,
            (StatusCode::BAD_REQUEST, "invalid browser origin").into_response(),
        )
        .await;
    };
    let redirect_uri = format!("{browser_origin}/federation/callback");
    // 换 token(reqwest→上游 token_endpoint;endpoint 来自登记 config = SSRF 防线)。
    let tokens = match state
        .upstream_token_exchanger
        .exchange_code(&UpstreamTokenExchangeRequest {
            token_endpoint: &oidc.token_endpoint,
            client_id: &oidc.client_id,
            client_secret: &secret,
            code,
            code_verifier: &flow.code_verifier,
            redirect_uri: &redirect_uri,
        })
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::BAD_REQUEST, "upstream rejected code").into_response(),
            )
            .await
        }
        Err(_) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable").into_response(),
            )
            .await
        }
    };

    // 验签上游 id_token:JWKS MUST 来自 config.jwks_uri(信任锚绑 config,不接受 token 自带 jku)。
    let kid = peek_kid(&tokens.id_token);
    let keys = match state.jwks_fetcher.fetch(&oidc.jwks_uri).await {
        Ok(k) => k,
        Err(_) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::SERVICE_UNAVAILABLE, "upstream jwks unavailable").into_response(),
            )
            .await
        }
    };
    let key = match select_key(&keys, kid.as_deref()) {
        Some(k) => k,
        None => {
            // kid 未命中 → force-refresh 一次(上游 key 轮换)。
            match state.jwks_fetcher.fetch_fresh(&oidc.jwks_uri).await {
                Ok(fresh) => match select_key(&fresh, kid.as_deref()) {
                    Some(k) => k,
                    None => {
                        return audit_federation_rejection(
                            &state,
                            &flow.tenant_id,
                            (StatusCode::BAD_REQUEST, "no matching upstream key").into_response(),
                        )
                        .await
                    }
                },
                Err(_) => {
                    return audit_federation_rejection(
                        &state,
                        &flow.tenant_id,
                        (StatusCode::SERVICE_UNAVAILABLE, "upstream jwks unavailable")
                            .into_response(),
                    )
                    .await
                }
            }
        }
    };
    let verified = match agent_auth_workload::verify_rs256(
        &tokens.id_token,
        &key.n,
        &key.e,
        key.kid.as_deref(),
    ) {
        Ok(v) => v,
        Err(_) => {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::BAD_REQUEST, "id_token signature invalid").into_response(),
            )
            .await
        }
    };

    // F9 claims 完整校验(iss/aud/azp/nonce/exp/nbf/iat)。
    let sub = match verify_upstream_id_token_claims(
        &verified.claims,
        &IdTokenExpectations {
            upstream_issuer: &config.upstream_issuer,
            client_id: &oidc.client_id,
            nonce: &flow.nonce,
            now: now_secs(),
            clock_skew_secs: CLOCK_SKEW_SECS,
        },
    ) {
        Ok(s) => s.to_string(),
        Err(error) => {
            if error == IdTokenClaimError::IssuerMismatch {
                if let Some(issuer) = verified.claims.get("iss").and_then(|value| value.as_str()) {
                    audit_federation_issuer_boundary(&state, &flow.tenant_id, issuer).await;
                }
            }
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                (StatusCode::BAD_REQUEST, "id_token claims invalid").into_response(),
            )
            .await;
        }
    };

    // 信任锚 + tenant 纵深(claims 已验签;此处再断 iss==config.upstream_issuer + tenant 一致)+
    // **提取上游 acr/amr**(C9.5b:透传进本 AS 签发的 token;存会话,consent→CodeRecord→token 链上带出)。
    let mut upstream_ctx =
        match resolve_upstream_context(&verified.claims, &config, &flow.tenant_id) {
            Ok(ctx) => ctx,
            Err(error) => {
                match error {
                    FederationError::TenantMismatch { actual, .. } => {
                        audit_federation_tenant_boundary(&state, &flow.tenant_id, &actual).await;
                    }
                    FederationError::IssuerMismatch { actual, .. } => {
                        audit_federation_issuer_boundary(&state, &flow.tenant_id, &actual).await;
                    }
                    FederationError::MissingIssuer => {}
                }
                return audit_federation_rejection(
                    &state,
                    &flow.tenant_id,
                    (StatusCode::BAD_REQUEST, "trust anchor / tenant mismatch").into_response(),
                )
                .await;
            }
        };
    let callback_now = now_secs();
    if let Some(auth_time) = upstream_ctx.auth_time {
        let Some(auth_time) = normalize_auth_time(auth_time, callback_now, CLOCK_SKEW_SECS) else {
            return audit_federation_rejection(
                &state,
                &flow.tenant_id,
                redirect_downstream_error(
                    &flow.original_authz_request,
                    "unmet_authentication_requirements",
                    Some("upstream authentication did not satisfy the requested assurance"),
                ),
            )
            .await;
        };
        upstream_ctx.auth_time = Some(auth_time);
    }
    let requires_strong =
        requested_class(query_param(&flow.original_authz_request, "acr_values").as_deref())
            .ok()
            .flatten()
            == Some(AssuranceClass::Strong);
    let required_max_age_secs = flow.required_max_age_secs.or_else(|| {
        query_param(&flow.original_authz_request, "max_age")
            .and_then(|value| value.parse::<i64>().ok())
    });
    let assurance_satisfied = !requires_strong || upstream_ctx.acr.as_deref() == Some(STRONG_ACR);
    let freshness_satisfied = required_max_age_secs.is_none_or(|max_age| {
        upstream_ctx
            .auth_time
            .is_some_and(|auth_time| authentication_is_fresh(auth_time, callback_now, max_age))
    });
    if !assurance_satisfied || !freshness_satisfied {
        return audit_federation_rejection(
            &state,
            &flow.tenant_id,
            redirect_downstream_error(
                &flow.original_authz_request,
                "unmet_authentication_requirements",
                Some("upstream authentication did not satisfy the requested assurance"),
            ),
        )
        .await;
    }

    // 复合键派生本地 user_id(F2:(tenant, upstream_issuer, sub);email 不参与)。
    let user_id = federated_user_id(
        &state.server_secret,
        &flow.tenant_id,
        &config.upstream_issuer,
        &sub,
    );
    match crate::governance::user_alias_is_suppressed(
        &state,
        &flow.tenant_id,
        crate::governance::GovernanceAliasKind::CanonicalId,
        &user_id,
    )
    .await
    {
        Ok(true) => {
            return audit_verified_federation_rejection(
                &state,
                &flow.tenant_id,
                &user_id,
                (StatusCode::FORBIDDEN, "account deleted").into_response(),
            )
            .await
        }
        Ok(false) => {}
        Err(_) => {
            return audit_verified_federation_rejection(
                &state,
                &flow.tenant_id,
                &user_id,
                (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
            )
            .await
        }
    }

    // 建本地 AS 会话(登入);**存上游 acr/amr**(C9.5b 透传起点)。auth_time 优先用上游断言的
    // auth_time(真人上游认证时刻),缺则用 now。
    let session_id = state.region.issue_id(rand_b64(32));
    // tenant 分区(spec 020 §2.3):会话落 flow 起始时捕获的 tenant 分区(federation callback 无请求 Host,
    // 用 flow.tenant_id;与 derive 的 SelfHosted="default"/Saas 子域标签同源;flag 关时 tenant_id 仍是
    // "default",但会话物理键会带 "default\x1f" 前缀——见下 current_session 读侧同口径 tenant)。
    let sess_tenant = if state.tenant_partitioning {
        flow.tenant_id.clone()
    } else {
        String::new()
    };
    let login_at = callback_now;
    // 此处不能直接复用 require_active_user:联邦首次登录尚无 UserRecord,必须先按稳定 user_id
    // JIT upsert,再基于返回的权威 status 判定。这样新用户可首登,既有 Disabled/Tombstoned 又不会放行。
    let user = match state
        .users
        .create_or_get_by_id(&sess_tenant, &user_id, login_at)
        .await
    {
        Ok(rec) if rec.status == crate::ports::UserStatus::Tombstoned => {
            return audit_verified_federation_rejection(
                &state,
                &sess_tenant,
                &user_id,
                (StatusCode::FORBIDDEN, "account deleted").into_response(),
            )
            .await;
        }
        Ok(rec) if rec.status == crate::ports::UserStatus::Disabled => {
            return audit_verified_federation_rejection(
                &state,
                &sess_tenant,
                &user_id,
                (StatusCode::FORBIDDEN, "account disabled").into_response(),
            )
            .await;
        }
        Ok(rec) => rec,
        Err(_) => {
            return audit_verified_federation_rejection(
                &state,
                &sess_tenant,
                &user_id,
                (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
            )
            .await
        }
    };
    let user = if matches!(state.form, agent_auth_discovery::Form::SelfHosted { .. }) {
        match state
            .reconcile_federated_attributes(
                crate::federation_attributes::FederationAttributeReconciliationRequest {
                    operation_id: flow.state.clone(),
                    logical_tenant_id: flow.tenant_id.clone(),
                    storage_tenant_id: sess_tenant.clone(),
                    upstream_idp_id: flow.upstream_idp_id.clone(),
                    upstream_issuer: config.upstream_issuer.clone(),
                    user_id: user_id.clone(),
                    verified_claims: verified.claims.clone(),
                },
            )
            .await
        {
            Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::Applied {
                    user,
                    ..
                },
            ) => *user,
            Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::UserDisabled,
            ) => {
                return audit_verified_federation_rejection(
                    &state,
                    &sess_tenant,
                    &user_id,
                    (StatusCode::FORBIDDEN, "account disabled").into_response(),
                )
                .await;
            }
            Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::UserNotFound
                | crate::federation_attributes::FederationAttributeReconciliationOutcome::UserTombstoned,
            ) => {
                return audit_verified_federation_rejection(
                    &state,
                    &sess_tenant,
                    &user_id,
                    (StatusCode::FORBIDDEN, "account unavailable").into_response(),
                )
                .await;
            }
            Ok(_) => {
                return audit_verified_federation_rejection(
                    &state,
                    &sess_tenant,
                    &user_id,
                    (StatusCode::FORBIDDEN, "federated attributes rejected").into_response(),
                )
                .await;
            }
            Err(_) => {
                return audit_verified_federation_rejection(
                    &state,
                    &sess_tenant,
                    &user_id,
                    (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
                )
                .await;
            }
        }
    } else {
        user
    };
    if state
        .sessions
        .create(
            &sess_tenant,
            SessionRecord {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                credential_epoch: user.credential_epoch,
                auth_time: upstream_ctx.auth_time.unwrap_or(login_at),
                created_at: login_at,
                last_used_at: login_at,
                device: crate::login::session_device(&headers),
                expires_at: login_at + SESSION_TTL_SECS,
                acr: upstream_ctx.acr.clone(),
                amr: upstream_ctx.amr.clone(),
            },
        )
        .await
        .is_err()
    {
        return audit_verified_federation_rejection(
            &state,
            &sess_tenant,
            &user_id,
            (StatusCode::SERVICE_UNAVAILABLE, "store unavailable").into_response(),
        )
        .await;
    }
    if let Some(error) = crate::user_gate::session_authority_error(
        crate::user_gate::validate_session_authority(&state, &sess_tenant, &session_id, &user_id)
            .await,
    ) {
        return audit_verified_federation_rejection(
            &state,
            &sess_tenant,
            &user_id,
            error.into_response(),
        )
        .await;
    }
    crate::user_gate::touch_last_login(&state, &sess_tenant, &user_id, login_at).await;
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            &sess_tenant,
            Some(&user_id),
            crate::security_event::AuthenticationMethod::Federation,
            crate::security_event::SecurityEventOutcome::Success,
        ))
        .await;

    // F1 续跑:带 session cookie 重定向回**原下游 authorize**(idp_hint 分支只在无会话时触发,
    // 此刻有会话 → authorize 正常续流发码回原 client,不再进联邦分支,无环)。
    let dest = format!("{browser_origin}/authorize?{}", flow.original_authz_request);
    (
        [(
            header::SET_COOKIE,
            set_cookie(SESSION_COOKIE, &session_id, SESSION_TTL_SECS),
        )],
        Redirect::to(&dest),
    )
        .into_response()
}

/// 上游 error 回跳原下游 client 的 redirect_uri(透传标准 OAuth error;从原 query 提取 redirect_uri/state)。
fn redirect_downstream_error(
    original_authz_request: &str,
    err: &str,
    err_desc: Option<&str>,
) -> Response {
    let redirect_uri = query_param(original_authz_request, "redirect_uri");
    let ds_state = query_param(original_authz_request, "state");
    let Some(ru) = redirect_uri.filter(|s| !s.is_empty()) else {
        // 无法定位下游 redirect_uri → 400(不臆测跳转目标)。
        return (StatusCode::BAD_REQUEST, format!("upstream error: {err}")).into_response();
    };
    let sep = if ru.contains('?') { '&' } else { '?' };
    let mut url = format!("{ru}{sep}error={}", urlencoding(err));
    if let Some(d) = err_desc {
        url.push_str(&format!("&error_description={}", urlencoding(d)));
    }
    if let Some(s) = ds_state {
        url.push_str(&format!("&state={}", urlencoding(&s)));
    }
    Redirect::to(&url).into_response()
}

/// 从 query 串取某参数(percent-decode 值)。
fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| crate::consent::pct_decode(k) == key)
        .map(|(_, v)| crate::consent::pct_decode(v))
}

/// 未验签窥探 id_token 的 header.kid(仅用于选 JWKS key;验签前不信任任何值)。
fn peek_kid(jwt: &str) -> Option<String> {
    let h = jwt.split('.').next()?;
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    header.get("kid").and_then(|v| v.as_str()).map(String::from)
}

/// 从 JWKS 按 kid 选 key(kid 有则精确匹配;无 kid 且集合唯一则取唯一)。
fn select_key(
    keys: &[crate::ports::PlatformJwk],
    kid: Option<&str>,
) -> Option<crate::ports::PlatformJwk> {
    match kid {
        Some(k) => keys.iter().find(|j| j.kid.as_deref() == Some(k)).cloned(),
        None if keys.len() == 1 => keys.first().cloned(),
        None => None,
    }
}

/// 最小 URL 编码(query 值:编码 &/=/空格/#/? 等)。
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(callback))
}
