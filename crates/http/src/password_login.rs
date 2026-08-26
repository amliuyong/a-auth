//! Local password login and first-login password change (spec 003 C9.8-C9.10).

use agent_auth_authn::password::{
    dummy_hash, hash_password, validate_password, verify_password, EncodedPasswordHash,
    PasswordValue,
};
use axum::{
    extract::{DefaultBodyLimit, Extension, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::ports::{PasswordCredential, PasswordStore, RateLimitStore, UserStatus, UsersStore};
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const ACCOUNT_CAPACITY: f64 = 5.0;
const ACCOUNT_REFILL_PER_SEC: f64 = 1.0 / 60.0;
const IP_CAPACITY: f64 = 30.0;
const IP_REFILL_PER_SEC: f64 = 0.5;
const TENANT_CAPACITY: f64 = 200.0;
const TENANT_REFILL_PER_SEC: f64 = 5.0;
const GLOBAL_CAPACITY: f64 = 500.0;
const GLOBAL_REFILL_PER_SEC: f64 = 10.0;

#[derive(Deserialize, ToSchema)]
pub struct PasswordLoginRequest {
    pub email: String,
    #[schema(value_type = String, format = Password)]
    pub password: PasswordValue,
    #[serde(default)]
    pub authorize_query: String,
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordChangeRequest {
    pub email: String,
    #[schema(value_type = String, format = Password)]
    pub current_password: PasswordValue,
    #[schema(value_type = String, format = Password)]
    pub new_password: PasswordValue,
    #[serde(default)]
    pub authorize_query: String,
}

#[derive(Serialize, ToSchema)]
pub struct PasswordLoginResponse {
    pub authenticated: bool,
    pub password_change_required: bool,
}

fn no_store_json<T: Serialize>(status: StatusCode, body: T) -> axum::response::Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn error_json(status: StatusCode, message: &'static str) -> axum::response::Response {
    no_store_json(status, serde_json::json!({ "message": message }))
}

fn account_digest(state: &AppState, tenant: &str, email: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(&state.server_secret).expect("HMAC any key length");
    mac.update(b"password-account\0");
    mac.update(tenant.as_bytes());
    mac.update(b"\0");
    mac.update(email.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn account_bucket_key(state: &AppState, tenant: &str, email: &str) -> String {
    format!(
        "pwd:account:{tenant}:{}",
        account_digest(state, tenant, email)
    )
}

enum GateResult {
    Allowed,
    Throttled(i64),
    Unavailable,
}

fn gate_rejection(result: GateResult) -> Option<axum::response::Response> {
    match result {
        GateResult::Allowed => None,
        GateResult::Throttled(retry_after) => Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    (header::CACHE_CONTROL, "no-store".to_string()),
                    (header::RETRY_AFTER, retry_after.to_string()),
                ],
                Json(serde_json::json!({ "message": "try again later" })),
            )
                .into_response(),
        ),
        GateResult::Unavailable => Some(error_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication unavailable",
        )),
    }
}

async fn password_attempt_gate(
    state: &AppState,
    tenant: &str,
    email: &str,
    trusted_source_ip: Option<&crate::mtls::TrustedSourceIp>,
) -> GateResult {
    let Some(store) = state.rate_limit.as_ref() else {
        return GateResult::Unavailable;
    };
    let source_ip = match trusted_source_ip {
        Some(ip) if !ip.0.trim().is_empty() => ip.0.as_str(),
        None if state.allow_login_placeholder => "dev-local",
        _ => return GateResult::Unavailable,
    };
    let now = crate::token::current_unix_secs_pub();
    let account_key = account_bucket_key(state, tenant, email);
    let ip_key = format!("pwd:ip:{tenant}:{source_ip}");
    let tenant_key = format!("pwd:tenant:{tenant}");
    let (account_result, ip_result, tenant_result, global_result) = tokio::join!(
        store.check_available(
            &account_key,
            now,
            ACCOUNT_CAPACITY,
            ACCOUNT_REFILL_PER_SEC,
            1.0,
        ),
        store.try_consume(&ip_key, now, IP_CAPACITY, IP_REFILL_PER_SEC, 1.0),
        store.try_consume(
            &tenant_key,
            now,
            TENANT_CAPACITY,
            TENANT_REFILL_PER_SEC,
            1.0,
        ),
        store.try_consume(
            "pwd:deployment-global",
            now,
            GLOBAL_CAPACITY,
            GLOBAL_REFILL_PER_SEC,
            1.0,
        ),
    );
    let results = [account_result, ip_result, tenant_result, global_result];
    if results.iter().any(Result::is_err) {
        return GateResult::Unavailable;
    }
    let mut retry_after = 1;
    for decision in results.into_iter().flatten() {
        if !decision.allowed {
            retry_after = retry_after.max(decision.retry_after_secs.unwrap_or(1));
            return GateResult::Throttled(retry_after);
        }
    }
    GateResult::Allowed
}

async fn record_password_failure(state: &AppState, tenant: &str, email: &str) -> GateResult {
    let Some(store) = state.rate_limit.as_ref() else {
        return GateResult::Unavailable;
    };
    match store
        .try_consume(
            &account_bucket_key(state, tenant, email),
            crate::token::current_unix_secs_pub(),
            ACCOUNT_CAPACITY,
            ACCOUNT_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(decision) if decision.allowed => GateResult::Allowed,
        Ok(decision) => GateResult::Throttled(decision.retry_after_secs.unwrap_or(1).max(1)),
        Err(_) => GateResult::Unavailable,
    }
}

pub(crate) enum PasswordWorkError {
    Busy,
    Failed,
}

pub(crate) async fn hash_with_budget(
    state: &AppState,
    password: PasswordValue,
) -> Result<(PasswordValue, EncodedPasswordHash), PasswordWorkError> {
    let permit = state
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| PasswordWorkError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let hash = hash_password(password.expose()).map_err(|_| PasswordWorkError::Failed)?;
        Ok((password, hash))
    })
    .await
    .map_err(|_| PasswordWorkError::Failed)?
}

pub(crate) async fn verify_with_budget(
    state: &AppState,
    password: PasswordValue,
    hash: EncodedPasswordHash,
) -> Result<bool, PasswordWorkError> {
    let permit = state
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| PasswordWorkError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(password.expose(), &hash).map_err(|_| PasswordWorkError::Failed)
    })
    .await
    .map_err(|_| PasswordWorkError::Failed)?
}

enum Authentication {
    Valid(PasswordCredential),
    Invalid(Option<String>),
    Unavailable,
    Busy,
}

async fn audit_password_authentication(
    state: &AppState,
    tenant: &str,
    user_id: Option<&str>,
    outcome: crate::security_event::SecurityEventOutcome,
) {
    state
        .record_security_event(crate::security_event::SecurityEventDraft::authentication(
            tenant,
            user_id,
            crate::security_event::AuthenticationMethod::Password,
            outcome,
        ))
        .await;
}

async fn authenticate(
    state: &AppState,
    tenant: &str,
    normalized_email: &str,
    password: PasswordValue,
) -> Authentication {
    // Initialize and clone the dummy before account-dependent reads, including
    // the first process request, so initialization does not reveal existence.
    let dummy = dummy_hash().clone();
    let is_valid_email = crate::local_identity::is_valid_email(normalized_email);
    let digest = account_digest(state, tenant, normalized_email);
    let fallback_user_id = format!("user:invalid:{digest}");
    let user_result = if is_valid_email {
        state.users.get_by_email(tenant, normalized_email).await
    } else {
        Ok(None)
    };
    let credential_user_id = user_result
        .as_ref()
        .ok()
        .and_then(|user| user.as_ref())
        .map_or(fallback_user_id.as_str(), |user| user.user_id.as_str());
    let credential_result = state.passwords.get(tenant, credential_user_id).await;
    let selected_hash = credential_result
        .as_ref()
        .ok()
        .and_then(|credential| credential.as_ref())
        .map(|credential| credential.password_hash.clone())
        .unwrap_or(dummy);
    let verified = match verify_with_budget(state, password, selected_hash).await {
        Ok(value) => value,
        Err(PasswordWorkError::Busy) => return Authentication::Busy,
        Err(PasswordWorkError::Failed) => return Authentication::Unavailable,
    };
    let user_id_hint = user_result
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .map(|user| user.user_id.clone());
    let (user, credential) = match (user_result, credential_result) {
        (Ok(Some(user)), Ok(Some(credential))) => (user, credential),
        (Err(_), _) | (_, Err(_)) => return Authentication::Unavailable,
        _ => return Authentication::Invalid(user_id_hint),
    };
    if !verified
        || !is_valid_email
        || !crate::local_identity::is_password_capable_user_id(&user.user_id)
        || user.user_id != credential.user_id
        || user.email != normalized_email
        || user.status != UserStatus::Active
    {
        return Authentication::Invalid(Some(user.user_id));
    }
    Authentication::Valid(credential)
}

fn login_success(session_id: &str) -> axum::response::Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::SET_COOKIE,
                crate::login::set_cookie(
                    crate::login::SESSION_COOKIE,
                    session_id,
                    crate::login::SESSION_TTL_SECS,
                ),
            ),
        ],
        Json(PasswordLoginResponse {
            authenticated: true,
            password_change_required: false,
        }),
    )
        .into_response()
}

/// `POST /login/password`:authenticate an existing local user.
#[utoipa::path(
    post,
    path = "/login/password",
    tag = "login",
    request_body = PasswordLoginRequest,
    responses(
        (status = 200, description = "Authenticated or first-login password change required", body = PasswordLoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Password attempt budget exhausted"),
        (status = 503, description = "Password authentication unavailable")
    )
)]
pub async fn password_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    source_ip: Option<Extension<crate::mtls::TrustedSourceIp>>,
    Json(request): Json<PasswordLoginRequest>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "invalid request"),
    };
    let email = crate::local_identity::normalize_email(&request.email);
    let gate = password_attempt_gate(
        &state,
        &tenant,
        &email,
        source_ip.as_ref().map(|Extension(ip)| ip),
    )
    .await;
    let gate_outcome = match &gate {
        GateResult::Allowed => None,
        GateResult::Throttled(_) => Some(crate::security_event::SecurityEventOutcome::Denied),
        GateResult::Unavailable => Some(crate::security_event::SecurityEventOutcome::Failure),
    };
    if let Some(response) = gate_rejection(gate) {
        audit_password_authentication(
            &state,
            &tenant,
            None,
            gate_outcome.expect("rejected gate has an outcome"),
        )
        .await;
        return response;
    }
    match authenticate(&state, &tenant, &email, request.password).await {
        Authentication::Valid(credential) if credential.must_change => {
            audit_password_authentication(
                &state,
                &tenant,
                Some(&credential.user_id),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            no_store_json(
                StatusCode::OK,
                PasswordLoginResponse {
                    authenticated: false,
                    password_change_required: true,
                },
            )
        }
        Authentication::Valid(credential) => {
            let user_id = credential.user_id.clone();
            match crate::login::establish_local_session(
                &state,
                &tenant,
                credential.user_id,
                &request.authorize_query,
                crate::login::LocalSessionMethod::Password {
                    credential_version: credential.version,
                },
                crate::login::session_device(&headers),
            )
            .await
            {
                Ok(session_id) => login_success(&session_id),
                Err(()) => {
                    audit_password_authentication(
                        &state,
                        &tenant,
                        Some(&user_id),
                        crate::security_event::SecurityEventOutcome::Failure,
                    )
                    .await;
                    error_json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "authentication unavailable",
                    )
                }
            }
        }
        Authentication::Invalid(user_id) => {
            let failure_gate = record_password_failure(&state, &tenant, &email).await;
            audit_password_authentication(
                &state,
                &tenant,
                user_id.as_deref(),
                crate::security_event::SecurityEventOutcome::Denied,
            )
            .await;
            if let Some(response) = gate_rejection(failure_gate) {
                return response;
            }
            error_json(StatusCode::UNAUTHORIZED, "invalid credentials")
        }
        Authentication::Unavailable | Authentication::Busy => {
            audit_password_authentication(
                &state,
                &tenant,
                None,
                crate::security_event::SecurityEventOutcome::Failure,
            )
            .await;
            error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        }
    }
}

/// `POST /login/password/change`:replace a verified temporary password using CAS.
#[utoipa::path(
    post,
    path = "/login/password/change",
    tag = "login",
    request_body = PasswordChangeRequest,
    responses(
        (status = 200, description = "Password changed and authenticated", body = PasswordLoginResponse),
        (status = 400, description = "New password policy violation"),
        (status = 401, description = "Invalid credentials"),
        (status = 409, description = "Password no longer temporary or concurrent change won"),
        (status = 429, description = "Password attempt budget exhausted"),
        (status = 503, description = "Password authentication unavailable")
    )
)]
pub async fn password_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    source_ip: Option<Extension<crate::mtls::TrustedSourceIp>>,
    Json(request): Json<PasswordChangeRequest>,
) -> impl IntoResponse {
    let tenant = match crate::tenant::tenant_or_400(&state, &headers) {
        Ok(tenant) => tenant,
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "invalid request"),
    };
    let email = crate::local_identity::normalize_email(&request.email);
    if let Some(response) = gate_rejection(
        password_attempt_gate(
            &state,
            &tenant,
            &email,
            source_ip.as_ref().map(|Extension(ip)| ip),
        )
        .await,
    ) {
        return response;
    }

    let same_password = request.current_password.expose() == request.new_password.expose();
    let new_password_valid = validate_password(request.new_password.expose()).is_ok();
    let credential = match authenticate(&state, &tenant, &email, request.current_password).await {
        Authentication::Valid(credential) => credential,
        Authentication::Invalid(_) => {
            if let Some(response) =
                gate_rejection(record_password_failure(&state, &tenant, &email).await)
            {
                return response;
            }
            return error_json(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
        Authentication::Unavailable | Authentication::Busy => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        }
    };
    if credential.revocation_pending {
        return error_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "password reset is still being finalized",
        );
    }
    if !credential.must_change {
        return error_json(StatusCode::CONFLICT, "password change no longer required");
    }
    if same_password {
        return error_json(StatusCode::BAD_REQUEST, "new password must differ");
    }
    if !new_password_valid {
        return error_json(StatusCode::BAD_REQUEST, "password must be 12 to 128 bytes");
    }
    let new_hash = match hash_with_budget(&state, request.new_password).await {
        Ok((_, hash)) => hash,
        Err(_) => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        }
    };
    let updated_at = crate::token::current_unix_secs_pub();
    let Some(updated_version) = credential.version.checked_add(1) else {
        return error_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication unavailable",
        );
    };
    match state
        .passwords
        .replace_if_version_and_temporary(
            &tenant,
            &credential.user_id,
            new_hash,
            credential.version,
            updated_at,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return error_json(StatusCode::CONFLICT, "password was changed concurrently"),
        Err(_) => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        }
    }
    state
        .audit_credential_event(
            crate::credential::CredentialAuditEvent::UserCredentialOperation {
                action: "set",
                tenant: &tenant,
                actor: &credential.user_id,
                kind: "password",
                target: &credential.user_id,
                result: "success",
            },
        )
        .await;
    match crate::login::establish_local_session(
        &state,
        &tenant,
        credential.user_id,
        &request.authorize_query,
        crate::login::LocalSessionMethod::Password {
            credential_version: updated_version,
        },
        crate::login::session_device(&headers),
    )
    .await
    {
        Ok(session_id) => login_success(&session_id),
        Err(()) => error_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication unavailable",
        ),
    }
}

async fn add_no_store(request: axum::extract::Request, next: Next) -> axum::response::Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(password_login))
        .routes(routes!(password_change))
        .layer(DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn(add_no_store))
}

#[cfg(test)]
mod tests {
    use super::{account_bucket_key, AppState};
    use syn::visit::Visit;

    fn assert_exactly_once(body: &str, needle: &str) {
        assert_eq!(
            body.matches(needle).count(),
            1,
            "{needle} must occur exactly once in the reviewed function body"
        );
    }

    fn assert_call_inside_spawn_blocking(body: &str, call: &str) {
        let spawn = body
            .find("tokio::task::spawn_blocking(move || {")
            .expect("spawn_blocking closure");
        let call_position = body.find(call).expect("password operation");
        let await_join = body.rfind(".await").expect("spawn_blocking join await");
        assert_exactly_once(body, "try_acquire_owned()");
        assert_exactly_once(body, "tokio::task::spawn_blocking(move || {");
        assert_exactly_once(body, call);
        assert!(
            spawn < call_position && call_position < await_join,
            "password work must execute inside the spawn_blocking closure"
        );
        assert!(
            body.find("try_acquire_owned()").expect("worker permit") < spawn,
            "the bounded worker permit must be acquired before offloading password work"
        );
    }

    #[test]
    fn account_bucket_keys_are_tenant_scoped_hmacs_without_email_pii() {
        let mut state = AppState::dev("localhost");
        state.server_secret = std::sync::Arc::new(b"known-password-hmac-key".to_vec());
        let first = account_bucket_key(&state, "tenant-a", "alice@example.com");
        assert_eq!(
            first,
            account_bucket_key(&state, "tenant-a", "alice@example.com")
        );
        assert_eq!(
            first, "pwd:account:tenant-a:NxvHqdTtk16wABSWu3Qh48T5on7k1t6QmeLxYp7oYEs",
            "the fixed vector pins the keyed domain/tenant/NUL/email input sequence"
        );
        assert_ne!(
            first,
            account_bucket_key(&state, "tenant-b", "alice@example.com")
        );
        assert_ne!(
            first,
            account_bucket_key(&state, "tenant-a", "bob@example.com")
        );
        assert!(first.starts_with("pwd:account:tenant-a:"));
        assert!(!first.contains("alice"));
        assert!(!first.contains("example.com"));

        let mut other_secret = state.clone();
        other_secret.server_secret = std::sync::Arc::new(b"independent-password-test-key".to_vec());
        assert_ne!(
            first,
            account_bucket_key(&other_secret, "tenant-a", "alice@example.com"),
            "the account digest must be keyed by the configured server secret"
        );

        let source = include_str!("password_login.rs");
        let digest_body = source
            .split_once("fn account_digest")
            .expect("account_digest source")
            .1
            .split_once("fn account_bucket_key")
            .expect("account_bucket_key follows account_digest")
            .0;
        assert_exactly_once(
            digest_body,
            "HmacSha256::new_from_slice(&state.server_secret)",
        );
    }

    #[derive(Default)]
    struct MacroPaths(Vec<String>);

    impl<'ast> Visit<'ast> for MacroPaths {
        fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
            self.0.push(
                node.mac
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
            syn::visit::visit_expr_macro(self, node);
        }
    }

    fn function_macros(source: &str, function_name: &str) -> Vec<String> {
        let file = syn::parse_file(source).expect("password_login.rs parses as Rust");
        let function = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == function_name => Some(function),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{function_name} function"));
        let mut visitor = MacroPaths::default();
        visitor.visit_block(&function.block);
        visitor.0
    }

    #[test]
    fn password_hash_and_verify_work_are_offloaded_to_spawn_blocking() {
        let source = include_str!("password_login.rs");
        let hash_body = source
            .split_once("pub(crate) async fn hash_with_budget")
            .expect("hash_with_budget source")
            .1
            .split_once("pub(crate) async fn verify_with_budget")
            .expect("verify_with_budget follows hash_with_budget")
            .0;
        let verify_body = source
            .split_once("pub(crate) async fn verify_with_budget")
            .expect("verify_with_budget source")
            .1
            .split_once("enum Authentication")
            .expect("Authentication follows verify_with_budget")
            .0;
        let authenticate_body = source
            .split_once("async fn authenticate")
            .expect("authenticate source")
            .1
            .split_once("fn login_success")
            .expect("login_success follows authenticate")
            .0;

        assert_call_inside_spawn_blocking(hash_body, "hash_password(");
        assert_call_inside_spawn_blocking(verify_body, "verify_password(");
        assert_exactly_once(authenticate_body, "state.users.get_by_email(");
        assert_exactly_once(authenticate_body, "state.passwords.get(");
        assert_exactly_once(authenticate_body, "verify_with_budget(");
        let alias_read = authenticate_body
            .find("state.users.get_by_email(")
            .expect("single alias read");
        let credential_read = authenticate_body
            .find("state.passwords.get(")
            .expect("single credential read");
        let verification = authenticate_body
            .find("verify_with_budget(")
            .expect("single password verification");
        assert!(
            alias_read < credential_read && credential_read < verification,
            "alias and credential reads must each occur once before Argon2 verification"
        );
        for branch in [
            "match (user_result, credential_result)",
            "if !verified",
            "user.status != UserStatus::Active",
        ] {
            assert!(
                verification
                    < authenticate_body
                        .find(branch)
                        .expect("authentication branch"),
                "the single reviewed-profile verification must happen before {branch}"
            );
        }
        for function_name in [
            "hash_with_budget",
            "verify_with_budget",
            "password_login",
            "password_change",
        ] {
            assert!(
                function_macros(source, function_name).is_empty(),
                "{function_name} must not invoke macros that could log secret-bearing values"
            );
        }
        assert_eq!(
            function_macros(source, "authenticate"),
            ["format"],
            "authenticate may only use the reviewed fallback user-id format macro"
        );
    }
}
