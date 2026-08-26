//! C4.2 — 逐 client 校验 `token_endpoint_auth_method`。
//!
//! public(`none`+PKCE)与 confidential(`client_secret_basic`/`client_secret_post`/`private_key_jwt`)
//! 在同一 AS 共存且互不串用:用与注册记录**不符**的认证方式 MUST 被拒。校验按 client 注册的
//! `token_endpoint_auth_method` 分支(见 DESIGN §3.1)。secret 比对用常量时间(防时序侧信道)。
//!
//! `private_key_jwt` 走异步路径,以便加载远程 JWKS 并原子消费 `jti`;其余三种方法复用同步
//! secret helper。所有调用方必须经过返回认证快照的共享边界,不得直接绕过。

use std::future::Future;

use agent_auth_client::RegisteredClientAuthMethod;
use agent_auth_discovery::derive_issuer;
use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::ports::{
    ClientRecord, ClientStore, JwksFetcher, PlatformJwk, RegisteredClientJwk, RegisteredClientJwks,
    ReplayStore,
};
use crate::state::AppState;

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_ASSERTION_LIFETIME_SECS: i64 = 300;
const CLOCK_SKEW_SECS: i64 = 30;
const MIN_RSA_MODULUS_BITS: usize = 2048;
const MAX_RSA_MODULUS_BYTES: usize = 1024;
const MAX_RSA_EXPONENT_BYTES: usize = 8;
const MAX_CLIENT_ID_BYTES: usize = 2048;
const MAX_JWKS_URI_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy)]
pub enum ClientAuthEndpoint<'a> {
    Token,
    Revocation,
    Introspection,
    Par,
    BackchannelAuthentication,
    Prm,
    Sessions,
    Session(&'a str),
}

impl<'a> ClientAuthEndpoint<'a> {
    fn path(self) -> std::borrow::Cow<'a, str> {
        match self {
            Self::Token => "/token".into(),
            Self::Revocation => "/revoke".into(),
            Self::Introspection => "/introspect".into(),
            Self::Par => "/par".into(),
            Self::BackchannelAuthentication => "/bc-authorize".into(),
            Self::Prm => "/rs/prm".into(),
            Self::Sessions => "/sessions".into(),
            Self::Session(session_id) => format!("/sessions/{session_id}").into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PresentedClientAuth<'a> {
    pub client_secret: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

impl<'a> PresentedClientAuth<'a> {
    pub const fn new(
        client_secret: Option<&'a str>,
        client_assertion_type: Option<&'a str>,
        client_assertion: Option<&'a str>,
    ) -> Self {
        Self {
            client_secret,
            client_assertion_type,
            client_assertion,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthError {
    InvalidRequest(&'static str),
    InvalidClient(&'static str),
    TemporarilyUnavailable,
    ServerMisconfigured,
}

impl ClientAuthError {
    pub const fn description(self) -> &'static str {
        match self {
            Self::InvalidRequest(message) | Self::InvalidClient(message) => message,
            Self::TemporarilyUnavailable => "client authentication dependency unavailable",
            Self::ServerMisconfigured => "client authentication is not configured",
        }
    }
}

pub struct RegistrationKeyConfig {
    pub jwks: Option<RegisteredClientJwks>,
    pub jwks_uri: Option<String>,
    pub signing_alg: Option<String>,
}

pub fn validate_registration_key_config(
    auth_method: &str,
    jwks: Option<RegisteredClientJwks>,
    jwks_uri: Option<String>,
    signing_alg: Option<String>,
) -> Result<RegistrationKeyConfig, &'static str> {
    if jwks.is_some() && jwks_uri.is_some() {
        return Err("jwks 与 jwks_uri 互斥");
    }
    if let Some(uri) = jwks_uri.as_deref() {
        validate_jwks_uri(uri)?;
    }

    if auth_method != "private_key_jwt" {
        if signing_alg.is_some() {
            return Err("token_endpoint_auth_signing_alg 仅适用于 private_key_jwt");
        }
        if let Some(keys) = &jwks {
            validate_general_inline_jwks(keys)?;
        }
        return Ok(RegistrationKeyConfig {
            jwks,
            jwks_uri,
            signing_alg: None,
        });
    }

    let alg = signing_alg
        .as_deref()
        .filter(|alg| matches!(*alg, "RS256" | "ES256"))
        .ok_or("private_key_jwt 须 pin RS256 或 ES256")?;
    match (&jwks, jwks_uri.as_deref()) {
        (Some(_), Some(_)) | (None, None) => {
            return Err("private_key_jwt 须且只能提供 jwks 或 jwks_uri")
        }
        (None, Some(_)) => {}
        (Some(keys), None) => validate_inline_jwks(keys, alg)?,
    }

    Ok(RegistrationKeyConfig {
        jwks,
        jwks_uri,
        signing_alg,
    })
}

fn validate_jwks_uri(uri: &str) -> Result<(), &'static str> {
    if uri.len() > MAX_JWKS_URI_BYTES {
        return Err("jwks_uri 过长");
    }
    agent_auth_ciba::validate_endpoint_url(uri, None)
        .map(|_| ())
        .map_err(|_| "jwks_uri 须为受保护的 HTTPS URL")
}

fn validate_general_inline_jwks(jwks: &RegisteredClientJwks) -> Result<(), &'static str> {
    validate_jwks_size(jwks)?;
    for key in &jwks.keys {
        if key.kid.len() > 128 {
            return Err("JWK kid 过长");
        }
        validate_public_jwk(key, &key.alg)?;
    }
    Ok(())
}

fn validate_inline_jwks(
    jwks: &RegisteredClientJwks,
    allowed_alg: &str,
) -> Result<(), &'static str> {
    validate_jwks_size(jwks)?;
    let mut kids = std::collections::HashSet::new();
    for key in &jwks.keys {
        if key.kid.is_empty() || key.kid.len() > 128 || !kids.insert(key.kid.as_str()) {
            return Err("每把 JWK 须有唯一非空 kid");
        }
        validate_public_jwk(key, allowed_alg)?;
    }
    Ok(())
}

fn validate_jwks_size(jwks: &RegisteredClientJwks) -> Result<(), &'static str> {
    if jwks.keys.is_empty() || jwks.keys.len() > 10 {
        return Err("jwks keys 数量须为 1..10");
    }
    Ok(())
}

fn validate_public_jwk(key: &RegisteredClientJwk, allowed_alg: &str) -> Result<(), &'static str> {
    if key.alg != allowed_alg
        || key
            .public_key_use
            .as_deref()
            .is_some_and(|use_| use_ != "sig")
    {
        return Err("JWK alg/use 与 client assertion policy 不一致");
    }
    match (key.kty.as_str(), allowed_alg) {
        ("EC", "ES256") => {
            if key.crv.as_deref() != Some("P-256") || key.n.is_some() || key.e.is_some() {
                return Err("ES256 仅接受 EC P-256 public JWK");
            }
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Err("EC JWK 缺 x/y");
            };
            let x = URL_SAFE_NO_PAD.decode(x).map_err(|_| "EC JWK x 非法")?;
            let y = URL_SAFE_NO_PAD.decode(y).map_err(|_| "EC JWK y 非法")?;
            if x.len() != 32 || y.len() != 32 {
                return Err("EC JWK x/y 长度非法");
            }
            let mut encoded = Vec::with_capacity(65);
            encoded.push(4);
            encoded.extend_from_slice(&x);
            encoded.extend_from_slice(&y);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| "EC JWK 公钥非法")?;
        }
        ("RSA", "RS256") => {
            if key.crv.is_some() || key.x.is_some() || key.y.is_some() {
                return Err("RS256 仅接受 RSA public JWK");
            }
            let (Some(n), Some(e)) = (key.n.as_deref(), key.e.as_deref()) else {
                return Err("RSA JWK 缺 n/e");
            };
            let n_bytes = URL_SAFE_NO_PAD.decode(n).map_err(|_| "RSA JWK n 非法")?;
            if n_bytes.len() > MAX_RSA_MODULUS_BYTES {
                return Err("RSA JWK modulus 最大为 8192 bit");
            }
            if rsa_modulus_bits(&n_bytes) < MIN_RSA_MODULUS_BITS {
                return Err("RSA JWK modulus 须至少 2048 bit");
            }
            let n = rsa::BigUint::from_bytes_be(&n_bytes);
            let e_bytes = URL_SAFE_NO_PAD.decode(e).map_err(|_| "RSA JWK e 非法")?;
            if e_bytes.is_empty() || e_bytes.len() > MAX_RSA_EXPONENT_BYTES {
                return Err("RSA JWK exponent 长度非法");
            }
            let e = rsa::BigUint::from_bytes_be(&e_bytes);
            rsa::RsaPublicKey::new(n, e).map_err(|_| "RSA JWK 公钥非法")?;
        }
        _ => return Err("JWK kty 与 pin 的算法不一致"),
    }
    Ok(())
}

fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    rsa::BigUint::from_bytes_be(modulus).bits()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormValue {
    value: String,
}

fn decode_form_component(value: &str) -> Option<String> {
    serde_urlencoded::from_str::<FormValue>(&format!("value={value}"))
        .ok()
        .map(|decoded| decoded.value)
}

/// 解析 RFC 6749 §2.3.1 Basic 凭证。username/password 在 Base64 前均按
/// `application/x-www-form-urlencoded` 编码，故要在分隔后分别解码。
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, b64) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (client_id, secret) = s.split_once(':')?;
    Some((
        decode_form_component(client_id)?,
        decode_form_component(secret)?,
    ))
}

/// 从 `Authorization: Basic base64(client_id:secret)` 取出 client_id(username 部分)。
/// introspection 用它与 form `client_id` 交叉核对(评审 codex LOW:防 Basic/form client_id 不一致)。
pub fn basic_client_id(headers: &HeaderMap) -> Option<String> {
    basic_credentials(headers).map(|(client_id, _)| client_id)
}

/// 统一解析 form/Basic 中的 client_id；两处同时提供时必须一致。
pub fn resolve_client_id(
    form_client_id: Option<&str>,
    headers: &HeaderMap,
) -> Result<Option<String>, &'static str> {
    match (form_client_id, basic_client_id(headers)) {
        (Some(form), Some(basic)) if form != basic => Err("Basic 与 form client_id 不一致"),
        (Some(form), _) => Ok(Some(form.to_string())),
        (None, Some(basic)) => Ok(Some(basic)),
        (None, None) => Ok(None),
    }
}

/// Resolve the candidate client id without trusting assertion claims. Every
/// presented identity source must agree; signature verification happens later.
pub fn resolve_client_id_with_assertion(
    form_client_id: Option<&str>,
    headers: &HeaderMap,
    client_assertion: Option<&str>,
) -> Result<Option<String>, ClientAuthError> {
    let basic = basic_client_id(headers);
    let assertion = client_assertion
        .map(unverified_assertion_client_id)
        .transpose()?;
    let mut resolved: Option<&str> = None;
    for candidate in [form_client_id, basic.as_deref(), assertion.as_deref()]
        .into_iter()
        .flatten()
    {
        if resolved.is_some_and(|current| current != candidate) {
            return Err(ClientAuthError::InvalidClient(
                "presented client identifiers do not match",
            ));
        }
        resolved = Some(candidate);
    }
    Ok(resolved.map(str::to_string))
}

fn unverified_assertion_client_id(assertion: &str) -> Result<String, ClientAuthError> {
    if assertion.len() > MAX_ASSERTION_BYTES {
        return Err(ClientAuthError::InvalidRequest(
            "client_assertion too large",
        ));
    }
    let mut parts = assertion.split('.');
    let (_header, payload, _signature) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(payload), Some(signature), None) => (header, payload, signature),
            _ => {
                return Err(ClientAuthError::InvalidRequest(
                    "malformed client_assertion",
                ))
            }
        };
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ClientAuthError::InvalidRequest("malformed client_assertion"))?,
    )
    .map_err(|_| ClientAuthError::InvalidRequest("malformed client_assertion"))?;
    let issuer = claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_CLIENT_ID_BYTES)
        .ok_or(ClientAuthError::InvalidRequest(
            "client_assertion requires iss",
        ))?;
    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or(ClientAuthError::InvalidRequest(
            "client_assertion requires sub",
        ))?;
    if issuer != subject {
        return Err(ClientAuthError::InvalidClient(
            "client_assertion iss/sub mismatch",
        ));
    }
    Ok(issuer.to_string())
}

/// Authenticate a client and return the exact record snapshot whose credentials were verified.
///
/// Lazy legacy-secret migration reloads the persisted record after its credential CAS, whether the
/// CAS wins or loses. Callers must use this returned snapshot after authentication rather than the
/// record originally passed in.
pub async fn authenticate_loaded_snapshot(
    state: &AppState,
    tenant: &str,
    endpoint: ClientAuthEndpoint<'_>,
    client: &ClientRecord,
    headers: &HeaderMap,
    presented: PresentedClientAuth<'_>,
) -> Result<ClientRecord, ClientAuthError> {
    authenticate_loaded_snapshot_with_audit_identifier(
        state,
        tenant,
        endpoint,
        client,
        headers,
        presented,
        &client.client_id,
    )
    .await
}

/// Authenticate a client while attributing failures to a caller-controlled stable audit identity,
/// and return the exact record snapshot whose credentials were verified.
pub fn authenticate_loaded_snapshot_with_audit_identifier<'a>(
    state: &'a AppState,
    tenant: &'a str,
    endpoint: ClientAuthEndpoint<'a>,
    client: &'a ClientRecord,
    headers: &'a HeaderMap,
    presented: PresentedClientAuth<'a>,
    audit_identifier: &'a str,
) -> impl Future<Output = Result<ClientRecord, ClientAuthError>> + Send + 'a {
    // Keep the common secret/public methods out of the slow future that also
    // carries legacy migration, remote JWKS, and replay-store adapter states.
    let fast_path = authenticate_loaded_fast_path(state, tenant, client, headers, presented);
    async move {
        let result = match fast_path {
            Some(result) => result.map(|_| client.clone()),
            None => {
                Box::pin(authenticate_loaded_slow(
                    state, tenant, endpoint, client, headers, presented,
                ))
                .await
            }
        };
        match result {
            Ok(authenticated_client) => Ok(authenticated_client),
            Err(error) => {
                let audited = Box::pin(record_client_auth_error(
                    state,
                    tenant,
                    audit_identifier,
                    error,
                ))
                .await
                .expect_err("record_client_auth_error always returns the audited error");
                Err(audited)
            }
        }
    }
}

async fn record_client_auth_error(
    state: &AppState,
    tenant: &str,
    audit_identifier: &str,
    error: ClientAuthError,
) -> Result<(), ClientAuthError> {
    let outcome = match error {
        ClientAuthError::TemporarilyUnavailable | ClientAuthError::ServerMisconfigured => {
            crate::security_event::SecurityEventOutcome::Failure
        }
        ClientAuthError::InvalidRequest(_) | ClientAuthError::InvalidClient(_) => {
            crate::security_event::SecurityEventOutcome::Denied
        }
    };
    state
        .record_security_event(
            crate::security_event::SecurityEventDraft::new(
                tenant,
                crate::security_event::SecurityActor::system("anonymous"),
                Some(crate::security_event::SecuritySubject::client(
                    audit_identifier,
                )),
                crate::security_event::SecurityEventCategory::Authentication,
                "authentication.client",
                outcome,
            )
            .correlated(crate::security_event::SecurityEventCorrelation {
                client_id: Some(audit_identifier.to_string()),
                ..Default::default()
            }),
        )
        .await;
    Err(error)
}

fn authenticate_loaded_fast_path(
    state: &AppState,
    tenant: &str,
    client: &ClientRecord,
    headers: &HeaderMap,
    presented: PresentedClientAuth<'_>,
) -> Option<Result<(), ClientAuthError>> {
    if client.is_tombstoned() {
        return Some(Err(ClientAuthError::InvalidClient("client is tombstoned")));
    }
    if let Err(error) = validate_none_auth_client_type(client) {
        return Some(Err(ClientAuthError::InvalidClient(error)));
    }
    let requires_legacy_migration =
        client.client_secret.is_some() && client.client_secret_credentials.current.is_none();
    if requires_legacy_migration || client.token_endpoint_auth_method == "private_key_jwt" {
        return None;
    }
    if presented.client_assertion.is_some() || presented.client_assertion_type.is_some() {
        return Some(Err(ClientAuthError::InvalidClient(
            "client assertion method does not match registration",
        )));
    }
    Some(
        verify_client_auth_at(
            client,
            headers,
            &presented.client_secret.map(str::to_string),
            &state.server_secret,
            tenant,
            crate::token::current_unix_secs_pub(),
        )
        .map_err(ClientAuthError::InvalidClient),
    )
}

async fn authenticate_loaded_slow(
    state: &AppState,
    tenant: &str,
    endpoint: ClientAuthEndpoint<'_>,
    client: &ClientRecord,
    headers: &HeaderMap,
    presented: PresentedClientAuth<'_>,
) -> Result<ClientRecord, ClientAuthError> {
    if client.is_tombstoned() {
        return Err(ClientAuthError::InvalidClient("client is tombstoned"));
    }
    validate_none_auth_client_type(client).map_err(ClientAuthError::InvalidClient)?;
    let migrated_client = migrate_legacy_client_secret(state, tenant, client).await?;
    let client = migrated_client.as_ref().unwrap_or(client);
    if client.is_tombstoned() {
        return Err(ClientAuthError::InvalidClient("client is tombstoned"));
    }
    validate_none_auth_client_type(client).map_err(ClientAuthError::InvalidClient)?;
    if client.token_endpoint_auth_method != "private_key_jwt" {
        if presented.client_assertion.is_some() || presented.client_assertion_type.is_some() {
            return Err(ClientAuthError::InvalidClient(
                "client assertion method does not match registration",
            ));
        }
        return verify_client_auth_at(
            client,
            headers,
            &presented.client_secret.map(str::to_string),
            &state.server_secret,
            tenant,
            crate::token::current_unix_secs_pub(),
        )
        .map(|_| client.clone())
        .map_err(ClientAuthError::InvalidClient);
    }

    if headers.contains_key(header::AUTHORIZATION) || presented.client_secret.is_some() {
        return Err(ClientAuthError::InvalidClient(
            "private_key_jwt must not mix other credentials",
        ));
    }
    if presented.client_assertion_type.is_none() && presented.client_assertion.is_none() {
        return Err(ClientAuthError::InvalidClient(
            "private_key_jwt credentials are required",
        ));
    }
    if presented.client_assertion_type != Some(CLIENT_ASSERTION_TYPE) {
        return Err(ClientAuthError::InvalidRequest(
            "invalid client_assertion_type",
        ));
    }
    let assertion = presented
        .client_assertion
        .ok_or(ClientAuthError::InvalidRequest(
            "client_assertion is required",
        ))?;
    if assertion.len() > MAX_ASSERTION_BYTES {
        return Err(ClientAuthError::InvalidRequest(
            "client_assertion too large",
        ));
    }
    let (kid, alg) = assertion_header(assertion)?;
    if client.token_endpoint_auth_signing_alg.as_deref() != Some(alg.as_str()) {
        return Err(ClientAuthError::InvalidClient(
            "client assertion algorithm is not registered",
        ));
    }
    let key = select_registered_key(state, client, &kid).await?;
    let claims = verify_with_registered_key(assertion, &key, &kid, &alg)?;

    let host = crate::hostutil::issuer_host(headers)
        .ok_or(ClientAuthError::InvalidRequest("invalid request host"))?;
    let issuer = derive_issuer(&host, &state.form)
        .map_err(|_| ClientAuthError::InvalidRequest("bad host"))?;
    let expected_audience = format!("{}{}", issuer.as_str(), endpoint.path());
    let (jti, expires_at, issued_at) =
        validate_assertion_claims(&claims, &client.client_id, &expected_audience)?;
    if !state.region.accepts_external_issued_at(issued_at) {
        return Err(ClientAuthError::InvalidClient(
            "client assertion predates this Region activation",
        ));
    }

    let replay_store = state
        .replay_store
        .as_ref()
        .ok_or(ClientAuthError::ServerMisconfigured)?;
    let replay_key = replay_key(&state.server_secret, tenant, &client.client_id, jti)?;
    let replay_expires_at = assertion_replay_expires_at(expires_at)?;
    match replay_store
        .check_and_set(tenant, &replay_key, replay_expires_at)
        .await
    {
        Ok(true) => Ok(client.clone()),
        Ok(false) => Err(ClientAuthError::InvalidClient("client assertion replayed")),
        Err(_) => Err(ClientAuthError::TemporarilyUnavailable),
    }
}

async fn migrate_legacy_client_secret(
    state: &AppState,
    tenant: &str,
    client: &ClientRecord,
) -> Result<Option<ClientRecord>, ClientAuthError> {
    let Some(plaintext) = client.client_secret.as_deref() else {
        return Ok(None);
    };
    if client.client_secret_credentials.current.is_some() {
        return Ok(None);
    }
    let now = crate::token::current_unix_secs_pub();
    let created_at = if client.created_at > 0 {
        client.created_at
    } else {
        now
    };
    let credentials = crate::credential::CredentialSet {
        current: Some(crate::credential::new_credential_record(
            &state.server_secret,
            crate::credential::CredentialKind::ClientSecret,
            tenant,
            format!("cred_{}", crate::register::rand_token(12)),
            client.client_id.clone(),
            plaintext,
            created_at,
            now.checked_add(crate::credential::DEFAULT_CLIENT_SECRET_TTL_SECS)
                .ok_or(ClientAuthError::TemporarilyUnavailable)?,
            "system:lazy-legacy-migration".into(),
            None,
        )),
        version: client.client_secret_credentials.version.saturating_add(1),
        ..Default::default()
    };
    match state
        .clients
        .replace_credential_set(
            tenant,
            &client.client_id,
            crate::credential::CredentialKind::ClientSecret,
            client.client_secret_credentials.version,
            credentials,
        )
        .await
    {
        Ok(_) => state
            .clients
            .get(tenant, &client.client_id)
            .await
            .map_err(|_| ClientAuthError::TemporarilyUnavailable)?
            .ok_or(ClientAuthError::InvalidClient("client not found"))
            .map(Some),
        Err(_) => Err(ClientAuthError::TemporarilyUnavailable),
    }
}

fn assertion_header(assertion: &str) -> Result<(String, String), ClientAuthError> {
    let encoded = assertion
        .split('.')
        .next()
        .ok_or(ClientAuthError::InvalidRequest(
            "malformed client_assertion",
        ))?;
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ClientAuthError::InvalidRequest("malformed client_assertion"))?,
    )
    .map_err(|_| ClientAuthError::InvalidRequest("malformed client_assertion"))?;
    let object = header.as_object().ok_or(ClientAuthError::InvalidRequest(
        "malformed client_assertion",
    ))?;
    if ["jku", "x5u", "jwk", "crit"]
        .iter()
        .any(|name| object.contains_key(*name))
    {
        return Err(ClientAuthError::InvalidClient(
            "untrusted client assertion header",
        ));
    }
    let kid = object
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .filter(|kid| !kid.is_empty())
        .ok_or(ClientAuthError::InvalidClient(
            "client assertion requires kid",
        ))?;
    let alg = object
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .filter(|alg| matches!(*alg, "RS256" | "ES256"))
        .ok_or(ClientAuthError::InvalidClient(
            "unsupported client assertion algorithm",
        ))?;
    Ok((kid.to_string(), alg.to_string()))
}

async fn select_registered_key(
    state: &AppState,
    client: &ClientRecord,
    kid: &str,
) -> Result<PlatformJwk, ClientAuthError> {
    if let Some(jwks) = &client.jwks {
        return jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .map(platform_jwk)
            .ok_or(ClientAuthError::InvalidClient("unknown client key"));
    }
    let uri = client
        .jwks_uri
        .as_deref()
        .ok_or(ClientAuthError::ServerMisconfigured)?;
    let select = |keys: &[PlatformJwk]| {
        keys.iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .cloned()
    };
    let cached = state
        .jwks_fetcher
        .fetch(uri)
        .await
        .map_err(|_| ClientAuthError::TemporarilyUnavailable)?;
    if let Some(key) = select(&cached) {
        return Ok(key);
    }
    let fresh = state
        .jwks_fetcher
        .fetch_fresh(uri)
        .await
        .map_err(|_| ClientAuthError::TemporarilyUnavailable)?;
    select(&fresh).ok_or(ClientAuthError::InvalidClient("unknown client key"))
}

fn platform_jwk(key: &RegisteredClientJwk) -> PlatformJwk {
    PlatformJwk {
        kid: Some(key.kid.clone()),
        kty: Some(key.kty.clone()),
        n: key.n.clone().unwrap_or_default(),
        e: key.e.clone().unwrap_or_default(),
        crv: key.crv.clone(),
        x: key.x.clone(),
        y: key.y.clone(),
        alg: Some(key.alg.clone()),
    }
}

fn verify_with_registered_key(
    assertion: &str,
    key: &PlatformJwk,
    kid: &str,
    alg: &str,
) -> Result<serde_json::Value, ClientAuthError> {
    if key
        .alg
        .as_deref()
        .is_some_and(|registered| registered != alg)
    {
        return Err(ClientAuthError::InvalidClient(
            "client key algorithm mismatch",
        ));
    }
    match alg {
        "ES256"
            if key.kty.as_deref() == Some("EC")
                && key.crv.as_deref() == Some("P-256")
                && key.n.is_empty()
                && key.e.is_empty() =>
        {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Err(ClientAuthError::ServerMisconfigured);
            };
            agent_auth_workload::verify_es256(assertion, x, y, Some(kid))
                .map(|verified| verified.claims)
                .map_err(|_| ClientAuthError::InvalidClient("client assertion rejected"))
        }
        "RS256"
            if key.kty.as_deref() == Some("RSA")
                && key.x.is_none()
                && key.y.is_none()
                && key.crv.is_none() =>
        {
            let modulus = URL_SAFE_NO_PAD
                .decode(&key.n)
                .map_err(|_| ClientAuthError::InvalidClient("client assertion rejected"))?;
            if modulus.len() > MAX_RSA_MODULUS_BYTES {
                return Err(ClientAuthError::InvalidClient(
                    "client RSA key must not exceed 8192 bits",
                ));
            }
            if rsa_modulus_bits(&modulus) < MIN_RSA_MODULUS_BITS {
                return Err(ClientAuthError::InvalidClient(
                    "client RSA key must be at least 2048 bits",
                ));
            }
            let exponent = URL_SAFE_NO_PAD
                .decode(&key.e)
                .map_err(|_| ClientAuthError::InvalidClient("client assertion rejected"))?;
            if exponent.is_empty() || exponent.len() > MAX_RSA_EXPONENT_BYTES {
                return Err(ClientAuthError::InvalidClient(
                    "client RSA exponent size is not allowed",
                ));
            }
            agent_auth_workload::verify_rs256(assertion, &key.n, &key.e, Some(kid))
                .map(|verified| verified.claims)
                .map_err(|_| ClientAuthError::InvalidClient("client assertion rejected"))
        }
        _ => Err(ClientAuthError::InvalidClient(
            "client key type does not match algorithm",
        )),
    }
}

fn validate_assertion_claims<'a>(
    claims: &'a serde_json::Value,
    client_id: &str,
    expected_audience: &str,
) -> Result<(&'a str, i64, i64), ClientAuthError> {
    let object = claims
        .as_object()
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    if object.get("iss").and_then(serde_json::Value::as_str) != Some(client_id)
        || object.get("sub").and_then(serde_json::Value::as_str) != Some(client_id)
    {
        return Err(ClientAuthError::InvalidClient("client assertion rejected"));
    }
    let audience_matches = match object.get("aud") {
        Some(serde_json::Value::String(audience)) => audience == expected_audience,
        Some(serde_json::Value::Array(audiences)) if audiences.len() == 1 => {
            audiences[0].as_str() == Some(expected_audience)
        }
        _ => false,
    };
    if !audience_matches {
        return Err(ClientAuthError::InvalidClient("client assertion rejected"));
    }
    let exp = object
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    let iat = object
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    let nbf = object
        .get("nbf")
        .and_then(serde_json::Value::as_i64)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    let jti = object
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= 256)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    let now = crate::token::current_unix_secs_pub();
    let lifetime = exp
        .checked_sub(iat)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))?;
    if exp < now - CLOCK_SKEW_SECS
        || iat > now + CLOCK_SKEW_SECS
        || nbf > now + CLOCK_SKEW_SECS
        || exp < iat
        || lifetime > MAX_ASSERTION_LIFETIME_SECS
    {
        return Err(ClientAuthError::InvalidClient("client assertion rejected"));
    }
    Ok((jti, exp, iat))
}

fn assertion_replay_expires_at(expires_at: i64) -> Result<i64, ClientAuthError> {
    expires_at
        .checked_add(CLOCK_SKEW_SECS)
        .ok_or(ClientAuthError::InvalidClient("client assertion rejected"))
}

fn replay_key(
    server_secret: &[u8],
    tenant: &str,
    client_id: &str,
    jti: &str,
) -> Result<String, ClientAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret)
        .map_err(|_| ClientAuthError::ServerMisconfigured)?;
    mac.update(b"private_key_jwt\0");
    mac.update(tenant.as_bytes());
    mac.update(b"\0");
    mac.update(client_id.as_bytes());
    mac.update(b"\0");
    mac.update(jti.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// 校验客户端认证(C4.2)。通过返回 `Ok(())`,否则返回错误说明串。
/// - `none`:public 客户端,MUST NOT 带 secret(带了说明串用错方法)——只靠 PKCE(在别处校)。
/// - `client_secret_basic`:secret 来自 Authorization: Basic 头。
/// - `client_secret_post`:secret 来自 form 的 `client_secret`。
/// - `private_key_jwt`:必须走上层异步验证器(JWKS + replay store),本同步 helper 拒绝。
#[cfg(test)]
fn verify_client_auth(
    client: &ClientRecord,
    headers: &HeaderMap,
    form_secret: &Option<String>,
) -> Result<(), &'static str> {
    verify_client_auth_at(client, headers, form_secret, b"", "", i64::MIN)
}

pub fn verify_client_auth_at(
    client: &ClientRecord,
    headers: &HeaderMap,
    form_secret: &Option<String>,
    server_secret: &[u8],
    tenant: &str,
    now: i64,
) -> Result<(), &'static str> {
    match RegisteredClientAuthMethod::parse_executable(&client.token_endpoint_auth_method) {
        Some(RegisteredClientAuthMethod::None) => {
            validate_none_auth_client_type(client)?;
            // public 客户端不应携带凭证(用错方法);带 secret 视为方法串用 → 拒。
            if form_secret.is_some() || headers.contains_key(header::AUTHORIZATION) {
                return Err("public 客户端(none)MUST NOT 带 client_secret");
            }
            Ok(())
        }
        Some(RegisteredClientAuthMethod::ClientSecretBasic) => {
            if form_secret.is_some() {
                return Err("client_secret_basic MUST NOT 混用 form client_secret");
            }
            let (presented_client_id, presented_secret) =
                basic_credentials(headers).ok_or("缺 Authorization: Basic 凭证")?;
            if presented_client_id != client.client_id {
                return Err("Basic client_id 不匹配");
            }
            if verify_presented_secret(client, server_secret, tenant, &presented_secret, now) {
                Ok(())
            } else {
                Err("client_secret 不匹配")
            }
        }
        Some(RegisteredClientAuthMethod::ClientSecretPost) => {
            if headers.contains_key(header::AUTHORIZATION) {
                return Err("client_secret_post MUST NOT 混用 Authorization 凭证");
            }
            let presented = form_secret.as_deref().ok_or("缺 client_secret(post)")?;
            if verify_presented_secret(client, server_secret, tenant, presented, now) {
                Ok(())
            } else {
                Err("client_secret 不匹配")
            }
        }
        Some(RegisteredClientAuthMethod::PrivateKeyJwt) => {
            Err("private_key_jwt 必须走异步 JWKS/replay 验证器")
        }
        None => Err("未知 token_endpoint_auth_method"),
    }
}

fn validate_none_auth_client_type(client: &ClientRecord) -> Result<(), &'static str> {
    if client.token_endpoint_auth_method == "none"
        && client.client_type() != agent_auth_workload::ClientType::Public
    {
        return Err("token_endpoint_auth_method=none 仅允许 public client");
    }
    Ok(())
}

fn verify_presented_secret(
    client: &ClientRecord,
    server_secret: &[u8],
    tenant: &str,
    presented: &str,
    now: i64,
) -> bool {
    client
        .client_secret_credentials
        .verify(
            server_secret,
            crate::credential::CredentialKind::ClientSecret,
            tenant,
            presented,
            now,
        )
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(method: &str, secret: Option<&str>) -> ClientRecord {
        let client_secret_credentials = secret
            .map(|secret| crate::credential::CredentialSet {
                current: Some(crate::credential::new_credential_record(
                    b"",
                    crate::credential::CredentialKind::ClientSecret,
                    "",
                    "credential-c".into(),
                    "c".into(),
                    secret,
                    i64::MIN,
                    i64::MAX,
                    "test".into(),
                    None,
                )),
                version: 1,
                ..Default::default()
            })
            .unwrap_or_default();
        ClientRecord {
            client_id: "c".into(),
            redirect_uris: vec![],
            application_type: None,
            token_endpoint_auth_method: method.into(),
            client_secret: None,
            client_secret_credentials,
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            default_resource: None,
            introspect_enabled: false,
            resource_ids: vec![],
            post_logout_redirect_uris: vec![],
            reg_token_hash: None,
            registration_token_credentials: Default::default(),
            client_type: None,
            id_token_signed_response_alg: None,
            oidc_sector_identifier: None,
            allowed_resources: vec![],
            allowed_scopes: vec![],
            redirect_mode: None,
            created_at: 0,
            last_used_day: None,
            authority_revision: 0,
            tombstoned_at: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            require_dpop: false,
            prm_domains: vec![],
        }
    }

    fn basic_header(client_id: &str, secret: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let b64 = STANDARD.encode(format!("{client_id}:{secret}"));
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {b64}").parse().unwrap(),
        );
        h
    }

    fn rsa_jwks(modulus: Vec<u8>, exponent: Vec<u8>) -> RegisteredClientJwks {
        RegisteredClientJwks {
            keys: vec![RegisteredClientJwk {
                kid: "rsa-key".to_string(),
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                public_key_use: Some("sig".to_string()),
                crv: None,
                n: Some(URL_SAFE_NO_PAD.encode(modulus)),
                e: Some(URL_SAFE_NO_PAD.encode(exponent)),
                x: None,
                y: None,
            }],
        }
    }

    // none:无凭证通过;带凭证拒(方法串用)。
    #[test]
    fn none_no_secret_ok() {
        assert!(verify_client_auth(&client("none", None), &HeaderMap::new(), &None).is_ok());
    }
    #[test]
    fn none_with_secret_rejected() {
        assert!(
            verify_client_auth(&client("none", None), &HeaderMap::new(), &Some("x".into()))
                .is_err()
        );
        assert!(verify_client_auth(&client("none", None), &basic_header("c", "x"), &None).is_err());
    }

    #[test]
    fn none_auth_rejects_explicit_non_public_client_types() {
        for client_type in ["confidential", "workload"] {
            let mut record = client("none", None);
            record.client_type = Some(client_type.to_string());
            assert_eq!(
                verify_client_auth(&record, &HeaderMap::new(), &None),
                Err("token_endpoint_auth_method=none 仅允许 public client")
            );
        }

        let mut public = client("none", None);
        public.client_type = Some("public".into());
        assert!(verify_client_auth(&public, &HeaderMap::new(), &None).is_ok());
    }

    // client_secret_basic:对的 secret 通过、错的拒、缺的拒。
    #[test]
    fn basic_correct_ok() {
        let c = client("client_secret_basic", Some("s3cret"));
        assert!(verify_client_auth(&c, &basic_header("c", "s3cret"), &None).is_ok());
    }
    #[test]
    fn basic_wrong_rejected() {
        let c = client("client_secret_basic", Some("s3cret"));
        assert!(verify_client_auth(&c, &basic_header("c", "wrong"), &None).is_err());
    }
    #[test]
    fn basic_wrong_client_id_rejected_even_when_secret_matches() {
        let c = client("client_secret_basic", Some("s3cret"));
        assert!(verify_client_auth(&c, &basic_header("other", "s3cret"), &None).is_err());
    }
    #[test]
    fn basic_missing_rejected() {
        let c = client("client_secret_basic", Some("s3cret"));
        assert!(verify_client_auth(&c, &HeaderMap::new(), &None).is_err());
    }
    #[test]
    fn basic_decodes_form_encoded_client_id_and_secret() {
        let headers = basic_header("client%3Aid+with+space", "s%3Aecret");
        assert_eq!(
            basic_credentials(&headers),
            Some(("client:id with space".to_string(), "s:ecret".to_string()))
        );
    }

    // client_secret_post:form secret 对/错。
    #[test]
    fn post_correct_ok() {
        let c = client("client_secret_post", Some("pw"));
        assert!(verify_client_auth(&c, &HeaderMap::new(), &Some("pw".into())).is_ok());
    }
    #[test]
    fn post_wrong_rejected() {
        let c = client("client_secret_post", Some("pw"));
        assert!(verify_client_auth(&c, &HeaderMap::new(), &Some("bad".into())).is_err());
    }
    #[test]
    fn post_rejects_basic_username_with_form_secret() {
        let c = client("client_secret_post", Some("pw"));
        assert!(verify_client_auth(&c, &basic_header("c", "ignored"), &Some("pw".into())).is_err());
    }

    // private_key_jwt 必须走异步验证边界;同步 secret helper fail-closed。
    #[test]
    fn private_key_jwt_rejected_by_synchronous_secret_helper() {
        assert!(
            verify_client_auth(&client("private_key_jwt", None), &HeaderMap::new(), &None).is_err()
        );
    }

    #[test]
    fn private_key_jwt_registration_rejects_weak_rsa_modulus() {
        let mut modulus = vec![0_u8; 128];
        modulus[0] = 0x80;
        modulus[127] = 1;
        let result = validate_registration_key_config(
            "private_key_jwt",
            Some(rsa_jwks(modulus, vec![1, 0, 1])),
            None,
            Some("RS256".to_string()),
        );
        assert!(matches!(result, Err("RSA JWK modulus 须至少 2048 bit")));
    }

    #[test]
    fn private_key_jwt_registration_rejects_duplicate_kids() {
        let mut modulus = vec![0_u8; 256];
        modulus[0] = 0x80;
        modulus[255] = 1;
        let mut jwks = rsa_jwks(modulus, vec![1, 0, 1]);
        jwks.keys.push(jwks.keys[0].clone());

        let result = validate_registration_key_config(
            "private_key_jwt",
            Some(jwks),
            None,
            Some("RS256".to_string()),
        );

        assert!(matches!(result, Err("每把 JWK 须有唯一非空 kid")));
    }

    #[test]
    fn general_client_metadata_accepts_jwks_uri_but_not_private_auth_signing_alg() {
        let uri = "https://keys.example.com/client.jwks".to_string();
        let config =
            validate_registration_key_config("client_secret_basic", None, Some(uri.clone()), None)
                .unwrap();
        assert!(config.jwks.is_none());
        assert_eq!(config.jwks_uri, Some(uri));
        assert!(config.signing_alg.is_none());

        assert!(matches!(
            validate_registration_key_config(
                "client_secret_basic",
                None,
                None,
                Some("RS256".to_string()),
            ),
            Err("token_endpoint_auth_signing_alg 仅适用于 private_key_jwt")
        ));
    }

    #[test]
    fn general_client_metadata_rejects_conflicting_jwk_sources() {
        let mut modulus = vec![0_u8; 256];
        modulus[0] = 0x80;
        modulus[255] = 1;
        assert!(matches!(
            validate_registration_key_config(
                "client_secret_basic",
                Some(rsa_jwks(modulus, vec![1, 0, 1])),
                Some("https://keys.example.com/client.jwks".to_string()),
                None,
            ),
            Err("jwks 与 jwks_uri 互斥")
        ));
    }

    #[test]
    fn private_key_jwt_registration_bounds_remote_uri_and_rsa_integer_sizes() {
        let oversized_uri = format!(
            "https://keys.example.com/{}",
            "a".repeat(MAX_JWKS_URI_BYTES)
        );
        assert!(matches!(
            validate_registration_key_config(
                "private_key_jwt",
                None,
                Some(oversized_uri),
                Some("RS256".to_string()),
            ),
            Err("jwks_uri 过长")
        ));

        let mut oversized_modulus = vec![0_u8; MAX_RSA_MODULUS_BYTES + 1];
        oversized_modulus[0] = 0x80;
        assert!(matches!(
            validate_registration_key_config(
                "private_key_jwt",
                Some(rsa_jwks(oversized_modulus, vec![1, 0, 1])),
                None,
                Some("RS256".to_string()),
            ),
            Err("RSA JWK modulus 最大为 8192 bit")
        ));

        let mut modulus = vec![0_u8; 256];
        modulus[0] = 0x80;
        modulus[255] = 1;
        assert!(matches!(
            validate_registration_key_config(
                "private_key_jwt",
                Some(rsa_jwks(modulus, vec![1_u8; MAX_RSA_EXPONENT_BYTES + 1])),
                None,
                Some("RS256".to_string()),
            ),
            Err("RSA JWK exponent 长度非法")
        ));
    }

    #[test]
    fn remote_private_key_jwt_rejects_weak_rsa_modulus_before_verification() {
        let mut modulus = vec![0_u8; 128];
        modulus[0] = 0x80;
        modulus[127] = 1;
        let key = PlatformJwk {
            kid: Some("weak-rsa".to_string()),
            kty: Some("RSA".to_string()),
            n: URL_SAFE_NO_PAD.encode(modulus),
            e: "AQAB".to_string(),
            alg: Some("RS256".to_string()),
            ..PlatformJwk::default()
        };
        assert_eq!(
            verify_with_registered_key("not.a.jwt", &key, "weak-rsa", "RS256"),
            Err(ClientAuthError::InvalidClient(
                "client RSA key must be at least 2048 bits"
            ))
        );
    }

    #[test]
    fn private_key_jwt_rejects_timestamp_arithmetic_overflow() {
        let claims = serde_json::json!({
            "iss": "c",
            "sub": "c",
            "aud": "https://issuer.example/token",
            "exp": i64::MAX,
            "iat": i64::MIN,
            "nbf": 0,
            "jti": "extreme-timestamps"
        });
        assert_eq!(
            validate_assertion_claims(&claims, "c", "https://issuer.example/token"),
            Err(ClientAuthError::InvalidClient("client assertion rejected"))
        );
        assert_eq!(
            assertion_replay_expires_at(i64::MAX),
            Err(ClientAuthError::InvalidClient("client assertion rejected"))
        );
    }

    // 方法串用:注册 basic 的 client 用 post 提交 secret → 无 Basic 头 → 拒。
    #[test]
    fn method_confusion_basic_client_post_secret() {
        let c = client("client_secret_basic", Some("s"));
        // 只在 form 带 secret、无 Basic 头 → 缺 Basic 凭证 → 拒。
        assert!(verify_client_auth(&c, &HeaderMap::new(), &Some("s".into())).is_err());
        // Basic 正确也不得同时带 form secret。
        assert!(verify_client_auth(&c, &basic_header("c", "s"), &Some("s".into())).is_err());
    }

    #[test]
    fn lifecycle_secret_verification_requires_explicit_context() {
        let now = 10_000;
        let mut c = client("client_secret_basic", None);
        c.client_secret_credentials = crate::credential::CredentialSet {
            current: Some(crate::credential::new_credential_record(
                b"pepper",
                crate::credential::CredentialKind::ClientSecret,
                "tenant-a",
                "credential-a".into(),
                "c".into(),
                "lifecycle-secret",
                now,
                now + 60,
                "test".into(),
                None,
            )),
            version: 1,
            ..Default::default()
        };
        assert!(verify_client_auth_at(
            &c,
            &basic_header("c", "lifecycle-secret"),
            &None,
            b"pepper",
            "tenant-a",
            now,
        )
        .is_ok());
        assert!(verify_client_auth_at(
            &c,
            &basic_header("c", "lifecycle-secret"),
            &None,
            b"wrong-pepper",
            "tenant-a",
            now,
        )
        .is_err());
    }

    #[test]
    fn resolve_client_id_covers_basic_form_conflict_and_missing() {
        let basic = basic_header("c", "s");
        assert_eq!(
            resolve_client_id(None, &basic).unwrap().as_deref(),
            Some("c")
        );
        assert_eq!(
            resolve_client_id(Some("c"), &HeaderMap::new())
                .unwrap()
                .as_deref(),
            Some("c")
        );
        assert_eq!(
            resolve_client_id(Some("c"), &basic).unwrap().as_deref(),
            Some("c")
        );
        assert!(resolve_client_id(Some("other"), &basic).is_err());
        assert_eq!(resolve_client_id(None, &HeaderMap::new()).unwrap(), None);
    }

    #[test]
    fn assertion_client_id_accepts_the_cimd_url_size_limit() {
        let prefix = "https://client.example.com/";
        let client_id = format!("{prefix}{}", "a".repeat(MAX_CLIENT_ID_BYTES - prefix.len()));
        let payload = serde_json::json!({
            "iss": client_id.as_str(),
            "sub": client_id.as_str()
        });
        let assertion = format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );

        assert_eq!(
            resolve_client_id_with_assertion(Some(&client_id), &HeaderMap::new(), Some(&assertion))
                .unwrap()
                .as_deref(),
            Some(client_id.as_str())
        );
    }
}
