//! Payment resource authentication: every request is checked online against
//! the authoritative token, Grant, lineage and user state, for the payment
//! audience only. Results are never cached.

use agent_auth_token::claims::NAMESPACE;
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::PaymentError;
use super::PaymentModule;
use crate::state::AppState;

/// An online-verified caller of the payment resource.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// RFC 7662 active introspection body.
    pub claims: Map<String, Value>,
    /// Payer subject on the payment resource.
    pub subject: String,
    /// Token `client_id` (the actor for a delegated token).
    pub client_id: String,
    pub scopes: Vec<String>,
    /// `act.sub` of a single-hop delegated token.
    pub actor: Option<String>,
    /// Number of nested `act` levels (0 = not delegated).
    pub act_depth: usize,
    pub grant_id: Option<String>,
    pub jti_sha256: String,
    /// When the authoritative check returned active.
    pub checked_at: i64,
}

impl Caller {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }
}

/// Authenticate the bearer token for `module`'s audience.
pub(crate) async fn authenticate(
    state: &AppState,
    module: &PaymentModule,
    tenant: &str,
    headers: &HeaderMap,
) -> Result<Caller, PaymentError> {
    let token = crate::tenant_admin::bearer(headers)
        .filter(|token| !token.is_empty())
        .ok_or(PaymentError::InvalidToken("missing bearer token"))?;
    let claims = match crate::introspect::authoritative_claims(
        state,
        tenant,
        headers,
        &token,
        std::slice::from_ref(&module.config.resource),
    )
    .await
    {
        Ok(Some(claims)) => claims,
        Ok(None) => return Err(PaymentError::InvalidToken("token is not active")),
        Err(_) => {
            return Err(PaymentError::Unavailable(
                "authorization authority unavailable",
            ))
        }
    };
    let checked_at = crate::token::current_unix_secs_pub();
    // A sender-constrained token must never be accepted as a bearer token.
    if claims.contains_key("cnf") {
        return Err(PaymentError::InvalidToken(
            "sender-constrained tokens are not supported by the payment resource",
        ));
    }
    let namespace = claims.get(NAMESPACE);
    if namespace
        .and_then(|ns| ns.get("sub_type"))
        .and_then(Value::as_str)
        != Some("user")
    {
        return Err(PaymentError::Forbidden(
            "payment tokens must represent a user",
        ));
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(PaymentError::InvalidToken("token has no subject"))?
        .to_string();
    let client_id = claims
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(PaymentError::InvalidToken("token has no client"))?
        .to_string();
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(PaymentError::InvalidToken("token has no identifier"))?;
    let scopes = claims
        .get("scope")
        .and_then(Value::as_str)
        .map(|scope| {
            scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let mut act_depth = 0;
    let mut cursor = claims.get("act");
    while let Some(act) = cursor {
        act_depth += 1;
        cursor = act.get("act");
    }
    let actor = claims
        .get("act")
        .and_then(|act| act.get("sub"))
        .and_then(Value::as_str)
        .map(String::from);
    let grant_id = namespace
        .and_then(|ns| ns.get("auth_grant"))
        .and_then(Value::as_str)
        .map(String::from);
    Ok(Caller {
        jti_sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(jti.as_bytes())),
        claims,
        subject,
        client_id,
        scopes,
        actor,
        act_depth,
        grant_id,
        checked_at,
    })
}
