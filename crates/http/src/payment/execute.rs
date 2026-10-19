//! `execute(intent_id)`: verify the exact approved authorization online, then
//! accept the single attempt with a conditional write before any channel call.
//!
//! The caller supplies no amount, payee or funding source. A repeated or
//! concurrent execute with a valid authorization returns the existing record;
//! it never derives a new idempotency key or calls the channel again.

use agent_auth_authn::assurance::STRONG_ACR;
use agent_auth_payment::{AuthorizationEvidence, Expectation, PaymentIntent, PaymentStatus};
use axum::http::HeaderMap;
use serde_json::Value;

use super::authority::{authenticate, Caller};
use super::store::{CasGuard, PaymentStore};
use super::PaymentError;
use super::PaymentModule;
use crate::ports::GrantStore;
use crate::state::AppState;

/// Every authorization fact that must hold for this caller to execute `intent`.
async fn authorize(
    state: &AppState,
    tenant: &str,
    caller: &Caller,
    intent: &PaymentIntent,
) -> Result<String, PaymentError> {
    let terms = &intent.terms;
    if caller.act_depth != 1 || caller.actor.as_deref() != Some(terms.actor.as_str()) {
        return Err(PaymentError::Forbidden(
            "only the designated workload may execute, through one delegation hop",
        ));
    }
    if caller.subject != terms.payer {
        return Err(PaymentError::Forbidden("token subject is not the payer"));
    }
    if !caller.has_scope(agent_auth_payment::SCOPE_EXECUTE) {
        return Err(PaymentError::InsufficientScope(
            "payments:execute is required",
        ));
    }
    if caller.claims.get("acr").and_then(Value::as_str) != Some(STRONG_ACR) {
        return Err(PaymentError::Forbidden(
            "payment authorization requires strong assurance",
        ));
    }
    let Some(grant_id) = caller.grant_id.as_deref() else {
        return Err(PaymentError::Forbidden("token is not backed by a Grant"));
    };
    let grant = match state.grants.get(tenant, grant_id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => return Err(PaymentError::InvalidToken("Grant no longer exists")),
        Err(_) => {
            return Err(PaymentError::Unavailable(
                "authorization authority unavailable",
            ))
        }
    };
    if grant.client_id != terms.client_id
        || grant.constraints.actor_allowlist != [terms.actor.clone()]
        || grant.constraints.max_act_chain != 1
    {
        return Err(PaymentError::Forbidden(
            "Grant does not authorize this client and actor",
        ));
    }
    let expected = Expectation {
        resource: &terms.resource,
        intent_id: &intent.intent_id,
        terms,
        terms_digest: &intent.terms_digest,
    };
    agent_auth_payment::verify_execution(caller.claims.get("authorization_details"), &expected)
        .map_err(|_| {
            PaymentError::Forbidden("authorization_details do not authorize this exact payment")
        })?;
    Ok(grant_id.to_string())
}

/// Execute the intent for an online-verified caller.
pub(crate) async fn execute(
    state: &AppState,
    module: &PaymentModule,
    tenant: &str,
    headers: &HeaderMap,
    intent_id: &str,
) -> Result<PaymentIntent, PaymentError> {
    let caller = authenticate(state, module, tenant, headers).await?;
    let intent = module.load(tenant, intent_id).await?;
    if !intent.is_intact() || intent.terms.resource != module.config.resource {
        return Err(PaymentError::Conflict(
            "payment intent failed its integrity check",
        ));
    }
    let grant_id = authorize(state, tenant, &caller, &intent).await?;
    if intent.attempt.is_some() {
        return Ok(intent);
    }
    let intent = super::recovery::expire_if_due(module, tenant, intent).await?;
    match intent.status {
        PaymentStatus::Prepared => {}
        _ if intent.attempt.is_some() => return Ok(intent),
        _ => {
            return Err(PaymentError::Conflict(
                "payment intent can no longer be executed",
            ))
        }
    }
    match super::consent::registry_terms_are_current(module, tenant, &intent).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(PaymentError::Conflict(
                "payment terms are no longer current",
            ))
        }
        Err(()) => return Err(PaymentError::Unavailable("payment registry unavailable")),
    }
    let now = crate::token::current_unix_secs_pub();
    let keys = agent_auth_payment::derive_attempt_keys(
        &state.server_secret,
        super::logical_tenant(tenant),
        &intent.intent_id,
    );
    let evidence = AuthorizationEvidence {
        grant_id,
        token_jti_sha256: caller.jti_sha256.clone(),
        actor: intent.terms.actor.clone(),
        client_id: intent.terms.client_id.clone(),
        acr: STRONG_ACR.to_string(),
        auth_time: caller.claims.get("auth_time").and_then(Value::as_i64),
        checked_at: caller.checked_at,
    };
    let Some(accepted) = intent.accept(
        keys,
        evidence,
        module.adapter.idempotency_retention_secs(),
        now,
    ) else {
        return Err(PaymentError::Conflict(
            "payment intent can no longer be executed",
        ));
    };
    match module
        .store
        .compare_and_set(tenant, CasGuard::accepting(&intent, now), &accepted)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Another request accepted first, or the deadline passed: report
            // the persisted record instead of attempting anything new.
            let current = module.load(tenant, intent_id).await?;
            return if current.attempt.is_some() {
                Ok(current)
            } else {
                Err(PaymentError::Conflict(
                    "payment intent can no longer be executed",
                ))
            };
        }
        Err(_) => {
            return Err(PaymentError::Unavailable(
                "acceptance outcome unknown; retrying returns the persisted attempt",
            ))
        }
    }
    super::recovery::submit(module, tenant, accepted).await
}
