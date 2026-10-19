//! The controlled internal interface a-auth uses to admit, display and bind a
//! payment authorization request.
//!
//! The browser-visible request only names an intent. Amount, payee, funding
//! source, actor and deadline are read here from the payment module and the
//! trusted registry, so consent displays and stores exactly the frozen terms.

use agent_auth_payment::{FundingSourceRef, PayeeRef, PaymentIntent, PaymentStatus};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use super::registry::PaymentRegistry;
use super::store::PaymentStore;
use crate::state::AppState;

/// Registry-backed funding source displayed on the consent page.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaymentFundingSourceView {
    pub id: String,
    pub version: u64,
    /// Masked registry label.
    pub label: String,
}

/// Registry-backed payee displayed on the consent page.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaymentPayeeView {
    pub id: String,
    pub version: u64,
    pub name: String,
}

impl From<&FundingSourceRef> for PaymentFundingSourceView {
    fn from(source: &FundingSourceRef) -> Self {
        Self {
            id: source.id.clone(),
            version: source.version,
            label: source.label.clone(),
        }
    }
}

impl From<&PayeeRef> for PaymentPayeeView {
    fn from(payee: &PayeeRef) -> Self {
        Self {
            id: payee.id.clone(),
            version: payee.version,
            name: payee.name.clone(),
        }
    }
}

/// The exact single payment the user is asked to approve.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaymentConsentView {
    pub intent_id: String,
    /// Digest the approval must acknowledge (`payment_terms_digest`).
    pub terms_digest: String,
    pub order_id: String,
    /// Total in minor units (decimal string, never a float).
    pub amount_minor: String,
    pub currency: String,
    pub currency_exponent: u8,
    pub funding_source: PaymentFundingSourceView,
    pub payee: PaymentPayeeView,
    /// The only workload that may execute this payment.
    pub actor: String,
    /// Latest first-acceptance instant (Unix seconds).
    pub execute_before: i64,
    pub resource: String,
}

/// A payment request admitted against its frozen intent.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedPayment {
    /// Canonical `agent_auth_payment_v1` detail stored in the code and Grant.
    pub detail: Value,
    pub view: PaymentConsentView,
}

fn invalid(description: &'static str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        format!("invalid_authorization_details: {description}"),
    )
        .into_response()
}

fn unavailable() -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable: payment authority unavailable",
    )
        .into_response()
}

/// Admit a payment-typed `authorization_details` request.
///
/// `Ok(None)` when no entry has the payment type. Otherwise the request must be
/// exactly one reference to a prepared, unexpired intent of this tenant,
/// client, workload actor and payment resource, whose registry versions are
/// still current. When `user_id` is known it must be the intent's payer.
pub(crate) async fn admit(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    workload_actor: Option<&str>,
    resources: &[String],
    authorization_details: &Value,
    user_id: Option<&str>,
) -> Result<Option<AdmittedPayment>, axum::response::Response> {
    if !agent_auth_payment::contains_payment_detail(authorization_details) {
        return Ok(None);
    }
    let Some(module) = state.payments.as_deref() else {
        return Err(invalid("payment authorization is not enabled"));
    };
    if !state.phase.at_least(crate::Phase::P2) {
        return Err(invalid("payment authorization requires P2"));
    }
    let resource = module.config.resource.as_str();
    let intent_id = match agent_auth_payment::request_reference(authorization_details, resource) {
        Ok(Some(intent_id)) => intent_id,
        Ok(None) | Err(_) => {
            return Err(invalid(
                "payment authorization must be exactly one intent reference",
            ))
        }
    };
    let Some(actor) = workload_actor else {
        return Err(invalid("payment authorization requires workload_actor"));
    };
    if resources.len() != 1 || resources[0] != resource {
        return Err(invalid(
            "payment authorization requires the payment resource only",
        ));
    }
    let now = crate::token::current_unix_secs_pub();
    let intent = match module.store.get(tenant, &intent_id).await {
        Ok(Some(intent)) => intent,
        Ok(None) => return Err(invalid("unknown payment intent")),
        Err(_) => return Err(unavailable()),
    };
    let terms = &intent.terms;
    if !intent.is_intact()
        || intent.effective_status(now) != PaymentStatus::Prepared
        || terms.tenant != super::logical_tenant(tenant)
        || terms.client_id != client_id
        || terms.actor != actor
        || terms.resource != resource
    {
        return Err(invalid("payment intent is not awaiting this authorization"));
    }
    match registry_terms_are_current(module, tenant, &intent).await {
        Ok(true) => {}
        Ok(false) => return Err(invalid("payment terms are no longer current")),
        Err(()) => return Err(unavailable()),
    }
    if let Some(user_id) = user_id {
        if payer_subject(state, tenant, user_id, resource) != terms.payer {
            return Err((
                StatusCode::FORBIDDEN,
                "access_denied: payment intent belongs to another payer",
            )
                .into_response());
        }
    }
    let detail = agent_auth_payment::canonical_detail(&intent.intent_id, terms);
    let view = PaymentConsentView {
        intent_id: intent.intent_id.clone(),
        terms_digest: intent.terms_digest.clone(),
        order_id: terms.order_id.clone(),
        amount_minor: terms.amount_minor.clone(),
        currency: terms.currency.clone(),
        currency_exponent: terms.currency_exponent,
        funding_source: (&terms.funding_source).into(),
        payee: (&terms.payee).into(),
        actor: terms.actor.clone(),
        execute_before: terms.execute_before,
        resource: terms.resource.clone(),
    };
    Ok(Some(AdmittedPayment { detail, view }))
}

/// The payer subject a token for `resource` carries for `user_id`.
pub(crate) fn payer_subject(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    resource: &str,
) -> String {
    agent_auth_token::derive_user_sub(
        crate::token::subject_mode(state.subject_type_for_tenant(tenant)),
        &state.server_secret,
        user_id,
        resource,
    )
}

/// True when the frozen funding source and payee are still the registry's
/// current, active versions and the payer still owns the funding source.
pub(crate) async fn registry_terms_are_current(
    module: &super::PaymentModule,
    tenant: &str,
    intent: &PaymentIntent,
) -> Result<bool, ()> {
    let terms = &intent.terms;
    let source = module
        .registry
        .funding_source(tenant, &terms.funding_source.id)
        .await
        .map_err(|_| ())?;
    let payee = module
        .registry
        .payee(tenant, &terms.payee.id)
        .await
        .map_err(|_| ())?;
    Ok(source.is_some_and(|source| {
        source.active
            && source.owner == terms.payer
            && source.version == terms.funding_source.version
            && source.label == terms.funding_source.label
            && source.currency == terms.currency
    }) && payee.is_some_and(|payee| {
        payee.active && payee.version == terms.payee.version && payee.name == terms.payee.name
    }))
}
