//! `/payments` routes of the payment resource server.
//!
//! - `POST /payments/intents` — freeze one payment (`payments:prepare`, the
//!   3LO client's own user token). Identity comes only from the token.
//! - `GET /payments/intents/{intent_id}` — status for the payer's client or
//!   the designated actor.
//! - `POST /payments/intents/{intent_id}/cancel` — payer cancels a prepared intent.
//! - `POST /payments/intents/{intent_id}/execute` — the designated actor
//!   executes with a delegated `payments:execute` token carrying the exact
//!   `agent_auth_payment_v1` detail.
//! - `POST /payments/intents/{intent_id}/reconcile` — recover the persisted
//!   attempt against the channel (query rights only; never a new attempt).
//! - `POST /payments/channel/callback` — authenticated channel callback.

use agent_auth_payment::{
    ChannelOutcome, EvidenceSource, FundingSourceRef, PayeeRef, PaymentIntent, PaymentStatus,
    PaymentTerms,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::authority::{authenticate, Caller};
use super::consent::{PaymentFundingSourceView, PaymentPayeeView};
use super::registry::PaymentRegistry;
use super::store::{CasGuard, CreateOutcome, PaymentStore};
use super::PaymentModule;
use crate::ports::ClientStore;
use crate::state::AppState;

/// Payment resource errors (`{"error", "error_description"}`, never cached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    NotFound,
    InvalidRequest(&'static str),
    InvalidToken(&'static str),
    InsufficientScope(&'static str),
    Forbidden(&'static str),
    Conflict(&'static str),
    Unavailable(&'static str),
}

impl IntoResponse for PaymentError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "payment intent not found",
            ),
            Self::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d),
            Self::InvalidToken(d) => (StatusCode::UNAUTHORIZED, "invalid_token", d),
            Self::InsufficientScope(d) => (StatusCode::FORBIDDEN, "insufficient_scope", d),
            Self::Forbidden(d) => (StatusCode::FORBIDDEN, "access_denied", d),
            Self::Conflict(d) => (StatusCode::CONFLICT, "conflict", d),
            Self::Unavailable(d) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                d,
            ),
        };
        let mut response = (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": error, "error_description": description})),
        )
            .into_response();
        match status {
            StatusCode::UNAUTHORIZED => {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
            StatusCode::FORBIDDEN if error == "insufficient_scope" => {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
                );
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            _ => {}
        }
        response
    }
}

/// Intent preparation request. Payer, tenant and client come from the token.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    /// Business order identifier (unique per tenant and payee).
    pub order_id: String,
    /// Registered workload client that alone may execute.
    pub actor: String,
    pub funding_source_id: String,
    pub payee_id: String,
    /// Total in minor units: a decimal string, never a JSON number.
    pub amount_minor: String,
    pub currency: String,
    /// Latest first-acceptance instant (Unix seconds).
    pub execute_before: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatusView {
    Prepared,
    Accepted,
    Pending,
    Unknown,
    Succeeded,
    Failed,
    Expired,
    Cancelled,
}

impl From<PaymentStatus> for PaymentStatusView {
    fn from(status: PaymentStatus) -> Self {
        match status {
            PaymentStatus::Prepared => Self::Prepared,
            PaymentStatus::Accepted => Self::Accepted,
            PaymentStatus::Pending => Self::Pending,
            PaymentStatus::Unknown => Self::Unknown,
            PaymentStatus::Succeeded => Self::Succeeded,
            PaymentStatus::Failed => Self::Failed,
            PaymentStatus::Expired => Self::Expired,
            PaymentStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// The single execution attempt (no idempotency key or token material).
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentAttemptView {
    pub attempt_id: String,
    pub accepted_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_channel_check_at: Option<i64>,
    /// Contradictory channel evidence or an expired idempotency window.
    pub needs_review: bool,
}

/// A frozen payment intent and its execution status.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentIntentView {
    pub intent_id: String,
    pub status: PaymentStatusView,
    pub order_id: String,
    pub amount_minor: String,
    pub currency: String,
    pub currency_exponent: u8,
    pub funding_source: PaymentFundingSourceView,
    pub payee: PaymentPayeeView,
    pub client_id: String,
    pub actor: String,
    pub resource: String,
    pub execute_before: i64,
    pub terms_digest: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// The `authorization_details` value to send to `/authorize` for this intent.
    #[schema(value_type = Vec<Object>)]
    pub authorization_details: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt: Option<PaymentAttemptView>,
}

impl PaymentIntentView {
    pub(crate) fn of(intent: &PaymentIntent, now: i64) -> Self {
        let terms = &intent.terms;
        Self {
            intent_id: intent.intent_id.clone(),
            status: intent.effective_status(now).into(),
            order_id: terms.order_id.clone(),
            amount_minor: terms.amount_minor.clone(),
            currency: terms.currency.clone(),
            currency_exponent: terms.currency_exponent,
            funding_source: PaymentFundingSourceView {
                id: terms.funding_source.id.clone(),
                version: terms.funding_source.version,
                label: terms.funding_source.label.clone(),
            },
            payee: PaymentPayeeView {
                id: terms.payee.id.clone(),
                version: terms.payee.version,
                name: terms.payee.name.clone(),
            },
            client_id: terms.client_id.clone(),
            actor: terms.actor.clone(),
            resource: terms.resource.clone(),
            execute_before: terms.execute_before,
            terms_digest: intent.terms_digest.clone(),
            created_at: intent.created_at,
            updated_at: intent.updated_at,
            authorization_details: json!([{
                "type": agent_auth_payment::PAYMENT_RAR_TYPE,
                "intent_id": intent.intent_id,
                "locations": [terms.resource],
                "actions": [agent_auth_payment::EXECUTE_ACTION],
            }]),
            attempt: intent.attempt.as_ref().map(|attempt| PaymentAttemptView {
                attempt_id: attempt.attempt_id.clone(),
                accepted_at: attempt.accepted_at,
                channel_transaction_id: attempt.channel_transaction_id.clone(),
                last_channel_check_at: attempt.last_channel_check_at,
                needs_review: attempt.needs_review,
            }),
        }
    }
}

/// Acknowledgement of an authenticated channel callback.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentCallbackResult {
    pub intent_id: String,
    pub status: PaymentStatusView,
}

fn ok(status: StatusCode, intent: &PaymentIntent) -> Response {
    let now = crate::token::current_unix_secs_pub();
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(PaymentIntentView::of(intent, now)),
    )
        .into_response()
}

fn module(state: &AppState) -> Result<&PaymentModule, PaymentError> {
    state.payments.as_deref().ok_or(PaymentError::NotFound)
}

fn tenant(state: &AppState, headers: &HeaderMap) -> Result<String, PaymentError> {
    crate::tenant::tenant_or_400(state, headers)
        .map_err(|_| PaymentError::InvalidRequest("invalid host"))
}

async fn load(
    module: &PaymentModule,
    tenant: &str,
    intent_id: &str,
) -> Result<PaymentIntent, PaymentError> {
    match module.store.get(tenant, intent_id).await {
        Ok(Some(intent)) => Ok(intent),
        Ok(None) => Err(PaymentError::NotFound),
        Err(_) => Err(PaymentError::Unavailable("payment store unavailable")),
    }
}

/// The payer's own (non-delegated) client token.
fn require_payer_client(caller: &Caller, intent: &PaymentIntent) -> Result<(), PaymentError> {
    if caller.act_depth != 0
        || caller.subject != intent.terms.payer
        || caller.client_id != intent.terms.client_id
    {
        return Err(PaymentError::NotFound);
    }
    Ok(())
}

/// Read rights: the payer's client, or the designated actor for that payer.
fn require_reader(caller: &Caller, intent: &PaymentIntent) -> Result<(), PaymentError> {
    let terms = &intent.terms;
    let party = caller.subject == terms.payer
        && match caller.act_depth {
            0 => caller.client_id == terms.client_id,
            1 => caller.actor.as_deref() == Some(terms.actor.as_str()),
            _ => false,
        };
    if !party {
        return Err(PaymentError::NotFound);
    }
    if !caller.has_scope(agent_auth_payment::SCOPE_PREPARE)
        && !caller.has_scope(agent_auth_payment::SCOPE_EXECUTE)
    {
        return Err(PaymentError::InsufficientScope(
            "payments:prepare or payments:execute is required",
        ));
    }
    Ok(())
}

fn new_intent_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("pi_{}", URL_SAFE_NO_PAD.encode(bytes))
}

async fn prepare(
    state: &AppState,
    module: &PaymentModule,
    tenant: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(StatusCode, PaymentIntent), PaymentError> {
    let caller = authenticate(state, module, tenant, headers).await?;
    if caller.act_depth != 0 {
        return Err(PaymentError::Forbidden(
            "preparation requires the payer's own client token",
        ));
    }
    if !caller.has_scope(agent_auth_payment::SCOPE_PREPARE) {
        return Err(PaymentError::InsufficientScope(
            "payments:prepare is required",
        ));
    }
    let request: PrepareRequest = serde_json::from_slice(body)
        .map_err(|_| PaymentError::InvalidRequest("malformed preparation request"))?;
    let config = &module.config;
    if request.currency != config.currency {
        return Err(PaymentError::InvalidRequest("unsupported currency"));
    }
    match agent_auth_payment::terms::parse_amount_minor(&request.amount_minor) {
        Some(amount) if amount <= config.max_amount_minor => {}
        _ => return Err(PaymentError::InvalidRequest("invalid amount_minor")),
    }
    let now = crate::token::current_unix_secs_pub();
    if request.execute_before <= now
        || request.execute_before > now.saturating_add(config.max_execute_window_secs)
    {
        return Err(PaymentError::InvalidRequest(
            "execute_before is outside the allowed window",
        ));
    }
    match state.clients.get(tenant, &request.actor).await {
        Ok(Some(client)) if client.is_workload() && !client.is_tombstoned() => {}
        Ok(_) => {
            return Err(PaymentError::InvalidRequest(
                "actor must be an active registered workload",
            ))
        }
        Err(_) => return Err(PaymentError::Unavailable("client registry unavailable")),
    }
    let source = module
        .registry
        .funding_source(tenant, &request.funding_source_id)
        .await
        .map_err(|_| PaymentError::Unavailable("payment registry unavailable"))?
        .filter(|source| {
            source.active && source.owner == caller.subject && source.currency == config.currency
        })
        .ok_or(PaymentError::Forbidden(
            "funding source is not available to this payer",
        ))?;
    let payee = module
        .registry
        .payee(tenant, &request.payee_id)
        .await
        .map_err(|_| PaymentError::Unavailable("payment registry unavailable"))?
        .filter(|payee| payee.active)
        .ok_or(PaymentError::InvalidRequest("unknown payee"))?;
    let terms = PaymentTerms {
        tenant: super::logical_tenant(tenant).to_string(),
        payer: caller.subject.clone(),
        client_id: caller.client_id.clone(),
        actor: request.actor,
        resource: config.resource.clone(),
        order_id: request.order_id,
        funding_source: FundingSourceRef {
            id: source.funding_source_id,
            version: source.version,
            label: source.label,
        },
        payee: PayeeRef {
            id: payee.payee_id,
            version: payee.version,
            name: payee.name,
        },
        amount_minor: request.amount_minor,
        currency: request.currency,
        currency_exponent: config.currency_exponent,
        execute_before: request.execute_before,
    };
    terms
        .validate()
        .map_err(|_| PaymentError::InvalidRequest("invalid payment terms"))?;
    let intent = PaymentIntent::prepared(new_intent_id(), terms, now);
    let existing_id = match module.store.create(tenant, &intent, None).await {
        Ok(CreateOutcome::Created) => return Ok((StatusCode::CREATED, intent)),
        Ok(CreateOutcome::OrderTaken(existing)) => existing,
        Err(_) => return Err(PaymentError::Unavailable("payment store unavailable")),
    };
    let existing = load(module, tenant, &existing_id).await?;
    let existing = super::recovery::expire_if_due(module, tenant, existing).await?;
    if existing.terms == intent.terms {
        return Ok((StatusCode::OK, existing));
    }
    let replaceable = existing.attempt.is_none()
        && matches!(
            existing.status,
            PaymentStatus::Expired | PaymentStatus::Cancelled
        );
    if replaceable {
        if let Ok(CreateOutcome::Created) = module
            .store
            .create(tenant, &intent, Some(&existing.intent_id))
            .await
        {
            return Ok((StatusCode::CREATED, intent));
        }
    }
    Err(PaymentError::Conflict(
        "this order already has a different payment intent",
    ))
}

/// `POST /payments/intents`.
#[utoipa::path(
    post, path = "/payments/intents", tag = "payments",
    request_body = PrepareRequest,
    responses(
        (status = 201, description = "Intent frozen", body = PaymentIntentView),
        (status = 200, description = "Identical intent already exists for this order", body = PaymentIntentView),
        (status = 400, description = "Malformed request, identity field, unsupported amount/currency/deadline, unknown payee or inactive actor"),
        (status = 401, description = "Missing or inactive token"),
        (status = 403, description = "Missing payments:prepare, delegated token, or funding source not owned by the payer"),
        (status = 404, description = "Payment resource not enabled"),
        (status = 409, description = "The order already has a different intent"),
        (status = 503, description = "Authorization, registry or payment store unavailable")
    )
)]
pub async fn prepare_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let module = match module(&state) {
        Ok(module) => module,
        Err(error) => return error.into_response(),
    };
    let tenant = match tenant(&state, &headers) {
        Ok(tenant) => tenant,
        Err(error) => return error.into_response(),
    };
    match prepare(&state, module, &tenant, &headers, &body).await {
        Ok((status, intent)) => ok(status, &intent),
        Err(error) => error.into_response(),
    }
}

/// `GET /payments/intents/{intent_id}`.
#[utoipa::path(
    get, path = "/payments/intents/{intent_id}", tag = "payments",
    params(("intent_id" = String, Path, description = "Payment intent identifier")),
    responses(
        (status = 200, description = "Current intent status", body = PaymentIntentView),
        (status = 401, description = "Missing or inactive token"),
        (status = 403, description = "Missing payment scope"),
        (status = 404, description = "Unknown intent, not a party of the intent, or payment resource not enabled"),
        (status = 503, description = "Authorization or payment store unavailable")
    )
)]
pub async fn get_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
) -> Response {
    let result = async {
        let module = module(&state)?;
        let tenant = tenant(&state, &headers)?;
        let caller = authenticate(&state, module, &tenant, &headers).await?;
        let intent = load(module, &tenant, &intent_id).await?;
        require_reader(&caller, &intent)?;
        super::recovery::expire_if_due(module, &tenant, intent).await
    }
    .await;
    match result {
        Ok(intent) => ok(StatusCode::OK, &intent),
        Err(error) => error.into_response(),
    }
}

/// `POST /payments/intents/{intent_id}/cancel`.
#[utoipa::path(
    post, path = "/payments/intents/{intent_id}/cancel", tag = "payments",
    params(("intent_id" = String, Path, description = "Payment intent identifier")),
    responses(
        (status = 200, description = "Intent cancelled", body = PaymentIntentView),
        (status = 401, description = "Missing or inactive token"),
        (status = 403, description = "Missing payments:prepare"),
        (status = 404, description = "Unknown intent or not the payer's client"),
        (status = 409, description = "Intent was already accepted, expired or cancelled"),
        (status = 503, description = "Authorization or payment store unavailable")
    )
)]
pub async fn cancel_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
) -> Response {
    let result = async {
        let module = module(&state)?;
        let tenant = tenant(&state, &headers)?;
        let caller = authenticate(&state, module, &tenant, &headers).await?;
        let intent = load(module, &tenant, &intent_id).await?;
        require_payer_client(&caller, &intent)?;
        if !caller.has_scope(agent_auth_payment::SCOPE_PREPARE) {
            return Err(PaymentError::InsufficientScope(
                "payments:prepare is required",
            ));
        }
        let now = crate::token::current_unix_secs_pub();
        let Some(next) = intent.close_unaccepted(PaymentStatus::Cancelled, "cancel", now) else {
            return Err(PaymentError::Conflict(
                "payment intent can no longer be cancelled",
            ));
        };
        match module
            .store
            .compare_and_set(&tenant, CasGuard::of(&intent), &next)
            .await
        {
            Ok(true) => Ok(next),
            Ok(false) => Err(PaymentError::Conflict("payment intent changed; retry")),
            Err(_) => Err(PaymentError::Unavailable("payment store unavailable")),
        }
    }
    .await;
    match result {
        Ok(intent) => ok(StatusCode::OK, &intent),
        Err(error) => error.into_response(),
    }
}

/// `POST /payments/intents/{intent_id}/execute`.
#[utoipa::path(
    post, path = "/payments/intents/{intent_id}/execute", tag = "payments",
    params(("intent_id" = String, Path, description = "Payment intent identifier")),
    responses(
        (status = 200, description = "The single attempt's current status (a repeated call returns the same attempt)", body = PaymentIntentView),
        (status = 401, description = "Missing, inactive or sender-constrained token"),
        (status = 403, description = "Not the designated actor, payer, client or exact payment authorization; missing payments:execute or strong assurance"),
        (status = 404, description = "Unknown intent or payment resource not enabled"),
        (status = 409, description = "Intent expired, cancelled, or its registry terms changed"),
        (status = 503, description = "Online authorization check, registry or acceptance write unavailable; no new attempt was started")
    )
)]
pub async fn execute_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
) -> Response {
    let result = async {
        let module = module(&state)?;
        let tenant = tenant(&state, &headers)?;
        super::execute::execute(&state, module, &tenant, &headers, &intent_id).await
    }
    .await;
    match result {
        Ok(intent) => ok(StatusCode::OK, &intent),
        Err(error) => error.into_response(),
    }
}

/// `POST /payments/intents/{intent_id}/reconcile`.
#[utoipa::path(
    post, path = "/payments/intents/{intent_id}/reconcile", tag = "payments",
    params(("intent_id" = String, Path, description = "Payment intent identifier")),
    responses(
        (status = 200, description = "Status after reconciling the persisted attempt", body = PaymentIntentView),
        (status = 401, description = "Missing or inactive token"),
        (status = 403, description = "Missing payment scope"),
        (status = 404, description = "Unknown intent, not a party of the intent, or payment resource not enabled"),
        (status = 503, description = "Authorization, channel or payment store unavailable")
    )
)]
pub async fn reconcile_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
) -> Response {
    let result = async {
        let module = module(&state)?;
        let tenant = tenant(&state, &headers)?;
        let caller = authenticate(&state, module, &tenant, &headers).await?;
        let intent = load(module, &tenant, &intent_id).await?;
        require_reader(&caller, &intent)?;
        super::recovery::reconcile_intent(module, &tenant, &intent_id).await
    }
    .await;
    match result {
        Ok(intent) => ok(StatusCode::OK, &intent),
        Err(error) => error.into_response(),
    }
}

/// `POST /payments/channel/callback`.
#[utoipa::path(
    post, path = "/payments/channel/callback", tag = "payments",
    request_body(content = super::adapter::PaymentChannelCallback, content_type = "application/json"),
    params(("x-payment-signature" = String, Header, description = "Channel callback signature")),
    responses(
        (status = 200, description = "Callback verified and reconciled against the persisted attempt", body = PaymentCallbackResult),
        (status = 400, description = "Malformed callback or unknown attempt key"),
        (status = 401, description = "Invalid callback signature"),
        (status = 404, description = "Unknown intent or payment resource not enabled"),
        (status = 503, description = "Payment store unavailable")
    )
)]
pub async fn callback_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        let module = module(&state)?;
        let tenant = tenant(&state, &headers)?;
        let signature = headers
            .get("x-payment-signature")
            .and_then(|value| value.to_str().ok());
        let event =
            module
                .adapter
                .verify_callback(signature, &body)
                .map_err(|error| match error {
                    super::adapter::CallbackError::BadSignature => {
                        PaymentError::InvalidToken("invalid callback signature")
                    }
                    super::adapter::CallbackError::Malformed => {
                        PaymentError::InvalidRequest("malformed callback")
                    }
                })?;
        let intent = load(module, &tenant, &event.reference).await?;
        if intent
            .attempt
            .as_ref()
            .is_none_or(|attempt| attempt.idempotency_key != event.idempotency_key)
        {
            return Err(PaymentError::InvalidRequest(
                "callback does not match the persisted attempt",
            ));
        }
        super::recovery::apply_outcome(
            module,
            &tenant,
            intent,
            &ChannelOutcome::Reported(event.report),
            EvidenceSource::Callback,
        )
        .await
    }
    .await;
    match result {
        Ok(intent) => {
            let now = crate::token::current_unix_secs_pub();
            (
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-store")],
                Json(PaymentCallbackResult {
                    intent_id: intent.intent_id.clone(),
                    status: intent.effective_status(now).into(),
                }),
            )
                .into_response()
        }
        Err(error) => error.into_response(),
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(prepare_handler))
        .routes(routes!(get_handler))
        .routes(routes!(cancel_handler))
        .routes(routes!(execute_handler))
        .routes(routes!(reconcile_handler))
        .routes(routes!(callback_handler))
}
