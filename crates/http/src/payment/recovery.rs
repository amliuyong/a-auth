//! Execution recovery from the persisted attempt.
//!
//! Recovery never needs the user's token and never creates a new attempt or
//! idempotency key. It first asks the channel about the persisted key. Only an
//! authoritative "no such transaction" inside the channel's idempotency
//! retention window allows resubmission, with that same key; outside the
//! window the attempt is flagged for manual reconciliation.

use agent_auth_payment::{Applied, ChannelOutcome, EvidenceSource, PaymentIntent, PaymentStatus};

use super::adapter::{QueryResult, SubmitRequest};
use super::store::{CasGuard, PaymentStore};
use super::{PaymentError, PaymentModule};

const CAS_ATTEMPTS: usize = 4;

pub(crate) fn submit_request(intent: &PaymentIntent) -> Option<SubmitRequest> {
    let attempt = intent.attempt.as_ref()?;
    Some(SubmitRequest {
        idempotency_key: attempt.idempotency_key.clone(),
        reference: intent.intent_id.clone(),
        amount_minor: intent.terms.amount_minor.clone(),
        currency: intent.terms.currency.clone(),
        payee_id: intent.terms.payee.id.clone(),
        funding_source_id: intent.terms.funding_source.id.clone(),
    })
}

/// Persist `step(current, now)` with compare-and-set, re-reading and
/// re-deriving on contention so a concurrent callback or recovery is never
/// overwritten. `None` from `step` means there is nothing to write.
async fn update(
    module: &PaymentModule,
    tenant: &str,
    mut current: PaymentIntent,
    step: impl Fn(&PaymentIntent, i64) -> Option<PaymentIntent>,
) -> Result<PaymentIntent, PaymentError> {
    for _ in 0..CAS_ATTEMPTS {
        let Some(next) = step(&current, crate::token::current_unix_secs_pub()) else {
            return Ok(current);
        };
        match module
            .store
            .compare_and_set(tenant, CasGuard::of(&current), &next)
            .await
        {
            Ok(true) => return Ok(next),
            Ok(false) => current = module.load(tenant, &current.intent_id).await?,
            Err(_) => return Err(PaymentError::Unavailable("payment store unavailable")),
        }
    }
    Err(PaymentError::Unavailable(
        "payment record is changing; retry",
    ))
}

/// Apply one channel observation under the monotonic settlement rules.
pub(crate) async fn apply_outcome(
    module: &PaymentModule,
    tenant: &str,
    current: PaymentIntent,
    outcome: &ChannelOutcome,
    source: EvidenceSource,
) -> Result<PaymentIntent, PaymentError> {
    update(module, tenant, current, |intent, now| {
        match intent.apply_outcome(outcome, source, now) {
            Applied::Changed(next) => Some(*next),
            Applied::Unchanged => None,
        }
    })
    .await
}

/// Submit the persisted attempt with its own idempotency key and record the answer.
pub(crate) async fn submit(
    module: &PaymentModule,
    tenant: &str,
    intent: PaymentIntent,
) -> Result<PaymentIntent, PaymentError> {
    let Some(request) = submit_request(&intent) else {
        return Ok(intent);
    };
    let outcome = module.adapter.submit(&request).await;
    apply_outcome(module, tenant, intent, &outcome, EvidenceSource::Submit).await
}

/// Reconcile one intent's unsettled attempt against the channel.
pub async fn reconcile_intent(
    module: &PaymentModule,
    tenant: &str,
    intent_id: &str,
) -> Result<PaymentIntent, PaymentError> {
    let intent = module.load(tenant, intent_id).await?;
    if !intent.status.is_unsettled() {
        return Ok(intent);
    }
    let Some(attempt) = intent.attempt.clone() else {
        return Ok(intent);
    };
    match module.adapter.query(&attempt.idempotency_key).await {
        QueryResult::Found(report) => {
            apply_outcome(
                module,
                tenant,
                intent,
                &ChannelOutcome::Reported(report),
                EvidenceSource::Query,
            )
            .await
        }
        // Asking failed: nothing is learned, and nothing is resubmitted.
        QueryResult::Indeterminate => Ok(intent),
        QueryResult::NotFound => {
            let now = crate::token::current_unix_secs_pub();
            if now < attempt.idempotency_expires_at {
                submit(module, tenant, intent).await
            } else {
                update(module, tenant, intent, |intent, now| {
                    intent.flag_for_review("reconcile", now)
                })
                .await
            }
        }
    }
}

/// Internal recovery pass over a tenant's unsettled attempts, oldest first.
///
/// Each attempt is reconciled independently: a failure is reported in its
/// slot and never stops recovery of the others. `Err` only when the
/// unsettled attempts cannot be listed.
pub async fn reconcile_unsettled(
    module: &PaymentModule,
    tenant: &str,
    limit: usize,
) -> Result<Vec<Result<PaymentIntent, PaymentError>>, PaymentError> {
    let pending = module
        .store
        .list_unsettled(tenant, limit)
        .await
        .map_err(|_| PaymentError::Unavailable("payment store unavailable"))?;
    let mut reconciled = Vec::with_capacity(pending.len());
    for intent in pending {
        reconciled.push(reconcile_intent(module, tenant, &intent.intent_id).await);
    }
    Ok(reconciled)
}

/// Persist the deadline of a prepared intent that was never accepted.
pub(crate) async fn expire_if_due(
    module: &PaymentModule,
    tenant: &str,
    intent: PaymentIntent,
) -> Result<PaymentIntent, PaymentError> {
    let now = crate::token::current_unix_secs_pub();
    if intent.status != PaymentStatus::Prepared
        || intent.effective_status(now) != PaymentStatus::Expired
    {
        return Ok(intent);
    }
    update(module, tenant, intent, |intent, now| {
        intent.close_unaccepted(PaymentStatus::Expired, "deadline", now)
    })
    .await
}
