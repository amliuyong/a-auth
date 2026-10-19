//! Intent, execution attempt and channel-result state machine.
//!
//! ```text
//! PREPARED --valid authorization + conditional acceptance--> ACCEPTED
//! PREPARED --deadline / payer cancellation--------------> EXPIRED / CANCELLED
//! ACCEPTED -----------------------------------------------> PENDING / UNKNOWN / SUCCEEDED / FAILED
//! PENDING / UNKNOWN --authoritative channel result--------> SUCCEEDED / FAILED
//! ```
//!
//! `PREPARED` only means the terms are frozen. Consent is a separate fact that
//! execution verifies online. Only an authoritative channel report can settle
//! an attempt; timeouts, lost responses, expiry and revocation never turn an
//! unknown result into `FAILED`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::terms::PaymentTerms;

/// Persisted lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    Prepared,
    Accepted,
    Pending,
    Unknown,
    Succeeded,
    Failed,
    Expired,
    Cancelled,
}

impl PaymentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Accepted => "ACCEPTED",
            Self::Pending => "PENDING",
            Self::Unknown => "UNKNOWN",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Expired => "EXPIRED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Prepared,
            Self::Accepted,
            Self::Pending,
            Self::Unknown,
            Self::Succeeded,
            Self::Failed,
            Self::Expired,
            Self::Cancelled,
        ]
        .into_iter()
        .find(|status| status.as_str() == value)
    }

    /// An execution attempt exists and has not reached a channel-final result.
    pub const fn is_unsettled(self) -> bool {
        matches!(self, Self::Accepted | Self::Pending | Self::Unknown)
    }

    /// No further transition can occur.
    pub const fn is_final(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Expired | Self::Cancelled
        )
    }
}

/// Authorization facts checked immediately before acceptance (no raw token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationEvidence {
    pub grant_id: String,
    /// `base64url(SHA-256(jti))` of the delegated access token.
    pub token_jti_sha256: String,
    pub actor: String,
    pub client_id: String,
    pub acr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// When the online authoritative check returned active.
    pub checked_at: i64,
}

/// A channel-authoritative transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    /// Received by the channel, not settled.
    Pending,
    /// Charged.
    Succeeded,
    /// Definitively not charged.
    Declined,
}

/// Where a channel observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Submit,
    Query,
    Callback,
}

/// One channel observation, kept for reconciliation and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelEvidence {
    pub at: i64,
    pub source: EvidenceSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ChannelState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_transaction_id: Option<String>,
    /// `applied`, `duplicate`, `stale`, `indeterminate`, `mismatch` or `conflict`.
    pub disposition: String,
}

/// A channel answer as reported by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelOutcome {
    /// The channel authoritatively reported this transaction.
    Reported(ChannelReport),
    /// No authoritative answer: timeout, connection loss or temporary error.
    Indeterminate,
}

/// Authoritative transaction facts reported by the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReport {
    pub channel_transaction_id: String,
    pub state: ChannelState,
    pub amount_minor: String,
    pub currency: String,
    pub payee_id: String,
}

/// The single execution attempt of an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttempt {
    pub attempt_id: String,
    pub idempotency_key: String,
    pub terms_digest: String,
    pub accepted_at: i64,
    /// Automatic resubmission with this key is allowed only before this instant.
    pub idempotency_expires_at: i64,
    pub authorization: AuthorizationEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_transaction_id: Option<String>,
    #[serde(default)]
    pub submissions: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_channel_check_at: Option<i64>,
    #[serde(default)]
    pub evidence: Vec<ChannelEvidence>,
    /// Contradictory evidence or an expired idempotency window needs an operator.
    #[serde(default)]
    pub needs_review: bool,
}

/// One persisted status change (audit trail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusChange {
    pub at: i64,
    pub from: PaymentStatus,
    pub to: PaymentStatus,
    pub source: String,
}

/// The immutable intent and its execution record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentIntent {
    pub intent_id: String,
    pub terms: PaymentTerms,
    pub terms_digest: String,
    pub status: PaymentStatus,
    /// Optimistic concurrency version; every write increments it.
    pub revision: u64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<ExecutionAttempt>,
    #[serde(default)]
    pub history: Vec<StatusChange>,
}

/// Deterministic identifiers of the only attempt an intent can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptKeys {
    pub attempt_id: String,
    pub idempotency_key: String,
}

/// Result of applying channel evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// A new record to persist with compare-and-set.
    Changed(Box<PaymentIntent>),
    /// Nothing to persist (duplicate or not applicable).
    Unchanged,
}

impl PaymentIntent {
    /// A newly prepared intent. Callers validate terms first.
    pub fn prepared(intent_id: String, terms: PaymentTerms, now: i64) -> Self {
        let terms_digest = terms.digest(&intent_id);
        Self {
            intent_id,
            terms,
            terms_digest,
            status: PaymentStatus::Prepared,
            revision: 1,
            created_at: now,
            updated_at: now,
            attempt: None,
            history: Vec::new(),
        }
    }

    /// Status as observed at `now`; a prepared intent past its deadline is expired.
    pub fn effective_status(&self, now: i64) -> PaymentStatus {
        if self.status == PaymentStatus::Prepared && now >= self.terms.execute_before {
            PaymentStatus::Expired
        } else {
            self.status
        }
    }

    /// True when the frozen digest still matches the frozen terms.
    pub fn is_intact(&self) -> bool {
        self.terms.digest(&self.intent_id) == self.terms_digest
    }

    fn next(&self, to: PaymentStatus, source: &str, now: i64) -> Self {
        let mut next = self.clone();
        if to != self.status {
            next.history.push(StatusChange {
                at: now,
                from: self.status,
                to,
                source: source.to_string(),
            });
        }
        next.status = to;
        next.revision = self.revision + 1;
        next.updated_at = now;
        next
    }

    /// PREPARED → ACCEPTED with the single attempt. `None` if not acceptable at `now`.
    pub fn accept(
        &self,
        keys: AttemptKeys,
        authorization: AuthorizationEvidence,
        idempotency_retention_secs: i64,
        now: i64,
    ) -> Option<Self> {
        if self.status != PaymentStatus::Prepared
            || now >= self.terms.execute_before
            || self.attempt.is_some()
        {
            return None;
        }
        let mut next = self.next(PaymentStatus::Accepted, "execute", now);
        next.attempt = Some(ExecutionAttempt {
            attempt_id: keys.attempt_id,
            idempotency_key: keys.idempotency_key,
            terms_digest: self.terms_digest.clone(),
            accepted_at: now,
            idempotency_expires_at: now.saturating_add(idempotency_retention_secs),
            authorization,
            channel_transaction_id: None,
            submissions: 0,
            last_channel_check_at: None,
            evidence: Vec::new(),
            needs_review: false,
        });
        Some(next)
    }

    /// PREPARED → CANCELLED (payer) or EXPIRED (deadline passed).
    pub fn close_unaccepted(&self, to: PaymentStatus, source: &str, now: i64) -> Option<Self> {
        let allowed = match to {
            PaymentStatus::Cancelled => now < self.terms.execute_before,
            PaymentStatus::Expired => now >= self.terms.execute_before,
            _ => false,
        };
        (self.status == PaymentStatus::Prepared && allowed).then(|| self.next(to, source, now))
    }

    /// Record that the adapter is about to submit with the persisted key.
    pub fn record_submission(&self, now: i64) -> Option<Self> {
        let attempt = self.attempt.as_ref()?;
        if !self.status.is_unsettled() {
            return None;
        }
        let mut next = self.next(self.status, "submit", now);
        let next_attempt = next.attempt.as_mut().expect("attempt");
        next_attempt.submissions = attempt.submissions.saturating_add(1);
        Some(next)
    }

    /// Mark the attempt for manual reconciliation without changing its status.
    pub fn flag_for_review(&self, source: &str, now: i64) -> Option<Self> {
        let attempt = self.attempt.as_ref()?;
        if attempt.needs_review {
            return None;
        }
        let mut next = self.next(self.status, source, now);
        next.attempt.as_mut().expect("attempt").needs_review = true;
        Some(next)
    }

    /// Apply one channel observation under the monotonic settlement rules.
    pub fn apply_outcome(
        &self,
        outcome: &ChannelOutcome,
        source: EvidenceSource,
        now: i64,
    ) -> Applied {
        let Some(attempt) = self.attempt.as_ref() else {
            return Applied::Unchanged;
        };
        let report = match outcome {
            ChannelOutcome::Indeterminate => {
                if self.status != PaymentStatus::Accepted {
                    // Pending stays pending and unknown stays unknown; a final
                    // result is never reopened by missing information.
                    return Applied::Unchanged;
                }
                let mut next = self.next(PaymentStatus::Unknown, source_name(source), now);
                push_evidence(&mut next, source, None, None, "indeterminate", now);
                return Applied::Changed(Box::new(next));
            }
            ChannelOutcome::Reported(report) => report,
        };
        let matches_terms = report.amount_minor == self.terms.amount_minor
            && report.currency == self.terms.currency
            && report.payee_id == self.terms.payee.id
            && attempt
                .channel_transaction_id
                .as_deref()
                .is_none_or(|known| known == report.channel_transaction_id);
        if !matches_terms {
            let mut next = self.next(self.status, source_name(source), now);
            push_evidence(
                &mut next,
                source,
                Some(report.state),
                Some(&report.channel_transaction_id),
                "mismatch",
                now,
            );
            next.attempt.as_mut().expect("attempt").needs_review = true;
            return Applied::Changed(Box::new(next));
        }
        let target = match report.state {
            ChannelState::Pending => PaymentStatus::Pending,
            ChannelState::Succeeded => PaymentStatus::Succeeded,
            ChannelState::Declined => PaymentStatus::Failed,
        };
        let disposition = match (self.status, target) {
            (from, to) if from == to => "duplicate",
            (PaymentStatus::Succeeded | PaymentStatus::Failed, PaymentStatus::Pending) => "stale",
            (PaymentStatus::Succeeded, PaymentStatus::Failed)
            | (PaymentStatus::Failed, PaymentStatus::Succeeded) => "conflict",
            (from, _) if from.is_unsettled() => "applied",
            _ => return Applied::Unchanged,
        };
        if disposition == "duplicate"
            && attempt.channel_transaction_id.as_deref()
                == Some(report.channel_transaction_id.as_str())
        {
            return Applied::Unchanged;
        }
        let to = if disposition == "applied" {
            target
        } else {
            self.status
        };
        let mut next = self.next(to, source_name(source), now);
        push_evidence(
            &mut next,
            source,
            Some(report.state),
            Some(&report.channel_transaction_id),
            disposition,
            now,
        );
        let next_attempt = next.attempt.as_mut().expect("attempt");
        if next_attempt.channel_transaction_id.is_none() {
            next_attempt.channel_transaction_id = Some(report.channel_transaction_id.clone());
        }
        if disposition == "conflict" {
            next_attempt.needs_review = true;
        }
        Applied::Changed(Box::new(next))
    }
}

fn source_name(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Submit => "submit",
        EvidenceSource::Query => "reconcile",
        EvidenceSource::Callback => "callback",
    }
}

fn push_evidence(
    intent: &mut PaymentIntent,
    source: EvidenceSource,
    state: Option<ChannelState>,
    channel_transaction_id: Option<&str>,
    disposition: &str,
    now: i64,
) {
    let attempt = intent.attempt.as_mut().expect("attempt");
    attempt.last_channel_check_at = Some(now);
    attempt.evidence.push(ChannelEvidence {
        at: now,
        source,
        state,
        channel_transaction_id: channel_transaction_id.map(str::to_string),
        disposition: disposition.to_string(),
    });
}

/// Deterministic attempt identifiers for `(tenant, intent_id)`.
///
/// Every acceptance attempt, retry and recovery derives the same values, so a
/// lost acceptance response cannot lead to a second idempotency key.
pub fn derive_attempt_keys(secret: &[u8], tenant: &str, intent_id: &str) -> AttemptKeys {
    AttemptKeys {
        attempt_id: format!(
            "pa_{}",
            keyed(secret, b"agent-auth:payment-attempt:v1", tenant, intent_id)
        ),
        idempotency_key: format!(
            "pk_{}",
            keyed(
                secret,
                b"agent-auth:payment-idempotency:v1",
                tenant,
                intent_id
            )
        ),
    }
}

fn keyed(secret: &[u8], domain: &[u8], tenant: &str, intent_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(domain);
    for part in [tenant, intent_id] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::tests::sample_terms;

    fn evidence() -> AuthorizationEvidence {
        AuthorizationEvidence {
            grant_id: "grant".into(),
            token_jti_sha256: "jti-hash".into(),
            actor: "pay-runtime".into(),
            client_id: "coveai".into(),
            acr: "urn:agent-auth:assurance:strong".into(),
            auth_time: Some(10),
            checked_at: 100,
        }
    }

    fn accepted() -> PaymentIntent {
        let intent = PaymentIntent::prepared("pi_one".into(), sample_terms(), 1);
        intent
            .accept(
                derive_attempt_keys(b"secret", "default", "pi_one"),
                evidence(),
                86_400,
                100,
            )
            .unwrap()
    }

    fn report(state: ChannelState) -> ChannelOutcome {
        let terms = sample_terms();
        ChannelOutcome::Reported(ChannelReport {
            channel_transaction_id: "ch_1".into(),
            state,
            amount_minor: terms.amount_minor,
            currency: terms.currency,
            payee_id: terms.payee.id,
        })
    }

    fn changed(applied: Applied) -> PaymentIntent {
        match applied {
            Applied::Changed(next) => *next,
            Applied::Unchanged => panic!("expected a change"),
        }
    }

    #[test]
    fn payment_attempt_keys_are_deterministic_and_domain_separated() {
        let a = derive_attempt_keys(b"secret", "default", "pi_one");
        assert_eq!(a, derive_attempt_keys(b"secret", "default", "pi_one"));
        assert_ne!(a, derive_attempt_keys(b"secret", "default", "pi_two"));
        assert_ne!(a, derive_attempt_keys(b"secret", "acme", "pi_one"));
        assert_ne!(a, derive_attempt_keys(b"other", "default", "pi_one"));
        assert_ne!(a.attempt_id[3..], a.idempotency_key[3..]);
    }

    #[test]
    fn payment_acceptance_happens_once_and_only_before_the_deadline() {
        let intent = PaymentIntent::prepared("pi_one".into(), sample_terms(), 1);
        let deadline = intent.terms.execute_before;
        assert!(intent
            .accept(
                derive_attempt_keys(b"s", "t", "pi_one"),
                evidence(),
                60,
                deadline
            )
            .is_none());
        let accepted = accepted();
        assert_eq!(accepted.status, PaymentStatus::Accepted);
        assert_eq!(accepted.revision, 2);
        assert!(accepted
            .accept(
                derive_attempt_keys(b"s", "t", "pi_one"),
                evidence(),
                60,
                100
            )
            .is_none());
        assert!(accepted
            .close_unaccepted(PaymentStatus::Cancelled, "cancel", 100)
            .is_none());
        assert_eq!(intent.effective_status(deadline), PaymentStatus::Expired);
        assert_eq!(accepted.effective_status(deadline), PaymentStatus::Accepted);
        assert!(intent
            .close_unaccepted(PaymentStatus::Expired, "expire", deadline - 1)
            .is_none());
        assert_eq!(
            intent
                .close_unaccepted(PaymentStatus::Expired, "expire", deadline)
                .unwrap()
                .status,
            PaymentStatus::Expired
        );
    }

    #[test]
    fn payment_unknown_results_settle_only_from_authoritative_channel_reports() {
        let accepted = accepted();
        let unknown = changed(accepted.apply_outcome(
            &ChannelOutcome::Indeterminate,
            EvidenceSource::Submit,
            101,
        ));
        assert_eq!(unknown.status, PaymentStatus::Unknown);
        assert_eq!(
            unknown.apply_outcome(&ChannelOutcome::Indeterminate, EvidenceSource::Query, 102),
            Applied::Unchanged
        );
        let pending = changed(unknown.apply_outcome(
            &report(ChannelState::Pending),
            EvidenceSource::Query,
            103,
        ));
        assert_eq!(pending.status, PaymentStatus::Pending);
        assert_eq!(
            pending.apply_outcome(&ChannelOutcome::Indeterminate, EvidenceSource::Query, 104),
            Applied::Unchanged
        );
        let succeeded = changed(pending.apply_outcome(
            &report(ChannelState::Succeeded),
            EvidenceSource::Callback,
            105,
        ));
        assert_eq!(succeeded.status, PaymentStatus::Succeeded);
        assert_eq!(
            succeeded
                .attempt
                .as_ref()
                .unwrap()
                .channel_transaction_id
                .as_deref(),
            Some("ch_1")
        );
        // Duplicate final report: nothing to persist.
        assert_eq!(
            succeeded.apply_outcome(
                &report(ChannelState::Succeeded),
                EvidenceSource::Callback,
                106
            ),
            Applied::Unchanged
        );
        // An old pending callback arriving late cannot reopen the result.
        let stale = changed(succeeded.apply_outcome(
            &report(ChannelState::Pending),
            EvidenceSource::Callback,
            107,
        ));
        assert_eq!(stale.status, PaymentStatus::Succeeded);
        assert_eq!(
            stale
                .attempt
                .as_ref()
                .unwrap()
                .evidence
                .last()
                .unwrap()
                .disposition,
            "stale"
        );
        // Contradictory final evidence is retained for review, never overwritten.
        let conflict = changed(stale.apply_outcome(
            &report(ChannelState::Declined),
            EvidenceSource::Callback,
            108,
        ));
        assert_eq!(conflict.status, PaymentStatus::Succeeded);
        assert!(conflict.attempt.as_ref().unwrap().needs_review);
        let declined = changed(accepted.apply_outcome(
            &report(ChannelState::Declined),
            EvidenceSource::Submit,
            101,
        ));
        assert_eq!(declined.status, PaymentStatus::Failed);
    }

    #[test]
    fn payment_channel_reports_that_do_not_match_the_terms_are_kept_for_review() {
        let accepted = accepted();
        for mutate in [
            |r: &mut ChannelReport| r.amount_minor = "1".into(),
            |r: &mut ChannelReport| r.currency = "EUR".into(),
            |r: &mut ChannelReport| r.payee_id = "merchant_other".into(),
        ] {
            let ChannelOutcome::Reported(mut wrong) = report(ChannelState::Succeeded) else {
                unreachable!()
            };
            mutate(&mut wrong);
            let next = changed(accepted.apply_outcome(
                &ChannelOutcome::Reported(wrong),
                EvidenceSource::Callback,
                101,
            ));
            assert_eq!(next.status, PaymentStatus::Accepted);
            assert!(next.attempt.as_ref().unwrap().needs_review);
        }
        let pending = changed(accepted.apply_outcome(
            &report(ChannelState::Pending),
            EvidenceSource::Submit,
            101,
        ));
        let ChannelOutcome::Reported(mut other_txn) = report(ChannelState::Succeeded) else {
            unreachable!()
        };
        other_txn.channel_transaction_id = "ch_other".into();
        let next = changed(pending.apply_outcome(
            &ChannelOutcome::Reported(other_txn),
            EvidenceSource::Callback,
            102,
        ));
        assert_eq!(next.status, PaymentStatus::Pending);
        assert!(next.attempt.as_ref().unwrap().needs_review);
    }

    #[test]
    fn payment_status_round_trips_and_records_audit_history() {
        for status in [
            PaymentStatus::Prepared,
            PaymentStatus::Accepted,
            PaymentStatus::Pending,
            PaymentStatus::Unknown,
            PaymentStatus::Succeeded,
            PaymentStatus::Failed,
            PaymentStatus::Expired,
            PaymentStatus::Cancelled,
        ] {
            assert_eq!(PaymentStatus::parse(status.as_str()), Some(status));
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::json!(status.as_str())
            );
        }
        let accepted = accepted();
        assert!(accepted.is_intact());
        assert_eq!(accepted.history.len(), 1);
        assert_eq!(accepted.history[0].from, PaymentStatus::Prepared);
        assert_eq!(accepted.history[0].to, PaymentStatus::Accepted);
        let encoded = serde_json::to_string(&accepted).unwrap();
        assert!(!encoded.contains("eyJ"), "no raw JWT is persisted");
        assert_eq!(
            serde_json::from_str::<PaymentIntent>(&encoded).unwrap(),
            accepted
        );
    }
}
