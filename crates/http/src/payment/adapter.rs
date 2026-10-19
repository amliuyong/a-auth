//! Payment channel adapter contract and the controlled (synthetic) channel.
//!
//! An adapter must provide idempotent submission keyed by the persisted
//! idempotency key, an authoritative query by that key, authenticated
//! callbacks and a stated idempotency retention window. The controlled channel
//! implements that contract over synthetic accounts and injects faults; it is
//! test infrastructure and never a production channel.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use agent_auth_payment::{ChannelOutcome, ChannelReport, ChannelState};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

/// One submission, always derived from the persisted intent and attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRequest {
    pub idempotency_key: String,
    /// Merchant reference echoed by the channel (the intent id).
    pub reference: String,
    pub amount_minor: String,
    pub currency: String,
    pub payee_id: String,
    pub funding_source_id: String,
}

/// Answer of an authoritative query by idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    Found(ChannelReport),
    /// The channel authoritatively has no transaction for this key.
    NotFound,
    /// The channel could not be asked (timeout, transport or 5xx).
    Indeterminate,
}

/// A verified channel callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEvent {
    pub event_id: String,
    pub reference: String,
    pub idempotency_key: String,
    pub report: ChannelReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    BadSignature,
    Malformed,
}

/// Injected behavior of the next controlled submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitFault {
    /// No response and the channel never received the request.
    TimeoutBeforeProcessing,
    /// Temporary 5xx before processing.
    ServerErrorBeforeProcessing,
    /// The channel processed the request but the response timed out.
    TimeoutAfterProcessing,
    /// The channel processed the request and the connection dropped.
    LoseResponseAfterProcessing,
}

/// A synthetic transaction held by the controlled channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelTransaction {
    pub channel_transaction_id: String,
    pub idempotency_key: String,
    pub reference: String,
    pub amount_minor: String,
    pub currency: String,
    pub payee_id: String,
    pub funding_source_id: String,
    pub state: ChannelState,
}

impl ChannelTransaction {
    fn report(&self) -> ChannelReport {
        ChannelReport {
            channel_transaction_id: self.channel_transaction_id.clone(),
            state: self.state,
            amount_minor: self.amount_minor.clone(),
            currency: self.currency.clone(),
            payee_id: self.payee_id.clone(),
        }
    }
}

/// Controlled-channel callback body (signed with `x-payment-signature`).
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentChannelCallback {
    pub event_id: String,
    /// Merchant reference: the intent id.
    pub reference: String,
    pub idempotency_key: String,
    pub channel_transaction_id: String,
    /// `pending`, `succeeded` or `declined`.
    #[schema(value_type = String)]
    pub state: ChannelState,
    pub amount_minor: String,
    pub currency: String,
    pub payee_id: String,
}

struct Ledger {
    by_key: HashMap<String, ChannelTransaction>,
    submit_faults: VecDeque<SubmitFault>,
    indeterminate_queries: u32,
    initial_state: ChannelState,
    submit_calls: u64,
    query_calls: u64,
    next_id: u64,
}

/// Controlled channel over synthetic accounts.
#[derive(Clone)]
pub struct ControlledPaymentAdapter {
    ledger: Arc<Mutex<Ledger>>,
    callback_secret: Arc<Vec<u8>>,
    retention_secs: Arc<std::sync::atomic::AtomicI64>,
}

impl ControlledPaymentAdapter {
    pub fn new(callback_secret: &[u8]) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(Ledger {
                by_key: HashMap::new(),
                submit_faults: VecDeque::new(),
                indeterminate_queries: 0,
                initial_state: ChannelState::Succeeded,
                submit_calls: 0,
                query_calls: 0,
                next_id: 1,
            })),
            callback_secret: Arc::new(callback_secret.to_vec()),
            retention_secs: Arc::new(std::sync::atomic::AtomicI64::new(86_400)),
        }
    }

    /// Idempotency retention promised by this channel contract.
    pub fn idempotency_retention_secs(&self) -> i64 {
        self.retention_secs
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_idempotency_retention_secs(&self, secs: i64) {
        self.retention_secs
            .store(secs, std::sync::atomic::Ordering::SeqCst);
    }

    /// State of newly created transactions (default: `Succeeded`).
    pub async fn set_initial_state(&self, state: ChannelState) {
        self.ledger.lock().await.initial_state = state;
    }

    pub async fn push_submit_fault(&self, fault: SubmitFault) {
        self.ledger.lock().await.submit_faults.push_back(fault);
    }

    /// Make the next `count` queries indeterminate.
    pub async fn fail_next_queries(&self, count: u32) {
        self.ledger.lock().await.indeterminate_queries = count;
    }

    /// Settle a transaction on the channel side.
    pub async fn settle(&self, idempotency_key: &str, state: ChannelState) -> bool {
        let mut ledger = self.ledger.lock().await;
        match ledger.by_key.get_mut(idempotency_key) {
            Some(txn) => {
                txn.state = state;
                true
            }
            None => false,
        }
    }

    pub async fn transactions(&self) -> Vec<ChannelTransaction> {
        let mut txns: Vec<ChannelTransaction> =
            self.ledger.lock().await.by_key.values().cloned().collect();
        txns.sort_by(|a, b| a.channel_transaction_id.cmp(&b.channel_transaction_id));
        txns
    }

    pub async fn submit_calls(&self) -> u64 {
        self.ledger.lock().await.submit_calls
    }

    pub async fn query_calls(&self) -> u64 {
        self.ledger.lock().await.query_calls
    }

    /// Idempotent submission keyed by `idempotency_key`.
    pub async fn submit(&self, request: &SubmitRequest) -> ChannelOutcome {
        let mut ledger = self.ledger.lock().await;
        ledger.submit_calls += 1;
        let fault = ledger.submit_faults.pop_front();
        if matches!(
            fault,
            Some(SubmitFault::TimeoutBeforeProcessing | SubmitFault::ServerErrorBeforeProcessing)
        ) {
            return ChannelOutcome::Indeterminate;
        }
        let report = match ledger.by_key.get(&request.idempotency_key) {
            Some(existing) => {
                if existing.reference != request.reference
                    || existing.amount_minor != request.amount_minor
                    || existing.currency != request.currency
                    || existing.payee_id != request.payee_id
                {
                    // A key reused with different parameters is refused by the channel.
                    return ChannelOutcome::Indeterminate;
                }
                existing.report()
            }
            None => {
                let id = format!("ch_{:06}", ledger.next_id);
                ledger.next_id += 1;
                let txn = ChannelTransaction {
                    channel_transaction_id: id,
                    idempotency_key: request.idempotency_key.clone(),
                    reference: request.reference.clone(),
                    amount_minor: request.amount_minor.clone(),
                    currency: request.currency.clone(),
                    payee_id: request.payee_id.clone(),
                    funding_source_id: request.funding_source_id.clone(),
                    state: ledger.initial_state,
                };
                let report = txn.report();
                ledger.by_key.insert(request.idempotency_key.clone(), txn);
                report
            }
        };
        match fault {
            Some(
                SubmitFault::TimeoutAfterProcessing | SubmitFault::LoseResponseAfterProcessing,
            ) => ChannelOutcome::Indeterminate,
            _ => ChannelOutcome::Reported(report),
        }
    }

    /// Authoritative lookup by idempotency key.
    pub async fn query(&self, idempotency_key: &str) -> QueryResult {
        let mut ledger = self.ledger.lock().await;
        ledger.query_calls += 1;
        if ledger.indeterminate_queries > 0 {
            ledger.indeterminate_queries -= 1;
            return QueryResult::Indeterminate;
        }
        match ledger.by_key.get(idempotency_key) {
            Some(txn) => QueryResult::Found(txn.report()),
            None => QueryResult::NotFound,
        }
    }

    /// `v1=<base64url(HMAC-SHA256(secret, body))>`.
    pub fn sign(&self, body: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.callback_secret).expect("HMAC key length");
        mac.update(body);
        format!("v1={}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// Body and signature of a callback for the current channel state.
    pub async fn callback_for(
        &self,
        idempotency_key: &str,
        event_id: &str,
    ) -> Option<(Vec<u8>, String)> {
        let txn = self
            .ledger
            .lock()
            .await
            .by_key
            .get(idempotency_key)?
            .clone();
        let body = serde_json::to_vec(&PaymentChannelCallback {
            event_id: event_id.to_string(),
            reference: txn.reference,
            idempotency_key: txn.idempotency_key,
            channel_transaction_id: txn.channel_transaction_id,
            state: txn.state,
            amount_minor: txn.amount_minor,
            currency: txn.currency,
            payee_id: txn.payee_id,
        })
        .expect("callback body");
        let signature = self.sign(&body);
        Some((body, signature))
    }

    /// Authenticate and parse a callback.
    pub fn verify_callback(
        &self,
        signature: Option<&str>,
        body: &[u8],
    ) -> Result<ChannelEvent, CallbackError> {
        let presented = signature
            .and_then(|value| value.strip_prefix("v1="))
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .ok_or(CallbackError::BadSignature)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.callback_secret).expect("HMAC key length");
        mac.update(body);
        mac.verify_slice(&presented)
            .map_err(|_| CallbackError::BadSignature)?;
        let parsed: PaymentChannelCallback =
            serde_json::from_slice(body).map_err(|_| CallbackError::Malformed)?;
        Ok(ChannelEvent {
            event_id: parsed.event_id,
            reference: parsed.reference,
            idempotency_key: parsed.idempotency_key,
            report: ChannelReport {
                channel_transaction_id: parsed.channel_transaction_id,
                state: parsed.state,
                amount_minor: parsed.amount_minor,
                currency: parsed.currency,
                payee_id: parsed.payee_id,
            },
        })
    }
}

/// Configured channel adapter. Only the controlled channel exists in this delivery.
#[derive(Clone)]
pub enum PaymentAdapterImpl {
    Controlled(ControlledPaymentAdapter),
}

impl PaymentAdapterImpl {
    pub fn idempotency_retention_secs(&self) -> i64 {
        match self {
            Self::Controlled(adapter) => adapter.idempotency_retention_secs(),
        }
    }

    pub async fn submit(&self, request: &SubmitRequest) -> ChannelOutcome {
        match self {
            Self::Controlled(adapter) => adapter.submit(request).await,
        }
    }

    pub async fn query(&self, idempotency_key: &str) -> QueryResult {
        match self {
            Self::Controlled(adapter) => adapter.query(idempotency_key).await,
        }
    }

    pub fn verify_callback(
        &self,
        signature: Option<&str>,
        body: &[u8],
    ) -> Result<ChannelEvent, CallbackError> {
        match self {
            Self::Controlled(adapter) => adapter.verify_callback(signature, body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(key: &str) -> SubmitRequest {
        SubmitRequest {
            idempotency_key: key.into(),
            reference: "pi_1".into(),
            amount_minor: "1999".into(),
            currency: "USD".into(),
            payee_id: "merchant_books".into(),
            funding_source_id: "fs_1".into(),
        }
    }

    #[tokio::test]
    async fn controlled_channel_submission_is_idempotent_per_key() {
        let adapter = ControlledPaymentAdapter::new(b"callback-secret");
        let first = adapter.submit(&request("pk_1")).await;
        let second = adapter.submit(&request("pk_1")).await;
        assert_eq!(first, second);
        assert_eq!(adapter.transactions().await.len(), 1);
        let mut changed = request("pk_1");
        changed.amount_minor = "1".into();
        assert_eq!(
            adapter.submit(&changed).await,
            ChannelOutcome::Indeterminate
        );
        assert_eq!(adapter.transactions().await.len(), 1);
        assert_eq!(adapter.submit_calls().await, 3);
    }

    #[tokio::test]
    async fn controlled_channel_faults_distinguish_processed_from_unprocessed() {
        let adapter = ControlledPaymentAdapter::new(b"callback-secret");
        adapter
            .push_submit_fault(SubmitFault::TimeoutBeforeProcessing)
            .await;
        assert_eq!(
            adapter.submit(&request("pk_1")).await,
            ChannelOutcome::Indeterminate
        );
        assert_eq!(adapter.query("pk_1").await, QueryResult::NotFound);
        adapter
            .push_submit_fault(SubmitFault::LoseResponseAfterProcessing)
            .await;
        assert_eq!(
            adapter.submit(&request("pk_1")).await,
            ChannelOutcome::Indeterminate
        );
        assert!(matches!(adapter.query("pk_1").await, QueryResult::Found(_)));
        adapter.fail_next_queries(1).await;
        assert_eq!(adapter.query("pk_1").await, QueryResult::Indeterminate);
    }

    #[tokio::test]
    async fn controlled_channel_callbacks_require_a_valid_signature() {
        let adapter = ControlledPaymentAdapter::new(b"callback-secret");
        adapter.set_initial_state(ChannelState::Pending).await;
        adapter.submit(&request("pk_1")).await;
        assert!(adapter.settle("pk_1", ChannelState::Succeeded).await);
        let (body, signature) = adapter.callback_for("pk_1", "evt_1").await.unwrap();
        let event = adapter.verify_callback(Some(&signature), &body).unwrap();
        assert_eq!(event.report.state, ChannelState::Succeeded);
        assert_eq!(event.reference, "pi_1");
        assert_eq!(
            adapter.verify_callback(None, &body),
            Err(CallbackError::BadSignature)
        );
        let other = ControlledPaymentAdapter::new(b"other-secret");
        assert_eq!(
            adapter.verify_callback(Some(&other.sign(&body)), &body),
            Err(CallbackError::BadSignature)
        );
        let mut tampered = body.clone();
        tampered.extend_from_slice(b" ");
        assert_eq!(
            adapter.verify_callback(Some(&signature), &tampered),
            Err(CallbackError::BadSignature)
        );
        let unknown = br#"{"event_id":"e"}"#;
        assert_eq!(
            adapter.verify_callback(Some(&adapter.sign(unknown)), unknown),
            Err(CallbackError::Malformed)
        );
    }
}
