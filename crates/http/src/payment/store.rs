//! Payment intent store: create-once per order and compare-and-set updates.
//!
//! The acceptance write is the only point that turns a prepared intent into an
//! execution attempt. It is conditional on the expected revision and status
//! and, for acceptance, on the frozen `execute_before` deadline, so concurrent
//! executions, retries and recovery all converge on one persisted attempt.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

use agent_auth_payment::{PaymentIntent, PaymentStatus};
use tokio::sync::{Mutex, Notify};

use crate::ports::StoreError;

/// Result of an order-unique intent creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    /// The `(tenant, payee, order)` key already points at this intent.
    OrderTaken(String),
}

/// Conditions of a compare-and-set write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasGuard {
    pub expected_revision: u64,
    pub expected_status: PaymentStatus,
    /// Acceptance only: the write must happen before `execute_before` at this instant.
    pub accept_at: Option<i64>,
}

impl CasGuard {
    pub fn of(current: &PaymentIntent) -> Self {
        Self {
            expected_revision: current.revision,
            expected_status: current.status,
            accept_at: None,
        }
    }

    pub fn accepting(current: &PaymentIntent, now: i64) -> Self {
        Self {
            accept_at: Some(now),
            ..Self::of(current)
        }
    }

    fn holds(&self, current: &PaymentIntent) -> bool {
        current.revision == self.expected_revision
            && current.status == self.expected_status
            && self
                .accept_at
                .is_none_or(|now| now < current.terms.execute_before)
    }
}

pub trait PaymentStore: Send + Sync {
    /// Create `intent` and bind its order key atomically. `replaces` names a
    /// closed, never-accepted intent whose order key may be moved.
    fn create(
        &self,
        tenant: &str,
        intent: &PaymentIntent,
        replaces: Option<&str>,
    ) -> impl Future<Output = Result<CreateOutcome, StoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        intent_id: &str,
    ) -> impl Future<Output = Result<Option<PaymentIntent>, StoreError>> + Send;

    /// Replace the intent when `guard` holds; `Ok(false)` when it does not.
    fn compare_and_set(
        &self,
        tenant: &str,
        guard: CasGuard,
        next: &PaymentIntent,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Intents with an attempt that has no channel-final result.
    fn list_unsettled(
        &self,
        tenant: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<PaymentIntent>, StoreError>> + Send;
}

/// Order uniqueness key within a tenant partition: trusted payee identity and
/// business order id. Stores combine it with the tenant.
pub fn order_key(intent: &PaymentIntent) -> (String, String) {
    (intent.terms.payee.id.clone(), intent.terms.order_id.clone())
}

/// A deterministic pause inside the memory store for concurrency tests.
#[derive(Clone, Default)]
pub struct PausePoint {
    /// Notified when the store reaches the pause.
    pub reached: Arc<Notify>,
    /// Notify to let the store continue.
    pub release: Arc<Notify>,
}

#[derive(Default)]
struct MemoryState {
    intents: HashMap<(String, String), PaymentIntent>,
    orders: HashMap<(String, String, String), String>,
}

/// In-memory store with fault hooks for the controlled acceptance suite.
#[derive(Clone, Default)]
pub struct MemoryPaymentStore {
    state: Arc<Mutex<MemoryState>>,
    lose_next_accept_response: Arc<AtomicU8>,
    fail_next_get: Arc<AtomicU8>,
    pause_before_accept: Arc<std::sync::Mutex<Option<PausePoint>>>,
    pause_after_accept: Arc<std::sync::Mutex<Option<PausePoint>>>,
}

impl MemoryPaymentStore {
    /// Commit the next acceptance, then report a transient error to the caller.
    pub fn lose_next_accept_response(&self) {
        self.lose_next_accept_response.store(1, Ordering::SeqCst);
    }

    /// Fail the next `get` with a transient error.
    pub fn fail_next_get(&self) {
        self.fail_next_get.store(1, Ordering::SeqCst);
    }

    /// Pause the next acceptance before it evaluates its condition.
    pub fn pause_next_accept(&self) -> PausePoint {
        let point = PausePoint::default();
        *self.pause_before_accept.lock().expect("pause lock") = Some(point.clone());
        point
    }

    /// Pause the next acceptance after it has committed.
    pub fn pause_after_next_accept(&self) -> PausePoint {
        let point = PausePoint::default();
        *self.pause_after_accept.lock().expect("pause lock") = Some(point.clone());
        point
    }

    async fn wait(slot: &std::sync::Mutex<Option<PausePoint>>) {
        let point = slot.lock().expect("pause lock").take();
        if let Some(point) = point {
            point.reached.notify_one();
            point.release.notified().await;
        }
    }
}

fn is_acceptance(guard: &CasGuard, next: &PaymentIntent) -> bool {
    guard.expected_status == PaymentStatus::Prepared && next.status == PaymentStatus::Accepted
}

impl PaymentStore for MemoryPaymentStore {
    async fn create(
        &self,
        tenant: &str,
        intent: &PaymentIntent,
        replaces: Option<&str>,
    ) -> Result<CreateOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let (payee, order) = order_key(intent);
        let order_key = (tenant.to_string(), payee, order);
        let intent_key = (tenant.to_string(), intent.intent_id.clone());
        if state.intents.contains_key(&intent_key) {
            return Err(StoreError::Permanent("intent id collision".into()));
        }
        match (state.orders.get(&order_key), replaces) {
            (None, None) => {}
            (Some(current), Some(expected)) if current == expected => {
                let closed = state
                    .intents
                    .get(&(tenant.to_string(), current.clone()))
                    .is_some_and(PaymentIntent::is_replaceable);
                if !closed {
                    return Ok(CreateOutcome::OrderTaken(current.clone()));
                }
            }
            (Some(current), _) => return Ok(CreateOutcome::OrderTaken(current.clone())),
            (None, Some(_)) => {
                return Err(StoreError::Transient(
                    "payment order binding changed during creation".into(),
                ))
            }
        }
        state.orders.insert(order_key, intent.intent_id.clone());
        state.intents.insert(intent_key, intent.clone());
        Ok(CreateOutcome::Created)
    }

    async fn get(
        &self,
        tenant: &str,
        intent_id: &str,
    ) -> Result<Option<PaymentIntent>, StoreError> {
        if self.fail_next_get.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected payment store read failure".into(),
            ));
        }
        Ok(self
            .state
            .lock()
            .await
            .intents
            .get(&(tenant.to_string(), intent_id.to_string()))
            .cloned())
    }

    async fn compare_and_set(
        &self,
        tenant: &str,
        guard: CasGuard,
        next: &PaymentIntent,
    ) -> Result<bool, StoreError> {
        let accepting = is_acceptance(&guard, next);
        if accepting {
            Self::wait(&self.pause_before_accept).await;
        }
        {
            let mut state = self.state.lock().await;
            let key = (tenant.to_string(), next.intent_id.clone());
            let Some(current) = state.intents.get(&key) else {
                return Ok(false);
            };
            if !guard.holds(current) {
                return Ok(false);
            }
            state.intents.insert(key, next.clone());
        }
        if accepting {
            Self::wait(&self.pause_after_accept).await;
            if self.lose_next_accept_response.swap(0, Ordering::SeqCst) != 0 {
                return Err(StoreError::Transient(
                    "injected lost acceptance response".into(),
                ));
            }
        }
        Ok(true)
    }

    async fn list_unsettled(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<PaymentIntent>, StoreError> {
        let state = self.state.lock().await;
        let mut unsettled: Vec<PaymentIntent> = state
            .intents
            .iter()
            .filter(|((owner, _), intent)| owner == tenant && intent.status.is_unsettled())
            .map(|(_, intent)| intent.clone())
            .collect();
        unsettled.sort_by_key(|intent| intent.updated_at);
        unsettled.truncate(limit);
        Ok(unsettled)
    }
}

#[derive(Clone)]
pub enum PaymentStoreImpl {
    Memory(MemoryPaymentStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPaymentStore),
}

impl PaymentStore for PaymentStoreImpl {
    async fn create(
        &self,
        tenant: &str,
        intent: &PaymentIntent,
        replaces: Option<&str>,
    ) -> Result<CreateOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.create(tenant, intent, replaces).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.create(tenant, intent, replaces).await,
        }
    }

    async fn get(
        &self,
        tenant: &str,
        intent_id: &str,
    ) -> Result<Option<PaymentIntent>, StoreError> {
        match self {
            Self::Memory(store) => store.get(tenant, intent_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get(tenant, intent_id).await,
        }
    }

    async fn compare_and_set(
        &self,
        tenant: &str,
        guard: CasGuard,
        next: &PaymentIntent,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.compare_and_set(tenant, guard, next).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.compare_and_set(tenant, guard, next).await,
        }
    }

    async fn list_unsettled(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<PaymentIntent>, StoreError> {
        match self {
            Self::Memory(store) => store.list_unsettled(tenant, limit).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_unsettled(tenant, limit).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use agent_auth_payment::{derive_attempt_keys, AuthorizationEvidence, PaymentTerms};

    pub(crate) fn terms(order_id: &str, execute_before: i64) -> PaymentTerms {
        serde_json::from_value(serde_json::json!({
            "tenant": "default",
            "payer": "payer-sub",
            "client_id": "coveai",
            "actor": "pay-runtime",
            "resource": "https://payments.example",
            "order_id": order_id,
            "funding_source": {"id": "fs_1", "version": 1, "label": "Card •••• 4242"},
            "payee": {"id": "merchant_books", "version": 1, "name": "Example Books"},
            "amount_minor": "1999",
            "currency": "USD",
            "currency_exponent": 2,
            "execute_before": execute_before
        }))
        .unwrap()
    }

    pub(crate) fn evidence() -> AuthorizationEvidence {
        AuthorizationEvidence {
            grant_id: "g".into(),
            token_jti_sha256: "h".into(),
            actor: "pay-runtime".into(),
            client_id: "coveai".into(),
            acr: "urn:agent-auth:assurance:strong".into(),
            auth_time: None,
            checked_at: 10,
        }
    }

    fn accept(intent: &PaymentIntent, now: i64) -> PaymentIntent {
        intent
            .accept(
                derive_attempt_keys(b"s", "", &intent.intent_id),
                evidence(),
                60,
                now,
            )
            .unwrap()
    }

    #[tokio::test]
    async fn payment_store_binds_one_intent_per_order_until_it_closes_unaccepted() {
        let store = MemoryPaymentStore::default();
        let first = PaymentIntent::prepared("pi_1".into(), terms("o-1", 100), 1);
        assert_eq!(
            store.create("", &first, None).await,
            Ok(CreateOutcome::Created)
        );
        let second = PaymentIntent::prepared("pi_2".into(), terms("o-1", 100), 2);
        assert_eq!(
            store.create("", &second, None).await,
            Ok(CreateOutcome::OrderTaken("pi_1".into()))
        );
        // A live prepared intent cannot be replaced, even when named.
        assert_eq!(
            store.create("", &second, Some("pi_1")).await,
            Ok(CreateOutcome::OrderTaken("pi_1".into()))
        );
        // Another tenant has an independent order space.
        assert_eq!(
            store.create("acme", &second, None).await,
            Ok(CreateOutcome::Created)
        );
        let expired = first
            .close_unaccepted(PaymentStatus::Expired, "expire", 100)
            .unwrap();
        assert!(store
            .compare_and_set("", CasGuard::of(&first), &expired)
            .await
            .unwrap());
        assert_eq!(
            store.create("", &second, Some("pi_1")).await,
            Ok(CreateOutcome::Created)
        );
        // An accepted intent can never be replaced.
        let third = PaymentIntent::prepared("pi_3".into(), terms("o-1", 100), 3);
        let accepted = accept(&second, 10);
        assert!(store
            .compare_and_set("", CasGuard::accepting(&second, 10), &accepted)
            .await
            .unwrap());
        assert_eq!(
            store.create("", &third, Some("pi_2")).await,
            Ok(CreateOutcome::OrderTaken("pi_2".into()))
        );
    }

    #[tokio::test]
    async fn payment_store_compare_and_set_rejects_stale_revision_status_and_deadline() {
        let store = MemoryPaymentStore::default();
        let prepared = PaymentIntent::prepared("pi_1".into(), terms("o-1", 100), 1);
        store.create("", &prepared, None).await.unwrap();
        let accepted = accept(&prepared, 10);
        // Deadline reached at write time.
        assert!(!store
            .compare_and_set("", CasGuard::accepting(&prepared, 100), &accepted)
            .await
            .unwrap());
        let mut stale = CasGuard::accepting(&prepared, 10);
        stale.expected_revision += 1;
        assert!(!store.compare_and_set("", stale, &accepted).await.unwrap());
        assert!(store
            .compare_and_set("", CasGuard::accepting(&prepared, 10), &accepted)
            .await
            .unwrap());
        // A concurrent second acceptance built from the same snapshot loses.
        assert!(!store
            .compare_and_set(
                "",
                CasGuard::accepting(&prepared, 11),
                &accept(&prepared, 11)
            )
            .await
            .unwrap());
        assert_eq!(store.get("", "pi_1").await.unwrap(), Some(accepted.clone()));
        assert_eq!(store.list_unsettled("", 10).await.unwrap(), vec![accepted]);
        assert!(store.list_unsettled("acme", 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn payment_store_lost_acceptance_response_still_commits_once() {
        let store = MemoryPaymentStore::default();
        let prepared = PaymentIntent::prepared("pi_1".into(), terms("o-1", 100), 1);
        store.create("", &prepared, None).await.unwrap();
        store.lose_next_accept_response();
        let accepted = accept(&prepared, 10);
        assert!(store
            .compare_and_set("", CasGuard::accepting(&prepared, 10), &accepted)
            .await
            .is_err());
        assert_eq!(store.get("", "pi_1").await.unwrap(), Some(accepted));
    }
}
