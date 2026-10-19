//! Trusted funding-source and payee registry.
//!
//! Display names and versions come only from here, never from the agent
//! request. A funding source is usable only by its registered owner (the
//! payer subject on the payment resource) while active; a version change makes
//! every intent frozen against the previous version unusable.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

use tokio::sync::Mutex;

use crate::ports::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSource {
    pub funding_source_id: String,
    /// Payer subject on the payment resource that may debit this source.
    pub owner: String,
    pub version: u64,
    /// Masked display label (never a full account number).
    pub label: String,
    pub currency: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payee {
    pub payee_id: String,
    pub version: u64,
    pub name: String,
    pub active: bool,
}

pub trait PaymentRegistry: Send + Sync {
    fn funding_source(
        &self,
        tenant: &str,
        funding_source_id: &str,
    ) -> impl Future<Output = Result<Option<FundingSource>, StoreError>> + Send;

    fn payee(
        &self,
        tenant: &str,
        payee_id: &str,
    ) -> impl Future<Output = Result<Option<Payee>, StoreError>> + Send;
}

/// Synthetic registry used by the controlled adapter acceptance suite.
#[derive(Clone, Default)]
pub struct MemoryPaymentRegistry {
    funding_sources: Arc<Mutex<HashMap<(String, String), FundingSource>>>,
    payees: Arc<Mutex<HashMap<(String, String), Payee>>>,
    fail_next_lookup: Arc<AtomicU8>,
}

impl MemoryPaymentRegistry {
    pub async fn put_funding_source(&self, tenant: &str, source: FundingSource) {
        self.funding_sources.lock().await.insert(
            (tenant.to_string(), source.funding_source_id.clone()),
            source,
        );
    }

    pub async fn put_payee(&self, tenant: &str, payee: Payee) {
        self.payees
            .lock()
            .await
            .insert((tenant.to_string(), payee.payee_id.clone()), payee);
    }

    /// Fail the next lookup with a transient error.
    pub fn fail_next_lookup(&self) {
        self.fail_next_lookup.store(1, Ordering::SeqCst);
    }

    fn injected(&self) -> Result<(), StoreError> {
        if self.fail_next_lookup.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected payment registry failure".into(),
            ));
        }
        Ok(())
    }
}

impl PaymentRegistry for MemoryPaymentRegistry {
    async fn funding_source(
        &self,
        tenant: &str,
        funding_source_id: &str,
    ) -> Result<Option<FundingSource>, StoreError> {
        self.injected()?;
        Ok(self
            .funding_sources
            .lock()
            .await
            .get(&(tenant.to_string(), funding_source_id.to_string()))
            .cloned())
    }

    async fn payee(&self, tenant: &str, payee_id: &str) -> Result<Option<Payee>, StoreError> {
        self.injected()?;
        Ok(self
            .payees
            .lock()
            .await
            .get(&(tenant.to_string(), payee_id.to_string()))
            .cloned())
    }
}

#[derive(Clone)]
pub enum PaymentRegistryImpl {
    Memory(MemoryPaymentRegistry),
}

impl PaymentRegistry for PaymentRegistryImpl {
    async fn funding_source(
        &self,
        tenant: &str,
        funding_source_id: &str,
    ) -> Result<Option<FundingSource>, StoreError> {
        match self {
            Self::Memory(registry) => registry.funding_source(tenant, funding_source_id).await,
        }
    }

    async fn payee(&self, tenant: &str, payee_id: &str) -> Result<Option<Payee>, StoreError> {
        match self {
            Self::Memory(registry) => registry.payee(tenant, payee_id).await,
        }
    }
}
