//! Payment resource server for single-transaction agent payments (issue #77).
//!
//! The module is logically separate from the authorization server: it has its
//! own audience (`PaymentConfig::resource`), routes under `/payments`, and its
//! own store, registry and channel adapter. a-auth reads frozen intents only
//! through [`consent`] to display and bind them during consent; nothing in the
//! `/token` path calls the channel or touches the execution record.
//!
//! `AppState::payments == None` (every deployed runtime in this delivery)
//! disables the RAR profile and all routes. The controlled profile uses
//! synthetic accounts and the controlled channel only.

pub mod adapter;
pub(crate) mod authority;
pub(crate) mod consent;
mod error;
pub(crate) mod execute;
pub mod recovery;
pub mod registry;
pub mod routes;
pub mod store;

use adapter::{ControlledPaymentAdapter, PaymentAdapterImpl};
use agent_auth_payment::PaymentIntent;
pub use error::PaymentError;
use registry::{MemoryPaymentRegistry, PaymentRegistryImpl};
use store::{MemoryPaymentStore, PaymentStore, PaymentStoreImpl};

/// Deployment-level payment profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentConfig {
    /// Payment resource server audience (RFC 8707 `resource`).
    pub resource: String,
    /// The single supported currency.
    pub currency: String,
    /// Minor-unit decimal places of `currency`.
    pub currency_exponent: u8,
    /// Channel/business ceiling for one payment, in minor units.
    pub max_amount_minor: u64,
    /// Longest allowed distance between preparation and `execute_before`.
    pub max_execute_window_secs: i64,
}

impl PaymentConfig {
    fn accepts_execute_before(&self, now: i64, execute_before: i64) -> bool {
        execute_before > now && execute_before <= now.saturating_add(self.max_execute_window_secs)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if agent_auth_payment::terms::validate_resource(&self.resource).is_err() {
            return Err("payment resource must be an absolute https URI");
        }
        if !agent_auth_payment::terms::is_currency_code(&self.currency) {
            return Err("payment currency must be three uppercase letters");
        }
        if self.currency_exponent > agent_auth_payment::terms::MAX_CURRENCY_EXPONENT {
            return Err("payment currency exponent must be between 0 and 4");
        }
        if self.max_amount_minor == 0 || self.max_amount_minor > 999_999_999_999_999_999 {
            return Err("payment amount ceiling must fit 18 decimal digits");
        }
        if !(60..=86_400).contains(&self.max_execute_window_secs) {
            return Err("payment execution window must be between 60 and 86400 seconds");
        }
        Ok(())
    }
}

/// Configured payment resource server.
pub struct PaymentModule {
    pub config: PaymentConfig,
    pub store: PaymentStoreImpl,
    pub registry: PaymentRegistryImpl,
    pub adapter: PaymentAdapterImpl,
}

/// Handles to the controlled profile's synthetic components.
#[derive(Clone)]
pub struct ControlledParts {
    pub store: MemoryPaymentStore,
    pub registry: MemoryPaymentRegistry,
    pub adapter: ControlledPaymentAdapter,
}

impl PaymentModule {
    pub fn new(
        config: PaymentConfig,
        store: PaymentStoreImpl,
        registry: PaymentRegistryImpl,
        adapter: PaymentAdapterImpl,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            config,
            store,
            registry,
            adapter,
        })
    }

    /// Read an intent; an absent intent is `NotFound` and a store failure fails closed.
    pub(crate) async fn load(
        &self,
        tenant: &str,
        intent_id: &str,
    ) -> Result<PaymentIntent, PaymentError> {
        match self.store.get(tenant, intent_id).await {
            Ok(Some(intent)) => Ok(intent),
            Ok(None) => Err(PaymentError::NotFound),
            Err(_) => Err(PaymentError::Unavailable("payment store unavailable")),
        }
    }

    /// Controlled acceptance profile: memory store and registry with the
    /// synthetic channel. Never a production configuration.
    pub fn controlled(
        config: PaymentConfig,
        callback_secret: &[u8],
    ) -> Result<(Self, ControlledParts), &'static str> {
        let parts = ControlledParts {
            store: MemoryPaymentStore::default(),
            registry: MemoryPaymentRegistry::default(),
            adapter: ControlledPaymentAdapter::new(callback_secret),
        };
        let module = Self::new(
            config,
            PaymentStoreImpl::Memory(parts.store.clone()),
            PaymentRegistryImpl::Memory(parts.registry.clone()),
            PaymentAdapterImpl::Controlled(parts.adapter.clone()),
        )?;
        Ok((module, parts))
    }
}

/// Logical tenant recorded in terms (`default` for the single-tenant form).
pub(crate) fn logical_tenant(tenant: &str) -> &str {
    if tenant.is_empty() {
        "default"
    } else {
        tenant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PaymentConfig {
        PaymentConfig {
            resource: "https://payments.example".into(),
            currency: "USD".into(),
            currency_exponent: 2,
            max_amount_minor: 100_000,
            max_execute_window_secs: 3600,
        }
    }

    #[test]
    fn payment_config_rejects_unsafe_profiles() {
        assert_eq!(config().validate(), Ok(()));
        for mutate in [
            |c: &mut PaymentConfig| c.resource = "http://payments.example".into(),
            |c: &mut PaymentConfig| c.currency = "usd".into(),
            |c: &mut PaymentConfig| c.currency_exponent = 5,
            |c: &mut PaymentConfig| c.max_amount_minor = 0,
            |c: &mut PaymentConfig| c.max_execute_window_secs = 86_401,
        ] {
            let mut c = config();
            mutate(&mut c);
            assert!(c.validate().is_err(), "{c:?}");
        }
    }

    #[test]
    fn execution_deadline_uses_fixed_clock_bounds() {
        let config = config();
        let now = 10_000;
        for execute_before in [now - 1, now, now + config.max_execute_window_secs + 1] {
            assert!(!config.accepts_execute_before(now, execute_before));
        }
        for execute_before in [now + 1, now + config.max_execute_window_secs] {
            assert!(config.accepts_execute_before(now, execute_before));
        }
        assert!(config.accepts_execute_before(i64::MAX - 1, i64::MAX));
        assert!(!config.accepts_execute_before(i64::MAX, i64::MAX));
    }
}
