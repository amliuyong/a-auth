//! Agent Auth issue #77 — single-transaction payment authorization domain (pure logic, no IO).
//!
//! The payment resource server freezes a [`PaymentIntent`] before asking the
//! user to approve it, binds the approval to a canonical [`terms`] digest
//! through the [`profile`] RAR type, and runs the single execution attempt
//! through the [`execution`] state machine. Storage, channel adapters and HTTP
//! live in `agent-auth-http`. Normative contract: `docs/AGENT_PAYMENT.md`.

pub mod execution;
pub mod profile;
pub mod terms;

pub use execution::{
    derive_attempt_keys, Applied, AttemptKeys, AuthorizationEvidence, ChannelEvidence,
    ChannelOutcome, ChannelReport, ChannelState, EvidenceDisposition, EvidenceSource,
    ExecutionAttempt, PaymentIntent, PaymentStatus, StatusChange,
};
pub use profile::{
    canonical_detail, contains_payment_detail, is_payment_detail, parse_canonical_detail,
    request_reference, verify_execution, Expectation, PaymentAuthzError, ProfileError,
};
pub use terms::{FundingSourceRef, PayeeRef, PaymentTerms, TermsError};

/// RFC 9396 `type` of the payment authorization profile.
pub const PAYMENT_RAR_TYPE: &str = "agent_auth_payment_v1";
/// The only action the profile authorizes.
pub const EXECUTE_ACTION: &str = "execute";
/// Scope required to freeze an intent. It never authorizes execution.
pub const SCOPE_PREPARE: &str = "payments:prepare";
/// Scope required, together with the payment detail, to execute one intent.
pub const SCOPE_EXECUTE: &str = "payments:execute";
