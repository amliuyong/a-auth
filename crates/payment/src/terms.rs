//! Frozen payment terms and their canonical v1 encoding.
//!
//! The digest never hashes a JSON serialization. Every field is written in a
//! fixed order as `u32_be(len(utf8)) || utf8` after a domain separator, and
//! integers use canonical decimal ASCII. `specs/fixtures/agent_auth_payment_v1.json`
//! pins the byte layout for every SDK implementation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::PAYMENT_RAR_TYPE;

/// Domain separator prepended to the canonical encoding.
pub const TERMS_DIGEST_DOMAIN: &[u8] = b"agent-auth:payment-terms:v1\0";

/// Largest number of decimal digits accepted for `amount_minor` (fits `u64`).
pub const MAX_AMOUNT_DIGITS: usize = 18;
/// Largest supported number of minor-unit decimal places.
pub const MAX_CURRENCY_EXPONENT: u8 = 4;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_RESOURCE_BYTES: usize = 2048;
const MAX_LABEL_CHARS: usize = 128;

/// Trusted funding-source reference frozen into the intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingSourceRef {
    pub id: String,
    pub version: u64,
    /// Registry display label (for example a masked account); never a full account number.
    pub label: String,
}

/// Trusted payee reference frozen into the intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayeeRef {
    pub id: String,
    pub version: u64,
    /// Registry display name; never taken from the agent request.
    pub name: String,
}

/// The complete set of facts a user approves for one payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentTerms {
    /// Logical tenant (`default` for the single-tenant form).
    pub tenant: String,
    /// Payer subject as seen by the payment resource (`sub` for that audience).
    pub payer: String,
    /// Initiating 3LO client.
    pub client_id: String,
    /// The only workload allowed to execute.
    pub actor: String,
    /// Payment resource server audience.
    pub resource: String,
    pub order_id: String,
    pub funding_source: FundingSourceRef,
    pub payee: PayeeRef,
    /// Total amount in minor units as a canonical positive decimal string.
    pub amount_minor: String,
    pub currency: String,
    pub currency_exponent: u8,
    /// Latest first-acceptance instant (Unix seconds, exclusive).
    pub execute_before: i64,
}

/// Why a terms object is not admissible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermsError {
    InvalidField(&'static str),
}

impl PaymentTerms {
    /// Validate every field against the v1 value rules.
    pub fn validate(&self) -> Result<(), TermsError> {
        identifier(&self.tenant, "tenant")?;
        identifier(&self.payer, "payer")?;
        identifier(&self.client_id, "client_id")?;
        identifier(&self.actor, "actor")?;
        resource(&self.resource)?;
        identifier(&self.order_id, "order_id")?;
        identifier(&self.funding_source.id, "funding_source.id")?;
        version(self.funding_source.version, "funding_source.version")?;
        label(&self.funding_source.label, "funding_source.label")?;
        identifier(&self.payee.id, "payee.id")?;
        version(self.payee.version, "payee.version")?;
        label(&self.payee.name, "payee.name")?;
        if parse_amount_minor(&self.amount_minor).is_none() {
            return Err(TermsError::InvalidField("amount_minor"));
        }
        if !is_currency_code(&self.currency) {
            return Err(TermsError::InvalidField("currency"));
        }
        if self.currency_exponent > MAX_CURRENCY_EXPONENT {
            return Err(TermsError::InvalidField("currency_exponent"));
        }
        if self.execute_before <= 0 {
            return Err(TermsError::InvalidField("execute_before"));
        }
        Ok(())
    }

    /// Canonical v1 bytes for `intent_id` and these terms. Callers validate first.
    pub fn canonical_bytes(&self, intent_id: &str) -> Vec<u8> {
        let funding_version = self.funding_source.version.to_string();
        let payee_version = self.payee.version.to_string();
        let exponent = self.currency_exponent.to_string();
        let execute_before = self.execute_before.to_string();
        let fields: [&str; 18] = [
            PAYMENT_RAR_TYPE,
            intent_id,
            &self.tenant,
            &self.payer,
            &self.client_id,
            &self.actor,
            &self.resource,
            &self.order_id,
            &self.funding_source.id,
            &funding_version,
            &self.funding_source.label,
            &self.payee.id,
            &payee_version,
            &self.payee.name,
            &self.amount_minor,
            &self.currency,
            &exponent,
            &execute_before,
        ];
        let mut out = TERMS_DIGEST_DOMAIN.to_vec();
        for field in fields {
            let len = u32::try_from(field.len()).expect("validated field fits in u32");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    /// `base64url_nopad(SHA-256(canonical_bytes))`, 43 characters.
    pub fn digest(&self, intent_id: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.canonical_bytes(intent_id)))
    }

    /// Parsed amount (validated terms only).
    pub fn amount(&self) -> u64 {
        parse_amount_minor(&self.amount_minor).unwrap_or(0)
    }
}

/// Validate an intent identifier with the same rule as other identifiers.
pub fn validate_intent_id(intent_id: &str) -> Result<(), TermsError> {
    identifier(intent_id, "intent_id")
}

/// Parse a canonical `amount_minor`: `^[1-9][0-9]{0,17}$`.
pub fn parse_amount_minor(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_AMOUNT_DIGITS
        || bytes[0] == b'0'
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    value.parse().ok()
}

/// ISO 4217-shaped alphabetic code: three ASCII uppercase letters.
pub fn is_currency_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|b| b.is_ascii_uppercase())
}

fn identifier(value: &str, field: &'static str) -> Result<(), TermsError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(TermsError::InvalidField(field));
    }
    Ok(())
}

fn resource(value: &str) -> Result<(), TermsError> {
    if value.len() > MAX_RESOURCE_BYTES
        || !value.starts_with("https://")
        || value.len() == "https://".len()
        || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(TermsError::InvalidField("resource"));
    }
    Ok(())
}

fn version(value: u64, field: &'static str) -> Result<(), TermsError> {
    if value == 0 {
        return Err(TermsError::InvalidField(field));
    }
    Ok(())
}

fn label(value: &str, field: &'static str) -> Result<(), TermsError> {
    if value.is_empty()
        || value.chars().count() > MAX_LABEL_CHARS
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TermsError::InvalidField(field));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    pub(crate) fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/fixtures/agent_auth_payment_v1.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).unwrap()
    }

    pub(crate) fn sample_terms() -> PaymentTerms {
        serde_json::from_value(vectors()["valid"][0]["terms"].clone()).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn payment_terms_canonical_encoding_matches_cross_language_vectors() {
        let doc = vectors();
        assert_eq!(doc["profile"], PAYMENT_RAR_TYPE);
        assert_eq!(doc["digest_domain_hex"], hex(TERMS_DIGEST_DOMAIN));
        let valid = doc["valid"].as_array().unwrap();
        assert!(valid.len() >= 3);
        for case in valid {
            let terms: PaymentTerms = serde_json::from_value(case["terms"].clone()).unwrap();
            let intent_id = case["intent_id"].as_str().unwrap();
            assert_eq!(terms.validate(), Ok(()), "{}", case["name"]);
            validate_intent_id(intent_id).unwrap();
            assert_eq!(
                hex(&terms.canonical_bytes(intent_id)),
                case["canonical_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert_eq!(
                terms.digest(intent_id),
                case["terms_digest"],
                "{}",
                case["name"]
            );
            assert_eq!(terms.digest(intent_id).len(), 43);
        }
    }

    #[test]
    fn payment_terms_reject_every_invalid_vector() {
        for case in vectors()["invalid_terms"].as_array().unwrap() {
            let parsed = serde_json::from_value::<PaymentTerms>(case["terms"].clone());
            assert!(
                parsed
                    .map(|terms| terms.validate().is_err())
                    .unwrap_or(true),
                "invalid vector {} was admitted",
                case["name"]
            );
        }
    }

    #[test]
    fn payment_terms_digest_binds_every_field_and_ignores_json_key_order() {
        let terms = sample_terms();
        let digest = terms.digest("pi_a");
        assert_ne!(digest, terms.digest("pi_b"));
        let mut changed = vec![];
        let mut t = terms.clone();
        t.amount_minor = "2000".into();
        changed.push(t);
        let mut t = terms.clone();
        t.payee.version += 1;
        changed.push(t);
        let mut t = terms.clone();
        t.funding_source.label = "Visa •••• 4243".into();
        changed.push(t);
        let mut t = terms.clone();
        t.actor = "other-runtime".into();
        changed.push(t);
        let mut t = terms.clone();
        t.execute_before += 1;
        changed.push(t);
        let mut t = terms.clone();
        t.currency_exponent = 3;
        changed.push(t);
        for t in changed {
            assert_ne!(t.digest("pi_a"), digest);
        }
        // Moving bytes between adjacent fields must not collide (length framing).
        let mut a = terms.clone();
        a.client_id = "ab".into();
        a.actor = "c".into();
        let mut b = terms.clone();
        b.client_id = "a".into();
        b.actor = "bc".into();
        assert_ne!(a.digest("pi_a"), b.digest("pi_a"));
        let reordered: PaymentTerms = serde_json::from_str(
            &serde_json::to_string(&serde_json::json!({
                "execute_before": terms.execute_before,
                "currency_exponent": terms.currency_exponent,
                "currency": terms.currency,
                "amount_minor": terms.amount_minor,
                "payee": {"name": terms.payee.name, "version": terms.payee.version, "id": terms.payee.id},
                "funding_source": {"label": terms.funding_source.label, "version": terms.funding_source.version, "id": terms.funding_source.id},
                "order_id": terms.order_id,
                "resource": terms.resource,
                "actor": terms.actor,
                "client_id": terms.client_id,
                "payer": terms.payer,
                "tenant": terms.tenant,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reordered.digest("pi_a"), digest);
    }

    #[test]
    fn payment_amount_rules_are_exact() {
        assert_eq!(parse_amount_minor("1"), Some(1));
        assert_eq!(
            parse_amount_minor("999999999999999999"),
            Some(999_999_999_999_999_999)
        );
        for bad in [
            "", "0", "00", "01", "-1", "+1", "1.0", "1e3", " 1", "1 ", "１",
        ] {
            assert_eq!(parse_amount_minor(bad), None, "{bad:?}");
        }
        assert_eq!(parse_amount_minor("1000000000000000000"), None);
    }
}
