//! `agent_auth_payment_v1` RFC 9396 profile.
//!
//! Two shapes exist and neither accepts unknown members:
//!
//! - **request reference** (sent by the client to `/authorize`/`/par`):
//!   `{"type", "intent_id", ["locations"], ["actions"]}`. The AS never trusts
//!   amounts, payees or URLs from this object; it loads the frozen intent.
//! - **canonical detail** (stored in the code, Grant and token):
//!   `{"type", "locations", "actions", "intent_id", "terms_digest", "terms"}`,
//!   built only by [`canonical_detail`].
//!
//! Payment execution accepts exactly one canonical detail in the whole
//! `authorization_details` array. It does not reuse the generic SDK semantics
//! where a missing RAR falls back to scope or any applicable entry may allow.

use serde_json::{json, Value};

use crate::terms::{validate_intent_id, PaymentTerms};
use crate::{EXECUTE_ACTION, PAYMENT_RAR_TYPE};

const REQUEST_KEYS: &[&str] = &["type", "intent_id", "locations", "actions"];
const DETAIL_KEYS: &[&str] = &[
    "type",
    "locations",
    "actions",
    "intent_id",
    "terms_digest",
    "terms",
];

/// Profile shape violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The array also contains another entry (mixed or duplicated authorization).
    NotExactlyOneEntry,
    EntryNotObject,
    UnknownField(String),
    MissingField(&'static str),
    BadType,
    BadIntentId,
    BadLocations,
    BadActions,
    BadTerms,
    DigestMismatch,
}

/// Why an execution request does not carry the exact approved authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentAuthzError {
    /// No `authorization_details`, or none of the payment type.
    Missing,
    /// Malformed, mixed or unknown-member details.
    Malformed(ProfileError),
    IntentMismatch,
    ResourceMismatch,
    TermsMismatch,
    DigestMismatch,
}

/// What the payment resource expects for one execution.
#[derive(Debug, Clone, Copy)]
pub struct Expectation<'a> {
    pub resource: &'a str,
    pub intent_id: &'a str,
    pub terms: &'a PaymentTerms,
    pub terms_digest: &'a str,
}

/// True when `detail` declares the payment type (any shape).
pub fn is_payment_detail(detail: &Value) -> bool {
    detail.get("type").and_then(Value::as_str) == Some(PAYMENT_RAR_TYPE)
}

/// True when an `authorization_details` array contains a payment-typed entry.
pub fn contains_payment_detail(details: &Value) -> bool {
    details
        .as_array()
        .is_some_and(|entries| entries.iter().any(is_payment_detail))
}

/// Parse the client request reference.
///
/// Returns `Ok(None)` when no entry uses the payment type (the generic RAR
/// admission then applies unchanged), or the referenced intent id when the
/// array is exactly one well-formed reference for `resource`.
pub fn request_reference(details: &Value, resource: &str) -> Result<Option<String>, ProfileError> {
    if !contains_payment_detail(details) {
        return Ok(None);
    }
    let entries = details.as_array().expect("contains_payment_detail");
    if entries.len() != 1 {
        return Err(ProfileError::NotExactlyOneEntry);
    }
    let object = entries[0].as_object().ok_or(ProfileError::EntryNotObject)?;
    if let Some(key) = object
        .keys()
        .find(|key| !REQUEST_KEYS.contains(&key.as_str()))
    {
        return Err(ProfileError::UnknownField(key.clone()));
    }
    let intent_id = object
        .get("intent_id")
        .and_then(Value::as_str)
        .ok_or(ProfileError::MissingField("intent_id"))?;
    validate_intent_id(intent_id).map_err(|_| ProfileError::BadIntentId)?;
    if let Some(locations) = object.get("locations") {
        if !is_exact_string_list(locations, resource) {
            return Err(ProfileError::BadLocations);
        }
    }
    if let Some(actions) = object.get("actions") {
        if !is_exact_string_list(actions, EXECUTE_ACTION) {
            return Err(ProfileError::BadActions);
        }
    }
    Ok(Some(intent_id.to_string()))
}

/// Build the only canonical detail shape for validated terms.
pub fn canonical_detail(intent_id: &str, terms: &PaymentTerms) -> Value {
    json!({
        "type": PAYMENT_RAR_TYPE,
        "locations": [terms.resource],
        "actions": [EXECUTE_ACTION],
        "intent_id": intent_id,
        "terms_digest": terms.digest(intent_id),
        "terms": terms,
    })
}

/// Strictly parse one canonical detail and recompute its digest.
pub fn parse_canonical_detail(detail: &Value) -> Result<(String, PaymentTerms), ProfileError> {
    let object = detail.as_object().ok_or(ProfileError::EntryNotObject)?;
    if let Some(key) = object
        .keys()
        .find(|key| !DETAIL_KEYS.contains(&key.as_str()))
    {
        return Err(ProfileError::UnknownField(key.clone()));
    }
    for key in DETAIL_KEYS {
        if !object.contains_key(*key) {
            return Err(ProfileError::MissingField(key));
        }
    }
    if object.get("type").and_then(Value::as_str) != Some(PAYMENT_RAR_TYPE) {
        return Err(ProfileError::BadType);
    }
    let intent_id = object
        .get("intent_id")
        .and_then(Value::as_str)
        .ok_or(ProfileError::BadIntentId)?;
    validate_intent_id(intent_id).map_err(|_| ProfileError::BadIntentId)?;
    let terms: PaymentTerms =
        serde_json::from_value(object["terms"].clone()).map_err(|_| ProfileError::BadTerms)?;
    terms.validate().map_err(|_| ProfileError::BadTerms)?;
    if !is_exact_string_list(&object["locations"], &terms.resource) {
        return Err(ProfileError::BadLocations);
    }
    if !is_exact_string_list(&object["actions"], EXECUTE_ACTION) {
        return Err(ProfileError::BadActions);
    }
    if object.get("terms_digest").and_then(Value::as_str) != Some(terms.digest(intent_id).as_str())
    {
        return Err(ProfileError::DigestMismatch);
    }
    Ok((intent_id.to_string(), terms))
}

/// The payment-specific authorization check performed before acceptance.
///
/// `details` is the online-introspected `authorization_details`. The whole
/// array must be exactly the one canonical detail for this intent; a missing
/// array, an additional generic entry or a second payment entry is rejected.
pub fn verify_execution(
    details: Option<&Value>,
    expected: &Expectation<'_>,
) -> Result<(), PaymentAuthzError> {
    let Some(details) = details else {
        return Err(PaymentAuthzError::Missing);
    };
    let Some(entries) = details.as_array() else {
        return Err(PaymentAuthzError::Malformed(ProfileError::EntryNotObject));
    };
    if !entries.iter().any(is_payment_detail) {
        return Err(PaymentAuthzError::Missing);
    }
    if entries.len() != 1 {
        return Err(PaymentAuthzError::Malformed(
            ProfileError::NotExactlyOneEntry,
        ));
    }
    let (intent_id, terms) =
        parse_canonical_detail(&entries[0]).map_err(PaymentAuthzError::Malformed)?;
    if intent_id != expected.intent_id {
        return Err(PaymentAuthzError::IntentMismatch);
    }
    if terms.resource != expected.resource {
        return Err(PaymentAuthzError::ResourceMismatch);
    }
    if &terms != expected.terms {
        return Err(PaymentAuthzError::TermsMismatch);
    }
    if terms.digest(&intent_id) != expected.terms_digest {
        return Err(PaymentAuthzError::DigestMismatch);
    }
    Ok(())
}

fn is_exact_string_list(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.len() == 1 && items[0].as_str() == Some(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::tests::sample_terms;

    const RESOURCE: &str = "https://payments.example";

    fn expectation<'a>(terms: &'a PaymentTerms, digest: &'a str) -> Expectation<'a> {
        Expectation {
            resource: RESOURCE,
            intent_id: "pi_one",
            terms,
            terms_digest: digest,
        }
    }

    #[test]
    fn payment_request_reference_accepts_only_one_exact_reference() {
        assert_eq!(
            request_reference(&json!([{"type":"agent_auth_rar_v1"}]), RESOURCE),
            Ok(None)
        );
        assert_eq!(request_reference(&json!({"type":"x"}), RESOURCE), Ok(None));
        assert_eq!(
            request_reference(
                &json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one"}]),
                RESOURCE
            ),
            Ok(Some("pi_one".into()))
        );
        assert_eq!(
            request_reference(
                &json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","locations":[RESOURCE],"actions":["execute"]}]),
                RESOURCE
            ),
            Ok(Some("pi_one".into()))
        );
        let rejected = [
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one"},{"type":"agent_auth_rar_v1"}]),
                ProfileError::NotExactlyOneEntry,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one"},{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_two"}]),
                ProfileError::NotExactlyOneEntry,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","amount_minor":"1"}]),
                ProfileError::UnknownField("amount_minor".into()),
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","terms":{}}]),
                ProfileError::UnknownField("terms".into()),
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE}]),
                ProfileError::MissingField("intent_id"),
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi one"}]),
                ProfileError::BadIntentId,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","locations":["https://evil.example"]}]),
                ProfileError::BadLocations,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","locations":[RESOURCE,RESOURCE]}]),
                ProfileError::BadLocations,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","actions":["execute","refund"]}]),
                ProfileError::BadActions,
            ),
            (
                json!([{"type":PAYMENT_RAR_TYPE,"intent_id":"pi_one","actions":["transfer"]}]),
                ProfileError::BadActions,
            ),
        ];
        for (details, error) in rejected {
            assert_eq!(
                request_reference(&details, RESOURCE),
                Err(error),
                "{details}"
            );
        }
    }

    #[test]
    fn payment_canonical_detail_round_trips_and_rejects_unknown_members() {
        let terms = sample_terms();
        let detail = canonical_detail("pi_one", &terms);
        assert_eq!(
            parse_canonical_detail(&detail),
            Ok(("pi_one".into(), terms.clone()))
        );
        let mut extra = detail.clone();
        extra["max_amount"] = json!("1");
        assert_eq!(
            parse_canonical_detail(&extra),
            Err(ProfileError::UnknownField("max_amount".into()))
        );
        let mut nested = detail.clone();
        nested["terms"]["fee_minor"] = json!("10");
        assert_eq!(parse_canonical_detail(&nested), Err(ProfileError::BadTerms));
        let mut missing = detail.clone();
        missing.as_object_mut().unwrap().remove("terms_digest");
        assert_eq!(
            parse_canonical_detail(&missing),
            Err(ProfileError::MissingField("terms_digest"))
        );
        let mut tampered = detail.clone();
        tampered["terms"]["amount_minor"] = json!("1");
        assert_eq!(
            parse_canonical_detail(&tampered),
            Err(ProfileError::DigestMismatch)
        );
        let mut version = detail.clone();
        version["type"] = json!("agent_auth_payment_v2");
        assert_eq!(parse_canonical_detail(&version), Err(ProfileError::BadType));
        let mut actions = detail;
        actions["actions"] = json!(["execute", "refund"]);
        assert_eq!(
            parse_canonical_detail(&actions),
            Err(ProfileError::BadActions)
        );
    }

    #[test]
    fn payment_execution_requires_exactly_the_approved_detail() {
        let terms = sample_terms();
        let digest = terms.digest("pi_one");
        let expected = expectation(&terms, &digest);
        let detail = canonical_detail("pi_one", &terms);
        assert_eq!(
            verify_execution(Some(&json!([detail.clone()])), &expected),
            Ok(())
        );
        assert_eq!(
            verify_execution(None, &expected),
            Err(PaymentAuthzError::Missing)
        );
        assert_eq!(
            verify_execution(Some(&json!([])), &expected),
            Err(PaymentAuthzError::Missing)
        );
        assert_eq!(
            verify_execution(
                Some(&json!([{"type":"agent_auth_rar_v1","locations":[RESOURCE]}])),
                &expected
            ),
            Err(PaymentAuthzError::Missing),
            "a permissive generic entry is not a payment authorization"
        );
        assert_eq!(
            verify_execution(
                Some(&json!([detail.clone(), {"type":"agent_auth_rar_v1"}])),
                &expected
            ),
            Err(PaymentAuthzError::Malformed(
                ProfileError::NotExactlyOneEntry
            ))
        );
        assert_eq!(
            verify_execution(Some(&json!([detail.clone(), detail.clone()])), &expected),
            Err(PaymentAuthzError::Malformed(
                ProfileError::NotExactlyOneEntry
            ))
        );
        let other_intent = canonical_detail("pi_two", &terms);
        assert_eq!(
            verify_execution(Some(&json!([other_intent])), &expected),
            Err(PaymentAuthzError::IntentMismatch)
        );
        let mut other_terms = terms.clone();
        other_terms.amount_minor = "2000".into();
        assert_eq!(
            verify_execution(
                Some(&json!([canonical_detail("pi_one", &other_terms)])),
                &expected
            ),
            Err(PaymentAuthzError::TermsMismatch)
        );
        let mut other_resource = terms.clone();
        other_resource.resource = "https://other-payments.example".into();
        assert_eq!(
            verify_execution(
                Some(&json!([canonical_detail("pi_one", &other_resource)])),
                &expected
            ),
            Err(PaymentAuthzError::ResourceMismatch)
        );
        let stale = expectation(&terms, "stale-digest");
        assert_eq!(
            verify_execution(Some(&json!([detail])), &stale),
            Err(PaymentAuthzError::DigestMismatch)
        );
    }
}
