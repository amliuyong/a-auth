//! Product-level authentication assurance classes and step-up policy (C12.4).
//!
//! These classes are deliberately not NIST AAL claims. They are stable values
//! local to Agent Auth. External `acr` values only become `Strong` through an
//! explicit tenant/IdP allowlist; arbitrary `amr` strings never elevate an
//! upstream authentication event.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BASELINE_ACR: &str = "urn:agent-auth:assurance:baseline";
pub const STRONG_ACR: &str = "urn:agent-auth:assurance:strong";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceClass {
    Baseline,
    Strong,
}

impl AssuranceClass {
    pub const fn acr(self) -> &'static str {
        match self {
            Self::Baseline => BASELINE_ACR,
            Self::Strong => STRONG_ACR,
        }
    }

    pub fn from_internal_acr(value: &str) -> Option<Self> {
        match value {
            BASELINE_ACR => Some(Self::Baseline),
            STRONG_ACR => Some(Self::Strong),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcrValuesError {
    NoSupportedValue,
}

/// Select the first supported class from an RFC 9470/OIDC preference list.
pub fn requested_class(acr_values: Option<&str>) -> Result<Option<AssuranceClass>, AcrValuesError> {
    let Some(values) = acr_values.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    values
        .split_whitespace()
        .find_map(AssuranceClass::from_internal_acr)
        .map(Some)
        .ok_or(AcrValuesError::NoSupportedValue)
}

/// Classify a session from the canonical ACR assigned by the verified login
/// flow. AMR remains observational and never elevates a session.
pub fn classify_local_session(acr: Option<&str>, _amr: &[String]) -> AssuranceClass {
    acr.and_then(AssuranceClass::from_internal_acr)
        .unwrap_or(AssuranceClass::Baseline)
}

/// Map a verified upstream event into the internal model. `amr` is accepted
/// only for observability and never used as an elevation input.
pub fn classify_upstream(
    upstream_acr: Option<&str>,
    _upstream_amr: &[String],
    strong_acr_allowlist: &[String],
) -> AssuranceClass {
    if upstream_acr.is_some_and(|acr| strong_acr_allowlist.iter().any(|allowed| allowed == acr)) {
        AssuranceClass::Strong
    } else {
        AssuranceClass::Baseline
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssurancePolicy {
    strong_max_age_secs: i64,
    high_risk_rar_actions: BTreeSet<String>,
    high_risk_admin_actions: BTreeSet<String>,
}

impl Default for AssurancePolicy {
    fn default() -> Self {
        Self::new(300, ["transfer".to_string()], ["access.manage".to_string()])
            .expect("built-in assurance policy is valid")
    }
}

impl AssurancePolicy {
    pub fn new(
        strong_max_age_secs: i64,
        high_risk_rar_actions: impl IntoIterator<Item = String>,
        high_risk_admin_actions: impl IntoIterator<Item = String>,
    ) -> Result<Self, &'static str> {
        if !(1..=3600).contains(&strong_max_age_secs) {
            return Err("strong_max_age_secs must be between 1 and 3600");
        }
        let high_risk_rar_actions = normalized_set(high_risk_rar_actions)?;
        let high_risk_admin_actions = normalized_set(high_risk_admin_actions)?;
        Ok(Self {
            strong_max_age_secs,
            high_risk_rar_actions,
            high_risk_admin_actions,
        })
    }

    pub const fn strong_max_age_secs(&self) -> i64 {
        self.strong_max_age_secs
    }

    pub fn rar_requires_strong(&self, authorization_details: &[Value]) -> bool {
        authorization_details.iter().any(|detail| {
            detail
                .get("actions")
                .and_then(Value::as_array)
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|action| self.high_risk_rar_actions.contains(action))
                })
        })
    }

    pub fn admin_requires_strong(&self, action: &str) -> bool {
        self.high_risk_admin_actions.contains(action)
    }

    pub fn high_risk_rar_actions(&self) -> impl Iterator<Item = &str> {
        self.high_risk_rar_actions.iter().map(String::as_str)
    }

    pub fn high_risk_admin_actions(&self) -> impl Iterator<Item = &str> {
        self.high_risk_admin_actions.iter().map(String::as_str)
    }
}

fn normalized_set(
    values: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>, &'static str> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .try_fold(BTreeSet::new(), |mut set, value| {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_whitespace) {
                return Err("assurance policy actions must be non-empty tokens");
            }
            set.insert(value);
            Ok(set)
        })
}

pub fn authentication_is_fresh(auth_time: i64, now: i64, max_age_secs: i64) -> bool {
    max_age_secs >= 0 && auth_time <= now && now.saturating_sub(auth_time) <= max_age_secs
}

/// Accept bounded upstream clock skew without storing a future authentication
/// time or extending the effective freshness window.
pub fn normalize_auth_time(auth_time: i64, now: i64, max_future_skew_secs: i64) -> Option<i64> {
    if max_future_skew_secs < 0 || auth_time > now.saturating_add(max_future_skew_secs) {
        None
    } else {
        Some(auth_time.min(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_acr_controls_session_assurance_not_amr() {
        assert_eq!(
            classify_local_session(
                Some(STRONG_ACR),
                &["webauthn".to_string(), "hwk".to_string()]
            ),
            AssuranceClass::Strong
        );
        assert_eq!(
            classify_local_session(
                Some(BASELINE_ACR),
                &["webauthn".to_string(), "hwk".to_string()]
            ),
            AssuranceClass::Baseline,
            "passkey-shaped upstream AMR cannot override a mapped baseline ACR"
        );
        assert_eq!(
            classify_local_session(None, &["webauthn".to_string(), "hwk".to_string()]),
            AssuranceClass::Baseline
        );
    }

    #[test]
    fn upstream_only_elevates_through_explicit_acr_mapping() {
        let amr = vec!["pwd".to_string(), "mfa".to_string(), "otp".to_string()];
        assert_eq!(
            classify_upstream(Some("urn:customer:mfa"), &amr, &[]),
            AssuranceClass::Baseline,
            "untrusted amr and an unknown acr must not elevate"
        );
        assert_eq!(
            classify_upstream(
                Some("urn:customer:mfa"),
                &amr,
                &["urn:customer:mfa".to_string()]
            ),
            AssuranceClass::Strong
        );
    }

    #[test]
    fn acr_values_uses_first_supported_preference_and_rejects_unknown_only() {
        assert_eq!(
            requested_class(Some(&format!("unknown {STRONG_ACR} {BASELINE_ACR}"))),
            Ok(Some(AssuranceClass::Strong))
        );
        assert_eq!(
            requested_class(Some("unknown also-unknown")),
            Err(AcrValuesError::NoSupportedValue)
        );
        assert_eq!(requested_class(None), Ok(None));
    }

    #[test]
    fn default_policy_marks_transfer_and_access_management_high_risk() {
        let policy = AssurancePolicy::default();
        assert!(policy.rar_requires_strong(&[json!({
            "type": "agent_auth_rar_v1",
            "actions": ["read", "transfer"]
        })]));
        assert!(!policy.rar_requires_strong(&[json!({
            "type": "agent_auth_rar_v1",
            "actions": ["read"]
        })]));
        assert!(policy.admin_requires_strong("access.manage"));
        assert!(!policy.admin_requires_strong("tenant.read"));
    }

    #[test]
    fn freshness_is_bounded_and_rejects_future_events() {
        assert!(authentication_is_fresh(700, 1000, 300));
        assert!(!authentication_is_fresh(699, 1000, 300));
        assert!(!authentication_is_fresh(1001, 1000, 300));
        assert!(authentication_is_fresh(1000, 1000, 0));
        assert!(!authentication_is_fresh(999, 1000, 0));
    }

    #[test]
    fn upstream_auth_time_is_clamped_only_within_clock_skew() {
        assert_eq!(normalize_auth_time(900, 1000, 60), Some(900));
        assert_eq!(normalize_auth_time(1060, 1000, 60), Some(1000));
        assert_eq!(normalize_auth_time(1061, 1000, 60), None);
        assert_eq!(normalize_auth_time(1000, 1000, -1), None);
    }
}
