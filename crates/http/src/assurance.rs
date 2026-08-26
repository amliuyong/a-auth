use agent_auth_authn::assurance::{
    authentication_is_fresh, classify_local_session, requested_class, AcrValuesError,
    AssuranceClass, AssurancePolicy,
};

use crate::ports::SessionRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequirementError {
    UnsupportedAcrValues,
    InvalidMaxAge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssuranceRequirement {
    pub class: AssuranceClass,
    pub max_age_secs: Option<i64>,
    pub step_up: bool,
}

pub(crate) fn resolve_requirement(
    policy: &AssurancePolicy,
    acr_values: Option<&str>,
    authorization_details: &[serde_json::Value],
    requested_max_age_secs: Option<i64>,
) -> Result<AssuranceRequirement, RequirementError> {
    if requested_max_age_secs.is_some_and(|value| value < 0) {
        return Err(RequirementError::InvalidMaxAge);
    }

    let requested = requested_class(acr_values).map_err(|error| match error {
        AcrValuesError::NoSupportedValue => RequirementError::UnsupportedAcrValues,
    })?;
    let policy_requires_strong = policy.rar_requires_strong(authorization_details);
    let class = if policy_requires_strong || requested == Some(AssuranceClass::Strong) {
        AssuranceClass::Strong
    } else {
        AssuranceClass::Baseline
    };
    let max_age_secs = if class == AssuranceClass::Strong {
        Some(
            requested_max_age_secs
                .unwrap_or(policy.strong_max_age_secs())
                .min(policy.strong_max_age_secs()),
        )
    } else {
        requested_max_age_secs
    };

    Ok(AssuranceRequirement {
        class,
        max_age_secs,
        step_up: policy_requires_strong || requested == Some(AssuranceClass::Strong),
    })
}

pub(crate) fn session_class(session: &SessionRecord) -> AssuranceClass {
    classify_local_session(session.acr.as_deref(), &session.amr)
}

pub(crate) fn session_satisfies(
    requirement: AssuranceRequirement,
    session: Option<&SessionRecord>,
    now: i64,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    if session_class(session) < requirement.class {
        return false;
    }
    // OIDC max_age=0 requires an active reauthentication event even when the
    // existing session was created in the same one-second clock tick.
    if requirement.max_age_secs == Some(0) {
        return false;
    }
    requirement
        .max_age_secs
        .is_none_or(|max_age| authentication_is_fresh(session.auth_time, now, max_age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_auth_authn::assurance::{BASELINE_ACR, STRONG_ACR};
    use serde_json::json;

    fn session(acr: &str, auth_time: i64) -> SessionRecord {
        SessionRecord {
            session_id: "session".into(),
            user_id: "user:test@example.com".into(),
            credential_epoch: 0,
            auth_time,
            created_at: auth_time,
            last_used_at: auth_time,
            device: "Test browser".into(),
            expires_at: auth_time + 3600,
            acr: Some(acr.into()),
            amr: Vec::new(),
        }
    }

    #[test]
    fn high_risk_rar_forces_fresh_strong_assurance() {
        let policy = AssurancePolicy::default();
        let requirement = resolve_requirement(
            &policy,
            Some(BASELINE_ACR),
            &[json!({"type": "agent_auth_rar_v1", "actions": ["transfer"]})],
            Some(900),
        )
        .unwrap();
        assert_eq!(requirement.class, AssuranceClass::Strong);
        assert_eq!(requirement.max_age_secs, Some(300));
        assert!(!session_satisfies(
            requirement,
            Some(&session(BASELINE_ACR, 900)),
            1000
        ));
        assert!(session_satisfies(
            requirement,
            Some(&session(STRONG_ACR, 900)),
            1000
        ));
        assert!(!session_satisfies(
            requirement,
            Some(&session(STRONG_ACR, 699)),
            1000
        ));
    }

    #[test]
    fn negative_max_age_is_rejected() {
        assert_eq!(
            resolve_requirement(&AssurancePolicy::default(), None, &[], Some(-1)),
            Err(RequirementError::InvalidMaxAge)
        );
    }

    #[test]
    fn max_age_zero_requires_reauthentication_in_the_same_clock_tick() {
        let requirement =
            resolve_requirement(&AssurancePolicy::default(), None, &[], Some(0)).unwrap();
        assert!(!session_satisfies(
            requirement,
            Some(&session(BASELINE_ACR, 1000)),
            1000
        ));
    }
}
