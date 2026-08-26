use agent_auth_ciba::PollOutcome;

use crate::ports::StoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollClaimAction {
    Proceed,
    SlowDown,
    TemporarilyUnavailable,
    ServerError,
}

pub(crate) fn classify_poll_claim(
    outcome: PollOutcome,
    result: Result<bool, StoreError>,
) -> PollClaimAction {
    match result {
        Ok(true) => PollClaimAction::Proceed,
        Ok(false) if outcome == PollOutcome::ExpiredToken => PollClaimAction::Proceed,
        Ok(false) => PollClaimAction::SlowDown,
        Err(StoreError::Transient(_)) => PollClaimAction::TemporarilyUnavailable,
        Err(StoreError::Permanent(_)) => PollClaimAction::ServerError,
    }
}

#[cfg(test)]
mod tests {
    use agent_auth_ciba::PollOutcome;

    use crate::ports::StoreError;

    use super::{classify_poll_claim, PollClaimAction};

    #[test]
    fn poll_claim_policy_preserves_expiry_and_fails_closed() {
        assert_eq!(
            classify_poll_claim(PollOutcome::ExpiredToken, Ok(false)),
            PollClaimAction::Proceed
        );
        assert_eq!(
            classify_poll_claim(PollOutcome::AuthorizationPending, Ok(false)),
            PollClaimAction::SlowDown
        );
        assert_eq!(
            classify_poll_claim(
                PollOutcome::AuthorizationPending,
                Err(StoreError::Transient("unavailable".to_string())),
            ),
            PollClaimAction::TemporarilyUnavailable
        );
        assert_eq!(
            classify_poll_claim(
                PollOutcome::AuthorizationPending,
                Err(StoreError::Permanent("corrupt".to_string())),
            ),
            PollClaimAction::ServerError
        );
    }
}
