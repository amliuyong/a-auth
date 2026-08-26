//! 轮询决策(spec 013 C7b.2/C7b.4)——slow_down 瞬时判定 + 状态→标准错误码矩阵。纯逻辑。

/// 记录的持久状态(pending/approved/denied——由批准动作驱动;不含 slow_down,那是瞬时信号)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollStatus {
    /// 用户尚未批准。
    Pending,
    /// 用户已批准、等客户端轮询取 token。
    Approved,
    /// 用户已拒绝。
    Denied,
}

/// 一次轮询的结果(直接对应 `/token` 返回)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// 频率违规 → `slow_down`(优先于状态判定)。
    SlowDown,
    /// 审批中 → `authorization_pending`。
    AuthorizationPending,
    /// 已批准 → 签发 token(调用方据此走签发路径)。
    IssueToken,
    /// 用户拒绝 → `access_denied`。
    AccessDenied,
    /// 记录已过期 → `expired_token`。
    ExpiredToken,
    /// 已消费/重放/归属不符 → `invalid_grant`。
    InvalidGrant,
}

impl PollOutcome {
    /// 对应的 OAuth 错误码(IssueToken 无错误码,返回 None)。
    pub fn error_code(self) -> Option<&'static str> {
        match self {
            PollOutcome::SlowDown => Some("slow_down"),
            PollOutcome::AuthorizationPending => Some("authorization_pending"),
            PollOutcome::AccessDenied => Some("access_denied"),
            PollOutcome::ExpiredToken => Some("expired_token"),
            PollOutcome::InvalidGrant => Some("invalid_grant"),
            PollOutcome::IssueToken => None,
        }
    }
}

/// 轮询决策(C7b.2 矩阵)。顺序 fail-closed:
/// ①归属不符/已消费 → invalid_grant;②过期 → expired_token;③频率违规 → slow_down(先于状态);
/// ④按 status → pending/token/access_denied。
///
/// - `belongs_to_caller`:presented code 的记录 client_id == 认证调用方(归属校验)。
/// - `consumed`:已取过 token(一次性;重放拒)。
/// - `expires_at`/`now`:过期判定(fail-closed)。
/// - `last_poll_at`/`interval`:slow_down 判定(None = 首次轮询,不算过快)。
/// - `status`:记录持久态。
#[allow(clippy::too_many_arguments)]
pub fn poll_decision(
    belongs_to_caller: bool,
    consumed: bool,
    expires_at: i64,
    now: i64,
    last_poll_at: Option<i64>,
    interval: i64,
    status: PollStatus,
) -> PollOutcome {
    // ① 归属/一次性(不泄露:非本 caller 或已消费一律 invalid_grant)。
    if !belongs_to_caller || consumed {
        return PollOutcome::InvalidGrant;
    }
    // ② 过期(fail-closed;expires_at <= now 即过期)。
    if expires_at <= now {
        return PollOutcome::ExpiredToken;
    }
    // ③ 频率违规先判(即便 status 已 approved/denied,过快仍先 slow_down)。
    if let Some(last) = last_poll_at {
        if now - last < interval {
            return PollOutcome::SlowDown;
        }
    }
    // ④ 按持久态。
    match status {
        PollStatus::Pending => PollOutcome::AuthorizationPending,
        PollStatus::Approved => PollOutcome::IssueToken,
        PollStatus::Denied => PollOutcome::AccessDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 便捷:合规频率(距上次足够久)。
    fn ok_freq() -> (Option<i64>, i64, i64) {
        (Some(1000), 5, 1010) // last=1000, interval=5, now=1010 → 距 10s > 5s
    }

    #[test]
    fn belongs_and_consumed_gate_first() {
        // 非本 caller → invalid_grant(即便 status approved)。
        assert_eq!(
            poll_decision(
                false,
                false,
                9_999,
                1010,
                Some(1000),
                5,
                PollStatus::Approved
            ),
            PollOutcome::InvalidGrant
        );
        // 已消费 → invalid_grant。
        assert_eq!(
            poll_decision(true, true, 9_999, 1010, Some(1000), 5, PollStatus::Approved),
            PollOutcome::InvalidGrant
        );
    }

    #[test]
    fn expired_before_freq_and_status() {
        assert_eq!(
            poll_decision(true, false, 1005, 1010, Some(1000), 5, PollStatus::Approved),
            PollOutcome::ExpiredToken
        );
    }

    #[test]
    fn slow_down_precedes_status() {
        // 距上次仅 1s < interval 5s → slow_down,即便 status pending/approved/denied。
        for st in [
            PollStatus::Pending,
            PollStatus::Approved,
            PollStatus::Denied,
        ] {
            assert_eq!(
                poll_decision(true, false, 9_999, 1001, Some(1000), 5, st),
                PollOutcome::SlowDown
            );
        }
    }

    #[test]
    fn first_poll_no_slow_down() {
        // last_poll_at=None(首次)→ 不算过快,按 status。
        assert_eq!(
            poll_decision(true, false, 9_999, 1000, None, 5, PollStatus::Pending),
            PollOutcome::AuthorizationPending
        );
    }

    #[test]
    fn status_matrix_when_freq_ok() {
        let (last, iv, now) = ok_freq();
        assert_eq!(
            poll_decision(true, false, 9_999, now, last, iv, PollStatus::Pending),
            PollOutcome::AuthorizationPending
        );
        assert_eq!(
            poll_decision(true, false, 9_999, now, last, iv, PollStatus::Approved),
            PollOutcome::IssueToken
        );
        assert_eq!(
            poll_decision(true, false, 9_999, now, last, iv, PollStatus::Denied),
            PollOutcome::AccessDenied
        );
    }

    #[test]
    fn error_codes_map_to_standard() {
        assert_eq!(PollOutcome::SlowDown.error_code(), Some("slow_down"));
        assert_eq!(
            PollOutcome::AuthorizationPending.error_code(),
            Some("authorization_pending")
        );
        assert_eq!(
            PollOutcome::AccessDenied.error_code(),
            Some("access_denied")
        );
        assert_eq!(
            PollOutcome::ExpiredToken.error_code(),
            Some("expired_token")
        );
        assert_eq!(
            PollOutcome::InvalidGrant.error_code(),
            Some("invalid_grant")
        );
        assert_eq!(PollOutcome::IssueToken.error_code(), None);
    }

    #[test]
    fn advertised_interval_is_enforced_without_early_tolerance() {
        // interval=5:距 4s 仍在下发窗口内 → slow_down。
        assert_eq!(
            poll_decision(true, false, 9_999, 1004, Some(1000), 5, PollStatus::Pending),
            PollOutcome::SlowDown
        );
        // 恰好距 5s 才恢复按持久态返回。
        assert_eq!(
            poll_decision(true, false, 9_999, 1005, Some(1000), 5, PollStatus::Pending),
            PollOutcome::AuthorizationPending
        );
    }
}
