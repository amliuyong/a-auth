//! CIBA/device 态 ↔ 004 AuthzState 映射(spec 013 C6.4)——复用 004 枚举 + 语义澄清。
//!
//! 不新增 004 枚举值(避免 parse/count_active/transition 不一致);CIBA/device 各态映射到已有 AuthzState,
//! 记录另存 `flow_kind` 区分协议来源。此处给出映射的**权威字符串对照**(004 的 AuthzState::as_str 口径)。

/// CIBA/device 的协议态(对外语义)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CibaState {
    /// 异地待批(≤15min)。
    AuthorizationPending,
    /// device:等用户在另一端输入 user_code。
    AwaitingUserCode,
    /// 已批准、等客户端轮询取 token。
    ApprovedAwaitingPoll,
    /// 取到 token(终态)。
    Complete,
    /// 用户拒绝(终态)。
    Denied,
    /// 过期(终态)。
    Expired,
}

/// 映射到 004 `AuthzState` 的字符串(与 authn::authz_session::AuthzState::as_str 一致)。
/// 复用现有枚举:pending→pending_consent、await_code→pending_user_authentication、
/// approved→code_issued_awaiting_exchange、complete/denied/expired 直映。
pub fn ciba_state_str(s: CibaState) -> &'static str {
    match s {
        CibaState::AuthorizationPending => "pending_consent",
        CibaState::AwaitingUserCode => "pending_user_authentication",
        CibaState::ApprovedAwaitingPoll => "code_issued_awaiting_exchange",
        CibaState::Complete => "complete",
        CibaState::Denied => "denied",
        CibaState::Expired => "expired",
    }
}

/// CIBA/device 态的**单调序号**(spec 004 §3.3 / C6.5 事件投影用)。CIBA/device 记录**无 sequence 字段**
/// (轮询热记录不宜加计数器),但每个生命周期态在一次授权里**至多出现一次**,故用"态 → 固定序号"派生
/// 单调序号——消费方按 (投影键, sequence) 去重排序即得正确迁移序列,无需存储计数器。
/// 序号反映生命周期先后:pending(0/1)→ approved(2)→ 终态(complete/denied/expired 3);await_code=1
/// (device 先等输码再批准)。终态互斥(一次授权只走其一),共享 3 不冲突。
pub fn ciba_state_seq(s: CibaState) -> u64 {
    match s {
        CibaState::AuthorizationPending => 0,
        CibaState::AwaitingUserCode => 1,
        CibaState::ApprovedAwaitingPoll => 2,
        CibaState::Complete | CibaState::Denied | CibaState::Expired => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_to_existing_004_states() {
        // 映射目标必须是 004 AuthzState 已有的字符串(不发明新态)。
        let valid = [
            "pending_consent",
            "pending_user_authentication",
            "code_issued_awaiting_exchange",
            "complete",
            "denied",
            "expired",
        ];
        for s in [
            CibaState::AuthorizationPending,
            CibaState::AwaitingUserCode,
            CibaState::ApprovedAwaitingPoll,
            CibaState::Complete,
            CibaState::Denied,
            CibaState::Expired,
        ] {
            assert!(
                valid.contains(&ciba_state_str(s)),
                "{:?} 映射到非 004 态",
                s
            );
        }
    }

    #[test]
    fn approved_maps_to_awaiting_exchange_not_code() {
        // 已批待取语义 = "授权已定、等客户端来 /token 取",复用 code_issued_awaiting_exchange。
        assert_eq!(
            ciba_state_str(CibaState::ApprovedAwaitingPoll),
            "code_issued_awaiting_exchange"
        );
    }

    #[test]
    fn state_seq_monotonic_across_lifecycle() {
        // 序号按生命周期先后单调:pending < awaiting_poll < 终态;await_code(device)在 pending 与 approved 间。
        assert!(
            ciba_state_seq(CibaState::AuthorizationPending)
                < ciba_state_seq(CibaState::ApprovedAwaitingPoll)
        );
        assert!(
            ciba_state_seq(CibaState::AwaitingUserCode)
                < ciba_state_seq(CibaState::ApprovedAwaitingPoll)
        );
        assert!(
            ciba_state_seq(CibaState::ApprovedAwaitingPoll) < ciba_state_seq(CibaState::Complete)
        );
        // 终态互斥,共享同一序号(一次授权只走其一)。
        assert_eq!(
            ciba_state_seq(CibaState::Complete),
            ciba_state_seq(CibaState::Denied)
        );
        assert_eq!(
            ciba_state_seq(CibaState::Denied),
            ciba_state_seq(CibaState::Expired)
        );
    }
}
