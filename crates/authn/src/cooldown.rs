//! C9.1 — per-email **固定窗口冷却**(fixed-window cooldown)。
//!
//! ⚠️ **不是令牌桶**:语义是"同一邮箱发出一封 magic-link 后,冷却窗口(如 60s)内 MUST NOT 再发"。
//! 令牌桶按速率补充令牌、攒够即可连发,起不到"刚发过就别再发"的冷却作用——故 per-email 冷却
//! 用固定窗口(记住上次发送时刻),**不复用** `infra_core::ratelimit` 的令牌桶。
//! (全局发信配额那一半才是令牌桶,防跨邮箱洪水,见 spec 003 Task 1.1 / `infra_core::ratelimit`。)
//!
//! 本模块纯时间戳判定、零 AWS 依赖:上次发送时刻由上层从 DynamoDB 读入、`now` 由上层传入
//! (不读墙上时钟)。时间单位 = Unix 秒。
//! 决策真相源:docs/DESIGN §7(magic-link 发信滥用)·§0.1;docs/CONFORMANCE C9.1。

/// per-email 冷却配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CooldownConfig {
    /// 冷却窗口秒数:一封发出后,该邮箱在此秒数内不再发。
    pub window_secs: i64,
}

impl CooldownConfig {
    pub fn new(window_secs: i64) -> Self {
        CooldownConfig { window_secs }
    }
}

/// 一次发信尝试的判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownDecision {
    /// 可发送:更新 `last_sent_at = now`(上层写回 DynamoDB 后再实际发信)。
    Allow,
    /// 冷却中:距离可再次发送还剩 `retry_after_secs` 秒(> 0)。
    Cooling { retry_after_secs: i64 },
}

/// 判定某邮箱此刻是否可再发 magic-link(C9.1 固定窗口冷却)。
/// - `last_sent_at`:该邮箱上次成功发信的 Unix 秒;`None` = 从未发过(首发允许)。
/// - `now`:当前 Unix 秒。
///
/// 冷却边界:`now >= last_sent_at + window` 才可再发(到点即放行,非严格大于)。
/// 时钟回拨(now < last_sent_at)按"仍在冷却"保守处理,retry_after 用整窗口(不为负)。
pub fn check(cfg: &CooldownConfig, last_sent_at: Option<i64>, now: i64) -> CooldownDecision {
    let Some(last) = last_sent_at else {
        return CooldownDecision::Allow; // 首发
    };
    let ready_at = last.saturating_add(cfg.window_secs);
    if now >= ready_at {
        CooldownDecision::Allow
    } else {
        // 剩余冷却时间;时钟回拨时 now < last,remaining 会 > window,用 saturating 防负、并封顶到窗口。
        let remaining = ready_at.saturating_sub(now);
        let capped = remaining.min(cfg.window_secs.max(0));
        CooldownDecision::Cooling {
            retry_after_secs: capped.max(1), // 冷却中至少回 1s,避免回 0 让客户端立即重试
        }
    }
}

/// 便捷:是否允许发送。
pub fn is_allowed(cfg: &CooldownConfig, last_sent_at: Option<i64>, now: i64) -> bool {
    matches!(check(cfg, last_sent_at, now), CooldownDecision::Allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: CooldownConfig = CooldownConfig { window_secs: 60 };

    // C9.1:首发(从未发过)允许。
    #[test]
    fn first_send_allowed() {
        assert_eq!(check(&CFG, None, 1000), CooldownDecision::Allow);
        assert!(is_allowed(&CFG, None, 1000));
    }

    // C9.1:刚发过、窗口内再触发 → 冷却中(不再发)。
    #[test]
    fn within_window_cooling() {
        // last=1000, now=1030, window=60 → ready_at=1060, remaining=30
        assert_eq!(
            check(&CFG, Some(1000), 1030),
            CooldownDecision::Cooling {
                retry_after_secs: 30
            }
        );
        assert!(!is_allowed(&CFG, Some(1000), 1030));
    }

    // C9.1:窗口边界(恰好到点)→ 放行。
    #[test]
    fn at_window_boundary_allowed() {
        assert_eq!(check(&CFG, Some(1000), 1060), CooldownDecision::Allow);
    }

    // C9.1:窗口过后 → 放行。
    #[test]
    fn after_window_allowed() {
        assert_eq!(check(&CFG, Some(1000), 2000), CooldownDecision::Allow);
    }

    // 冷却中刚触发(same instant)→ retry_after = 整窗口。
    #[test]
    fn immediate_retry_full_window() {
        assert_eq!(
            check(&CFG, Some(1000), 1000),
            CooldownDecision::Cooling {
                retry_after_secs: 60
            }
        );
    }

    // ⚠️ 非令牌桶语义验证:连续两次发信,第二次即使"攒了时间"也不能像令牌桶那样连发——
    // 冷却窗口内一律拒(令牌桶会因补充令牌而放行,固定窗口不会)。
    #[test]
    fn not_token_bucket_no_accrual() {
        // 发于 1000。窗口 60s。在 1059(还差 1s)再试 → 仍冷却,不因"快到了"放行。
        assert!(!is_allowed(&CFG, Some(1000), 1059));
        // 直到 1060 才放行。固定窗口:发后整窗口静默,不按速率累积额度。
        assert!(is_allowed(&CFG, Some(1000), 1060));
    }

    // 时钟回拨:now < last_sent_at → 保守视为冷却中,retry_after 不为负、封顶窗口。
    #[test]
    fn clock_regression_conservative() {
        let d = check(&CFG, Some(2000), 1000); // now 远早于 last
        match d {
            CooldownDecision::Cooling { retry_after_secs } => {
                assert!(retry_after_secs > 0 && retry_after_secs <= 60);
            }
            CooldownDecision::Allow => panic!("时钟回拨不应放行(保守冷却)"),
        }
    }

    // window=0 的退化配置:任何时候都放行(等价无冷却)。
    #[test]
    fn zero_window_always_allow() {
        let cfg = CooldownConfig::new(0);
        assert!(is_allowed(&cfg, Some(1000), 1000));
    }
}
