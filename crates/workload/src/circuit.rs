//! STS 调用**熔断器纯逻辑**(spec 012 C5.4)——零 IO、零时钟(`now` 由调用方传入)。
//!
//! SigV4/STS 兜底是签发热路径上的同步外部依赖;STS 慢/挂时 MUST NOT 拖垮 `/token`。故对该路径加
//! 熔断:**连续 5 次超时/5xx → 打开(Open)**;**30s 后半开(HalfOpen)放一个探针**;探针成功 → 关闭
//! (Closed)、探针失败 → 重新打开。熔断打开期间 workload 认证快速失败(IO 层返 503),不长挂、不雪崩。
//!
//! 本模块只做**状态机 + 判定**(纯逻辑,确定性可测);超时本身(2s)、真实 STS 调用、状态持有
//! (`Arc<Mutex<CircuitBreaker>>`)在 IO 层(http 适配器)。决策真相源 docs §3.1 / §8;CONFORMANCE C5.4。

/// 连续失败多少次打开熔断(评审 M4)。
pub const FAILURE_THRESHOLD: u32 = 5;
/// 打开后多久转半开(秒)。
pub const OPEN_COOLDOWN_SECS: i64 = 30;

/// 熔断器状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// 正常:放行请求;累计连续失败。
    Closed,
    /// 打开:快速失败(不外呼);`opened_at` 起 `OPEN_COOLDOWN_SECS` 后可转半开。
    Open { opened_at: i64 },
    /// 半开:只放**一个**探针;成功 → Closed,失败 → Open。探针在途时其余请求仍快速失败。
    HalfOpen { probe_in_flight: bool },
}

/// 一次"是否放行"判定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 放行(Closed 常态,或 HalfOpen 的那个探针)。
    Allow,
    /// 快速失败(熔断打开且未到冷却,或半开已有探针在途)——IO 层返 503。
    Reject,
}

/// STS 熔断器(纯状态机)。IO 层持有(`Arc<Mutex<_>>`),每次 STS 调用前 `on_request(now)`,
/// 调用后按结果 `on_success()` / `on_failure(now)`。
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    state: CircuitState,
    /// Closed 态下的连续失败计数(成功清零)。
    consecutive_failures: u32,
    failure_threshold: u32,
    cooldown_secs: i64,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(FAILURE_THRESHOLD, OPEN_COOLDOWN_SECS)
    }
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown_secs: i64) -> Self {
        CircuitBreaker {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            failure_threshold: failure_threshold.max(1),
            cooldown_secs: cooldown_secs.max(0),
        }
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// 请求前判定是否放行(可能触发 Open→HalfOpen 的时间驱动转移)。**有副作用**:
    /// - Open 且已过冷却 → 转 HalfOpen 并放行该探针(标 `probe_in_flight`);
    /// - HalfOpen 且探针在途 → Reject(只允许一个探针);
    /// - Closed → Allow。
    pub fn on_request(&mut self, now: i64) -> Decision {
        match self.state {
            CircuitState::Closed => Decision::Allow,
            CircuitState::Open { opened_at } => {
                if now.saturating_sub(opened_at) >= self.cooldown_secs {
                    // 冷却已过 → 半开,放这一个探针。
                    self.state = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Decision::Allow
                } else {
                    Decision::Reject
                }
            }
            CircuitState::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    // 已有探针在途,其余请求快速失败。
                    Decision::Reject
                } else {
                    // 探针位空(理论上 on_request 会立即占用;防御性:放一个并占位)。
                    self.state = CircuitState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Decision::Allow
                }
            }
        }
    }

    /// STS 调用成功:Closed 清失败计数;HalfOpen 探针成功 → Closed(恢复)。
    pub fn on_success(&mut self) {
        self.state = CircuitState::Closed;
        self.consecutive_failures = 0;
    }

    /// STS 调用失败(超时 / 5xx):
    /// - Closed:连续失败 +1,达阈值 → Open;
    /// - HalfOpen 探针失败:重新 Open(冷却重新计时);
    /// - Open:维持(不重置计时,避免失败风暴无限推后冷却——以首次 opened_at 为准)。
    pub fn on_failure(&mut self, now: i64) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                if self.consecutive_failures >= self.failure_threshold {
                    self.state = CircuitState::Open { opened_at: now };
                }
            }
            CircuitState::HalfOpen { .. } => {
                // 探针失败 → 重新打开,冷却重新计时。
                self.state = CircuitState::Open { opened_at: now };
            }
            CircuitState::Open { .. } => {
                // 已打开:维持(不刷新 opened_at)。
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_allows_and_counts_failures() {
        let mut cb = CircuitBreaker::default();
        assert_eq!(cb.on_request(0), Decision::Allow);
        // 4 次失败还不打开。
        for i in 0..4 {
            cb.on_failure(i);
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.on_request(10), Decision::Allow, "未达阈值仍放行");
    }

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let mut cb = CircuitBreaker::default();
        for i in 0..FAILURE_THRESHOLD as i64 {
            cb.on_failure(i);
        }
        assert!(
            matches!(cb.state(), CircuitState::Open { .. }),
            "5 连败应打开"
        );
        assert_eq!(cb.on_request(5), Decision::Reject, "打开期快速失败");
    }

    #[test]
    fn success_resets_failure_count() {
        let mut cb = CircuitBreaker::default();
        cb.on_failure(0);
        cb.on_failure(1);
        cb.on_success(); // 清零
        for i in 2..(2 + FAILURE_THRESHOLD as i64 - 1) {
            cb.on_failure(i);
        }
        // 成功清零后只累计了 threshold-1 次,不应打开。
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn open_transitions_to_halfopen_after_cooldown() {
        assert_eq!(
            OPEN_COOLDOWN_SECS, 30,
            "C5.4 requires a literal thirty-second cooldown"
        );
        let mut cb = CircuitBreaker::default();
        for i in 0..FAILURE_THRESHOLD as i64 {
            cb.on_failure(i);
        }
        let opened_at = match cb.state() {
            CircuitState::Open { opened_at } => opened_at,
            s => panic!("应 Open,实为 {s:?}"),
        };
        // 冷却未过 → Reject。
        assert_eq!(cb.on_request(opened_at + 29), Decision::Reject);
        // 冷却到点 → 半开放一个探针。
        assert_eq!(cb.on_request(opened_at + 30), Decision::Allow);
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen {
                probe_in_flight: true
            }
        );
    }

    #[test]
    fn halfopen_probe_success_closes() {
        let mut cb = CircuitBreaker::new(2, 10);
        cb.on_failure(0);
        cb.on_failure(1); // Open@1
        assert_eq!(cb.on_request(11), Decision::Allow); // 半开探针
        cb.on_success(); // 探针成功 → Closed
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.on_request(12), Decision::Allow);
    }

    #[test]
    fn halfopen_probe_failure_reopens_with_fresh_cooldown() {
        let mut cb = CircuitBreaker::new(2, 10);
        cb.on_failure(0);
        cb.on_failure(1); // Open@1
        assert_eq!(cb.on_request(11), Decision::Allow); // 半开探针@11
        cb.on_failure(11); // 探针失败 → 重新 Open@11
        match cb.state() {
            CircuitState::Open { opened_at } => assert_eq!(opened_at, 11, "冷却重新计时"),
            s => panic!("探针失败应重新 Open,实为 {s:?}"),
        }
        // 新冷却窗内仍 Reject。
        assert_eq!(cb.on_request(11 + 9), Decision::Reject);
    }

    #[test]
    fn halfopen_second_request_rejected_while_probe_in_flight() {
        let mut cb = CircuitBreaker::new(1, 5);
        cb.on_failure(0); // Open@0
        assert_eq!(cb.on_request(5), Decision::Allow); // 探针占位
        assert_eq!(
            cb.on_request(5),
            Decision::Reject,
            "探针在途,并发请求快速失败"
        );
    }

    #[test]
    fn open_failure_does_not_refresh_cooldown() {
        let mut cb = CircuitBreaker::new(1, 10);
        cb.on_failure(0); // Open@0
        cb.on_failure(5); // 打开期再失败:不刷新 opened_at
                          // 仍以 opened_at=0 计冷却:t=10 应可半开。
        assert_eq!(cb.on_request(10), Decision::Allow);
    }
}
