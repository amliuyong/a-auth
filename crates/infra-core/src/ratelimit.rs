//! C10.7 / C10.8 — 应用层限流令牌桶(纯算法)。
//!
//! - **C10.7**:按 `client_id` 的主控限流闸落**应用层**(Lambda + DynamoDB 令牌桶/计数)。
//!   WAF 抓不到 `POST /token` body 里的 `client_id`(public 客户端 client_id 在 form body),
//!   故 WAF 只做 IP/Host/ASN 粗兜底,MUST NOT 承担 per-client_id 限流(见 DESIGN §3.2/§8)。
//! - **C10.8**:匿名/首次 `POST /register`(client_id 未铸造、per-client 限流有绕过口)MUST 用
//!   per-IP 粗兜底 + 全局配额,注册后再切 client_id 维度(见 DESIGN §3.2 零配置边界)。
//!
//! 本模块是令牌桶的**纯状态转移**:桶状态(tokens/last_refill)+ `now` 进,放行判定 + 新状态出。
//! DynamoDB 读改写(条件更新持久化桶状态)在 Lambda 层,不在此。`now` 由上层传入(不读墙上时钟)。
//! 决策真相源:docs/DESIGN §3.2·§8;docs/CONFORMANCE C10.7·C10.8。

/// 令牌桶配置:容量(突发上限)+ 每秒填充速率。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BucketConfig {
    /// 桶容量(允许的最大突发 token 数)。
    pub capacity: f64,
    /// 每秒填充的 token 数(稳态速率)。
    pub refill_per_sec: f64,
}

impl BucketConfig {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        BucketConfig {
            capacity,
            refill_per_sec,
        }
    }
}

/// 桶的可变状态(持久化在 DynamoDB;本模块只做纯转移)。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BucketState {
    /// 当前可用 token 数。
    pub tokens: f64,
    /// 上次填充时刻(Unix 秒,可为小数)。
    pub last_refill: f64,
}

impl BucketState {
    /// 新桶:初始装满(容量),从 `now` 起计。
    pub fn full(cfg: &BucketConfig, now: f64) -> Self {
        BucketState {
            tokens: cfg.capacity,
            last_refill: now,
        }
    }
}

/// 一次取 token 的结果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Decision {
    /// 是否放行(有足够 token)。
    pub allowed: bool,
    /// 取用(或拒绝)后的桶新状态——上层据此条件写回 DynamoDB。
    pub state: BucketState,
    /// 放行后剩余 token(拒绝时为当前可用量,便于填 `Retry-After` 估算)。
    pub remaining: f64,
}

/// 先按流逝时间补充 token(不超过容量),再尝试取 `cost` 个。
///
/// ⚠️ **时钟回拨安全**:持久化的 `last_refill` **永不倒退**——用 `effective_now = max(now, last_refill)`
/// 作为新 `last_refill`。若直接把 `last_refill` 写成回拨的 `now`,下次调用会从倒退时间戳重新计算
/// 流逝、凭空多补 token(绕过限流)。回拨时本次 elapsed=0(不倒扣、不多补)、且时间戳不落后。
pub fn try_acquire(cfg: &BucketConfig, state: BucketState, now: f64, cost: f64) -> Decision {
    // 时间永不倒退:即便本机 now 回拨,也不把桶的 last_refill 拉回过去。
    let effective_now = now.max(state.last_refill);
    let elapsed = effective_now - state.last_refill; // >= 0
    let refilled = (state.tokens + elapsed * cfg.refill_per_sec).min(cfg.capacity);

    if refilled >= cost {
        let after = refilled - cost;
        Decision {
            allowed: true,
            state: BucketState {
                tokens: after,
                last_refill: effective_now,
            },
            remaining: after,
        }
    } else {
        // 拒绝:不扣 token,但推进 last_refill 到 effective_now(已补充的量落袋,避免下次重复补)。
        Decision {
            allowed: false,
            state: BucketState {
                tokens: refilled,
                last_refill: effective_now,
            },
            remaining: refilled,
        }
    }
}

/// 估算 `Retry-After` 秒数:攒够 `cost` 个 token 还需多久(拒绝时用)。
/// - 已够 → `Some(0.0)`。
/// - `cost > capacity`:桶封顶 capacity,**永远攒不够** → `None`(永久拒,调用方 MUST NOT 让客户端空等)。
/// - 速率 ≤ 0:桶永不再充 → `None`(调用方应换更粗的兜底)。
pub fn retry_after_secs(cfg: &BucketConfig, state: BucketState, cost: f64) -> Option<f64> {
    if state.tokens >= cost {
        return Some(0.0);
    }
    if cost > cfg.capacity {
        return None; // 单次请求就超过桶容量,无论等多久都无法满足
    }
    if cfg.refill_per_sec <= 0.0 {
        return None;
    }
    Some((cost - state.tokens) / cfg.refill_per_sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    // C10.7:桶内有 token → 放行并扣减。
    #[test]
    fn acquire_within_capacity() {
        let cfg = BucketConfig::new(10.0, 1.0);
        let st = BucketState::full(&cfg, 0.0);
        let d = try_acquire(&cfg, st, 0.0, 1.0);
        assert!(d.allowed);
        assert_eq!(d.state.tokens, 9.0);
    }

    // C10.7:突发耗尽桶 → 超额被拒。
    #[test]
    fn burst_exhausts_then_rejects() {
        let cfg = BucketConfig::new(3.0, 1.0);
        let mut st = BucketState::full(&cfg, 0.0);
        for _ in 0..3 {
            let d = try_acquire(&cfg, st, 0.0, 1.0);
            assert!(d.allowed);
            st = d.state;
        }
        // 第 4 次同一时刻 → 无 token,拒。
        let d = try_acquire(&cfg, st, 0.0, 1.0);
        assert!(!d.allowed);
        assert_eq!(d.remaining, 0.0);
    }

    // C10.7:随时间填充,稳态速率放行。
    #[test]
    fn refills_over_time() {
        let cfg = BucketConfig::new(5.0, 2.0); // 2 token/s
        let st = BucketState {
            tokens: 0.0,
            last_refill: 100.0,
        };
        // 过 1.5s → 补 3 个 token。
        let d = try_acquire(&cfg, st, 101.5, 1.0);
        assert!(d.allowed);
        assert!((d.state.tokens - 2.0).abs() < 1e-9); // 3 补 - 1 取 = 2
    }

    // 填充不超过容量(突发上限)。
    #[test]
    fn refill_caps_at_capacity() {
        let cfg = BucketConfig::new(5.0, 10.0);
        let st = BucketState {
            tokens: 0.0,
            last_refill: 0.0,
        };
        let d = try_acquire(&cfg, st, 100.0, 1.0); // 过很久
        assert!(d.allowed);
        assert!((d.state.tokens - 4.0).abs() < 1e-9); // 封顶 5 - 1
    }

    // 时钟回拨不倒扣 token(elapsed 取 0)。
    #[test]
    fn clock_regression_no_penalty() {
        let cfg = BucketConfig::new(5.0, 1.0);
        let st = BucketState {
            tokens: 3.0,
            last_refill: 200.0,
        };
        let d = try_acquire(&cfg, st, 100.0, 1.0); // now < last_refill
        assert!(d.allowed);
        assert_eq!(d.state.tokens, 2.0); // 3 - 1,未因回拨多补/倒扣
    }

    // C10.8:全局/per-IP 兜底用同一算法,cost 可 >1(批量注册按权重扣)。
    #[test]
    fn multi_cost_acquire() {
        let cfg = BucketConfig::new(10.0, 1.0);
        let st = BucketState::full(&cfg, 0.0);
        let d = try_acquire(&cfg, st, 0.0, 4.0);
        assert!(d.allowed);
        assert_eq!(d.state.tokens, 6.0);
        // 再取 7 个 → 不足,拒。
        let d2 = try_acquire(&cfg, d.state, 0.0, 7.0);
        assert!(!d2.allowed);
    }

    // Retry-After 估算:攒够差额所需秒数。
    #[test]
    fn retry_after_estimate() {
        let cfg = BucketConfig::new(10.0, 2.0);
        let st = BucketState {
            tokens: 1.0,
            last_refill: 0.0,
        };
        // 需 3 个,差 2 个,2 token/s → 1s。
        assert_eq!(retry_after_secs(&cfg, st, 3.0), Some(1.0));
        // 已够 → 0。
        assert_eq!(retry_after_secs(&cfg, st, 1.0), Some(0.0));
    }

    // 速率 0 的桶:攒不够 → None(应换更粗兜底)。
    #[test]
    fn zero_rate_no_retry() {
        let cfg = BucketConfig::new(5.0, 0.0);
        let st = BucketState {
            tokens: 0.0,
            last_refill: 0.0,
        };
        assert_eq!(retry_after_secs(&cfg, st, 1.0), None);
    }

    // 时钟回拨:last_refill 永不倒退,回拨后下次调用 MUST NOT 从倒退时间戳凭空多补 token。
    #[test]
    fn clock_regression_does_not_mint_extra_next_call() {
        let cfg = BucketConfig::new(10.0, 1.0);
        // 桶在 t=200 有 2 个 token。
        let st = BucketState {
            tokens: 2.0,
            last_refill: 200.0,
        };
        // 回拨到 t=100 取 1 个:elapsed=0,不多补;last_refill MUST 停在 200(不落后到 100)。
        let d = try_acquire(&cfg, st, 100.0, 1.0);
        assert!(d.allowed);
        assert_eq!(d.state.tokens, 1.0);
        assert_eq!(d.state.last_refill, 200.0, "last_refill 永不倒退");
        // 下一次仍在 t=150(仍早于 200):elapsed 仍为 0,不因之前的回拨多补。
        let d2 = try_acquire(&cfg, d.state, 150.0, 1.0);
        assert!(d2.allowed);
        assert_eq!(d2.state.tokens, 0.0, "回拨期间不凭空多补 token");
        assert_eq!(d2.state.last_refill, 200.0);
        // 真正前进到 t=205:只补 5s × 1 = 5 个(从 200 起算,不含被丢弃的回拨时段)。
        let d3 = try_acquire(&cfg, d2.state, 205.0, 1.0);
        assert!(d3.allowed);
        assert!((d3.state.tokens - 4.0).abs() < 1e-9); // 0 + 5 补 - 1 取
    }

    // LOW:cost 超过桶容量 → 永远攒不够 → None(永久拒,不让客户端空等)。
    #[test]
    fn cost_exceeds_capacity_no_retry() {
        let cfg = BucketConfig::new(5.0, 1.0);
        let st = BucketState {
            tokens: 0.0,
            last_refill: 0.0,
        };
        assert_eq!(
            retry_after_secs(&cfg, st, 6.0),
            None,
            "cost>capacity 永不满足"
        );
        // 恰等于容量仍可等(攒满即可)。
        assert_eq!(retry_after_secs(&cfg, st, 5.0), Some(5.0));
    }
}
