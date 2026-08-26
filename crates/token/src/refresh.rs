//! C3.1 / C3.5 — refresh token family 状态机:强制 rotation、复用检测 → 全链吊销。
//!
//! 纯状态逻辑(不透明 token 的存储/加密属 §8):建模一个 refresh family 的活动版本、
//! rotation、复用检测。真实实现里"取当前版本→比对→轮换"必须是**原子**的条件写
//! (DynamoDB ConditionExpression,C3.1 并发原子性),本模块的 `consume` 给出该原子步的
//! 判定逻辑;并发原子性由上层 DB 条件写保证,单测在此断言状态转移正确。
//!
//! 决策真相源:docs/DESIGN §2(refresh rotation/复用检测)、§5.1(family)。

/// 一个 refresh family 的状态(内存模型;持久化在 DynamoDB)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamily {
    /// family 标识。
    pub family_id: String,
    /// 当前有效的 refresh 版本号(每 rotation +1)。
    pub current_version: u64,
    /// 是否已吊销(复用检测或显式 revoke)。
    pub revoked: bool,
}

/// 消费一个 refresh token 的结果(C3.1)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// 成功轮换:旧版本失效,返回新版本号(应签发新 access + 新 refresh)。
    Rotated { new_version: u64 },
    /// 检测到复用(用了非当前版本)→ MUST 全链吊销(C3.1),并**条件删除宽限缓存**(C3.5)。
    ReuseDetectedRevokeFamily,
    /// family 已被吊销,拒绝。
    AlreadyRevoked,
}

impl RefreshFamily {
    pub fn new(family_id: impl Into<String>) -> Self {
        RefreshFamily {
            family_id: family_id.into(),
            current_version: 0,
            revoked: false,
        }
    }

    /// 消费**呈现版本 `presented_version`** 的 refresh token(C3.1)。
    ///
    /// 语义(真实实现为单条原子条件写):
    /// - family 已吊销 → `AlreadyRevoked`。
    /// - 呈现版本 == 当前版本 → rotation,`current_version += 1`,返回新版本。
    /// - 呈现版本 != 当前版本(用了旧/已轮换的)→ 复用检测,置 `revoked=true`,返回 `ReuseDetectedRevokeFamily`。
    ///
    /// ⚠️ 并发:同一 (family, version) 被 N 个请求并发消费时,只有一个能把 version 从 v→v+1
    /// (条件写 `current_version == v`),其余会看到 version 已变 → 落入复用分支被吊销;
    /// 保证"至多一个成功"(C3.1 并发原子性)。宽限窗内**指纹一致**的合法重试不走此路径,
    /// 由 fingerprint::decide 先行返回缓存(C3.2)。
    pub fn consume(&mut self, presented_version: u64) -> ConsumeOutcome {
        if self.revoked {
            return ConsumeOutcome::AlreadyRevoked;
        }
        if presented_version == self.current_version {
            self.current_version += 1;
            ConsumeOutcome::Rotated {
                new_version: self.current_version,
            }
        } else {
            // 用了非当前版本 = 复用(旧 token 已被 rotation 作废)→ 全链吊销。
            self.revoked = true;
            ConsumeOutcome::ReuseDetectedRevokeFamily
        }
    }

    /// 显式吊销(如 /revoke 或 grant 吊销);同样要求上层条件删宽限缓存(C3.5)。
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // C3.1:当前版本消费 → rotation。
    #[test]
    fn current_version_rotates() {
        let mut f = RefreshFamily::new("fam_1");
        assert_eq!(f.consume(0), ConsumeOutcome::Rotated { new_version: 1 });
        assert_eq!(f.current_version, 1);
        assert!(!f.revoked);
    }

    // C3.1:复用旧版本 → 全链吊销。
    #[test]
    fn reusing_old_version_revokes_family() {
        let mut f = RefreshFamily::new("fam_1");
        f.consume(0); // rotation → v1
                      // 复用 v0(已作废):
        assert_eq!(f.consume(0), ConsumeOutcome::ReuseDetectedRevokeFamily);
        assert!(f.revoked);
    }

    // C3.1:吊销后再消费 → AlreadyRevoked。
    #[test]
    fn consume_after_revoke_rejected() {
        let mut f = RefreshFamily::new("fam_1");
        f.revoke();
        assert_eq!(f.consume(0), ConsumeOutcome::AlreadyRevoked);
    }

    // C3.1 并发原子性:同一版本被并发消费,至多一个 Rotated,其余全落复用→吊销。
    #[test]
    fn concurrent_consume_at_most_one_success() {
        // 模拟串行化的原子条件写:两个请求都持 v0。
        let mut f = RefreshFamily::new("fam_1");
        let first = f.consume(0); // 抢占成功 → v1
        let second = f.consume(0); // 第二个仍持 v0,但当前已是 v1 → 复用
        assert_eq!(first, ConsumeOutcome::Rotated { new_version: 1 });
        assert_eq!(second, ConsumeOutcome::ReuseDetectedRevokeFamily);
        assert!(f.revoked, "并发复用后 family MUST 吊销");
        // 不存在"两个都拿到新 token":second 不是 Rotated。
        assert!(!matches!(second, ConsumeOutcome::Rotated { .. }));
    }

    // C3.1(Kiro 边界):吊销后并发多次消费,全部 AlreadyRevoked、不再切状态。
    #[test]
    fn concurrent_consume_after_revoke_all_rejected() {
        let mut f = RefreshFamily::new("fam_1");
        f.revoke();
        for v in [0u64, 1, 2] {
            assert_eq!(f.consume(v), ConsumeOutcome::AlreadyRevoked);
        }
        assert!(f.revoked);
        assert_eq!(f.current_version, 0, "吊销后消费不得推进 version");
    }

    // 连续正常 rotation:v0→v1→v2。
    #[test]
    fn sequential_rotations() {
        let mut f = RefreshFamily::new("fam_1");
        assert_eq!(f.consume(0), ConsumeOutcome::Rotated { new_version: 1 });
        assert_eq!(f.consume(1), ConsumeOutcome::Rotated { new_version: 2 });
        assert!(!f.revoked);
    }
}
