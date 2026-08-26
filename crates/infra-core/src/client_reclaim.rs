//! 动态客户端**显式回收**判定纯逻辑(spec 005 C10.5,P0)。零 IO、零 AWS。
//!
//! **背景**(DESIGN §3.2/§8):持久身份(users/passkeys/clients/grants)**MUST NOT 挂裸 TTL**——
//! 否则身份静默消失、留悬空引用。client 回收 MUST 是**显式流程**:后台按 `last_used_at` 扫描出闲置
//! 够久的 client,**再**确认**无 active refresh family + 无未过期 code/session + 无 active Grant**
//! (Grant 是 P2 才判)后才回收;且**先转 tombstone、保留 ≥ access token 最大 TTL 后再硬删**
//! (其间离线校验的 access token 仍引用 client_id);审计元数据独立留存。
//!
//! **本模块**:回收判定 + tombstone→硬删时机的**纯逻辑**(决定性,零 IO)。扫描/信号聚合/写库/审计归档
//! 属 IO 层([c],后台 Lambda 遍历 + 跨表聚合;不在此)。
//!
//! **关键裁决(codex+Kiro 双评审)**:
//! - **idle 是回收的*必要条件*,非仅扫描筛选**(Kiro):`可回收 = 闲置够久 AND 无任何活跃引用`。
//!   若"无活跃引用"即可回收(idle 仅筛选),则 1 秒前还在用、恰好此刻所有 token 过期的 client 会被
//!   立即删——那是删除、不是回收。回收针对**长期未使用**的僵尸 client(短暂静默期不触发)。
//! - **fail-safe**(两家一致):任一活跃引用信号 → 不可回收(宁误留、绝不误删致悬空引用)。
//! - **P0/P1 vs P2**:active Grant 检查 P2 才有;`has_active_grant: Option<bool>`——None=P0/P1 不查该维度,
//!   Some(true)=P2 有活跃 Grant → 不可回收。
//!
//! 决策真相源:DESIGN §3.2(client 回收规则)/§8;CONFORMANCE C10.5。

/// 一个 client 的回收信号快照(由 IO 层扫描 + 跨表聚合后喂入;各布尔"是否有活跃引用")。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReclaimSignals {
    /// 最后使用时刻(Unix 秒);None = 从未激活(注册残渣)。
    pub last_used_at: Option<i64>,
    /// 是否有 active(未吊销)refresh-token family。
    pub has_active_refresh_family: bool,
    /// 是否有未过期的 code / session。
    pub has_unexpired_code_or_session: bool,
    /// 是否有 active Grant;**None = P0/P1 不查该维度**(Grant 是 P2),Some(b)=P2 查得结果。
    pub has_active_grant: Option<bool>,
    /// 当前状态:是否已 tombstone(Some=tombstone 时刻,None=Normal)。
    pub tombstoned_at: Option<i64>,
}

/// 回收策略(阈值 + 阶段开关;与信号分离便于注入不同配置单测)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimPolicy {
    /// 闲置阈值(秒):`now - last_used_at >= 此值` 才算"长期未使用"(必要条件)。
    pub idle_threshold_secs: i64,
    /// access token 最大 TTL(秒):tombstone 后须保留 ≥ 此值才硬删(离线 token 仍引用期)。
    pub max_access_ttl_secs: i64,
}

/// 回收判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimDecision {
    /// 保持活跃:未闲置够久,或有活跃引用(不动)。
    KeepActive { reason: KeepReason },
    /// 可转 tombstone(闲置够久 + 无任何活跃引用;IO 层据此写 tombstone,**不硬删**)。
    ConvertToTombstone,
    /// tombstone 猶予期已满,可硬删(IO 层据此 DeleteItem + 审计归档)。
    HardDelete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// 未闲置够久(idle 必要条件未满足;含"从未使用但要求 idle"——见 never-used 语义)。
    NotIdleLongEnough,
    /// 有 active refresh family。
    HasActiveRefreshFamily,
    /// 有未过期 code/session。
    HasUnexpiredCodeOrSession,
    /// 有 active Grant(P2)。
    HasActiveGrant,
    /// 已 tombstone 但猶予期未满(等硬删)。
    TombstoneGracePending,
}

/// 判定一个 client 当前应处置为:保持 / 转 tombstone / 硬删(纯逻辑,`now` 由调用方注入)。
///
/// 决策链:
/// 1. **已 tombstone** → 只判猶予期:`now - tombstoned_at >= max_access_ttl` → `HardDelete`,否则 `TombstoneGracePending`。
/// 2. **未 tombstone(Normal)**:先做 **fail-safe 活跃引用检查**(任一活跃[refresh family / code-session /
///    active Grant P2]→ KeepActive,绝不回收致悬空引用);再判 **idle 必要条件**(`last_used_at` 距今
///    < idle_threshold → `KeepActive(NotIdleLongEnough)`);闲置够久 + 无活跃引用 → `ConvertToTombstone`。
///
/// **never-used**(`last_used_at=None`):视为"从注册起从未激活"。仍要求闲置够久——用**注册残渣**语义:
/// 从未使用的 client 无 `last_used_at` 基准,保守起见**也要求无活跃引用**(必然满足)后可回收;
/// 但为不误删刚注册未及使用的 client,`None` 按"idle 未满足"处理(KeepActive)——真正的注册残渣清理
/// 由 IO 层可选的 TTL 例外(DESIGN §8"仅从未激活、无任何关联的注册残渣可挂 TTL")承担,不在本判定放行。
pub fn decide_reclaim(
    signals: &ClientReclaimSignals,
    policy: &ReclaimPolicy,
    now: i64,
) -> ReclaimDecision {
    // 1. 已 tombstone:只判猶予期(离线 access token 仍引用 client_id,须留 ≥ max_access_ttl)。
    if let Some(ts) = signals.tombstoned_at {
        if now - ts >= policy.max_access_ttl_secs {
            return ReclaimDecision::HardDelete;
        }
        return ReclaimDecision::KeepActive {
            reason: KeepReason::TombstoneGracePending,
        };
    }

    // 2a. fail-safe 活跃引用检查(任一活跃 → 绝不回收)。
    if signals.has_active_refresh_family {
        return ReclaimDecision::KeepActive {
            reason: KeepReason::HasActiveRefreshFamily,
        };
    }
    if signals.has_unexpired_code_or_session {
        return ReclaimDecision::KeepActive {
            reason: KeepReason::HasUnexpiredCodeOrSession,
        };
    }
    // active Grant:P2 才查(None=P0/P1 不查该维度;Some(true)=有活跃 Grant)。
    if signals.has_active_grant == Some(true) {
        return ReclaimDecision::KeepActive {
            reason: KeepReason::HasActiveGrant,
        };
    }

    // 2b. idle **必要条件**(Kiro 裁决:非仅扫描筛选)。None(从未使用)保守按未满足处理。
    let idle_ok = match signals.last_used_at {
        Some(last) => now - last >= policy.idle_threshold_secs,
        None => false, // 从未使用:不由本判定回收(交 IO 层注册残渣 TTL 例外)
    };
    if !idle_ok {
        return ReclaimDecision::KeepActive {
            reason: KeepReason::NotIdleLongEnough,
        };
    }

    // 2c. 闲置够久 + 无活跃引用 → 转 tombstone。
    ReclaimDecision::ConvertToTombstone
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: ReclaimPolicy = ReclaimPolicy {
        idle_threshold_secs: 2_592_000, // 30 天
        max_access_ttl_secs: 3_600,     // 60 分钟
    };
    const NOW: i64 = 1_000_000_000;

    fn base() -> ClientReclaimSignals {
        ClientReclaimSignals {
            last_used_at: Some(NOW - 3_000_000), // 闲置 > 30 天
            has_active_refresh_family: false,
            has_unexpired_code_or_session: false,
            has_active_grant: None,
            tombstoned_at: None,
        }
    }

    // 闲置够久 + 无活跃引用 → 可转 tombstone。
    #[test]
    fn idle_and_no_refs_convert_to_tombstone() {
        assert_eq!(
            decide_reclaim(&base(), &POLICY, NOW),
            ReclaimDecision::ConvertToTombstone
        );
    }

    // 红线:有 active refresh family → 绝不回收(悬空引用防护)。
    #[test]
    fn active_refresh_blocks_reclaim() {
        let s = ClientReclaimSignals {
            has_active_refresh_family: true,
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::HasActiveRefreshFamily
            }
        );
    }

    // 红线:有未过期 code/session → 绝不回收。
    #[test]
    fn unexpired_session_blocks_reclaim() {
        let s = ClientReclaimSignals {
            has_unexpired_code_or_session: true,
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::HasUnexpiredCodeOrSession
            }
        );
    }

    // P2:有 active Grant → 绝不回收。
    #[test]
    fn active_grant_blocks_reclaim_p2() {
        let s = ClientReclaimSignals {
            has_active_grant: Some(true),
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::HasActiveGrant
            }
        );
    }

    // P0/P1:has_active_grant=None(不查该维度)不阻止回收(其余条件满足则转 tombstone)。
    #[test]
    fn grant_none_p0p1_does_not_block() {
        let s = ClientReclaimSignals {
            has_active_grant: None,
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::ConvertToTombstone
        );
    }

    // P2:has_active_grant=Some(false)(查了无活跃 Grant)不阻止回收。
    #[test]
    fn grant_some_false_does_not_block() {
        let s = ClientReclaimSignals {
            has_active_grant: Some(false),
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::ConvertToTombstone
        );
    }

    // idle **必要条件**(Kiro 裁决):无活跃引用但闲置不够久 → KeepActive(非立即回收)。
    #[test]
    fn no_refs_but_not_idle_keeps_active() {
        let s = ClientReclaimSignals {
            last_used_at: Some(NOW - 100), // 100 秒前才用过,远不够 30 天
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::NotIdleLongEnough
            },
            "无活跃引用但刚用过 → 不回收(idle 是必要条件,防短暂静默被误删)"
        );
    }

    // idle 边界:恰好等于阈值 → 满足(>=)。
    #[test]
    fn idle_exactly_at_threshold_ok() {
        let s = ClientReclaimSignals {
            last_used_at: Some(NOW - POLICY.idle_threshold_secs),
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::ConvertToTombstone
        );
    }

    // 从未使用(last_used_at=None)→ 不由本判定回收(交 IO 层注册残渣 TTL 例外)。
    #[test]
    fn never_used_not_reclaimed_here() {
        let s = ClientReclaimSignals {
            last_used_at: None,
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::NotIdleLongEnough
            }
        );
    }

    // tombstone 猶予期未满 → 等(不硬删)。
    #[test]
    fn tombstone_grace_pending() {
        let s = ClientReclaimSignals {
            tombstoned_at: Some(NOW - 1_000), // 1000 秒前 tombstone,< 3600 猶予
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::KeepActive {
                reason: KeepReason::TombstoneGracePending
            }
        );
    }

    // tombstone 猶予期已满 → 硬删。
    #[test]
    fn tombstone_grace_elapsed_hard_delete() {
        let s = ClientReclaimSignals {
            tombstoned_at: Some(NOW - 3_600), // 恰好 60min,>= max_access_ttl
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::HardDelete
        );
    }

    // tombstone 状态优先于活跃引用检查(已 tombstone 的只看猶予期;活跃引用不该在 tombstone 后出现,
    // 但即便出现也按猶予期处置——tombstone 是已决策的终态前奏)。
    #[test]
    fn tombstoned_ignores_ref_signals_only_grace() {
        let s = ClientReclaimSignals {
            tombstoned_at: Some(NOW - 3_600),
            has_active_refresh_family: true, // 即便有(不该),tombstone 后只看猶予期
            ..base()
        };
        assert_eq!(
            decide_reclaim(&s, &POLICY, NOW),
            ReclaimDecision::HardDelete
        );
    }
}
