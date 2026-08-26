//! client 回收后台任务编排(spec 005 §9.5,C10.5)。**IO 编排**:扫候选 → 强一致聚合信号 →
//! `decide_reclaim` 判定 → ConvertToTombstone(并发守卫条件写)/ HardDelete(原子删+审计)。
//!
//! 判定纯逻辑在 `agent_auth_infra_core::client_reclaim::decide_reclaim`(fail-safe / idle 必要条件 /
//! tombstone 两阶段,12 UT);本模块只做"喂信号 + 执行处置",不重述判定规则。
//!
//! **fail-safe 铁律(评审收敛)**:任一活跃引用信号**强一致**读(GSI 最终一致会漏读刚建引用致误回收);
//! ConvertToTombstone 条件于 last_used_day 未越快照(并发使用则跳过);硬删 + 审计原子(审计失败不删)。
//! P0/P1:`has_active_grant=None`(Grant 是 P2 才查)。

use agent_auth_infra_core::client_reclaim::{
    decide_reclaim, ClientReclaimSignals, ReclaimDecision, ReclaimPolicy,
};

use crate::ports::{ClientStore, CodeStore, RefreshStore};
use crate::state::AppState;

/// 构造回收策略(bin 用 env 天/秒;`idle_days` 天 → 秒)。
pub fn reclaim_policy(idle_days: i64, max_access_ttl_secs: i64) -> ReclaimPolicy {
    ReclaimPolicy {
        idle_threshold_secs: idle_days * 86_400,
        max_access_ttl_secs,
    }
}

/// Validate the live-gate-only client scope. Production reclamation leaves this unset.
pub fn validate_test_client_prefix(prefix: &str) -> Result<(), &'static str> {
    const MARKER: &str = "c10-5-";
    let Some(run_id) = prefix
        .strip_prefix(MARKER)
        .and_then(|value| value.strip_suffix('-'))
    else {
        return Err("test client prefix must use c10-5-<run-id>-");
    };
    if run_id.len() != 32
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("test client prefix run-id must be 32 lowercase hex characters");
    }
    Ok(())
}

/// 一次回收扫描的统计(可观测 + 测试断言)。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReclaimStats {
    /// 扫到的候选数(last_used_day <= 阈值)。
    pub scanned: usize,
    /// 本轮转 tombstone 的数量。
    pub tombstoned: usize,
    /// 本轮硬删的数量。
    pub hard_deleted: usize,
    /// 判 KeepActive 跳过的数量(有活跃引用 / 未够 idle / tombstone 猶予未满 / 并发守卫跳过)。
    pub kept: usize,
    /// 处置出错跳过的数量(存储瞬时错误等;下轮重试,不阻断整批)。
    pub errored: usize,
}

/// 跑一次回收扫描 pass(spec 005 §9.5)。`now` 由调用方注入(bin 用系统时钟;测试注入固定值)。
///
/// 候选 = `last_used_day <= now_day - idle_threshold_days`(只取够旧的,不全表扫)。逐候选:
/// 1. 已 tombstone → decide_reclaim 判猶予期(HardDelete / KeepActive)。
/// 2. 未 tombstone → **强一致**聚合活跃引用信号 → decide_reclaim(ConvertToTombstone / KeepActive)。
///
/// 单个候选处置出错(存储瞬时)只计 `errored` 跳过,不 `?` 中断整批(下轮重试)。
pub async fn run_reclaim_pass(state: &AppState, policy: &ReclaimPolicy, now: i64) -> ReclaimStats {
    run_reclaim_pass_scoped(state, policy, now, None).await
}

/// Run reclamation with an optional, validated live-gate client prefix.
///
/// The scope is applied before any mutation. It exists only so a live conformance
/// gate can prove the worker against uniquely owned rows without exposing unrelated
/// candidates to a temporary test policy.
pub async fn run_reclaim_pass_scoped(
    state: &AppState,
    policy: &ReclaimPolicy,
    now: i64,
    client_id_prefix: Option<&str>,
) -> ReclaimStats {
    let mut stats = ReclaimStats::default();
    if let Some(prefix) = client_id_prefix {
        if let Err(error) = validate_test_client_prefix(prefix) {
            eprintln!("RECLAIM_SCOPE_INVALID err={error}");
            return stats;
        }
    }
    let now_day = crate::token::day_bucket(now);
    let idle_days = policy.idle_threshold_secs.div_euclid(86_400);
    // 候选:last_used_day <= now_day - idle_days(够旧才可能 idle 达标;含已 tombstone 供判猶予期)。
    let older_than_day = now_day - idle_days;
    // D3b:reclaim 是**跨租户维护作业**(无请求 Host)→ 空 tenant = 全局扫描,返 (记录所属 tenant, 记录);
    // 每条按其自身 tenant 处置(convert/hard_delete/信号读用该 tenant 构造正确物理键)。
    let mut candidates = match state
        .clients
        .list_reclaim_candidates("", older_than_day)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("RECLAIM_SCAN_FAIL err={e:?}");
            return stats;
        }
    };
    if let Some(prefix) = client_id_prefix {
        candidates.retain(|(_, client)| client.client_id.starts_with(prefix));
    }
    stats.scanned = candidates.len();

    for (tenant, client) in candidates {
        match crate::tenant::with_tenant_mutation_permit(
            state,
            &tenant,
            reclaim_one(state, policy, &tenant, &client, now),
        )
        .await
        {
            Ok(Ok(ReclaimOutcome::Tombstoned)) => stats.tombstoned += 1,
            Ok(Ok(ReclaimOutcome::HardDeleted)) => stats.hard_deleted += 1,
            Ok(Ok(ReclaimOutcome::Kept)) | Err(crate::tenant::TenantMutationFenceError::Frozen) => {
                stats.kept += 1
            }
            Ok(Err(())) | Err(_) => stats.errored += 1,
        }
    }
    stats
}

/// dry-run:扫候选 + 聚合信号 + decide_reclaim **只计数不处置**(spec 005 §9.5 fail-safe:未显式开
/// `AGENT_AUTH_RECLAIM_ENABLED=1` 时跑此,防误配调度批量删 client)。`tombstoned`/`hard_deleted` 表示
/// "**若启用**将会处置"的数量。
pub async fn dry_run_scan(state: &AppState, policy: &ReclaimPolicy, now: i64) -> ReclaimStats {
    dry_run_scan_scoped(state, policy, now, None).await
}

/// Dry-run counterpart to [`run_reclaim_pass_scoped`].
pub async fn dry_run_scan_scoped(
    state: &AppState,
    policy: &ReclaimPolicy,
    now: i64,
    client_id_prefix: Option<&str>,
) -> ReclaimStats {
    let mut stats = ReclaimStats::default();
    if let Some(prefix) = client_id_prefix {
        if let Err(error) = validate_test_client_prefix(prefix) {
            eprintln!("RECLAIM_SCOPE_INVALID err={error}");
            return stats;
        }
    }
    let now_day = crate::token::day_bucket(now);
    let older_than_day = now_day - policy.idle_threshold_secs.div_euclid(86_400);
    let mut candidates = match state
        .clients
        .list_reclaim_candidates("", older_than_day)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("RECLAIM_SCAN_FAIL err={e:?}");
            return stats;
        }
    };
    if let Some(prefix) = client_id_prefix {
        candidates.retain(|(_, client)| client.client_id.starts_with(prefix));
    }
    stats.scanned = candidates.len();
    for (tenant, client) in candidates {
        // 复用与 reclaim_one 一致的信号聚合(强一致),只把判定映射到计数。
        let signals = if client.tombstoned_at.is_some() {
            ClientReclaimSignals {
                last_used_at: client.last_used_day.map(|d| d * 86_400),
                has_active_refresh_family: false,
                has_unexpired_code_or_session: false,
                has_active_grant: None,
                tombstoned_at: client.tombstoned_at,
            }
        } else {
            let has_refresh = state
                .refresh
                .has_active_family_by_client(&tenant, &client.client_id)
                .await
                .unwrap_or(true); // 信号读失败 → 保守当"有引用"(dry-run 也 fail-safe)
            let has_code = state
                .codes
                .has_unexpired_by_client(&tenant, &client.client_id, now)
                .await
                .unwrap_or(true);
            ClientReclaimSignals {
                last_used_at: client.last_used_day.map(|d| d * 86_400),
                has_active_refresh_family: has_refresh,
                has_unexpired_code_or_session: has_code,
                has_active_grant: None,
                tombstoned_at: None,
            }
        };
        match decide_reclaim(&signals, policy, now) {
            ReclaimDecision::ConvertToTombstone => stats.tombstoned += 1,
            ReclaimDecision::HardDelete => stats.hard_deleted += 1,
            ReclaimDecision::KeepActive { .. } => stats.kept += 1,
        }
    }
    stats
}

enum ReclaimOutcome {
    Tombstoned,
    HardDeleted,
    Kept,
}

/// 处置单个候选。Err(()) = 本候选存储瞬时错误(跳过、下轮重试;不中断整批)。
async fn reclaim_one(
    state: &AppState,
    policy: &ReclaimPolicy,
    tenant: &str,
    client: &crate::ports::ClientRecord,
    now: i64,
) -> Result<ReclaimOutcome, ()> {
    // 已 tombstone:只判猶予期(不必聚合信号)。
    if client.tombstoned_at.is_some() {
        let signals = ClientReclaimSignals {
            last_used_at: client.last_used_day.map(|d| d * 86_400),
            has_active_refresh_family: false,
            has_unexpired_code_or_session: false,
            has_active_grant: None,
            tombstoned_at: client.tombstoned_at,
        };
        return match decide_reclaim(&signals, policy, now) {
            ReclaimDecision::HardDelete => {
                let has_refresh = state
                    .refresh
                    .has_active_family_by_client(tenant, &client.client_id)
                    .await;
                let has_code = state
                    .codes
                    .has_unexpired_by_client(tenant, &client.client_id, now)
                    .await;
                match (has_refresh, has_code) {
                    (Ok(false), Ok(false)) => {}
                    (Ok(true), _) | (_, Ok(true)) => return Ok(ReclaimOutcome::Kept),
                    (Err(error), _) => {
                        eprintln!(
                            "RECLAIM_HARDDELETE_SIGNAL_FAIL kind=refresh client={} err={error:?}",
                            client.client_id
                        );
                        return Err(());
                    }
                    (_, Err(error)) => {
                        eprintln!(
                            "RECLAIM_HARDDELETE_SIGNAL_FAIL kind=code client={} err={error:?}",
                            client.client_id
                        );
                        return Err(());
                    }
                }
                match state
                    .clients
                    .hard_delete_with_audit(tenant, client, now)
                    .await
                {
                    Ok(()) => Ok(ReclaimOutcome::HardDeleted),
                    Err(e) => {
                        eprintln!(
                            "RECLAIM_HARDDELETE_FAIL client={} err={e:?}",
                            client.client_id
                        );
                        Err(())
                    }
                }
            }
            _ => Ok(ReclaimOutcome::Kept), // 猶予期未满 → 留
        };
    }

    // 未 tombstone:**强一致**聚合活跃引用信号(fail-safe:漏读会误回收)。
    let has_refresh = match state
        .refresh
        .has_active_family_by_client(tenant, &client.client_id)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "RECLAIM_SIGNAL_FAIL kind=refresh client={} err={e:?}",
                client.client_id
            );
            return Err(()); // 信号读失败 → 不判定(宁跳过,不误回收)
        }
    };
    let has_code = match state
        .codes
        .has_unexpired_by_client(tenant, &client.client_id, now)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "RECLAIM_SIGNAL_FAIL kind=code client={} err={e:?}",
                client.client_id
            );
            return Err(());
        }
    };
    let signals = ClientReclaimSignals {
        last_used_at: client.last_used_day.map(|d| d * 86_400),
        has_active_refresh_family: has_refresh,
        has_unexpired_code_or_session: has_code,
        has_active_grant: None, // P0/P1 不查 Grant 维度(P2 起补)
        tombstoned_at: None,
    };
    match decide_reclaim(&signals, policy, now) {
        ReclaimDecision::ConvertToTombstone => {
            // 并发守卫条件写:期间 last_used_day 推进或新建 Code/Refresh 递增
            // authority_revision，任一变化都跳过。
            match state
                .clients
                .convert_to_tombstone(
                    tenant,
                    &client.client_id,
                    now,
                    client.last_used_day,
                    client.authority_revision,
                )
                .await
            {
                Ok(true) => Ok(ReclaimOutcome::Tombstoned),
                Ok(false) => Ok(ReclaimOutcome::Kept), // 被并发使用/已 tombstone → 跳过
                Err(e) => {
                    eprintln!(
                        "RECLAIM_TOMBSTONE_FAIL client={} err={e:?}",
                        client.client_id
                    );
                    Err(())
                }
            }
        }
        _ => Ok(ReclaimOutcome::Kept),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ClientRecord, RefreshFamilyRecord};

    fn policy() -> ReclaimPolicy {
        ReclaimPolicy {
            idle_threshold_secs: 30 * 86_400, // 闲置 30 天
            max_access_ttl_secs: 3600,        // tombstone 猶予 1 小时
        }
    }

    async fn seed_client(
        state: &AppState,
        id: &str,
        last_used_day: Option<i64>,
        tombstoned_at: Option<i64>,
    ) {
        state
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: id.into(),
                    created_at: 1,
                    last_used_day,
                    tombstoned_at,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    // now = day 100(= 100*86400)。idle 阈值 30 天 → 候选 = last_used_day <= 70。
    const NOW: i64 = 100 * 86_400;

    #[test]
    fn live_gate_prefix_is_strictly_namespaced() {
        assert!(validate_test_client_prefix("c10-5-0123456789abcdef0123456789abcdef-").is_ok());
        for invalid in [
            "",
            "c10-5-short-",
            "c10-5-0123456789ABCDEF0123456789ABCDEF-",
            "other-0123456789abcdef0123456789abcdef-",
            "c10-5-0123456789abcdef0123456789abcdef",
        ] {
            assert!(validate_test_client_prefix(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn live_gate_scope_excludes_unowned_candidates_before_mutation() {
        let state = AppState::dev("localhost");
        seed_client(
            &state,
            "c10-5-0123456789abcdef0123456789abcdef-owned",
            Some(50),
            None,
        )
        .await;
        seed_client(&state, "unrelated", Some(50), None).await;

        let stats = run_reclaim_pass_scoped(
            &state,
            &policy(),
            NOW,
            Some("c10-5-0123456789abcdef0123456789abcdef-"),
        )
        .await;
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.tombstoned, 1);
        assert!(state
            .clients
            .get("", "unrelated")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none());
    }

    #[tokio::test]
    async fn invalid_live_gate_scope_fails_closed_without_mutation() {
        let state = AppState::dev("localhost");
        seed_client(&state, "unrelated", Some(50), None).await;

        let stats = run_reclaim_pass_scoped(&state, &policy(), NOW, Some("unrelated")).await;
        assert_eq!(stats, ReclaimStats::default());
        assert!(state
            .clients
            .get("", "unrelated")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none());
    }

    // 闲置够久 + 无引用 → ConvertToTombstone。
    #[tokio::test]
    async fn idle_no_refs_converts_to_tombstone() {
        let state = AppState::dev("localhost");
        seed_client(&state, "idle", Some(50), None).await; // 50 << 70,够旧
        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.tombstoned, 1, "闲置无引用应转 tombstone");
        assert!(state
            .clients
            .get("", "idle")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_some());
    }

    // 闲置够久但有 active refresh → KeepActive(fail-safe 不回收)。
    #[tokio::test]
    async fn idle_with_active_refresh_kept() {
        use crate::ports::RefreshStore;
        let state = AppState::dev("localhost");
        seed_client(&state, "busy", Some(50), None).await;
        state
            .refresh
            .create(
                "",
                RefreshFamilyRecord {
                    family_id: "f1".into(),
                    current_version: 0,
                    revoked: false,
                    client_id: "busy".into(),
                    cimd_snapshot: None,
                    user_id: "u".into(),
                    credential_epoch: 0,
                    resources: vec![],
                    scope: vec![],
                    actor_allowlist: vec![],
                    max_act_chain: 1,
                    dpop_jkt: None,
                    pkce_code_challenge: None,
                    auth_time: None,
                    acr: None,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.tombstoned, 0, "有 active refresh MUST NOT 回收");
        assert_eq!(stats.kept, 1);
        assert!(state
            .clients
            .get("", "busy")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none());
    }

    // 近期使用(last_used_day > 阈值)→ 根本不在候选里。
    #[tokio::test]
    async fn recently_used_not_a_candidate() {
        let state = AppState::dev("localhost");
        seed_client(&state, "recent", Some(95), None).await; // 95 > 70,不够旧
        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.scanned, 0, "近期使用不入候选");
    }

    // 已 tombstone 且猶予期满 → HardDelete + 审计留存。
    #[tokio::test]
    async fn tombstoned_past_grace_hard_deleted_with_audit() {
        let state = AppState::dev("localhost");
        // tombstoned_at 远早于 now - max_access_ttl(NOW - 3600),猶予期满。
        seed_client(&state, "dead", Some(50), Some(NOW - 7200)).await;
        // 断言 Memory audit 初始为 0。
        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.hard_deleted, 1, "猶予期满应硬删");
        assert!(
            state.clients.get("", "dead").await.unwrap().is_none(),
            "client 记录已删"
        );
    }

    #[tokio::test]
    async fn tombstoned_past_grace_with_late_active_reference_is_kept() {
        use crate::ports::RefreshStore;

        let state = AppState::dev("localhost");
        seed_client(&state, "late-active", Some(50), Some(NOW - 7200)).await;
        state
            .refresh
            .create(
                "",
                RefreshFamilyRecord {
                    family_id: "late-family".into(),
                    current_version: 0,
                    revoked: false,
                    client_id: "late-active".into(),
                    cimd_snapshot: None,
                    user_id: "u".into(),
                    credential_epoch: 0,
                    resources: vec![],
                    scope: vec![],
                    actor_allowlist: vec![],
                    max_act_chain: 1,
                    dpop_jkt: None,
                    pkce_code_challenge: None,
                    auth_time: None,
                    acr: None,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();

        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.hard_deleted, 0);
        assert_eq!(stats.kept, 1);
        assert!(state
            .clients
            .get("", "late-active")
            .await
            .unwrap()
            .is_some());
    }

    // 已 tombstone 但猶予期未满 → 保留(等下轮)。
    #[tokio::test]
    async fn tombstoned_within_grace_kept() {
        let state = AppState::dev("localhost");
        seed_client(&state, "recent-dead", Some(50), Some(NOW - 60)).await; // 60s < 3600 猶予
        let stats = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(stats.hard_deleted, 0);
        assert_eq!(stats.kept, 1, "猶予期未满保留");
        assert!(state
            .clients
            .get("", "recent-dead")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn tenant_freeze_blocks_background_reclaim_recompute_and_policy_publish() {
        use crate::governance::{
            GovernanceJobKind, GovernanceJobPhase, GovernanceJobRecord, GovernanceJobStartOutcome,
            GovernanceJobState, TenantCleanupStage,
        };
        use crate::ports::GovernanceStore;

        let state = AppState::dev("localhost");
        seed_client(&state, "frozen-idle", Some(50), None).await;
        let job = GovernanceJobRecord {
            job_id: "freeze-background-writers".into(),
            tenant_id: "default".into(),
            kind: GovernanceJobKind::TenantOffboarding,
            target_id: None,
            target_aliases: vec![],
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Users,
            target_epoch: 1,
            state: GovernanceJobState::Queued,
            phase: GovernanceJobPhase::IntentRecorded,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: NOW,
            updated_at: NOW,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        assert!(matches!(
            state
                .governance
                .start_or_resume_job(job, 0, true)
                .await
                .unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));

        let reclaim = run_reclaim_pass(&state, &policy(), NOW).await;
        assert_eq!(reclaim.kept, 1);
        assert!(state
            .clients
            .get("", "frozen-idle")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none());

        let recompute = crate::recompute::run_recompute_pass(&state, "", false).await;
        assert_eq!(recompute.errored, 1);
        assert!(crate::recompute::publish_policy_from_env(
            &state,
            "",
            r#"permit(principal, action, resource);"#,
        )
        .await
        .unwrap_err()
        .contains("tenant is frozen"));
    }

    // dry-run:只计数不处置(fail-safe:未显式启用不删)。
    #[tokio::test]
    async fn dry_run_counts_but_does_not_mutate() {
        let state = AppState::dev("localhost");
        seed_client(&state, "idle", Some(50), None).await;
        let stats = dry_run_scan(&state, &policy(), NOW).await;
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.tombstoned, 1, "dry-run 报'将转 tombstone'");
        // 但实际未处置:client 仍未 tombstone。
        assert!(
            state
                .clients
                .get("", "idle")
                .await
                .unwrap()
                .unwrap()
                .tombstoned_at
                .is_none(),
            "dry-run MUST NOT 真处置"
        );
    }
}
