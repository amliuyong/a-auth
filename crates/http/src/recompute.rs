//! 后台策略重算任务编排(spec 005 §7 / C10.17,T7.6)。**镜像 reclaim 模式**(独立 Lambda + Schedule +
//! 默认 dry-run env gate)。
//!
//! 策略 bump 后,stale Grant(`effective_pv < current_pv`)由本任务异步重算:
//! `evaluate(授权=per_resource, 当前策略) → effective`(补强 ⑧:授权=输入天花板,放宽可回到授权上限、不越 consent)
//! → 写 effective_* + effective_pv=current(条件写 CAS,补强 ⑫:不覆盖并发吊销/更新)。
//! **交集是这里算的**(有 Cedar);热路径对仍 stale 的 Grant 只 fail-safe 拒(评审 Blocker)。
//!
//! 敏感度分档(spec §7):高敏 Grant 不再合规 → 吊销;一般 → 写 effective 交集。P2 起步:evaluate 后
//! **effective 为空(策略全 deny)→ 吊销**(该 Grant 已无任何生效权限,留着无用);**非空 → 写 effective**。
//!
//! **fail-closed**:工件缺失/parse 失败 → 该 tenant 本轮跳过(不误改 Grant);单条 evaluate/写错 → 计 errored 跳过。

use crate::ports::{GrantStore, PolicyArtifactStore, PolicyVersionStore};
use crate::state::AppState;
use agent_auth_authz::{evaluate, GrantInput, PolicyArtifact};
use sha2::{Digest, Sha256};

/// 一次重算 pass 的统计(可观测 + 测试断言)。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecomputeStats {
    /// 扫到的 stale Grant 数。
    pub scanned: usize,
    /// 重算后写 effective(收窄/放宽)的数量。
    pub recomputed: usize,
    /// 重算判不再合规 → 吊销的数量。
    pub revoked: usize,
    /// **无可评估单元 → 保留**的数量(补强 ⑯:resource-less / 空 scope+无 RAR;写空 effective + 打 pv 戳,
    /// **不吊销**)。单列一档(不混入 revoked/recomputed),便于断言"56 个落 preserved、0 落 revoked"。
    pub preserved: usize,
    /// 条件写冲突(并发吊销/更新)跳过的数量。
    pub conflicted: usize,
    /// 处置出错(evaluate/store 瞬时)跳过的数量。
    pub errored: usize,
}

/// 从 Grant 授权字段(per_resource=consent 上限)构造 evaluate 输入。
fn grant_input(g: &agent_auth_grant::Grant) -> GrantInput {
    GrantInput {
        user_id: g.user_id.clone(),
        client_id: g.client_id.clone(),
        per_resource: g
            .per_resource
            .iter()
            .map(|r| {
                (
                    r.resource.clone(),
                    r.scopes.clone(),
                    r.authorization_details.clone(),
                )
            })
            .collect(),
    }
}

/// 跑一次重算 pass(某 tenant)。`dry_run=true` 只扫描报数、不改任何 Grant(默认;fail-safe 防误配)。
/// `now` 未直接用(重算不看时钟,只看版本),保留签名对齐 reclaim 便于 bin 复用。
pub async fn run_recompute_pass(state: &AppState, tenant: &str, dry_run: bool) -> RecomputeStats {
    if dry_run {
        return run_recompute_pass_inner(state, tenant, true).await;
    }
    match crate::tenant::with_tenant_mutation_permit(
        state,
        tenant,
        run_recompute_pass_inner(state, tenant, false),
    )
    .await
    {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("RECOMPUTE_MUTATION_FENCE tenant={tenant} err={error}");
            RecomputeStats {
                errored: 1,
                ..RecomputeStats::default()
            }
        }
    }
}

async fn run_recompute_pass_inner(state: &AppState, tenant: &str, dry_run: bool) -> RecomputeStats {
    let mut stats = RecomputeStats::default();
    // 1. current_pv + 工件(fail-closed:取不到 → 本轮跳过,不误改)。
    let current_pv = match state.policy_versions.get(tenant).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("RECOMPUTE_PV_FAIL tenant={tenant} err={e:?}");
            return stats;
        }
    };
    if current_pv == 0 {
        return stats; // 未 bump 过策略 → 无 stale
    }
    let artifact = match state.policy_artifacts.get(tenant, current_pv).await {
        Ok(Some((text, _digest))) => match PolicyArtifact::parse(&text, current_pv) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("RECOMPUTE_POLICY_PARSE_FAIL tenant={tenant} v={current_pv} err={e}");
                return stats; // 工件坏 → fail-closed 本轮跳过(不误改 Grant)
            }
        },
        Ok(None) => {
            eprintln!("RECOMPUTE_ARTIFACT_MISSING tenant={tenant} v={current_pv}");
            return stats; // 工件缺失 → fail-closed
        }
        Err(e) => {
            eprintln!("RECOMPUTE_ARTIFACT_FAIL tenant={tenant} err={e:?}");
            return stats;
        }
    };
    // 2. 列 stale Grant(GSI Query effective_pv < current;分页)。
    let stale = match state.grants.list_stale(tenant, current_pv).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("RECOMPUTE_SCAN_FAIL tenant={tenant} err={e:?}");
            return stats;
        }
    };
    stats.scanned = stale.len();
    if dry_run {
        return stats; // dry-run:只报数(默认;AGENT_AUTH_RECOMPUTE_ENABLED 未设)
    }
    // 3. 逐条:evaluate(授权,当前策略)→ 分档写/吊销 → 条件写 CAS。
    let mut grant_events = Vec::new();
    for (t, mut g) in stale {
        let expected_rev = g.revision;
        let eff = match evaluate(&artifact, &grant_input(&g)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("RECOMPUTE_EVAL_FAIL grant={} err={e}", g.grant_id);
                stats.errored += 1;
                continue;
            }
        };
        // 补强 ⑯:**吊销 iff 有可评估单元 && effective 空**(有 resource/scope/RAR 可判、却被策略全 deny)。
        // 无可评估单元(resource-less / 空 scope+无 RAR)→ Cedar 无从表态 → **保留**(写空 effective + 打 pv 戳,
        // 不吊销;下轮不再扫)。绝不再用 `eff.per_resource.is_empty()` 单条件吊销(会误杀 resource-less)。
        if eff.per_resource.is_empty() && eff.has_evaluable_units {
            // 有可评估单元却被策略全剥光 → 吊销(留着无生效权限,无用)。
            let result = state
                .grants
                .revoke_if_revision(&t, &g.grant_id, expected_rev)
                .await;
            if !matches!(result, Ok(false)) {
                grant_events.push(crate::grants::revoke_event_draft(
                    &t,
                    crate::security_event::SecurityActor::system("policy-recompute"),
                    &g.grant_id,
                    result.is_ok(),
                ));
            }
            match result {
                Ok(true) => stats.revoked += 1,
                Ok(false) => stats.conflicted += 1, // 已不存在/已被吊销
                Err(_) => stats.errored += 1,
            }
            continue;
        }
        // 到此:要么有 effective(收窄/放宽),要么 effective 空但**无可评估单元**(保留)。两者都是"写 effective +
        // 打 pv 戳"(CAS),区别只在统计分档:无可评估单元 → preserved,有 effective → recomputed。
        let preserve = eff.per_resource.is_empty(); // 已排除"有可评估单元且空"(上面吊销了)→ 此处空 = 无可评估单元
        if !preserve {
            g.effective_per_resource = eff
                .per_resource
                .into_iter()
                .map(|(resource, scopes, rar)| agent_auth_grant::ResourceGrant {
                    resource,
                    scopes,
                    authorization_details: rar,
                })
                .collect();
            g.allowed_ip_cidrs = eff.allowed_ip_cidrs;
            g.allowed_vpce = eff.allowed_vpce;
        }
        g.effective_pv = current_pv; // 打戳(含保留档):下轮 list_stale(effective_pv<current)不再扫,滞后但有界。
        match state.grants.put_conditional(&t, g, expected_rev).await {
            Ok(true) => {
                if preserve {
                    stats.preserved += 1; // 无可评估单元:保留,不吊销(补强 ⑯)
                } else {
                    stats.recomputed += 1;
                }
            }
            Ok(false) => stats.conflicted += 1, // 并发吊销/更新 → 跳过(下轮再处理)
            Err(_) => stats.errored += 1,
        }
    }
    state.record_security_events(grant_events).await;
    stats
}

/// **publish-then-activate**(spec 005 §7 补强 ⑨):把部署级策略集文本(env `AGENT_AUTH_POLICY_SET`)
/// 发布为本租户下一版本工件并激活(bump policy_version)。**单写者**语义 —— 只在重算 Lambda(EventBridge
/// 调度,无并发)里调,绝不在主 API Lambda 冷启动做(并发冷启会竞 bump 计数器)。
///
/// **幂等**:当前激活版本工件 digest == 新文本 digest → no-op 返回 current(重复调度不涨版本)。
/// **fail-closed**:文本 parse 失败 → `Err`(绝不发布无法解析的策略,否则激活后签发侧全 fail-closed)。
/// **put-then-bump**:先写下一版本工件(存在后再激活),再 bump;bump 返回值 != 预期(理论并发)→ 补写以自愈。
///
/// 返回激活后的版本号。调用方随后应对该 tenant 跑一次 `seed_backfill`(把存量 Grant effective_pv 追平)。
pub async fn publish_policy_from_env(
    state: &AppState,
    tenant: &str,
    policy_text: &str,
) -> Result<u64, String> {
    crate::tenant::with_tenant_mutation_permit(
        state,
        tenant,
        publish_policy_from_env_inner(state, tenant, policy_text),
    )
    .await
    .map_err(|error| format!("tenant mutation fence: {error}"))?
}

async fn publish_policy_from_env_inner(
    state: &AppState,
    tenant: &str,
    policy_text: &str,
) -> Result<u64, String> {
    let current = state
        .policy_versions
        .get(tenant)
        .await
        .map_err(|e| format!("policy_version get: {e:?}"))?;
    let digest = format!("{:x}", Sha256::digest(policy_text.as_bytes()));
    // 幂等:当前版本工件 digest 相同 → 已发布,不涨版本(重复调度安全)。
    if current > 0 {
        if let Some((_text, existing_digest)) = state
            .policy_artifacts
            .get(tenant, current)
            .await
            .map_err(|e| format!("policy_artifact get: {e:?}"))?
        {
            if existing_digest == digest {
                return Ok(current);
            }
        }
    }
    // fail-closed:发布前必先 parse 通过(绝不激活无法解析的策略)。
    PolicyArtifact::parse(policy_text, current + 1).map_err(|e| format!("policy parse: {e}"))?;
    // publish-then-activate:先写下一版本工件(激活前工件必已存在),再 bump 激活。
    let next = current + 1;
    state
        .policy_artifacts
        .put(tenant, next, policy_text.to_string(), digest.clone())
        .await
        .map_err(|e| format!("policy_artifact put v{next}: {e:?}"))?;
    let activated = state
        .policy_versions
        .bump(tenant)
        .await
        .map_err(|e| format!("policy_version bump: {e:?}"))?;
    if activated != next {
        // 理论并发(单写者下不应发生):bump 返回值超预期 → 补写激活版本工件自愈(不留悬空 current_pv)。
        eprintln!("PUBLISH_VERSION_SKEW tenant={tenant} expected={next} activated={activated}");
        state
            .policy_artifacts
            .put(tenant, activated, policy_text.to_string(), digest)
            .await
            .map_err(|e| format!("policy_artifact heal put v{activated}: {e:?}"))?;
    }
    Ok(activated)
}

/// **seed backfill**(spec 005 §7 补强 ⑪):feature 启用时,在**当前策略**下把存量 Grant(effective_pv 落后)
/// 全部评估 + 盖 effective_pv=current,使**首次真 bump 只动真受影响 Grant**、不是全 fleet 一起 stale。
/// 实现 = 对当前 current_pv 跑一次非 dry-run 重算(把所有 effective_pv < current 的补齐)。分页/有界。
pub async fn seed_backfill(state: &AppState, tenant: &str) -> RecomputeStats {
    run_recompute_pass(state, tenant, false).await
}

#[cfg(test)]
mod tests {
    // 端到端行为(收紧/放宽/并发)测试在 crates/http/tests/authz_e2e.rs(需 AppState + store 装配)。
}
