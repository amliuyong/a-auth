//! Grant 创建/更新时的 Cedar 策略预判编排(spec 005 §7 / C10.17,T7.5)。
//!
//! **冷路径**(创建/重算时可调 Cedar;签发热路径**绝不**调本模块):读当前 `policy_version` + 工件 →
//! `agent_auth_authz::evaluate(授权 ∩ 策略) → effective`,写进 `grant.effective_*` + `effective_pv`
//! **原子对齐**(防 TOCTOU,补强 ⑦:effective 字段依据的版本 == 打的 pv 戳)。
//!
//! **fail-closed**(补强 ⑨):策略工件缺失 / parse 失败 / evaluate 错 → 返回 `Err`,调用方拒建 Grant
//! (绝不静默放行超策略授权)。**flag 关**(`authz_enabled=false`)→ **no-op**(effective 留空 →
//! `Grant::effective_view` 回退 `per_resource`,字节等价现网)。

use crate::ports::{PolicyArtifactStore, PolicyVersionStore};
use crate::state::AppState;
use agent_auth_authz::{evaluate, GrantInput, PolicyArtifact};

/// Grant 创建期策略预判的失败分类(补强 ⑯:调用方据此选正确错误码,避免对永久拒回可重试 503)。
#[derive(Debug)]
pub enum ApplyPolicyError {
    /// **瞬时**:策略工件缺失(激活但未写)/ parse 失败 / store 瞬时错 → 可重试(503 temporarily_unavailable)。
    Transient(String),
    /// **永久**:有可评估单元却被当前策略全 deny → 该授权被策略明确拒,重试无用(access_denied,不可重试)。
    Denied(String),
}

impl std::fmt::Display for ApplyPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyPolicyError::Transient(s) => write!(f, "transient: {s}"),
            ApplyPolicyError::Denied(s) => write!(f, "denied: {s}"),
        }
    }
}

/// 对新建/更新的 Grant 施策略预判(见模块注释)。`tenant` = store 分区键(空=自部署单租户)。
/// 成功 → `grant` 的 effective_* + effective_pv 已填(flag 关则不动);失败 → `Err(ApplyPolicyError)`,调用方 fail-closed
/// (Transient→503 可重试;Denied→access_denied 永久拒,补强 ⑯)。
pub async fn apply_policy_to_grant(
    state: &AppState,
    tenant: &str,
    grant: &mut agent_auth_grant::Grant,
) -> Result<(), ApplyPolicyError> {
    if !state.authz_enabled {
        return Ok(()); // flag 关:no-op,effective 留空 → effective_view 回退 per_resource(字节等价)。
    }
    // 1. 读当前 policy_version + 工件(先读版本,再取该版本工件 → 原子对齐版本与 effective)。
    let pv = state
        .policy_versions
        .get(tenant)
        .await
        .map_err(|e| ApplyPolicyError::Transient(format!("policy_version get: {e:?}")))?;
    // current_pv==0 = 本租户**从未发布过策略**(publish 由重算 Lambda 单写者做,可能还没首跑)。
    // 此时当 no-op(effective 留空 → effective_view 回退 per_resource,=flag 关行为),**不 fail-closed**:
    // 区分"未初始化"与"某激活版本工件缺失"(评审 H3 启用脚枪——否则一开 flag、publish 未跑,所有新建
    // Grant 立即 503,创建路径全站塌方)。热路径 stale_gate 对 current_pv==0 亦不 gate(is_stale 需 pv≥1)。
    if pv == 0 {
        return Ok(());
    }
    let Some((text, _digest)) = state
        .policy_artifacts
        .get(tenant, pv)
        .await
        .map_err(|e| ApplyPolicyError::Transient(format!("policy_artifact get: {e:?}")))?
    else {
        // 工件缺失 → fail-closed **瞬时**(不静默放行;补强 ⑨:激活前必先写工件;单写者未追平时可重试)。
        return Err(ApplyPolicyError::Transient(format!(
            "policy artifact missing for tenant={tenant} version={pv}"
        )));
    };
    // 2. parse(工件坏 → fail-closed **瞬时**:坏策略是部署配置问题,修复后可重试,非授权拒)。
    let artifact = PolicyArtifact::parse(&text, pv)
        .map_err(|e| ApplyPolicyError::Transient(format!("policy parse: {e}")))?;
    // 3. evaluate(授权 ∩ 策略 → effective;恒 ⊆ 授权)。输入 = per_resource(=用户授权 consent 上限)。
    let input = GrantInput {
        user_id: grant.user_id.clone(),
        client_id: grant.client_id.clone(),
        per_resource: grant
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
    };
    let eff = evaluate(&artifact, &input)
        .map_err(|e| ApplyPolicyError::Transient(format!("evaluate: {e}")))?;
    // 4. **fail-closed 对称(补强 ⑯ Blocker 1)**:有可评估单元却被策略全 deny(effective 空)→ 返回 Err,
    //    调用方 fail-closed 拒建 Grant。**绝不**写 (effective 空, pv≥1) 状态——否则 effective_view 因 pv≥1 用
    //    空 effective(=无授权),或更糟:若判据回退会签出 per_resource 全集。与重算的"吊销"对称:此状态绝不持久化。
    //    无可评估单元(resource-less / 空 scope+无 RAR)→ effective 空是正常"无从表态",写空 + 打 pv 戳保留(不 Err)。
    if eff.per_resource.is_empty() && eff.has_evaluable_units {
        return Err(ApplyPolicyError::Denied(format!(
            "policy denies all evaluable units for grant (tenant={tenant} pv={pv}); fail-closed 拒建"
        )));
    }
    // 5. 写 effective_* + effective_pv **原子对齐**(pv == 评估所依据版本)。无可评估单元时 effective 空 + pv≥1,
    //    effective_view 用空 effective;但此类 Grant per_resource 也无可换发 resource,签发走扁平 scope 不经 effective_view。
    grant.effective_per_resource = eff
        .per_resource
        .into_iter()
        .map(|(resource, scopes, rar)| agent_auth_grant::ResourceGrant {
            resource,
            scopes,
            authorization_details: rar,
        })
        .collect();
    grant.allowed_ip_cidrs = eff.allowed_ip_cidrs;
    grant.allowed_vpce = eff.allowed_vpce;
    grant.effective_pv = pv;
    Ok(())
}
