//! claims 级共享 key 的**分组封顶爆炸半径**纯逻辑(spec 020 C10.22b,SHOULD-if-enabled)。零 IO。
//!
//! **背景**(DEPLOYMENT §1/§8):claims 级隔离档(低保障、显式 opt-in)多个租户共用一把签名 key,
//! 防伪造全靠签发逻辑(见 [C10.22a] `assert_iss_belongs_to_tenant`),**非密钥边界**。共享 key 一旦
//! 泄露,紧急吊销/轮换会**同时命中所有共享它的租户**(集体停发 + 集体重签)——爆炸半径 = 整个共享组。
//!
//! **本模块**:把共享 key **分组**(每 N 个租户一把,而非单一全局 key)以**限爆炸半径**。组大小 N 是
//! "成本 vs 爆炸半径"的显式旋钮:**N=1 即退化为逐租户 CMK**(每租户独占一组=密码学隔离基线)。
//! 分组是**决定性**的(同 tenant_id + 同 N → 恒定组),便于运维/审计;紧急吊销只命中同组租户。
//!
//! ⚠️ **只适用 claims 级低保障档**;逐租户 CMK 基线(SaaS 第一天默认)有密码学边界、不用本模块。
//! 决策真相源:DEPLOYMENT §1(共享 key 分组限爆炸半径)、DESIGN §8;CONFORMANCE C10.22b。

/// 分组配置错误(可测的确定性错误,不 panic)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyGroupError {
    /// 组大小 N 必须 ≥ 1(N=1 = 逐租户 CMK 退化;N=0 无意义)。
    InvalidGroupSize,
}

/// FNV-1a 64 位哈希(决定性、零依赖;仅用于分组分桶,不作密码学用途)。
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 把 `tenant_id` 决定性分配到共享 key 组,返回组标识 `keygroup-<idx>`(idx ∈ [0, num_groups))。
///
/// - `group_size` N = 每组封顶租户数(**旋钮**);MUST ≥ 1(N=1 → 每组≈1 租户,退化逐租户)。
/// - `num_groups` = 当前该形态下的组总数(由控制面按已入组租户数 / N 预置;≥ 1)。
/// - 分配 = `fnv1a(tenant_id) % num_groups`(决定性:同 tenant + 同 num_groups → 恒定组)。
///
/// 注:真实"每组不超 N 个成员"的**硬封顶**由控制面登记时保证(满则开新组),本函数只做决定性映射;
/// `group_size` 在此仅作 N≥1 的合法性校验 + 文档旋钮语义(N=1 时调用方应令 num_groups=租户数)。
pub fn assign_key_group(
    tenant_id: &str,
    group_size: u32,
    num_groups: u32,
) -> Result<String, KeyGroupError> {
    if group_size < 1 || num_groups < 1 {
        return Err(KeyGroupError::InvalidGroupSize);
    }
    let idx = fnv1a(tenant_id) % (num_groups as u64);
    Ok(format!("keygroup-{idx}"))
}

/// 两个租户是否在**同一共享 key 组**(→ 一方触发紧急吊销/轮换时另一方受波及)。
/// 决定性:同 num_groups 下,组相同 ⟺ 会互相波及。
pub fn same_key_group(
    tenant_a: &str,
    tenant_b: &str,
    group_size: u32,
    num_groups: u32,
) -> Result<bool, KeyGroupError> {
    Ok(assign_key_group(tenant_a, group_size, num_groups)?
        == assign_key_group(tenant_b, group_size, num_groups)?)
}

/// **爆炸半径**:对某租户所在共享 key 组执行紧急吊销/轮换时,**受影响的租户集合** = 同组全体。
/// 他组租户 MUST NOT 在此集合(C10.22b:同组吊销不波及他组)。
///
/// 给定候选租户全集 + 触发租户,返回受影响子集(含触发者自身)。
pub fn blast_radius<'a>(
    triggering_tenant: &str,
    all_tenants: &'a [String],
    group_size: u32,
    num_groups: u32,
) -> Result<Vec<&'a str>, KeyGroupError> {
    let trigger_group = assign_key_group(triggering_tenant, group_size, num_groups)?;
    let mut affected = Vec::new();
    for t in all_tenants {
        if assign_key_group(t, group_size, num_groups)? == trigger_group {
            affected.push(t.as_str());
        }
    }
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_size_zero_rejected() {
        assert_eq!(
            assign_key_group("t1", 0, 4),
            Err(KeyGroupError::InvalidGroupSize)
        );
        assert_eq!(
            assign_key_group("t1", 4, 0),
            Err(KeyGroupError::InvalidGroupSize)
        );
    }

    // 决定性:同 tenant + 同 num_groups → 恒定组。
    #[test]
    fn assignment_is_deterministic() {
        let g1 = assign_key_group("tenant-a", 8, 4).unwrap();
        let g2 = assign_key_group("tenant-a", 8, 4).unwrap();
        assert_eq!(g1, g2, "同 tenant 同参数 → 恒定组(决定性)");
        assert!(g1.starts_with("keygroup-"));
    }

    // 组 idx ∈ [0, num_groups)。
    #[test]
    fn group_index_within_bounds() {
        for i in 0..100 {
            let g = assign_key_group(&format!("tenant-{i}"), 4, 4).unwrap();
            let idx: u32 = g.strip_prefix("keygroup-").unwrap().parse().unwrap();
            assert!(idx < 4, "组 idx MUST < num_groups");
        }
    }

    // N=1(num_groups=租户数)退化:大量租户各自不同组的概率(退化逐租户 CMK 的语义)。
    // 用足够多的组让碰撞低,断言不同 tenant 大多落不同组。
    #[test]
    fn large_num_groups_spreads_tenants() {
        let tenants: Vec<String> = (0..20).map(|i| format!("t{i}")).collect();
        let groups: std::collections::HashSet<String> = tenants
            .iter()
            .map(|t| assign_key_group(t, 1, 64).unwrap())
            .collect();
        // 20 租户散到 64 组,碰撞应很少(至少 > 半数落不同组)。
        assert!(
            groups.len() >= 10,
            "大 num_groups 应分散租户(退化逐租户方向)"
        );
    }

    // C10.22b 核心:同组互相波及、他组不波及。
    #[test]
    fn blast_radius_only_hits_same_group() {
        // 构造:找两个同组租户 + 一个他组租户。用 num_groups=2 提高同组概率。
        let all: Vec<String> = (0..30).map(|i| format!("tenant-{i}")).collect();
        // 以 tenant-0 为触发者,爆炸半径 = 与它同组的全体。
        let affected = blast_radius("tenant-0", &all, 15, 2).unwrap();
        let trigger_group = assign_key_group("tenant-0", 15, 2).unwrap();
        // 受影响的每个都与触发者同组;未受影响的都不同组(C10.22b:他组不波及)。
        for t in &all {
            let in_affected = affected.contains(&t.as_str());
            let same = assign_key_group(t, 15, 2).unwrap() == trigger_group;
            assert_eq!(in_affected, same, "受影响 ⟺ 同组(他组 MUST NOT 波及):{t}");
        }
        // 触发者自身在爆炸半径内。
        assert!(affected.contains(&"tenant-0"));
        // 至少有一个他组租户(num_groups=2,30 租户 → 两组都非空的概率极高)。
        assert!(
            affected.len() < all.len(),
            "num_groups=2 时爆炸半径 MUST < 全体(他组不波及)"
        );
    }

    // same_key_group 与 blast_radius 一致。
    #[test]
    fn same_group_consistent_with_blast() {
        let a = "alice-corp";
        let b = "bob-inc";
        let same = same_key_group(a, b, 10, 3).unwrap();
        let all = [a.to_string(), b.to_string()];
        let affected = blast_radius(a, &all, 10, 3).unwrap();
        assert_eq!(
            same,
            affected.contains(&b),
            "same_key_group(a,b) ⟺ b 在 a 的爆炸半径内"
        );
    }
}
