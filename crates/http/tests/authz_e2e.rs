//! 进程内 e2e:Cedar/AVP 授权引擎(spec 005 §7 / C10.17)。
//!
//! 分批随 Tasks 增长:T3 = store 端口(逐租户 policy_version + 不可变工件 + Grant put_conditional CAS);
//! T4 创建接 evaluate;T5 热路径 fail-safe 闸;T6 重算。本文件覆盖 store 级不变量 + 端到端 gate。

use agent_auth_http::ports::{GrantStore, PolicyArtifactStore, PolicyVersionStore};
use agent_auth_http::security_event::{
    SecurityActor, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
};
use agent_auth_http::state::{
    AppState, GrantStoreImpl, PolicyArtifactStoreImpl, PolicyVersionStoreImpl,
};

fn mk_grant(grant_id: &str, revision: u64) -> agent_auth_grant::Grant {
    let mut g = grant_with_resource(grant_id, vec![]);
    g.revision = revision;
    g
}

/// 建一个带单 resource(rs1,给定 scopes)的授权 Grant(per_resource=授权;effective 空)。
fn grant_with_resource(grant_id: &str, scopes: Vec<String>) -> agent_auth_grant::Grant {
    agent_auth_grant::Grant {
        grant_id: grant_id.into(),
        user_id: "user:alice".into(),
        client_id: "app".into(),
        per_resource: if scopes.is_empty() {
            vec![]
        } else {
            vec![agent_auth_grant::ResourceGrant {
                resource: "rs1".into(),
                scopes,
                authorization_details: vec![],
            }]
        },
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 0,
        revision: 0,
        constraints: agent_auth_grant::GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: i64::MAX,
        },
        status: agent_auth_grant::GrantStatus::Active,
    }
}

/// dev AppState 开 authz + seed 一份策略工件(version 1)并 bump current_pv 到 1。
async fn state_with_policy(policy_src: &str) -> AppState {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    // 先写工件(version 1)+ bump current_pv 到 1(先分发后激活⑨)。
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(policy_src.as_bytes()));
    state
        .policy_artifacts
        .put("", 1, policy_src.to_string(), digest)
        .await
        .unwrap();
    assert_eq!(state.policy_versions.bump("").await.unwrap(), 1);
    state
}

// spec 005 §7 补强 ②:policy_version 逐租户分区——t1 bump 不影响 t2(否则跨租户误 stale)。
#[tokio::test]
async fn policy_version_per_tenant_bump_isolated() {
    let s = PolicyVersionStoreImpl::Memory(Default::default());
    assert_eq!(s.get("t1").await.unwrap(), 0);
    assert_eq!(s.bump("t1").await.unwrap(), 1);
    assert_eq!(s.bump("t1").await.unwrap(), 2);
    assert_eq!(s.get("t1").await.unwrap(), 2);
    // t2 不受 t1 bump 影响。
    assert_eq!(
        s.get("t2").await.unwrap(),
        0,
        "逐租户:t1 bump 不误 stale t2"
    );
}

// 不可变工件:按 (tenant, version) 存取;跨租户 / 跨版本隔离。
#[tokio::test]
async fn policy_artifact_store_by_tenant_version() {
    let s = PolicyArtifactStoreImpl::Memory(Default::default());
    s.put(
        "t1",
        1,
        "permit(principal,action,resource);".into(),
        "dig1".into(),
    )
    .await
    .unwrap();
    let got = s.get("t1", 1).await.unwrap().unwrap();
    assert_eq!(got.1, "dig1");
    assert!(s.get("t1", 2).await.unwrap().is_none(), "未登记版本 → None");
    assert!(s.get("t2", 1).await.unwrap().is_none(), "跨租户隔离");
}

// spec 005 §7 补强 ⑫:put_conditional CAS —— 仅当 revision==expected 且未 Revoked 才写;冲突/吊销拒。
#[tokio::test]
async fn put_conditional_cas_rejects_stale_revision_and_revoked() {
    let s = GrantStoreImpl::Memory(Default::default());
    s.put("", mk_grant("g1", 0)).await.unwrap();
    // expected=0 命中 → 成功,revision→1。
    assert!(s.put_conditional("", mk_grant("g1", 0), 0).await.unwrap());
    assert_eq!(s.get("", "g1").await.unwrap().unwrap().revision, 1);
    // 再用 expected=0(已是 1)→ 冲突 false(不覆盖并发更新)。
    assert!(!s.put_conditional("", mk_grant("g1", 0), 0).await.unwrap());
    // 用正确 expected=1 → 成功,revision→2。
    assert!(s.put_conditional("", mk_grant("g1", 1), 1).await.unwrap());
    // 吊销(bump revision→3)后,任何旧 expected 都不复活。
    s.revoke("", "g1").await.unwrap();
    assert!(
        !s.put_conditional("", mk_grant("g1", 2), 2).await.unwrap(),
        "已吊销不复活"
    );
    // 不存在的 grant → false。
    assert!(!s.put_conditional("", mk_grant("nope", 0), 0).await.unwrap());

    // 真实 worker 路径:读取 stale snapshot 后发生并发 revision bump,重算 CAS 必须冲突而不覆盖。
    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let mut g = grant_with_resource("worker-cas", vec!["read".into(), "write".into()]);
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 0;
    seed_grant(&state, g.clone()).await;
    let GrantStoreImpl::Memory(store) = state.grants.as_ref() else {
        panic!("dev state must use MemoryGrantStore");
    };
    store.conflict_next_put_conditional();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 0);
    assert_eq!(stats.conflicted, 1);
    let current = state.grants.get("", "worker-cas").await.unwrap().unwrap();
    assert_eq!(current.revision, 1, "并发写必须推进权威 revision");
    assert_eq!(
        current.effective_pv, 0,
        "旧 worker snapshot 不得覆盖并发更新或错误盖上 completion stamp"
    );
    assert_eq!(
        current.effective_per_resource, g.effective_per_resource,
        "旧 worker snapshot 不得覆盖并发 Grant 权威状态"
    );
}

#[tokio::test]
async fn revision_fenced_revoke_rejects_a_stale_recompute_snapshot() {
    let s = GrantStoreImpl::Memory(Default::default());
    s.put("", mk_grant("g1", 0)).await.unwrap();

    assert!(s.put_conditional("", mk_grant("g1", 0), 0).await.unwrap());
    assert!(
        !s.revoke_if_revision("", "g1", 0).await.unwrap(),
        "an old policy worker must not revoke a concurrently updated Grant"
    );
    let current = s.get("", "g1").await.unwrap().unwrap();
    assert_eq!(current.revision, 1);
    assert_eq!(current.status, agent_auth_grant::GrantStatus::Active);

    assert!(s.revoke_if_revision("", "g1", 1).await.unwrap());
    let revoked = s.get("", "g1").await.unwrap().unwrap();
    assert_eq!(revoked.revision, 2);
    assert_eq!(revoked.status, agent_auth_grant::GrantStatus::Revoked);

    // 真实 worker 路径:全 deny 计算完成后发生并发 revision bump,旧 snapshot 不得吊销当前 Grant。
    let state =
        state_with_policy(r#"permit(principal, action == Action::"unrelated", resource);"#).await;
    let mut g = grant_with_resource("worker-revoke", vec!["read".into()]);
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 0;
    seed_grant(&state, g).await;
    let GrantStoreImpl::Memory(store) = state.grants.as_ref() else {
        panic!("dev state must use MemoryGrantStore");
    };
    store.conflict_next_revoke_if_revision();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.revoked, 0);
    assert_eq!(stats.conflicted, 1);
    let current = state
        .grants
        .get("", "worker-revoke")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, 1, "并发写必须推进权威 revision");
    assert_eq!(current.status, agent_auth_grant::GrantStatus::Active);
    assert_eq!(
        current.effective_pv, 0,
        "旧 worker snapshot 不得错误完成或吊销并发更新后的 Grant"
    );
}

// ===== T7.5:apply_policy_to_grant(创建接 evaluate)=====

// flag 开:策略只 permit read → 授权 {read,write} 被收窄成 effective {read},effective_pv 打戳=current。
#[tokio::test]
async fn apply_policy_narrows_effective_and_stamps_pv() {
    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g)
        .await
        .unwrap();
    assert_eq!(g.effective_pv, 1, "打戳=current_pv");
    assert_eq!(g.effective_per_resource.len(), 1);
    assert_eq!(
        g.effective_per_resource[0].scopes,
        vec!["read".to_string()],
        "授权{{read,write}}∩策略{{read}}={{read}};per_resource(授权)不动"
    );
    // per_resource(授权/consent)绝不被覆写。
    assert_eq!(
        g.per_resource[0].scopes,
        vec!["read".to_string(), "write".to_string()]
    );
}

// flag 关:no-op,effective 留空(effective_view 回退 per_resource,字节等价现网)。
#[tokio::test]
async fn apply_policy_flag_off_is_noop_byte_identical() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = false;
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g)
        .await
        .unwrap();
    assert!(g.effective_per_resource.is_empty(), "flag 关 no-op");
    assert_eq!(g.effective_pv, 0);
    // effective_view 回退授权。
    assert_eq!(
        g.effective_view()[0].scopes,
        vec!["read".to_string(), "write".to_string()]
    );
}

// fail-closed:flag 开但策略工件缺失(current_pv 指向未写工件的版本)→ Err(调用方拒建 Grant)。
#[tokio::test]
async fn apply_policy_missing_artifact_fail_closed() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    // bump current_pv 到 1 但**不写**工件 → 加载失败。
    assert_eq!(state.policy_versions.bump("").await.unwrap(), 1);
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    let r = agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await;
    assert!(r.is_err(), "工件缺失应 fail-closed Err,实得 {r:?}");
}

// 启用脚枪防呆(评审 H3):flag 开但 current_pv==0(**从未 publish 过策略**)→ **no-op**(非 fail-closed)。
// 区分"未初始化"与"某激活版本工件缺失":否则一开 flag、publish 未跑,所有新建 Grant 立即 503 塌方。
#[tokio::test]
async fn apply_policy_pv_zero_is_noop_not_fail_closed() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    // 不 bump(current_pv 恒 0)、不写工件 = 从未发布。
    assert_eq!(state.policy_versions.get("").await.unwrap(), 0);
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    let r = agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await;
    assert!(
        r.is_ok(),
        "current_pv==0(未发布)应 no-op 放行,不 fail-closed:{r:?}"
    );
    assert!(g.effective_per_resource.is_empty(), "no-op:effective 留空");
    assert_eq!(g.effective_pv, 0);
    // effective_view 回退授权(创建路径不塌方)。
    assert_eq!(
        g.effective_view()[0].scopes,
        vec!["read".to_string(), "write".to_string()]
    );
}

// fail-closed:工件坏(parse 失败)→ Err。
#[tokio::test]
async fn apply_policy_bad_artifact_fail_closed() {
    let state = state_with_policy("this is not valid cedar").await;
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    let r = agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await;
    assert!(r.is_err(), "坏策略应 fail-closed Err");
}

// ===== T7.4:热路径 stale_gate(token-exchange + refresh)=====
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

fn resp_status(r: Result<(), axum::response::Response>) -> Option<StatusCode> {
    r.err().map(|resp| resp.into_response().status())
}

// stale(grant.effective_pv < current_pv)→ 503 temporarily_unavailable(拒,非交集)。
#[tokio::test]
async fn stale_gate_stale_grant_rejected_503() {
    let state = state_with_policy(r#"permit(principal, action, resource);"#).await; // current_pv=1
    let now = 1_000_000_000;
    // Grant effective_pv=0 < current_pv=1 → stale。
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    g.effective_pv = 0;
    let r =
        agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &HeaderMap::new(), now).await;
    assert_eq!(
        resp_status(r),
        Some(StatusCode::SERVICE_UNAVAILABLE),
        "stale Grant 热路径 MUST 503 拒(待重算,可重试)"
    );
    // 不 stale(effective_pv==current)→ 放行。
    g.effective_pv = 1;
    let r2 =
        agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &HeaderMap::new(), now).await;
    assert!(r2.is_ok(), "effective_pv==current 非 stale,应放行");
}

// flag 关 → no-op(即便 effective_pv 落后也放行,字节等价现网)。
#[tokio::test]
async fn stale_gate_flag_off_noop() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = false;
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    g.effective_pv = 0;
    let r =
        agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &HeaderMap::new(), 1).await;
    assert!(r.is_ok(), "flag 关 stale_gate no-op");
}

// §7.2(补强 ⑬,评审 H1/H2 修后):allowed_ip_cidrs 非空 → **恒 fail-closed 拒**(可信来源 IP 未接线,
// source_ip 恒 None,绝不退回可伪造的 XFF);allowed_ip_cidrs 空 → 不 gate 放行。
#[tokio::test]
async fn stale_gate_ip_cidr_fail_closed_until_trusted_source_wired() {
    let state = state_with_policy(r#"permit(principal, action, resource);"#).await;
    let now = 1_000_000_000;
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    g.effective_pv = 1; // 非 stale

    // allowed_ip_cidrs 空 → IP 分支不触发,放行(§7.2 无约束)。
    assert!(
        agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &HeaderMap::new(), now)
            .await
            .is_ok(),
        "无 IP 约束应放行"
    );

    // allowed_ip_cidrs 非空 → fail-closed 拒(可信来源未接线;**绝不信 XFF**——伪造白名单内 IP 也不放行)。
    g.allowed_ip_cidrs = vec!["10.0.0.0/8".into()];
    let mut spoofed = HeaderMap::new();
    spoofed.insert("x-forwarded-for", "10.1.2.3".parse().unwrap()); // 伪造白名单内 IP
    assert_eq!(
        resp_status(
            agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &spoofed, now).await
        ),
        Some(StatusCode::FORBIDDEN),
        "策略要求 IP 白名单但无可信来源 → fail-closed 拒;伪造 XFF 首段 MUST NOT 放行(评审 H2)"
    );
    // 无任何头也拒(同 fail-closed)。
    assert_eq!(
        resp_status(
            agent_auth_http::policy_freshness::stale_gate(&state, "", &g, &HeaderMap::new(), now)
                .await
        ),
        Some(StatusCode::FORBIDDEN),
        "策略要求 IP 白名单但来源不可辨 → fail-closed 拒"
    );
}

// ===== T7.6:后台重算(run_recompute_pass)=====
use agent_auth_http::recompute::run_recompute_pass;

/// 直接把一个已授权 Grant(带 effective 快照 + pv)放进 store。
async fn seed_grant(state: &AppState, g: agent_auth_grant::Grant) {
    state.grants.put("", g).await.unwrap();
}

// 收紧策略后重算:stale Grant 的 effective 收窄 + effective_pv 追平 current;之后不再 stale。
#[tokio::test]
async fn recompute_narrows_stale_grant_and_clears_staleness() {
    // 初始策略 v1 permit read+write;Grant 授权 {read,write},effective 已 = {read,write},pv=1。
    let state = state_with_policy(
        r#"permit(principal, action == Action::"read", resource);
           permit(principal, action == Action::"write", resource);"#,
    )
    .await;
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 1;
    seed_grant(&state, g).await;

    // 收紧:写 v2 只 permit read + bump current_pv→2 → Grant 变 stale(effective_pv=1 < 2)。
    use sha2::{Digest, Sha256};
    let v2 = r#"permit(principal, action == Action::"read", resource);"#;
    state
        .policy_artifacts
        .put(
            "",
            2,
            v2.into(),
            format!("{:x}", Sha256::digest(v2.as_bytes())),
        )
        .await
        .unwrap();
    assert_eq!(state.policy_versions.bump("").await.unwrap(), 2);

    // 重算(非 dry-run)。
    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 1);
    // effective 收窄成 {read},pv 追平 2 → 不再 stale。
    let after = state.grants.get("", "g1").await.unwrap().unwrap();
    assert_eq!(after.effective_pv, 2);
    assert_eq!(
        after.effective_per_resource[0].scopes,
        vec!["read".to_string()]
    );
    // per_resource(授权)始终不动。
    assert_eq!(
        after.per_resource[0].scopes,
        vec!["read".to_string(), "write".to_string()]
    );
}

// 放宽策略后重算:effective 从**授权**恢复(不越 consent);证明 per_resource 未被此前收窄毁掉。
#[tokio::test]
async fn recompute_reloosen_restores_from_authorized_not_beyond_consent() {
    // v1 只 permit read;Grant 授权 {read,write},effective 已被收窄成 {read},pv=1。
    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    g.effective_per_resource = vec![agent_auth_grant::ResourceGrant {
        resource: "rs1".into(),
        scopes: vec!["read".into()],
        authorization_details: vec![],
    }];
    g.effective_pv = 1;
    seed_grant(&state, g).await;

    // 放宽:v2 permit read+write+delete + bump→2。delete 只在策略中存在,不在用户 consent 中。
    use sha2::{Digest, Sha256};
    let v2 = r#"permit(principal, action == Action::"read", resource);
                permit(principal, action == Action::"write", resource);
                permit(principal, action == Action::"delete", resource);"#;
    state
        .policy_artifacts
        .put(
            "",
            2,
            v2.into(),
            format!("{:x}", Sha256::digest(v2.as_bytes())),
        )
        .await
        .unwrap();
    state.policy_versions.bump("").await.unwrap();

    run_recompute_pass(&state, "", false).await;
    let after = state.grants.get("", "g1").await.unwrap().unwrap();
    // effective 回到 {read,write}(=授权上限),但不得获得 policy-only 的 delete。
    assert_eq!(
        after.effective_per_resource[0].scopes,
        vec!["read".to_string(), "write".to_string()]
    );
    assert_eq!(
        after.per_resource[0].scopes,
        vec!["read".to_string(), "write".to_string()],
        "后台重算不得扩大用户 consent 权威记录"
    );
    assert!(
        !after.effective_per_resource[0]
            .scopes
            .contains(&"delete".to_string()),
        "策略放宽不得授予用户未 consent 的 policy-only scope"
    );
    assert_eq!(after.effective_pv, 2);
}

// 重算判策略全 deny → 吊销该 Grant(effective 空,留着无用)。
#[tokio::test]
async fn recompute_revokes_when_policy_denies_all() {
    // v1 permit read;Grant 授权 {read},effective={read},pv=1。收紧到 permit 无关 action → 全 deny。
    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 1;
    seed_grant(&state, g).await;

    use sha2::{Digest, Sha256};
    let v2 = r#"permit(principal, action == Action::"unrelated", resource);"#;
    state
        .policy_artifacts
        .put(
            "",
            2,
            v2.into(),
            format!("{:x}", Sha256::digest(v2.as_bytes())),
        )
        .await
        .unwrap();
    state.policy_versions.bump("").await.unwrap();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.revoked, 1, "策略下无任何生效权限 → 吊销");
    let after = state.grants.get("", "g1").await.unwrap().unwrap();
    assert_eq!(after.status, agent_auth_grant::GrantStatus::Revoked);
    let events = state
        .security_events
        .list_by_tenant("default", 0, i64::MAX, 100)
        .await
        .unwrap();
    let revoked = events
        .iter()
        .find(|stored| stored.event.action == "grant.revoke")
        .expect("policy recompute revocation must emit a Grant security event");
    assert_eq!(revoked.event.outcome, SecurityEventOutcome::Success);
    assert_eq!(
        revoked.event.actor,
        SecurityActor::system("policy-recompute")
    );
    assert_eq!(revoked.event.subject, SecuritySubject::grant("g1"));
}

// ===== T7:publish_policy_from_env(发布-然后-激活,补强 ⑨)=====
use agent_auth_http::recompute::publish_policy_from_env;

// 首次发布:current_pv 0 → 写工件 v1 + 激活到 1;之后 apply_policy 能读到工件(非 fail-closed)。
#[tokio::test]
async fn publish_policy_activates_from_zero() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    assert_eq!(state.policy_versions.get("").await.unwrap(), 0);
    let src = r#"permit(principal, action == Action::"read", resource);"#;
    let v = publish_policy_from_env(&state, "", src).await.unwrap();
    assert_eq!(v, 1, "首发激活到 v1");
    assert_eq!(state.policy_versions.get("").await.unwrap(), 1);
    // 工件已在 store → apply_policy 不再 fail-closed,且收窄生效。
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g)
        .await
        .unwrap();
    assert_eq!(g.effective_pv, 1);
    assert_eq!(g.effective_per_resource[0].scopes, vec!["read".to_string()]);
}

// 幂等:相同策略文本重复发布不涨版本(重复调度安全)。
#[tokio::test]
async fn publish_policy_idempotent_same_text() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    let src = r#"permit(principal, action, resource);"#;
    assert_eq!(publish_policy_from_env(&state, "", src).await.unwrap(), 1);
    assert_eq!(
        publish_policy_from_env(&state, "", src).await.unwrap(),
        1,
        "同文本重复发布不涨版本"
    );
    // 改文本 → 涨到 v2。
    let src2 = r#"permit(principal, action == Action::"read", resource);"#;
    assert_eq!(
        publish_policy_from_env(&state, "", src2).await.unwrap(),
        2,
        "文本变更 → 新版本"
    );
}

// fail-closed:坏策略文本 → Err,不激活(current_pv 不动)。
#[tokio::test]
async fn publish_policy_bad_text_fail_closed_no_activation() {
    let mut state = AppState::dev("localhost");
    state.authz_enabled = true;
    let r = publish_policy_from_env(&state, "", "this is not valid cedar").await;
    assert!(r.is_err(), "坏策略应 Err");
    assert_eq!(
        state.policy_versions.get("").await.unwrap(),
        0,
        "发布失败不得激活(current_pv 不动)"
    );

    let PolicyArtifactStoreImpl::Memory(artifacts) = state.policy_artifacts.as_ref() else {
        panic!("dev state must use MemoryPolicyArtifactStore");
    };
    artifacts.fail_next_put();
    let valid = r#"permit(principal, action == Action::"read", resource);"#;
    let r = publish_policy_from_env(&state, "", valid).await;
    assert!(r.is_err(), "工件写失败必须阻止策略激活");
    assert_eq!(
        state.policy_versions.get("").await.unwrap(),
        0,
        "工件写失败后 current_pv MUST 保持 0"
    );
    assert!(
        state.policy_artifacts.get("", 1).await.unwrap().is_none(),
        "失败写入不得留下可被误激活的 v1 工件"
    );
}

// dry-run:只扫描报数,不改任何 Grant。
#[tokio::test]
async fn recompute_dry_run_scans_but_does_not_mutate() {
    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into(), "write".into()]);
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 0; // stale(< current_pv=1)
    seed_grant(&state, g).await;
    let before = state.grants.get("", "g1").await.unwrap().unwrap();

    let stats = run_recompute_pass(&state, "", true).await; // dry-run
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 0, "dry-run 不改");
    assert_eq!(
        stats,
        agent_auth_http::recompute::RecomputeStats {
            scanned: 1,
            ..Default::default()
        },
        "dry-run 只报告扫描数,不得报告任何写入/吊销/冲突"
    );
    let after = state.grants.get("", "g1").await.unwrap().unwrap();
    assert_eq!(
        after, before,
        "dry-run 必须保持 Grant 的完整权威快照逐字段不变"
    );
}

// ===== T8:C10.17 核心不变量结构守卫 =====

#[derive(Default)]
struct CallPaths(Vec<String>);

impl<'ast> syn::visit::Visit<'ast> for CallPaths {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            self.0.push(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn rust_call_paths(source: &str) -> Vec<String> {
    use syn::visit::Visit;

    let file = syn::parse_file(source).expect("reviewed Rust source must parse");
    let mut visitor = CallPaths::default();
    visitor.visit_file(&file);
    visitor.0
}

fn assert_no_calls_ending(paths: &[String], source_name: &str, forbidden: &[&str]) {
    for suffix in forbidden {
        assert!(
            !paths.iter().any(|path| path.ends_with(suffix)),
            "C10.17 违反:热路径 {source_name} 实际调用了 {suffix}"
        );
    }
}

// **C10.17 铁律**:签发热路径**永不同步调 Cedar/AVP**。这是设计的核心裁决(评审 Blocker,frozen §7);
// 用 AST 调用守卫**回归化**——evaluate 只许出现在冷路径 authz_gate[创建] + recompute[后台]。
#[test]
fn c10_17_issuance_hot_path_has_zero_cedar_reference() {
    let hot_paths = [
        ("token.rs", include_str!("../src/token.rs")),
        (
            "token_exchange.rs",
            include_str!("../src/token_exchange.rs"),
        ),
        ("refresh_flow.rs", include_str!("../src/refresh_flow.rs")),
    ];
    for (name, src) in hot_paths {
        let paths = rust_call_paths(src);
        assert_no_calls_ending(&paths, name, &["evaluate", "run_recompute_pass"]);
        if name != "token.rs" {
            assert_no_calls_ending(&paths, name, &["apply_policy_to_grant"]);
        }
    }

    let freshness_paths = rust_call_paths(include_str!("../src/policy_freshness.rs"));
    assert_no_calls_ending(
        &freshness_paths,
        "policy_freshness.rs",
        &["evaluate", "apply_policy_to_grant", "run_recompute_pass"],
    );
    let refresh_paths = rust_call_paths(include_str!("../src/refresh_flow.rs"));
    let exchange_paths = rust_call_paths(include_str!("../src/token_exchange.rs"));
    assert!(
        refresh_paths
            .iter()
            .any(|path| path.ends_with("policy_freshness::stale_gate"))
            && exchange_paths
                .iter()
                .any(|path| path.ends_with("policy_freshness::stale_gate")),
        "C10.17 refresh 与 token-exchange 热路径必须实际调用零 Cedar 的 stale read-gate"
    );
}

// 佐证:冷路径**确实**读策略工件并产生策略特异性收窄(否则热路径守卫可能因引擎根本没接而"假绿")。
#[tokio::test]
async fn c10_17_cold_path_does_use_cedar() {
    let creation_paths = rust_call_paths(include_str!("../src/authz_gate.rs"));
    assert!(
        creation_paths.iter().any(|path| path.ends_with("evaluate")),
        "authz_gate 创建冷路径必须实际调用 Cedar evaluate"
    );
    let recompute_paths = rust_call_paths(include_str!("../src/recompute.rs"));
    assert!(
        recompute_paths
            .iter()
            .any(|path| path.ends_with("evaluate")),
        "recompute 后台冷路径必须实际调用 Cedar evaluate"
    );

    let state =
        state_with_policy(r#"permit(principal, action == Action::"read", resource);"#).await;
    let PolicyArtifactStoreImpl::Memory(artifacts) = state.policy_artifacts.as_ref() else {
        panic!("dev state must use MemoryPolicyArtifactStore");
    };

    let mut creation_grant =
        grant_with_resource("cold-create", vec!["read".into(), "write".into()]);
    let reads_before_creation = artifacts.get_count();
    agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut creation_grant)
        .await
        .expect("Grant creation cold path must evaluate the active policy artifact");
    assert_eq!(
        artifacts.get_count(),
        reads_before_creation + 1,
        "Grant creation cold path must read the active policy artifact exactly once"
    );
    assert_eq!(
        creation_grant.effective_per_resource[0].scopes,
        vec!["read".to_string()],
        "Grant creation cold path must apply the policy-specific read-only result"
    );

    let mut stale = grant_with_resource("cold-recompute", vec!["read".into(), "write".into()]);
    stale.effective_per_resource = stale.per_resource.clone();
    stale.effective_pv = 0;
    seed_grant(&state, stale).await;
    let reads_before_recompute = artifacts.get_count();
    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 1);
    assert_eq!(
        artifacts.get_count(),
        reads_before_recompute + 1,
        "background recompute cold path must read the active policy artifact exactly once"
    );
    let recomputed = state
        .grants
        .get("", "cold-recompute")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recomputed.effective_per_resource[0].scopes,
        vec!["read".to_string()],
        "background recompute cold path must apply the policy-specific read-only result"
    );
}

// ===== 补强 ⑯:空 effective 三态消歧 + 无可评估单元不吊销 =====

// resource-less Grant(per_resource 空)在 deny-all 策略下重算 → **保留**(preserved,不 revoked)。
#[tokio::test]
async fn recompute_preserves_resource_less_grant_under_deny_all() {
    // 策略 permit 无关 action = 对任何 (resource,scope) 全 deny。
    let state =
        state_with_policy(r#"permit(principal, action == Action::"unrelated", resource);"#).await;
    // resource-less:per_resource 空(有 scope 无 RS 的 Grant;真机 56/66 属此)。effective_pv=0 → stale。
    let mut g = grant_with_resource("rless", vec![]); // 空 scopes → per_resource 空
    assert!(g.per_resource.is_empty(), "构造的应是 resource-less");
    g.effective_per_resource = vec![agent_auth_grant::ResourceGrant {
        resource: "legacy-rs".into(),
        scopes: vec!["legacy-scope".into()],
        authorization_details: vec![],
    }];
    g.allowed_ip_cidrs = vec!["198.51.100.0/24".into()];
    g.allowed_vpce = vec!["vpce-legacy".into()];
    g.effective_pv = 0;
    seed_grant(&state, g).await;
    let before = state.grants.get("", "rless").await.unwrap().unwrap();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.revoked, 0, "resource-less MUST NOT 吊销");
    assert_eq!(
        stats.preserved, 1,
        "resource-less → preserved(无可评估单元,Cedar 无从表态)"
    );
    let after = state.grants.get("", "rless").await.unwrap().unwrap();
    let mut expected = before;
    expected.effective_pv = 1;
    expected.revision += 1;
    assert_eq!(
        after, expected,
        "resource-less preserve 只能写入完成 stamp,不得清空或改写既有 Grant 权威上下文"
    );
}

// resource 有但 scopes 空+无 RAR("RS 默认权限")→ 无可评估单元 → 保留,不吊销。
#[tokio::test]
async fn recompute_preserves_empty_scopes_resource() {
    let state = state_with_policy(r#"permit(principal, action == Action::"x", resource);"#).await;
    let mut g = grant_with_resource("emptyscope", vec![]);
    // 手动放一个 scopes 空 + 无 RAR 的 resource 项(合法"默认权限"形态)。
    g.per_resource = vec![agent_auth_grant::ResourceGrant {
        resource: "rs1".into(),
        scopes: vec![],
        authorization_details: vec![],
    }];
    g.effective_pv = 0;
    seed_grant(&state, g).await;
    let before = state.grants.get("", "emptyscope").await.unwrap().unwrap();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.scanned, 1);
    assert_eq!(stats.recomputed, 0);
    assert_eq!(stats.revoked, 0);
    assert_eq!(stats.preserved, 1);
    assert_eq!(stats.conflicted, 0);
    assert_eq!(stats.errored, 0);
    let after = state.grants.get("", "emptyscope").await.unwrap().unwrap();
    let mut expected = before;
    expected.effective_pv = 1;
    expected.revision += 1;
    assert_eq!(
        after, expected,
        "空 scopes+无 RAR 只能写入完成 stamp,其余 Grant 权威状态必须逐字段保持"
    );
}

// 有可评估单元(有 scope)却被策略全 deny → **吊销**(与上面对比:此为真的"被剥光")。
#[tokio::test]
async fn recompute_revokes_resource_ful_all_denied() {
    let state = state_with_policy(r#"permit(principal, action == Action::"x", resource);"#).await;
    let mut g = grant_with_resource("rful", vec!["read".into()]); // 有 scope = 有可评估单元
    g.effective_per_resource = g.per_resource.clone();
    g.effective_pv = 1;
    seed_grant(&state, g).await;
    // 收紧:v2 仍全 deny read(permit 无关 action)+ bump。
    use sha2::{Digest, Sha256};
    let v2 = r#"permit(principal, action == Action::"y", resource);"#;
    state
        .policy_artifacts
        .put(
            "",
            2,
            v2.into(),
            format!("{:x}", Sha256::digest(v2.as_bytes())),
        )
        .await
        .unwrap();
    state.policy_versions.bump("").await.unwrap();

    let stats = run_recompute_pass(&state, "", false).await;
    assert_eq!(stats.revoked, 1, "有可评估单元 + 全 deny → 吊销");
    assert_eq!(stats.preserved, 0);
    let after = state.grants.get("", "rful").await.unwrap().unwrap();
    assert_eq!(after.status, agent_auth_grant::GrantStatus::Revoked);
}

// 创建路径对称(Blocker 1):有可评估单元被策略全 deny → apply 返回 Err(fail-closed 拒建)。
#[tokio::test]
async fn apply_policy_fail_closed_when_resource_ful_all_denied() {
    let state = state_with_policy(r#"permit(principal, action == Action::"x", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into()]); // 有 scope,策略不 permit read
    let r = agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await;
    assert!(
        r.is_err(),
        "有可评估单元 + 全 deny 创建时 MUST fail-closed Err,实得 {r:?}"
    );
}

// 补强 ⑯ 错误分档:有可评估单元全 deny → Denied(永久,access_denied);工件缺失/坏 → Transient(可重试 503)。
#[tokio::test]
async fn apply_policy_error_classifies_denied_vs_transient() {
    use agent_auth_http::authz_gate::ApplyPolicyError;
    // Denied:有 scope 被策略全 deny。
    let state = state_with_policy(r#"permit(principal, action == Action::"x", resource);"#).await;
    let mut g = grant_with_resource("g1", vec!["read".into()]);
    match agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await {
        Err(ApplyPolicyError::Denied(_)) => {}
        other => panic!("有可评估单元全 deny 应 Denied,实得 {other:?}"),
    }
    // Transient:bump 到 v1 但不写工件 → 工件缺失。
    let mut s2 = AppState::dev("localhost");
    s2.authz_enabled = true;
    s2.policy_versions.bump("").await.unwrap();
    let mut g2 = grant_with_resource("g2", vec!["read".into()]);
    match agent_auth_http::authz_gate::apply_policy_to_grant(&s2, "", &mut g2).await {
        Err(ApplyPolicyError::Transient(_)) => {}
        other => panic!("工件缺失应 Transient,实得 {other:?}"),
    }
}

// 创建路径:resource-less Grant 全 deny 策略下**不** Err(无可评估单元,写空 effective + pv 保留)。
#[tokio::test]
async fn apply_policy_resource_less_ok_under_deny_all() {
    let state =
        state_with_policy(r#"permit(principal, action == Action::"unrelated", resource);"#).await;
    let mut g = grant_with_resource("rless", vec![]); // per_resource 空
    let r = agent_auth_http::authz_gate::apply_policy_to_grant(&state, "", &mut g).await;
    assert!(
        r.is_ok(),
        "resource-less 无可评估单元,创建应 OK(不 fail-closed):{r:?}"
    );
    assert!(g.effective_per_resource.is_empty(), "effective 空");
    assert_eq!(g.effective_pv, 1, "打 pv 戳(已评估)");
}
