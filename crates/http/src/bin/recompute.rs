//! 策略重算后台任务 Lambda 入口(`lambda` + `aws` feature,spec 005 §7 / C10.17,T7.6)。
//!
//! 触发源 = **EventBridge Schedule**(定时兜底,有界收敛)+ 管理面 bump 即触发(同 Lambda,best-effort)。
//! 每次调用对目标 tenant 跑一次 `run_recompute_pass`:扫 stale Grant(GSI Query effective_pv < current)→
//! evaluate(授权,当前策略)→ 分档写 effective / 吊销(条件写 CAS)。复用 API Lambda 同 `AppState::from_env_aws`。
//!
//! **默认关**:`AGENT_AUTH_RECOMPUTE_ENABLED=1` 才真处置;未开则 dry-run 只扫描报数(fail-safe,防误配批量改 Grant)。
//! tenant 集:`AGENT_AUTH_RECOMPUTE_TENANTS`(逗号分隔;缺省 = 仅空 tenant 自部署单租户)。SaaS 传全部租户子域标签。
//!
//! 打包:`cargo lambda build --release --arm64 --features lambda,aws --bin agent-auth-recompute`。

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{service_fn, LambdaEvent};

    let func = service_fn(|_event: LambdaEvent<serde_json::Value>| async {
        let state = agent_auth_http::AppState::from_env_aws()
            .await
            .map_err(|e| lambda_runtime::Error::from(e.to_string()))?;
        let now = agent_auth_http::current_unix_secs();
        match state.region.admit(now).await {
            Ok(agent_auth_http::region::RegionAdmission::Active) => {}
            Ok(agent_auth_http::region::RegionAdmission::Inactive { .. }) => {
                println!("RECOMPUTE_PASS skipped=region_inactive");
                return Ok(serde_json::json!({ "skipped": "region_inactive" }));
            }
            Err(error) => {
                return Err(lambda_runtime::Error::from(format!(
                    "Region admission unavailable: {error:?}"
                )))
            }
        }

        let enabled = std::env::var("AGENT_AUTH_RECOMPUTE_ENABLED").as_deref() == Ok("1");
        // tenant 集:缺省仅空 tenant(自部署);SaaS 经 env 传逗号分隔租户标签。
        let tenants: Vec<String> = std::env::var("AGENT_AUTH_RECOMPUTE_TENANTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec![String::new()]);

        // publish-then-activate(补强 ⑨):authz 开 + 有策略集文本 → 单写者发布/激活策略工件(幂等)。
        // 只在本重算 Lambda 做(EventBridge 调度无并发);主 API Lambda 冷启不发布(会竞 bump)。
        let policy_set = std::env::var("AGENT_AUTH_POLICY_SET").ok();
        if state.authz_enabled {
            if let Some(text) = policy_set.as_deref().filter(|t| !t.trim().is_empty()) {
                for tenant in &tenants {
                    match agent_auth_http::recompute::publish_policy_from_env(&state, tenant, text)
                        .await
                    {
                        Ok(v) => {
                            // **发布即 seed backfill(补强 ⑪,与 dry-run 解耦)**:publish 若真涨了版本(bump
                            // current_pv),存量 Grant 的 effective_pv 立即落后 → 若不追平,热路径对它们全 503
                            // 直到运维手设 RECOMPUTE_ENABLED=1(评审 H3 启用脚枪:能 bump 的 publish 与能追平的
                            // backfill 归属不同 flag)。故发布**无条件**跟一次 seed_backfill(非 dry-run):它恒
                            // ⊆ 授权(不越 consent)、且是"把存量对齐到刚发布的版本"这一发布固有语义,不受
                            // RECOMPUTE_ENABLED(那只门控**常规调度**的 stale 处置)约束。幂等发布(版本没涨)时
                            // 存量本就不 stale,backfill 扫 0 条,无副作用。
                            let bf =
                                agent_auth_http::recompute::seed_backfill(&state, tenant).await;
                            println!(
                                "POLICY_PUBLISHED tenant={tenant} version={v} backfill_scanned={} backfill_recomputed={} backfill_revoked={} backfill_errored={}",
                                bf.scanned, bf.recomputed, bf.revoked, bf.errored
                            );
                        }
                        // fail-closed:发布失败(parse/store)不激活;记录并继续其余 tenant(本 tenant 保持旧版本)。
                        Err(e) => eprintln!("POLICY_PUBLISH_FAIL tenant={tenant} err={e}"),
                    }
                }
            }
        }

        let mut total = agent_auth_http::recompute::RecomputeStats::default();
        for tenant in &tenants {
            let s = agent_auth_http::recompute::run_recompute_pass(&state, tenant, !enabled).await;
            println!(
                "RECOMPUTE_PASS enabled={enabled} tenant={tenant} scanned={} recomputed={} preserved={} revoked={} conflicted={} errored={}",
                s.scanned, s.recomputed, s.preserved, s.revoked, s.conflicted, s.errored
            );
            total.scanned += s.scanned;
            total.recomputed += s.recomputed;
            total.preserved += s.preserved;
            total.revoked += s.revoked;
            total.conflicted += s.conflicted;
            total.errored += s.errored;
        }
        Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
            "enabled": enabled,
            "tenants": tenants.len(),
            "scanned": total.scanned,
            "recomputed": total.recomputed,
            "preserved": total.preserved,
            "revoked": total.revoked,
            "conflicted": total.conflicted,
            "errored": total.errored,
        }))
    });
    lambda_runtime::run(func).await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-recompute 需 --features lambda,aws 编译");
    std::process::exit(1);
}
