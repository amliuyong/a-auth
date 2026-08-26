//! client 回收后台任务 Lambda 入口(`lambda` + `aws` feature,spec 005 §9.5,C10.5)。
//!
//! 触发源 = **EventBridge Schedule**(非 HTTP;不经 API Gateway)。每次调用跑一次 `run_reclaim_pass`:
//! 扫 `last_used_day-index` 旧 client → 强一致聚合信号 → decide_reclaim → tombstone / 硬删+审计。
//! 复用 API Lambda 同一 `AppState::from_env_aws`(同套 KMS/DynamoDB 端口)。
//!
//! 策略 env(缺省保守):`RECLAIM_IDLE_DAYS`(闲置阈值天,默认 90)、`RECLAIM_MAX_ACCESS_TTL_SECS`
//! (tombstone 猶予秒,须 ≥ access 最大 TTL,默认 86400)。**默认关**:`AGENT_AUTH_RECLAIM_ENABLED=1`
//! 才真处置——未开则只扫描 + 打印统计(dry-run),避免误配的调度把 client 删掉(fail-safe)。
//!
//! 打包:`cargo lambda build --release --arm64 --features lambda,aws --bin agent-auth-reclaim`。

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{service_fn, LambdaEvent};

    let func = service_fn(|_event: LambdaEvent<serde_json::Value>| async {
        // 每次调度构造 AppState(冷启动缓存;回收任务低频,构造成本可接受)。
        let state = agent_auth_http::AppState::from_env_aws()
            .await
            .map_err(|e| lambda_runtime::Error::from(e.to_string()))?;

        let test_client_prefix = match std::env::var_os("AGENT_AUTH_RECLAIM_TEST_CLIENT_PREFIX") {
            None => None,
            Some(raw) => {
                let prefix = raw.into_string().map_err(|_| {
                    lambda_runtime::Error::from(
                        "AGENT_AUTH_RECLAIM_TEST_CLIENT_PREFIX must be valid UTF-8",
                    )
                })?;
                agent_auth_http::reclaim::validate_test_client_prefix(&prefix)
                    .map_err(lambda_runtime::Error::from)?;
                Some(prefix)
            }
        };
        let idle_days = std::env::var("RECLAIM_IDLE_DAYS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&d| d > 0)
            .unwrap_or(90);
        let max_access_ttl = std::env::var("RECLAIM_MAX_ACCESS_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&t| t > 0)
            .unwrap_or(86_400);
        let policy = agent_auth_http::reclaim::reclaim_policy(idle_days, max_access_ttl);
        let enabled = std::env::var("AGENT_AUTH_RECLAIM_ENABLED").as_deref() == Ok("1");
        if test_client_prefix.is_some() && !enabled {
            return Err(lambda_runtime::Error::from(
                "AGENT_AUTH_RECLAIM_TEST_CLIENT_PREFIX requires AGENT_AUTH_RECLAIM_ENABLED=1",
            ));
        }
        let now = agent_auth_http::current_unix_secs();
        match state.region.admit(now).await {
            Ok(agent_auth_http::region::RegionAdmission::Active) => {}
            Ok(agent_auth_http::region::RegionAdmission::Inactive { .. }) => {
                println!("RECLAIM_PASS skipped=region_inactive");
                return Ok(serde_json::json!({ "skipped": "region_inactive" }));
            }
            Err(error) => {
                return Err(lambda_runtime::Error::from(format!(
                    "Region admission unavailable: {error:?}"
                )))
            }
        }

        let stats = if enabled {
            agent_auth_http::reclaim::run_reclaim_pass_scoped(
                &state,
                &policy,
                now,
                test_client_prefix.as_deref(),
            )
            .await
        } else {
            // dry-run:未显式开则只扫描报数,绝不处置(fail-safe,防误配调度批量删 client)。
            agent_auth_http::reclaim::dry_run_scan(&state, &policy, now).await
        };
        // 结构化统计到 stdout(CloudWatch 可 metric filter)。
        println!(
            "RECLAIM_PASS enabled={enabled} scanned={} tombstoned={} hard_deleted={} kept={} errored={}",
            stats.scanned, stats.tombstoned, stats.hard_deleted, stats.kept, stats.errored
        );
        Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
            "enabled": enabled,
            "scanned": stats.scanned,
            "tombstoned": stats.tombstoned,
            "hard_deleted": stats.hard_deleted,
            "kept": stats.kept,
            "errored": stats.errored,
            "test_scope_enabled": test_client_prefix.is_some(),
        }))
    });
    lambda_runtime::run(func).await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-reclaim 需 --features lambda,aws 编译");
    std::process::exit(1);
}
