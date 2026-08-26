//! Lambda 入口(`lambda` + `aws` feature)——触发源 = **API Gateway**(HTTP API),绝不用 Function URL。
//!
//! lambda_http 把 API Gateway 事件适配成 axum 可处理的 `http::Request`;同一套 handler
//! 与本地 server 共用。AWS-backed 状态从环境变量构造(KMS 签名 + DynamoDB 存储)。
//!
//! 打包:`cargo lambda build --release --arm64 --features lambda,aws --bin agent-auth-lambda`。

#[cfg(any(all(feature = "lambda", feature = "aws"), test))]
const DEFAULT_PASSWORD_WORKERS: usize = 2;
#[cfg(any(all(feature = "lambda", feature = "aws"), test))]
const MAX_PASSWORD_WORKERS: usize = 8;

#[cfg(any(all(feature = "lambda", feature = "aws"), test))]
fn password_worker_limit(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| (1..=MAX_PASSWORD_WORKERS).contains(count))
        .unwrap_or(DEFAULT_PASSWORD_WORKERS)
}

#[cfg(any(all(feature = "lambda", feature = "aws"), test))]
fn lambda_runtime(password_workers: usize) -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Argon2 keeps about 19 MiB in each blocking worker's allocator arena.
        // Match the existing semaphore so warm Lambda environments cannot retain
        // Tokio's default near-unbounded number of blocking workers.
        .max_blocking_threads(password_workers)
        .build()
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn main() -> Result<(), lambda_http::Error> {
    let password_workers =
        password_worker_limit(std::env::var("AGENT_AUTH_PASSWORD_WORKERS").ok().as_deref());
    lambda_runtime(password_workers)?.block_on(run())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn run() -> Result<(), lambda_http::Error> {
    let route_scope =
        agent_auth_http::RouteScope::from_deployment_env(std::env::var("SCOPE").ok().as_deref())
            .map_err(lambda_http::Error::from)?;
    route_scope
        .validate_runtime_environment(
            std::env::var("GRACE_TABLE").ok().as_deref(),
            std::env::var("GRACE_KMS_KEY_ID").ok().as_deref(),
        )
        .map_err(lambda_http::Error::from)?;
    let state = agent_auth_http::AppState::from_env_aws()
        .await
        .map_err(|e| lambda_http::Error::from(e.to_string()))?;
    let (router, _api) = agent_auth_http::build_router_for_scope(state, route_scope);
    lambda_http::run(router).await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-lambda 需 --features lambda,aws 编译");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, thread, time::Duration};

    use super::*;

    #[test]
    fn password_worker_limit_accepts_only_the_runtime_budget() {
        assert_eq!(password_worker_limit(None), DEFAULT_PASSWORD_WORKERS);
        assert_eq!(password_worker_limit(Some("1")), 1);
        assert_eq!(password_worker_limit(Some("8")), 8);
        for invalid in ["", "0", "9", "invalid"] {
            assert_eq!(
                password_worker_limit(Some(invalid)),
                DEFAULT_PASSWORD_WORKERS
            );
        }
    }

    #[test]
    fn blocking_pool_never_exceeds_the_password_worker_budget() {
        let runtime = lambda_runtime(2).expect("runtime");
        let thread_ids = runtime.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..16 {
                tasks.push(tokio::task::spawn_blocking(|| {
                    thread::sleep(Duration::from_millis(25));
                    thread::current().id()
                }));
            }
            let mut thread_ids = HashSet::new();
            for task in tasks {
                thread_ids.insert(task.await.expect("blocking task"));
            }
            thread_ids
        });
        assert!((1..=2).contains(&thread_ids.len()));
    }

    #[test]
    fn deployed_route_scope_is_required_and_closed() {
        use agent_auth_http::RouteScope;

        assert_eq!(
            RouteScope::from_deployment_env(Some("token")),
            Ok(RouteScope::Token)
        );
        assert_eq!(
            RouteScope::from_deployment_env(Some("non_token")),
            Ok(RouteScope::NonToken)
        );
        for invalid in [None, Some(""), Some("full"), Some("TOKEN")] {
            assert!(RouteScope::from_deployment_env(invalid).is_err());
        }
        assert!(RouteScope::Token
            .validate_runtime_environment(Some("table"), None)
            .is_err());
        assert!(RouteScope::Token
            .validate_runtime_environment(Some("table"), Some("key"))
            .is_ok());
        assert!(RouteScope::NonToken
            .validate_runtime_environment(Some("table"), None)
            .is_ok());
        assert!(RouteScope::NonToken
            .validate_runtime_environment(None, None)
            .is_err());
        assert!(RouteScope::NonToken
            .validate_runtime_environment(Some("table"), Some("key"))
            .is_err());
    }
}
