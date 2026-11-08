//! AWS-free HTTP, migration and worker entrypoints for Kubernetes.

use agent_auth_http::{
    ports::StoreError,
    postgres_runtime::PostgresRuntime,
    production_server::{self, ListenOptions},
    production_worker::{self, WorkerKind},
    RouteScope,
};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        production_server::log(serde_json::json!({"event":"process_failed"}));
        std::process::exit(1);
    }
}

async fn run() -> Result<(), StoreError> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) || (arguments.len() == 3 && arguments[0] != "migrate") {
        return Err(StoreError::Permanent("Expected MODE CONFIG_PATH".into()));
    }
    let path = &arguments[1];
    match arguments[0].as_str() {
        "migrate" => {
            if let Some(role) = arguments.get(2) {
                PostgresRuntime::migrate_with_runtime_role(path, role).await?;
            } else {
                PostgresRuntime::migrate(path).await?;
            }
            production_server::log(serde_json::json!({"event":"migrations_applied"}));
            Ok(())
        }
        "serve-token" | "serve-web" => {
            let scope = if arguments[0] == "serve-token" {
                RouteScope::Token
            } else {
                RouteScope::NonToken
            };
            let runtime = PostgresRuntime::load_for_scope(path, scope).await?;
            production_server::serve(runtime, scope, ListenOptions::from_env()?).await
        }
        mode if WorkerKind::from_mode(mode).is_some() => {
            let kind = WorkerKind::from_mode(mode)
                .ok_or_else(|| StoreError::Permanent("Invalid worker mode".into()))?;
            let runtime = PostgresRuntime::load_for_scope(path, RouteScope::NonToken).await?;
            production_worker::run(runtime, kind).await
        }
        mode @ ("job-retention" | "job-reclaim" | "job-recompute") => {
            let runtime = PostgresRuntime::load_for_scope(path, RouteScope::NonToken).await?;
            let result = production_worker::maintenance(&runtime, mode).await;
            runtime.database.close().await;
            production_server::log(
                serde_json::json!({"event":"maintenance_pass","counts":result?}),
            );
            Ok(())
        }
        _ => Err(StoreError::Permanent(
            "Unsupported PostgreSQL process mode".into(),
        )),
    }
}
