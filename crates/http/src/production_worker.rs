//! Kubernetes worker processes reuse the durable, fenced adapter orchestrators.

use crate::{
    adapters::http_transport::HttpSsfPushClient,
    ports::StoreError,
    postgres_runtime::PostgresRuntime,
    production_server::{self, ListenOptions, ProductionHealth},
    state::{NotifierImpl, SecurityEventFallbackImpl, SsfStoreImpl},
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Copy)]
pub enum WorkerKind {
    Governance,
    Events,
    Smtp,
    Ssf,
}

impl WorkerKind {
    pub fn from_mode(value: &str) -> Option<Self> {
        match value {
            "work-governance" => Some(Self::Governance),
            "work-events" => Some(Self::Events),
            "work-smtp" => Some(Self::Smtp),
            "work-ssf" => Some(Self::Ssf),
            _ => None,
        }
    }
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL worker composition".into())
}

pub async fn run_once(runtime: &PostgresRuntime, kind: WorkerKind) -> Result<Value, StoreError> {
    let now = crate::current_unix_secs();
    match kind {
        WorkerKind::Governance => {
            let batch =
                crate::governance_worker::run_postgres_queue_once(&runtime.state, now, 16).await?;
            serde_json::to_value(batch).map_err(|_| invalid())
        }
        WorkerKind::Events => {
            let Some(fallback) = &runtime.state.security_event_fallback else {
                return Err(invalid());
            };
            let SecurityEventFallbackImpl::Postgres(fallback) = fallback.as_ref() else {
                return Err(invalid());
            };
            let batch = fallback.run_once(now, 16).await?;
            Ok(json!({"claimed":batch.claimed,"persisted":batch.persisted,
                "acknowledged":batch.acknowledged,"retried":batch.retried,
                "dead_lettered":batch.dead_lettered,"authority_lost":batch.authority_lost}))
        }
        WorkerKind::Smtp => {
            let NotifierImpl::Postgres(notifier) = runtime.state.notifier.as_ref() else {
                return Err(invalid());
            };
            serde_json::to_value(notifier.run_once(now, 16).await?).map_err(|_| invalid())
        }
        WorkerKind::Ssf => {
            let SsfStoreImpl::Postgres(store) = runtime.state.ssf.as_ref() else {
                return Err(invalid());
            };
            let batch = crate::ssf_worker::process_due_deliveries(
                store,
                runtime.state.tenant_keys.as_ref(),
                &HttpSsfPushClient::new(),
                now,
            )
            .await?;
            Ok(
                json!({"acquired":batch.acquired,"delivered":batch.delivered,
                "retrying":batch.retrying,"terminal":batch.terminal,
                "dead_lettered":batch.dead_lettered,"lost_leases":batch.lost_leases}),
            )
        }
    }
}

/// SIGTERM closes admission immediately but lets the current bounded pass
/// settle. Crashes/timeouts leave the existing durable lease/journal semantics.
pub async fn run(runtime: PostgresRuntime, kind: WorkerKind) -> Result<(), StoreError> {
    let runtime = Arc::new(runtime);
    let health = ProductionHealth::new();
    let listener = tokio::net::TcpListener::bind(ListenOptions::from_env()?.probes)
        .await
        .map_err(|_| StoreError::Permanent("Worker probe bind failed".into()))?;
    let (sender, mut receiver) = watch::channel(false);
    let probes = {
        let shutdown = receiver.clone();
        let router = production_server::probe_router(health.clone());
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(production_server::stopping(shutdown))
                .await
        })
    };
    let signal = {
        let (sender, health) = (sender.clone(), health.clone());
        tokio::spawn(async move {
            let result = production_server::shutdown_signal().await;
            health.begin_shutdown();
            let _ = sender.send(true);
            result
        })
    };
    while !*receiver.borrow_and_update() {
        if probes.is_finished() {
            break;
        }
        let ready = matches!(
            tokio::time::timeout(Duration::from_secs(4), runtime.verify_ready()).await,
            Ok(Ok(()))
        );
        if *receiver.borrow() {
            break;
        }
        if ready {
            health.mark_ready();
            match tokio::time::timeout(Duration::from_secs(240), run_once(&runtime, kind)).await {
                Ok(Ok(counts)) => {
                    production_server::log(json!({"event":"worker_pass","counts":counts}))
                }
                _ => {
                    health.mark_unready();
                    production_server::log(json!({"event":"worker_pass_failed"}));
                }
            }
        } else {
            health.mark_unready();
            production_server::log(json!({"event":"worker_authority_unavailable"}));
        }
        tokio::select! {
            _ = receiver.changed() => {},
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
    let stopped_by_signal = *receiver.borrow();
    health.begin_shutdown();
    let _ = sender.send(true);
    let result = if stopped_by_signal {
        signal
            .await
            .map_err(|_| StoreError::Transient("Worker signal task failed".into()))?
    } else {
        signal.abort();
        Err(StoreError::Transient(
            "Worker probe listener stopped".into(),
        ))
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), probes).await;
    runtime.database.close().await;
    production_server::log(json!({"event":"worker_stopped"}));
    result
}

pub async fn maintenance(runtime: &PostgresRuntime, mode: &str) -> Result<Value, StoreError> {
    match mode {
        "job-retention" => {
            let completed = crate::governance_worker::run_retention_pass(
                &runtime.state,
                crate::current_unix_secs(),
            )
            .await
            .map_err(|_| StoreError::Transient("Retention pass unavailable".into()))?;
            Ok(json!({"completed":completed}))
        }
        "job-reclaim" => {
            let policy = crate::reclaim::reclaim_policy(90, 86_400);
            let stats = if std::env::var("AGENT_AUTH_RECLAIM_ENABLED").as_deref() == Ok("1") {
                crate::reclaim::run_reclaim_pass(
                    &runtime.state,
                    &policy,
                    crate::current_unix_secs(),
                )
                .await
            } else {
                crate::reclaim::dry_run_scan(&runtime.state, &policy, crate::current_unix_secs())
                    .await
            };
            if stats.errored > 0 {
                return Err(StoreError::Transient("Reclaim pass incomplete".into()));
            }
            Ok(
                json!({"scanned":stats.scanned,"tombstoned":stats.tombstoned,"hard_deleted":stats.hard_deleted,"kept":stats.kept}),
            )
        }
        "job-recompute" => {
            let apply = std::env::var("AGENT_AUTH_RECOMPUTE_ENABLED").as_deref() == Ok("1");
            let stats = crate::recompute::run_recompute_pass(&runtime.state, "", !apply).await;
            if stats.errored > 0 {
                return Err(StoreError::Transient("Recompute pass incomplete".into()));
            }
            Ok(
                json!({"scanned":stats.scanned,"recomputed":stats.recomputed,"preserved":stats.preserved,"revoked":stats.revoked,"conflicted":stats.conflicted}),
            )
        }
        _ => Err(invalid()),
    }
}
