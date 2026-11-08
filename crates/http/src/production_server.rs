//! Separate public, authenticated management and probe listeners for the
//! portable deployment. Access logs omit URLs, cookies, credentials and bodies.

use crate::{ports::StoreError, postgres_runtime::PostgresRuntime, AppState, RouteScope};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

#[derive(Clone, Default)]
pub struct ProductionHealth {
    ready: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

impl ProductionHealth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_ready(&self) {
        if !self.stopping.load(Ordering::SeqCst) {
            self.ready.store(true, Ordering::SeqCst);
        }
    }

    pub fn mark_unready(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }

    pub fn begin_shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.mark_unready();
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst) && !self.stopping.load(Ordering::SeqCst)
    }
}

fn private_path(path: &str) -> bool {
    path == "/admin" || path.starts_with("/admin/") || path == "/scim" || path.starts_with("/scim/")
}

async fn public_plane(request: Request, next: Next) -> Response {
    if private_path(request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

async fn management_plane(request: Request, next: Next) -> Response {
    if !private_path(request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

async fn peer_source_ip(mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string());
    request
        .extensions_mut()
        .remove::<crate::mtls::TrustedSourceIp>();
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(crate::mtls::TrustedSourceIp(peer));
    }
    next.run(request).await
}

async fn admission(
    State(health): State<ProductionHealth>,
    request: Request,
    next: Next,
) -> Response {
    if !health.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error":"temporarily_unavailable"})),
        )
            .into_response();
    }
    next.run(request).await
}

async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    log(serde_json::json!({
        "event":"http_request","method":method,"status":response.status().as_u16(),
        "elapsed_ms":started.elapsed().as_millis()
    }));
    response
}

async fn ready(State(health): State<ProductionHealth>) -> StatusCode {
    if health.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Public management paths return 404 even with valid administrator credentials.
/// The management plane preserves every existing handler's authentication.
pub fn production_routers(
    state: AppState,
    scope: RouteScope,
    health: ProductionHealth,
) -> Result<(Router, Router, Router), StoreError> {
    if scope == RouteScope::Full {
        return Err(StoreError::Permanent(
            "Production HTTP scope must be explicit".into(),
        ));
    }
    let router = crate::build_router_for_scope(state, scope).0;
    let public = router
        .clone()
        .layer(middleware::from_fn(public_plane))
        .layer(middleware::from_fn(peer_source_ip))
        .layer(middleware::from_fn_with_state(health.clone(), admission))
        .layer(middleware::from_fn(access_log));
    let management = if scope == RouteScope::NonToken {
        router
            .layer(middleware::from_fn(management_plane))
            .layer(middleware::from_fn(peer_source_ip))
            .layer(middleware::from_fn_with_state(health.clone(), admission))
            .layer(middleware::from_fn(access_log))
    } else {
        Router::new()
    };
    let probes = probe_router(health);
    Ok((public, management, probes))
}

pub fn probe_router(health: ProductionHealth) -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .with_state(health)
}

pub struct ListenOptions {
    pub public: SocketAddr,
    pub management: SocketAddr,
    pub probes: SocketAddr,
}

impl ListenOptions {
    pub fn from_env() -> Result<Self, StoreError> {
        fn address(name: &str, default: &str) -> Result<SocketAddr, StoreError> {
            std::env::var(name)
                .unwrap_or_else(|_| default.into())
                .parse()
                .map_err(|_| StoreError::Permanent("Invalid listener configuration".into()))
        }
        let options = Self {
            public: address("A_AUTH_BIND", "0.0.0.0:8080")?,
            management: address("A_AUTH_MANAGEMENT_BIND", "127.0.0.1:8081")?,
            probes: address("A_AUTH_PROBE_BIND", "0.0.0.0:8082")?,
        };
        if options.public.port() == 0
            || options.management.port() == 0
            || options.probes.port() == 0
            || options.public.port() == options.management.port()
            || options.public.port() == options.probes.port()
            || options.management.port() == options.probes.port()
        {
            return Err(StoreError::Permanent(
                "Listener ports must be distinct and nonzero".into(),
            ));
        }
        Ok(options)
    }
}

pub fn log(value: serde_json::Value) {
    println!("{}", value);
}

pub async fn shutdown_signal() -> Result<(), StoreError> {
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| StoreError::Permanent("Shutdown signal registration failed".into()))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|_| StoreError::Permanent("Shutdown signal unavailable".into())),
        _ = terminate.recv() => Ok(()),
    }
}

pub(crate) async fn stopping(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

pub async fn serve(
    runtime: PostgresRuntime,
    scope: RouteScope,
    options: ListenOptions,
) -> Result<(), StoreError> {
    let runtime = Arc::new(runtime);
    let health = ProductionHealth::new();
    let (public, management, probes) =
        production_routers(runtime.state.clone(), scope, health.clone())?;
    let mut listeners = vec![
        (TcpListener::bind(options.public).await, public),
        (TcpListener::bind(options.probes).await, probes),
    ];
    if scope == RouteScope::NonToken {
        listeners.push((TcpListener::bind(options.management).await, management));
    }
    let mut bound = Vec::new();
    for (listener, router) in listeners {
        bound.push((
            listener.map_err(|_| StoreError::Permanent("Listener bind failed".into()))?,
            router,
        ));
    }
    let (sender, receiver) = watch::channel(false);
    let mut servers = JoinSet::new();
    for (listener, router) in bound {
        let shutdown = receiver.clone();
        servers.spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(stopping(shutdown))
            .await
        });
    }
    let checker = {
        let (runtime, health) = (runtime.clone(), health.clone());
        let mut shutdown = receiver.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stopping(shutdown.clone()) => break,
                    _ = interval.tick() => {
                        let valid = matches!(tokio::time::timeout(Duration::from_secs(4), runtime.verify_ready()).await, Ok(Ok(())));
                        if valid { health.mark_ready(); } else { health.mark_unready(); }
                    }
                }
                shutdown.borrow_and_update();
            }
        })
    };
    log(
        serde_json::json!({"event":"http_started","scope":if scope == RouteScope::Token {"token"} else {"non_token"},
        "source_commit":runtime.state.deployment_commit}),
    );
    let result = tokio::select! {
        result = shutdown_signal() => result,
        _ = servers.join_next() => Err(StoreError::Transient("HTTP listener stopped unexpectedly".into())),
    };
    health.begin_shutdown();
    let _ = sender.send(true);
    log(serde_json::json!({"event":"http_draining"}));
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(result) = servers.join_next().await {
            result
                .map_err(|_| StoreError::Transient("HTTP task failed".into()))?
                .map_err(|_| StoreError::Transient("HTTP listener failed".into()))?;
        }
        Ok::<_, StoreError>(())
    })
    .await;
    if drained.is_err() {
        servers.abort_all();
    }
    let _ = checker.await;
    runtime.database.close().await;
    log(serde_json::json!({"event":"http_stopped"}));
    result.and(drained.map_err(|_| StoreError::Transient("HTTP drain deadline exceeded".into()))?)
}
