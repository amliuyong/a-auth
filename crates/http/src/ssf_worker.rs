//! Shared Signals outbox worker orchestration.

use std::future::Future;

use crate::{
    ports::{Signer, SignerError, StoreError},
    ssf::{sign_delivery_set, SsfAttemptResult, SsfDeliveryLease, SsfDeliveryStatus, SsfStore},
};

// Ten concurrent ten-second pushes drain one 20-row lease batch in roughly
// twenty seconds. Ten bounded batches remain inside the five-minute Lambda and
// lease window while preventing 32-stream tenants from outpacing one pass.
const DELIVERY_LEASE_SECS: i64 = 300;
const DELIVERY_BATCH_SIZE: usize = 20;
const DELIVERY_CONCURRENCY: usize = 10;
const MAX_DELIVERIES_PER_INVOCATION: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfPushRequest {
    pub endpoint: String,
    pub content_type: &'static str,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfPushResult {
    Response(u16),
    NetworkError(String),
}

pub trait SsfPushClient: Send + Sync {
    fn push(&self, request: SsfPushRequest) -> impl Future<Output = SsfPushResult> + Send;
}

pub trait SsfSignerResolver: Send + Sync {
    type Resolved: Signer + Clone + Send + Sync + 'static;

    fn resolve_signer(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Self::Resolved, SignerError>> + Send;
}

impl<K> SsfSignerResolver for K
where
    K: Signer + Clone + Send + Sync + 'static,
{
    type Resolved = K;

    async fn resolve_signer(&self, _tenant_id: &str) -> Result<Self::Resolved, SignerError> {
        Ok(self.clone())
    }
}

impl SsfSignerResolver for crate::tenant_keys::TenantKeyService {
    type Resolved = crate::state::SignerImpl;

    async fn resolve_signer(&self, tenant_id: &str) -> Result<Self::Resolved, SignerError> {
        self.resolve(tenant_id)
            .await
            .map(|signer| signer.as_ref().clone())
            .map_err(|error| match error {
                crate::tenant_keys::TenantSignerResolveError::RegistryUnavailable => {
                    SignerError::Transient(format!("tenant key registry unavailable: {error:?}"))
                }
                _ => SignerError::Permanent(format!("tenant signer unavailable: {error:?}")),
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SsfWorkerStats {
    pub acquired: usize,
    pub delivered: usize,
    pub retrying: usize,
    pub terminal: usize,
    pub dead_lettered: usize,
    pub lost_leases: usize,
}

impl SsfWorkerStats {
    pub fn is_idle(self) -> bool {
        self.acquired == 0
    }

    fn record(&mut self, outcome: SsfWorkerOutcome) {
        match outcome {
            SsfWorkerOutcome::Delivered => self.delivered += 1,
            SsfWorkerOutcome::Retrying => self.retrying += 1,
            SsfWorkerOutcome::Terminal => self.terminal += 1,
            SsfWorkerOutcome::DeadLettered => self.dead_lettered += 1,
            SsfWorkerOutcome::LostLease => self.lost_leases += 1,
            SsfWorkerOutcome::Other => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsfWorkerOutcome {
    Delivered,
    Retrying,
    Terminal,
    DeadLettered,
    LostLease,
    Other,
}

pub async fn process_due_deliveries<S, K, P>(
    store: &S,
    signer: &K,
    push_client: &P,
    now: i64,
) -> Result<SsfWorkerStats, StoreError>
where
    S: SsfStore + Clone + 'static,
    K: SsfSignerResolver + Clone + 'static,
    P: SsfPushClient + Clone + 'static,
{
    let mut stats = SsfWorkerStats::default();
    while stats.acquired < MAX_DELIVERIES_PER_INVOCATION {
        let limit =
            DELIVERY_BATCH_SIZE.min(MAX_DELIVERIES_PER_INVOCATION.saturating_sub(stats.acquired));
        let leases = store.acquire_due(now, DELIVERY_LEASE_SECS, limit).await?;
        if leases.is_empty() {
            break;
        }
        stats.acquired += leases.len();

        for chunk in leases.chunks(DELIVERY_CONCURRENCY) {
            let mut tasks = tokio::task::JoinSet::new();
            for lease in chunk.iter().cloned() {
                tasks.spawn(process_delivery(
                    store.clone(),
                    signer.clone(),
                    push_client.clone(),
                    lease,
                    now,
                ));
            }
            let mut first_error = None;
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(outcome)) => stats.record(outcome),
                    Ok(Err(error)) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(StoreError::Transient(format!(
                                "SSF delivery task failed: {error}"
                            )));
                        }
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        }
    }
    Ok(stats)
}

async fn process_delivery<S, K, P>(
    store: S,
    signer: K,
    push_client: P,
    lease: SsfDeliveryLease,
    now: i64,
) -> Result<SsfWorkerOutcome, StoreError>
where
    S: SsfStore,
    K: SsfSignerResolver,
    P: SsfPushClient,
{
    let compact_set = if let Some(compact_set) = &lease.delivery.compact_set {
        compact_set.clone()
    } else {
        let resolved = match signer.resolve_signer(&lease.delivery.tenant_id).await {
            Ok(resolved) => resolved,
            Err(SignerError::Transient(_)) => {
                return record_result(
                    &store,
                    &lease,
                    SsfAttemptResult::Retryable {
                        status_code: None,
                        error_class: "signing_snapshot_transient".to_string(),
                    },
                    now,
                )
                .await;
            }
            Err(SignerError::Permanent(_)) => {
                return record_result(
                    &store,
                    &lease,
                    SsfAttemptResult::Fatal {
                        error_class: "signing_snapshot_permanent".to_string(),
                    },
                    now,
                )
                .await;
            }
        };
        let signed = match sign_delivery_set(&resolved, &lease.delivery, now).await {
            Ok(signed) => signed,
            Err(SignerError::Transient(_)) => {
                return record_result(
                    &store,
                    &lease,
                    SsfAttemptResult::Retryable {
                        status_code: None,
                        error_class: "signing_transient".to_string(),
                    },
                    now,
                )
                .await;
            }
            Err(SignerError::Permanent(_)) => {
                return record_result(
                    &store,
                    &lease,
                    SsfAttemptResult::Fatal {
                        error_class: "signing_permanent".to_string(),
                    },
                    now,
                )
                .await;
            }
        };
        if !store.persist_signed_set(&lease, &signed, now, now).await? {
            return Ok(SsfWorkerOutcome::LostLease);
        }
        signed.compact_jws
    };

    let result = match push_client
        .push(SsfPushRequest {
            endpoint: lease.delivery.endpoint.clone(),
            content_type: "application/secevent+jwt",
            body: compact_set,
        })
        .await
    {
        SsfPushResult::Response(202) => SsfAttemptResult::Accepted,
        SsfPushResult::Response(status @ (408 | 429 | 500..=599)) => SsfAttemptResult::Retryable {
            status_code: Some(status),
            error_class: format!("http_{status}"),
        },
        SsfPushResult::Response(status) => SsfAttemptResult::Terminal {
            status_code: status,
            error_class: format!("http_{status}"),
        },
        SsfPushResult::NetworkError(error_class) => SsfAttemptResult::Retryable {
            status_code: None,
            error_class,
        },
    };
    record_result(&store, &lease, result, now).await
}

async fn record_result<S: SsfStore>(
    store: &S,
    lease: &SsfDeliveryLease,
    result: SsfAttemptResult,
    now: i64,
) -> Result<SsfWorkerOutcome, StoreError> {
    let Some(delivery) = store.finish_attempt(lease, result, now).await? else {
        return Ok(SsfWorkerOutcome::LostLease);
    };
    Ok(match delivery.status {
        SsfDeliveryStatus::Delivered => SsfWorkerOutcome::Delivered,
        SsfDeliveryStatus::RetryWait => SsfWorkerOutcome::Retrying,
        SsfDeliveryStatus::Terminal => SsfWorkerOutcome::Terminal,
        SsfDeliveryStatus::DeadLettered => SsfWorkerOutcome::DeadLettered,
        _ => SsfWorkerOutcome::Other,
    })
}
