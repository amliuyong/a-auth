//! Durable source snapshots for hot-ledger recovery. This queue shares the
//! ledger's database availability; it is not an independent outage buffer.

use super::{db_error, security_events::validate, PostgresStore};
use crate::{
    ports::StoreError,
    security_event::{
        SecurityEvent, SecurityEventDelivery, SecurityEventFallback, SecurityEventFallbackOutcome,
        SecurityEventIngress, SecurityEventStore,
    },
    security_event_archive::{prepare_ingress_receive, INGRESS_DELIVERY_ATTEMPTS},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

const COLUMNS: &str = "event_id, source_id, record, status, receive_count, \
    created_at, available_at, lease_id, lease_until";
const MAX_RECORD_BYTES: usize = 128 * 1024;

#[derive(Clone)]
pub struct PostgresSecurityEventFallback {
    store: PostgresStore,
}

/// Immutable received ingress and private settlement capability.
#[derive(Clone)]
pub struct PostgresSecurityEventLease {
    ingress: SecurityEventIngress,
    source_id: Vec<u8>,
    nonce: Vec<u8>,
    deadline: i64,
    receive_count: u32,
}

impl PostgresSecurityEventLease {
    pub fn ingress(&self) -> &SecurityEventIngress {
        &self.ingress
    }
}

#[derive(Default)]
pub struct PostgresSecurityEventBatch {
    pub claimed: usize,
    pub persisted: usize,
    pub acknowledged: usize,
    pub retried: usize,
    pub dead_lettered: usize,
    pub authority_lost: usize,
}

// Public ingress parsing accepts legacy missing counters. Durable queue records
// must carry their counter explicitly so corruption cannot reset spent attempts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIngress {
    event: SecurityEvent,
    delivery: SecurityEventDelivery,
    ingress_attempts: u32,
}

struct Record {
    ingress: SecurityEventIngress,
    source_id: Vec<u8>,
    status: String,
    receive_count: u32,
    nonce: Option<Vec<u8>>,
    deadline: Option<i64>,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL security event fallback authority".into())
}

fn time(now: i64) -> i64 {
    now.max(crate::current_unix_secs())
}

fn encode(ingress: &SecurityEventIngress) -> Result<String, StoreError> {
    validate(&ingress.event)?;
    if ingress.delivery.history.is_empty()
        || ingress.delivery.history.len() > 64
        || ingress.delivery.attempts < ingress.ingress_attempts
        || ingress
            .delivery
            .history
            .iter()
            .any(|entry| entry.occurred_at <= 0)
        || [
            ingress.delivery.last_attempt_at,
            ingress.delivery.archived_at,
            ingress.delivery.dead_lettered_at,
        ]
        .into_iter()
        .flatten()
        .any(|at| at <= 0)
    {
        return Err(invalid());
    }
    let record = serde_json::to_string(&WireIngress {
        event: ingress.event.clone(),
        delivery: ingress.delivery.clone(),
        ingress_attempts: ingress.ingress_attempts,
    })
    .map_err(|_| invalid())?;
    if record.len() > MAX_RECORD_BYTES {
        return Err(invalid());
    }
    Ok(record)
}

fn source_id(record: &str) -> Vec<u8> {
    Sha256::digest(record.as_bytes()).to_vec()
}

fn received(
    ingress: &SecurityEventIngress,
    count: u32,
    now: i64,
) -> Result<SecurityEventIngress, StoreError> {
    // The shared receive helper saturates for legacy SQS input. Here both
    // durable counters are checked first; exhaustion never resets authority.
    ingress
        .ingress_attempts
        .checked_add(count)
        .ok_or_else(invalid)?;
    ingress
        .delivery
        .attempts
        .checked_add(count)
        .ok_or_else(invalid)?;
    let mut next = ingress.clone();
    prepare_ingress_receive(&mut next, count, now).map_err(|_| invalid())?;
    Ok(next)
}

fn decode(row: PgRow) -> Result<Record, StoreError> {
    let text: String = row.try_get("record").map_err(db_error)?;
    if text.len() > MAX_RECORD_BYTES {
        return Err(invalid());
    }
    let wire: WireIngress = serde_json::from_str(&text).map_err(|_| invalid())?;
    let ingress = SecurityEventIngress {
        event: wire.event,
        delivery: wire.delivery,
        ingress_attempts: wire.ingress_attempts,
    };
    let canonical = encode(&ingress)?;
    let physical_source: Vec<u8> = row.try_get("source_id").map_err(db_error)?;
    let status: String = row.try_get("status").map_err(db_error)?;
    let nonce: Option<Vec<u8>> = row.try_get("lease_id").map_err(db_error)?;
    let deadline: Option<i64> = row.try_get("lease_until").map_err(db_error)?;
    let receive_count = u32::try_from(row.try_get::<i64, _>("receive_count").map_err(db_error)?)
        .map_err(|_| invalid())?;
    let _created_at: i64 = row.try_get("created_at").map_err(db_error)?;
    let _available_at: i64 = row.try_get("available_at").map_err(db_error)?;
    if canonical != text
        || physical_source != source_id(&canonical)
        || row.try_get::<String, _>("event_id").map_err(db_error)? != ingress.event.event_id
        || !matches!(
            status.as_str(),
            "pending" | "leased" | "acked" | "dead_lettered"
        )
        || (status == "leased") != nonce.is_some()
        || nonce.is_some() != deadline.is_some()
        || (status == "leased" && receive_count == 0)
        || nonce.as_ref().is_some_and(|value| {
            value.len() != 35
                || !value.starts_with(b"se_")
                || !value[3..].iter().all(u8::is_ascii_hexdigit)
        })
    {
        return Err(invalid());
    }
    Ok(Record {
        ingress,
        source_id: physical_source,
        status,
        receive_count,
        nonce,
        deadline,
    })
}

impl PostgresSecurityEventFallback {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    /// Claim at most 100 source snapshots for at most six minutes. Decode all
    /// selected records before mutation; a failed batch leaves no partial lease.
    pub async fn claim(
        &self,
        now: i64,
        lease_seconds: i64,
        limit: usize,
    ) -> Result<Vec<PostgresSecurityEventLease>, StoreError> {
        if !(1..=360).contains(&lease_seconds) || !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        let records = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.security_event_fallback \
             WHERE available_at <= $1 AND \
             (status='pending' OR (status='leased' AND lease_until <= $1)) \
             ORDER BY available_at, created_at, event_id, source_id \
             LIMIT $2 FOR UPDATE SKIP LOCKED"
        ))
        .bind(time(now))
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
        let observed = time(now);
        let deadline = observed.checked_add(lease_seconds).ok_or_else(invalid)?;
        let mut leases = Vec::with_capacity(records.len());
        for record in records {
            let count = record.receive_count.checked_add(1).ok_or_else(invalid)?;
            let ingress = received(&record.ingress, count, observed)?;
            let nonce = format!("se_{:032x}", rand::random::<u128>()).into_bytes();
            sqlx::query(
                "UPDATE a_auth.security_event_fallback SET status='leased', \
                 receive_count=$3, lease_id=$4, lease_until=$5 \
                 WHERE event_id=$1 AND source_id=$2",
            )
            .bind(&record.ingress.event.event_id)
            .bind(&record.source_id)
            .bind(i64::from(count))
            .bind(&nonce)
            .bind(deadline)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
            leases.push(PostgresSecurityEventLease {
                ingress,
                source_id: record.source_id,
                nonce,
                deadline,
                receive_count: count,
            });
        }
        if time(now) >= deadline {
            return Err(StoreError::Transient(
                "Security event fallback claim expired".into(),
            ));
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(leases)
    }

    async fn locked(
        transaction: &mut Transaction<'_, Postgres>,
        lease: &PostgresSecurityEventLease,
    ) -> Result<Option<Record>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.security_event_fallback \
             WHERE event_id=$1 AND source_id=$2 FOR UPDATE"
        ))
        .bind(&lease.ingress.event.event_id)
        .bind(&lease.source_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
    }

    async fn settle(
        &self,
        lease: &PostgresSecurityEventLease,
        now: i64,
        status: &str,
        delay_seconds: i64,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        let Some(record) = Self::locked(&mut transaction, lease).await? else {
            return Ok(false);
        };
        if record.status != "leased"
            || record.source_id != lease.source_id
            || record.nonce.as_deref() != Some(lease.nonce.as_slice())
            || record.deadline != Some(lease.deadline)
            || record.receive_count != lease.receive_count
            || time(now) >= lease.deadline
        {
            return Ok(false);
        }
        let available = time(now).checked_add(delay_seconds).ok_or_else(invalid)?;
        sqlx::query(
            "UPDATE a_auth.security_event_fallback SET status=$3, available_at=$4, \
             lease_id=NULL, lease_until=NULL WHERE event_id=$1 AND source_id=$2",
        )
        .bind(&lease.ingress.event.event_id)
        .bind(&lease.source_id)
        .bind(status)
        .bind(available)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if time(now) >= lease.deadline {
            return Ok(false);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    pub async fn acknowledge(
        &self,
        lease: &PostgresSecurityEventLease,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.settle(lease, now, "acked", 0).await
    }

    pub async fn retry(
        &self,
        lease: &PostgresSecurityEventLease,
        now: i64,
        delay_seconds: i64,
    ) -> Result<bool, StoreError> {
        if !(0..=3600).contains(&delay_seconds) {
            return Err(invalid());
        }
        self.settle(lease, now, "pending", delay_seconds).await
    }

    pub async fn dead_letter(
        &self,
        lease: &PostgresSecurityEventLease,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.settle(lease, now, "dead_lettered", 0).await
    }

    /// Idempotent hot-ledger writes precede settlement. A crash between the two
    /// commits is repaired by a later receive and source-history reconciliation.
    pub async fn run_once(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<PostgresSecurityEventBatch, StoreError> {
        let leases = self.claim(now, 360, limit).await?;
        let mut batch = PostgresSecurityEventBatch {
            claimed: leases.len(),
            ..Default::default()
        };
        for lease in leases {
            let result = self
                .store
                .put_with_delivery(&lease.ingress.event, &lease.ingress.delivery)
                .await;
            let (settled, successful) = match result {
                Ok(_) => {
                    batch.persisted += 1;
                    (self.acknowledge(&lease, time(now)).await?, true)
                }
                Err(StoreError::Transient(_))
                    if lease.ingress.ingress_attempts < INGRESS_DELIVERY_ATTEMPTS =>
                {
                    let settled = self.retry(&lease, time(now), 5).await?;
                    batch.retried += usize::from(settled);
                    (settled, false)
                }
                Err(_) => {
                    let settled = self.dead_letter(&lease, time(now)).await?;
                    batch.dead_lettered += usize::from(settled);
                    (settled, false)
                }
            };
            batch.acknowledged += usize::from(settled && successful);
            batch.authority_lost += usize::from(!settled);
        }
        Ok(batch)
    }
}

impl SecurityEventFallback for PostgresSecurityEventFallback {
    async fn enqueue(&self, ingress: &SecurityEventIngress) -> Result<(), StoreError> {
        let record = encode(ingress)?;
        let event = serde_json::to_string(&ingress.event).map_err(|_| invalid())?;
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO a_auth.security_event_fallback_identity (event_id,event) \
             VALUES ($1,$2) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(&ingress.event.event_id)
        .bind(&event)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let stored: String = sqlx::query_scalar(
            "SELECT event FROM a_auth.security_event_fallback_identity \
             WHERE event_id=$1 FOR UPDATE",
        )
        .bind(&ingress.event.event_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        if stored != event {
            return Err(invalid());
        }
        let source = source_id(&record);
        let at = crate::current_unix_secs();
        sqlx::query(
            "INSERT INTO a_auth.security_event_fallback \
             (event_id,source_id,record,status,receive_count,created_at,available_at) \
             VALUES ($1,$2,$3,'pending',0,$4,$4) \
             ON CONFLICT (event_id,source_id) DO NOTHING",
        )
        .bind(&ingress.event.event_id)
        .bind(&source)
        .bind(&record)
        .bind(at)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let existing = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.security_event_fallback \
             WHERE event_id=$1 AND source_id=$2 FOR UPDATE"
        ))
        .bind(&ingress.event.event_id)
        .bind(&source)
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        if decode(existing)?.ingress != *ingress {
            return Err(invalid());
        }
        transaction.commit().await.map_err(db_error)
    }

    async fn enqueue_batch(
        &self,
        ingresses: &[SecurityEventIngress],
    ) -> Result<Vec<SecurityEventFallbackOutcome>, StoreError> {
        if ingresses.len() > 10 {
            return Err(invalid());
        }
        let mut outcomes = Vec::with_capacity(ingresses.len());
        for ingress in ingresses {
            outcomes.push(match self.enqueue(ingress).await {
                Ok(()) => SecurityEventFallbackOutcome::Enqueued,
                Err(StoreError::Transient(message)) => {
                    SecurityEventFallbackOutcome::Retryable(message)
                }
                Err(StoreError::Permanent(message)) => {
                    SecurityEventFallbackOutcome::Permanent(message)
                }
            });
        }
        Ok(outcomes)
    }
}
