//! Durable governance wake-ups. Jobs remain the destructive authority.
//! A fresh wake arriving during a lease survives that lease's acknowledgment.

use super::{db_error, PostgresStore};
use crate::{
    governance::GovernanceJobCommand,
    ports::{GovernanceJobQueue, StoreError},
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

const COLUMNS: &str = "tenant, job_id, revision::TEXT AS revision, failure_attempt, \
    record, status, created_at, available_at, lease_id, lease_until, wake_requested";

#[derive(Clone)]
pub struct PostgresGovernanceQueue {
    store: PostgresStore,
}

/// An immutable command and private lease capability. Neither the nonce nor
/// mutable acknowledgment identity is exposed through serialization or Debug.
#[derive(Clone)]
pub struct PostgresGovernanceLease {
    command: GovernanceJobCommand,
    nonce: Vec<u8>,
    deadline: i64,
}

impl PostgresGovernanceLease {
    pub fn command(&self) -> &GovernanceJobCommand {
        &self.command
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCommand {
    tenant_id: String,
    job_id: String,
    expected_revision: u64,
    failure_attempt: u8,
}

struct Record {
    command: GovernanceJobCommand,
    status: String,
    nonce: Option<Vec<u8>>,
    deadline: Option<i64>,
    wake_requested: bool,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL governance queue authority".into())
}

fn time(now: i64) -> i64 {
    now.max(crate::token::current_unix_secs_pub())
}

fn validate(command: &GovernanceJobCommand) -> Result<(), StoreError> {
    if command.tenant_id.len() > 1024 || command.job_id.is_empty() || command.job_id.len() > 1024 {
        return Err(invalid());
    }
    Ok(())
}

fn encode(command: &GovernanceJobCommand) -> Result<String, StoreError> {
    validate(command)?;
    serde_json::to_string(&WireCommand {
        tenant_id: command.tenant_id.clone(),
        job_id: command.job_id.clone(),
        expected_revision: command.expected_revision,
        failure_attempt: command.failure_attempt,
    })
    .map_err(|_| invalid())
}

fn decode(row: PgRow) -> Result<Record, StoreError> {
    let wire: WireCommand =
        serde_json::from_str(&row.try_get::<String, _>("record").map_err(db_error)?)
            .map_err(|_| invalid())?;
    let command = GovernanceJobCommand {
        tenant_id: wire.tenant_id,
        job_id: wire.job_id,
        expected_revision: wire.expected_revision,
        failure_attempt: wire.failure_attempt,
    };
    validate(&command)?;
    let revision = row
        .try_get::<String, _>("revision")
        .map_err(db_error)?
        .parse::<u64>()
        .map_err(|_| invalid())?;
    let status: String = row.try_get("status").map_err(db_error)?;
    let nonce: Option<Vec<u8>> = row.try_get("lease_id").map_err(db_error)?;
    let deadline: Option<i64> = row.try_get("lease_until").map_err(db_error)?;
    let wake_requested: bool = row.try_get("wake_requested").map_err(db_error)?;
    let _created_at: i64 = row.try_get("created_at").map_err(db_error)?;
    let _available_at: i64 = row.try_get("available_at").map_err(db_error)?;
    if row.try_get::<Vec<u8>, _>("tenant").map_err(db_error)? != command.tenant_id.as_bytes()
        || row.try_get::<Vec<u8>, _>("job_id").map_err(db_error)? != command.job_id.as_bytes()
        || revision != command.expected_revision
        || row.try_get::<i16, _>("failure_attempt").map_err(db_error)?
            != i16::from(command.failure_attempt)
        || !matches!(
            status.as_str(),
            "pending" | "leased" | "acked" | "dead_lettered"
        )
        || (status == "leased") != nonce.is_some()
        || nonce.is_some() != deadline.is_some()
        || (status != "leased" && wake_requested)
        || nonce.as_ref().is_some_and(|value| {
            value.len() != 35
                || !value.starts_with(b"gq_")
                || !value[3..].iter().all(u8::is_ascii_hexdigit)
        })
    {
        return Err(invalid());
    }
    Ok(Record {
        command,
        status,
        nonce,
        deadline,
        wake_requested,
    })
}

impl PostgresGovernanceQueue {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    pub(crate) fn uses_governance(&self, governance: &super::PostgresGovernanceStore) -> bool {
        governance.belongs_to(&self.store)
    }

    async fn locked(
        transaction: &mut Transaction<'_, Postgres>,
        command: &GovernanceJobCommand,
    ) -> Result<Option<Record>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.governance_queue \
             WHERE tenant = $1 AND job_id = $2 AND revision = $3::TEXT::NUMERIC \
             AND failure_attempt = $4 FOR UPDATE"
        ))
        .bind(command.tenant_id.as_bytes())
        .bind(command.job_id.as_bytes())
        .bind(command.expected_revision.to_string())
        .bind(i16::from(command.failure_attempt))
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(decode)
        .transpose()
    }

    /// Bound claims to 100 rows and leases to six minutes. SKIP LOCKED allows
    /// distinct workers to progress without waiting for an occupied queue head.
    pub async fn claim(
        &self,
        now: i64,
        lease_seconds: i64,
        limit: usize,
    ) -> Result<Vec<PostgresGovernanceLease>, StoreError> {
        if !(1..=360).contains(&lease_seconds) || !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.governance_queue \
             WHERE available_at <= $1 AND \
             (status = 'pending' OR (status = 'leased' AND lease_until <= $1)) \
             ORDER BY available_at, created_at, tenant, job_id, revision, failure_attempt \
             LIMIT $2 FOR UPDATE SKIP LOCKED"
        ))
        .bind(time(now))
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(db_error)?;
        let records = rows
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        let deadline = time(now).checked_add(lease_seconds).ok_or_else(invalid)?;
        let mut leases = Vec::with_capacity(records.len());
        for record in records {
            let nonce = format!("gq_{:032x}", rand::random::<u128>()).into_bytes();
            sqlx::query(
                "UPDATE a_auth.governance_queue SET status = 'leased', lease_id = $5, \
                 lease_until = $6, wake_requested = FALSE \
                 WHERE tenant = $1 AND job_id = $2 AND revision = $3::TEXT::NUMERIC \
                 AND failure_attempt = $4",
            )
            .bind(record.command.tenant_id.as_bytes())
            .bind(record.command.job_id.as_bytes())
            .bind(record.command.expected_revision.to_string())
            .bind(i16::from(record.command.failure_attempt))
            .bind(&nonce)
            .bind(deadline)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
            leases.push(PostgresGovernanceLease {
                command: record.command,
                nonce,
                deadline,
            });
        }
        if time(now) >= deadline {
            return Err(StoreError::Transient(
                "Governance queue claim expired".into(),
            ));
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(leases)
    }

    async fn settle(
        &self,
        lease: &PostgresGovernanceLease,
        now: i64,
        status: &str,
        retry_delay: Option<i64>,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        let Some(record) = Self::locked(&mut transaction, &lease.command).await? else {
            return Ok(false);
        };
        if record.status != "leased"
            || record.nonce.as_deref() != Some(lease.nonce.as_slice())
            || record.deadline != Some(lease.deadline)
            || record.command != lease.command
            || time(now) >= lease.deadline
        {
            return Ok(false);
        }
        let available = time(now)
            .checked_add(if record.wake_requested {
                0
            } else {
                retry_delay.unwrap_or(0)
            })
            .ok_or_else(invalid)?;
        let status = if record.wake_requested {
            "pending"
        } else {
            status
        };
        sqlx::query(
            "UPDATE a_auth.governance_queue SET status = $5, available_at = $6, \
             lease_id = NULL, lease_until = NULL, wake_requested = FALSE \
             WHERE tenant = $1 AND job_id = $2 AND revision = $3::TEXT::NUMERIC \
             AND failure_attempt = $4",
        )
        .bind(lease.command.tenant_id.as_bytes())
        .bind(lease.command.job_id.as_bytes())
        .bind(lease.command.expected_revision.to_string())
        .bind(i16::from(lease.command.failure_attempt))
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
        lease: &PostgresGovernanceLease,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.settle(lease, now, "acked", None).await
    }

    pub async fn retry(
        &self,
        lease: &PostgresGovernanceLease,
        now: i64,
        delay_seconds: i64,
    ) -> Result<bool, StoreError> {
        if !(0..=3600).contains(&delay_seconds) {
            return Err(invalid());
        }
        self.settle(lease, now, "pending", Some(delay_seconds))
            .await
    }

    pub async fn dead_letter(
        &self,
        lease: &PostgresGovernanceLease,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.settle(lease, now, "dead_lettered", None).await
    }
}

impl GovernanceJobQueue for PostgresGovernanceQueue {
    async fn enqueue(&self, command: GovernanceJobCommand) -> Result<(), StoreError> {
        let encoded = encode(&command)?;
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO a_auth.governance_queue \
             (tenant, job_id, revision, failure_attempt, record, status, created_at, available_at) \
             VALUES ($1, $2, $3::TEXT::NUMERIC, $4, $5, 'pending', $6, $6) \
             ON CONFLICT DO NOTHING",
        )
        .bind(command.tenant_id.as_bytes())
        .bind(command.job_id.as_bytes())
        .bind(command.expected_revision.to_string())
        .bind(i16::from(command.failure_attempt))
        .bind(encoded)
        .bind(time(0))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let record = Self::locked(&mut transaction, &command)
            .await?
            .ok_or_else(invalid)?;
        if record.command != command {
            return Err(invalid());
        }
        sqlx::query(
            "UPDATE a_auth.governance_queue \
             SET wake_requested = (status = 'leased'), \
                 available_at = CASE WHEN status = 'leased' THEN available_at ELSE $5 END, \
                 status = CASE WHEN status = 'leased' THEN status ELSE 'pending' END \
             WHERE tenant = $1 AND job_id = $2 AND revision = $3::TEXT::NUMERIC \
             AND failure_attempt = $4",
        )
        .bind(command.tenant_id.as_bytes())
        .bind(command.job_id.as_bytes())
        .bind(command.expected_revision.to_string())
        .bind(i16::from(command.failure_attempt))
        .bind(time(0))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }
}
