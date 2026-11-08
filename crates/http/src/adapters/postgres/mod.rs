//! PostgreSQL authority for the portable single-tenant deployment.
//! All dependent mutations use conditional statements or locked transactions.

use crate::ports::{ParRecord, ParStore, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{sync::Arc, time::Duration};

mod admin_auth;
mod attribute_namespaces;
mod authz_sessions;
mod ciba;
mod clients;
mod codes;
mod device;
mod domain_map;
mod federation;
mod federation_authority;
mod federation_mappings;
mod governance;
mod governance_queue;
mod grace;
mod grants;
mod initial_access_tokens;
mod jti;
mod magic_links;
mod outbox;
mod passkey_challenges;
mod passkeys;
mod passwords;
mod policy;
mod rate_limits;
mod recovery;
mod refresh;
mod replay;
mod scim_groups;
mod security_event_fallback;
mod security_events;
mod serialization;
mod sessions;
mod smtp;
mod ssf;
mod users;
mod workload_trust;

pub use ciba::PostgresCibaStore;
pub use codes::ExchangeFailureRequest;
pub use governance::PostgresGovernanceStore;
pub use governance_queue::{PostgresGovernanceLease, PostgresGovernanceQueue};
pub use grace::PostgresGraceStore;
pub use outbox::PostgresMessageOutbox;
pub use refresh::RefreshRotationRequest;
pub use security_event_fallback::{
    PostgresSecurityEventBatch, PostgresSecurityEventFallback, PostgresSecurityEventLease,
};
pub use smtp::{PostgresSmtpBatch, PostgresSmtpLease, PostgresSmtpNotifier, PostgresSmtpSend};
pub use ssf::PostgresSsfStore;
pub use users::{PostgresInvitationStore, PostgresUsersStore, UserAuthorityKey};

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Clones share a bounded connection pool. Separately constructed instances
/// coordinate through PostgreSQL; correctness never relies on process locks.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    identity: Arc<()>,
}

impl PostgresStore {
    pub(crate) fn shares_pool_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }

    /// Open a pool without changing schema. Schema migration is an explicit
    /// deployment step so ordinary runtime roles need no DDL privileges.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        if max_connections == 0 {
            return Err(StoreError::Permanent(
                "PostgreSQL pool must have at least one connection".into(),
            ));
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query(
                        "SELECT set_config('statement_timeout', '15s', false), \
                         set_config('lock_timeout', '5s', false), \
                         set_config('idle_in_transaction_session_timeout', '15s', false)",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(db_error)?;
        let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .map_err(db_error)?;
        if version < 160_000 {
            pool.close().await;
            return Err(StoreError::Permanent(
                "PostgreSQL 16 or later is required".into(),
            ));
        }
        Ok(Self {
            pool,
            identity: Arc::new(()),
        })
    }

    /// Embedded, versioned forward migrations with database-wide locking and
    /// checksum verification. A failed migration never marks its version applied.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        // DDL startup needs a longer budget than an ordinary authority write.
        // Close this session so neither relaxed timeouts nor SQLx's advisory
        // lock on an early error/cancellation can return to the runtime pool.
        // Keep the pool permit until close completes to preserve its bound.
        let mut connection = self.pool.acquire().await.map_err(db_error)?;
        connection.close_on_drop();
        sqlx::query(
            "SELECT set_config('statement_timeout', '120s', false), \
             set_config('lock_timeout', '60s', false)",
        )
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
        let result = MIGRATIONS
            .run_direct(&mut *connection)
            .await
            .map_err(|error| match error {
                sqlx::migrate::MigrateError::Execute(error)
                | sqlx::migrate::MigrateError::ExecuteMigration(error, _) => db_error(error),
                _ => {
                    StoreError::Permanent("PostgreSQL migration version or checksum failed".into())
                }
            });
        let close = connection.close().await.map_err(db_error);
        result.and(close)
    }
}

/// Never include driver messages: they can contain SQL data or connection
/// credentials. SQLSTATE is sufficient for classification and diagnostics.
fn db_error(error: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(database) = &error {
        let state = database.code().unwrap_or_default();
        let message = format!("PostgreSQL operation failed (SQLSTATE {state})");
        if matches!(
            &state[..state.len().min(2)],
            "08" | "40" | "53" | "57" | "58"
        ) || state == "55P03"
        {
            return StoreError::Transient(message);
        }
        return StoreError::Permanent(message);
    }
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => {
            StoreError::Transient("PostgreSQL connection unavailable".into())
        }
        _ => StoreError::Permanent("PostgreSQL configuration or record decoding failed".into()),
    }
}

impl ParStore for PostgresStore {
    async fn put(&self, tenant: &str, record: ParRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO a_auth.par (tenant, request_uri, client_id, raw_params, expires_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant, request_uri) DO UPDATE \
             SET client_id = EXCLUDED.client_id, raw_params = EXCLUDED.raw_params, \
                 expires_at = EXCLUDED.expires_at",
        )
        .bind(tenant)
        .bind(&record.request_uri)
        .bind(&record.client_id)
        .bind(&record.raw_params)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume(
        &self,
        tenant: &str,
        request_uri: &str,
        now: i64,
    ) -> Result<Option<ParRecord>, StoreError> {
        // Delete expired records as well: validity is checked after the atomic
        // deletion, so an expired request cannot survive a clock rollback.
        let row = sqlx::query(
            "DELETE FROM a_auth.par WHERE tenant = $1 AND request_uri = $2 \
             RETURNING request_uri, client_id, raw_params, expires_at",
        )
        .bind(tenant)
        .bind(request_uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else { return Ok(None) };
        let expires_at = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= now {
            return Ok(None);
        }
        Ok(Some(ParRecord {
            request_uri: row.try_get("request_uri").map_err(db_error)?,
            client_id: row.try_get("client_id").map_err(db_error)?,
            raw_params: row.try_get("raw_params").map_err(db_error)?,
            expires_at,
        }))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let result = sqlx::query("DELETE FROM a_auth.par WHERE tenant = $1")
            .bind(tenant)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
