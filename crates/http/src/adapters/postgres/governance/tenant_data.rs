//! Tenant cleanup preserves governance suppression and retained SSF audit.

use super::{
    db_error,
    user_data::{check_fence, validate_tenant},
    PostgresUsersStore,
};
use crate::{
    governance::{GovernanceDestructiveFence, GovernanceJobKind, TenantCleanupStage},
    governance_data::{GovernanceInventory, PostgresTenantPlane},
    ports::StoreError,
};
use sqlx::{Postgres, Row, Transaction};

#[derive(Clone, Copy)]
enum Binding {
    DataText,
    DataBytes,
    LogicalText,
}

type Table = (&'static str, &'static str, Binding);
const TABLES: &[Table] = &[
    ("identities", "users", Binding::DataBytes),
    ("identity_claims", "scim_create_claims", Binding::DataBytes),
    ("clients", "clients", Binding::DataText),
    (
        "initial_access_tokens",
        "initial_access_tokens",
        Binding::DataText,
    ),
    ("directory_groups", "scim_groups", Binding::DataBytes),
    (
        "federation_configs",
        "federation_configs",
        Binding::LogicalText,
    ),
    (
        "federation_mapping_catalogs",
        "federation_mapping_catalogs",
        Binding::LogicalText,
    ),
    ("workload_trust", "workload_trust", Binding::LogicalText),
    ("admin_configs", "admin_oidc_configs", Binding::LogicalText),
    ("admin_flows", "admin_oidc_flows", Binding::LogicalText),
    ("admin_sessions", "admin_sessions", Binding::LogicalText),
    ("federation_flows", "federation_flows", Binding::LogicalText),
    ("codes", "codes", Binding::DataText),
    ("sessions", "login_sessions", Binding::DataBytes),
    (
        "session_generations",
        "login_session_generations",
        Binding::DataBytes,
    ),
    ("refresh_families", "refresh_families", Binding::DataText),
    (
        "passkey_challenges",
        "passkey_challenges",
        Binding::DataText,
    ),
    ("passkeys", "passkey_credentials", Binding::DataBytes),
    ("passwords", "password_credentials", Binding::DataText),
    ("recovery", "recovery_codes", Binding::DataBytes),
    (
        "recovery_results",
        "recovery_success_results",
        Binding::DataBytes,
    ),
    ("invitations", "invitations", Binding::DataBytes),
    ("magic_links", "magic_links", Binding::DataText),
    ("magic_cooldowns", "magic_link_cooldowns", Binding::DataText),
    ("messages", "message_outbox", Binding::DataBytes),
    ("ciba_requests", "ciba_requests", Binding::DataBytes),
    ("ciba_throttles", "ciba_throttle", Binding::DataBytes),
    ("device_grants", "device_grants", Binding::DataText),
    ("par", "par", Binding::DataText),
    ("authz_sessions", "authz_sessions", Binding::DataText),
    ("grants", "grants", Binding::DataText),
    ("domains", "domain_bindings", Binding::LogicalText),
    ("policy_artifacts", "policy_artifacts", Binding::DataText),
    ("policy_versions", "policy_versions", Binding::DataText),
];

async fn rows(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    binding: Binding,
    logical: &str,
    data: &str,
    remove: bool,
) -> Result<u64, StoreError> {
    let tenant = match binding {
        Binding::DataText | Binding::DataBytes => data,
        Binding::LogicalText => logical,
    };
    let statement = format!(
        "{} FROM a_auth.{table} WHERE tenant = $1",
        if remove {
            "DELETE"
        } else {
            "SELECT count(*) AS total"
        }
    );
    let query = sqlx::query(&statement);
    let query = match binding {
        Binding::DataText | Binding::LogicalText => query.bind(tenant),
        Binding::DataBytes => query.bind(tenant.as_bytes()),
    };
    if remove {
        Ok(query
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected())
    } else {
        let total: i64 = query
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?
            .try_get("total")
            .map_err(db_error)?;
        u64::try_from(total)
            .map_err(|_| StoreError::Permanent("governance inventory count exceeds u64".into()))
    }
}

async fn grace_rows(
    tx: &mut Transaction<'_, Postgres>,
    data: &str,
    remove: bool,
) -> Result<u64, StoreError> {
    let statement = format!(
        "{} FROM a_auth.grace_responses WHERE family_id IN \
         (SELECT convert_to(family_id, 'UTF8') FROM a_auth.refresh_families WHERE tenant = $1)",
        if remove {
            "DELETE"
        } else {
            "SELECT count(*) AS total"
        }
    );
    let query = sqlx::query(&statement).bind(data);
    if remove {
        Ok(query
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected())
    } else {
        let count: i64 = query
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?
            .try_get("total")
            .map_err(db_error)?;
        u64::try_from(count)
            .map_err(|_| StoreError::Permanent("invalid grace inventory count".into()))
    }
}

async fn rate_rows(
    tx: &mut Transaction<'_, Postgres>,
    data: &str,
    remove: bool,
) -> Result<u64, StoreError> {
    // Compare a literal prefix rather than LIKE, where tenant punctuation
    // would become wildcard syntax. Empty data tenant owns unprefixed keys.
    let prefix = format!("{data}{}", crate::tenant::SEP);
    let statement = format!(
        "{} FROM a_auth.rate_limits WHERE \
         ($1 = '' AND strpos(bucket_key, chr(31)) = 0) OR \
         ($1 <> '' AND left(bucket_key, length($2)) = $2)",
        if remove {
            "DELETE"
        } else {
            "SELECT count(*) AS total"
        }
    );
    let query = sqlx::query(&statement).bind(data).bind(prefix);
    if remove {
        Ok(query
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected())
    } else {
        let count: i64 = query
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?
            .try_get("total")
            .map_err(db_error)?;
        u64::try_from(count)
            .map_err(|_| StoreError::Permanent("invalid rate inventory count".into()))
    }
}

impl PostgresTenantPlane<'_> {
    pub(crate) async fn cleanup_stage(
        &self,
        logical: &str,
        data: &str,
        stage: TenantCleanupStage,
        fence: &GovernanceDestructiveFence,
        now: i64,
    ) -> Result<u64, StoreError> {
        let (mut tx, authority) = self
            .governance
            .begin_destructive(logical, data, fence, now)
            .await?;
        let job = authority
            .jobs
            .get(&(logical.into(), fence.job_id.clone()))
            .ok_or_else(|| StoreError::Transient("governance destructive fence conflict".into()))?;
        if job.kind != GovernanceJobKind::TenantOffboarding || job.tenant_cleanup_stage != stage {
            return Err(StoreError::Transient(
                "governance destructive fence conflict".into(),
            ));
        }
        let selected: &[&str] = match stage {
            TenantCleanupStage::Clients => &["clients"],
            TenantCleanupStage::InitialAccessTokens => &["initial_access_tokens"],
            TenantCleanupStage::DirectoryGroups => &["scim_groups"],
            TenantCleanupStage::Federation => {
                &["federation_configs", "federation_mapping_catalogs"]
            }
            TenantCleanupStage::WorkloadTrust => &["workload_trust"],
            TenantCleanupStage::AdminAuthority => {
                &["admin_oidc_configs", "admin_oidc_flows", "admin_sessions"]
            }
            TenantCleanupStage::ProtocolState => &[
                "federation_flows",
                "codes",
                "login_sessions",
                "login_session_generations",
                "refresh_families",
                "passkey_challenges",
                "passkey_credentials",
                "password_credentials",
                "recovery_codes",
                "recovery_success_results",
                "invitations",
                "magic_links",
                "magic_link_cooldowns",
                "message_outbox",
                "ciba_requests",
                "ciba_throttle",
                "device_grants",
                "par",
                "authz_sessions",
            ],
            TenantCleanupStage::PolicyAndDomains => &[
                "grants",
                "domain_bindings",
                "policy_artifacts",
                "policy_versions",
            ],
            TenantCleanupStage::SharedSignals => &[],
            TenantCleanupStage::Users
            | TenantCleanupStage::SigningKeysAndSecrets
            | TenantCleanupStage::Complete => {
                return Err(StoreError::Permanent(
                    "tenant cleanup stage is not a PostgreSQL authority-store stage".into(),
                ));
            }
        };
        let mut removed = 0;
        if stage == TenantCleanupStage::Clients {
            // Capture ownership before deleting clients. Orphans remain for
            // the protocol and domain stages instead of affecting neighbors.
            removed += sqlx::query(
                "DELETE FROM a_auth.domain_bindings WHERE tenant = $1 \
                AND client_id IN (SELECT client_id FROM a_auth.clients WHERE tenant = $2)",
            )
            .bind(logical)
            .bind(data)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?
            .rows_affected();
            removed += sqlx::query(
                "DELETE FROM a_auth.authz_sessions WHERE tenant = $1 \
                AND client_id IN (SELECT client_id FROM a_auth.clients WHERE tenant = $1)",
            )
            .bind(data)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?
            .rows_affected();
            if self.rate_limit {
                removed += rate_rows(&mut tx, data, true).await?;
            }
        }
        if stage == TenantCleanupStage::ProtocolState {
            if self.grace {
                removed += grace_rows(&mut tx, data, true).await?;
            }
            if self.jtis {
                removed += rows(&mut tx, "jti", Binding::LogicalText, logical, data, true).await?;
            }
            if self.replay {
                removed += rows(&mut tx, "replay", Binding::DataText, logical, data, true).await?;
            }
        }
        for (_, table, binding) in TABLES {
            if selected.contains(table) {
                removed += rows(&mut tx, table, *binding, logical, data, true).await?;
            }
        }
        if stage == TenantCleanupStage::SharedSignals {
            removed += u64::try_from(
                self.ssf
                    .revoke_in_transaction(&mut tx, logical, crate::current_unix_secs().max(now))
                    .await?,
            )
            .map_err(|_| StoreError::Permanent("invalid SSF cleanup count".into()))?;
        }
        check_fence(&authority, logical, fence, now)?;
        tx.commit().await.map_err(db_error)?;
        Ok(removed)
    }

    pub(crate) async fn inventory(
        &self,
        logical: &str,
        data: &str,
    ) -> Result<GovernanceInventory, StoreError> {
        validate_tenant(logical, data)?;
        let mut tx = self
            .governance
            .database
            .pool
            .begin()
            .await
            .map_err(db_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut tx, logical).await?;
        let mut inventory = GovernanceInventory::default();
        for (category, table, binding) in TABLES {
            inventory.live_counts.insert(
                (*category).into(),
                rows(&mut tx, table, *binding, logical, data, false).await?,
            );
        }
        inventory.live_counts.insert(
            "refresh_grace".into(),
            if self.grace {
                grace_rows(&mut tx, data, false).await?
            } else {
                0
            },
        );
        inventory.live_counts.insert(
            "jtis".into(),
            if self.jtis {
                rows(&mut tx, "jti", Binding::LogicalText, logical, data, false).await?
            } else {
                0
            },
        );
        inventory.live_counts.insert(
            "replay".into(),
            if self.replay {
                rows(&mut tx, "replay", Binding::DataText, logical, data, false).await?
            } else {
                0
            },
        );
        inventory.live_counts.insert(
            "rate_limits".into(),
            if self.rate_limit {
                rate_rows(&mut tx, data, false).await?
            } else {
                0
            },
        );
        let counts = self.ssf.governance_inventory(&mut tx, logical).await?;
        for ((category, retained), count) in [
            ("ssf_streams_live", false),
            ("ssf_stream_tombstones_retained", true),
            ("ssf_deliveries_live", false),
            ("ssf_delivery_tombstones_retained", true),
            ("ssf_delivery_audit_retained", true),
        ]
        .into_iter()
        .zip(counts)
        {
            if retained {
                inventory.retained_counts.insert(category.into(), count);
            } else {
                inventory.live_counts.insert(category.into(), count);
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok(inventory)
    }
}
