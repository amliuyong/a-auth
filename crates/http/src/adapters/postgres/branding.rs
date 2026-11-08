//! Deployment presentation with persisted revision compare-and-swap.

use super::{db_error, PostgresStore};
use crate::{
    branding::{valid_settings, BrandingSettings, MAX_REVISION},
    branding_store::StoredBranding,
    ports::StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgRow, Row};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    deployment_host: String,
    version: u32,
    revision: u64,
    settings: Value,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL branding record".into())
}

fn validate(host: &str, record: &StoredBranding) -> Result<(), StoreError> {
    let settings: BrandingSettings =
        serde_json::from_value(record.settings.clone()).map_err(|_| invalid())?;
    if host.is_empty()
        || host.len() > 1024
        || record.version != 1
        || record.revision == 0
        || record.revision > MAX_REVISION
        || !valid_settings(&settings)
    {
        return Err(invalid());
    }
    Ok(())
}

fn decode(row: PgRow, host: &str) -> Result<StoredBranding, StoreError> {
    let wire: Wire = serde_json::from_str(&row.try_get::<String, _>("record").map_err(db_error)?)
        .map_err(|_| invalid())?;
    let record = StoredBranding {
        version: wire.version,
        revision: wire.revision,
        settings: wire.settings,
    };
    validate(host, &record)?;
    let revision: String = row.try_get("revision").map_err(db_error)?;
    if wire.deployment_host != host
        || row
            .try_get::<Vec<u8>, _>("deployment_host")
            .map_err(db_error)?
            != host.as_bytes()
        || row.try_get::<i32, _>("version").map_err(db_error)? != record.version as i32
        || revision.parse::<u64>().map_err(|_| invalid())? != record.revision
    {
        return Err(invalid());
    }
    Ok(record)
}

impl PostgresStore {
    pub(crate) async fn get_branding(
        &self,
        host: &str,
    ) -> Result<Option<StoredBranding>, StoreError> {
        sqlx::query(
            "SELECT deployment_host,version,revision::TEXT AS revision,record \
             FROM a_auth.branding WHERE deployment_host=$1",
        )
        .bind(host.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(|row| decode(row, host))
        .transpose()
    }

    pub(crate) async fn put_branding(
        &self,
        host: &str,
        record: StoredBranding,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        validate(host, &record)?;
        if expected_revision.checked_add(1) != Some(record.revision) {
            return Ok(false);
        }
        let text = serde_json::to_string(&Wire {
            deployment_host: host.to_owned(),
            version: record.version,
            revision: record.revision,
            settings: record.settings,
        })
        .map_err(|_| invalid())?;
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        if expected_revision == 0 {
            let result = sqlx::query(
                "INSERT INTO a_auth.branding (deployment_host,version,revision,record) \
                 VALUES ($1,1,1,$2) ON CONFLICT (deployment_host) DO NOTHING",
            )
            .bind(host.as_bytes())
            .bind(&text)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
            if result.rows_affected() == 1 {
                transaction.commit().await.map_err(db_error)?;
                return Ok(true);
            }
        }
        let Some(row) = sqlx::query(
            "SELECT deployment_host,version,revision::TEXT AS revision,record \
             FROM a_auth.branding WHERE deployment_host=$1 FOR UPDATE",
        )
        .bind(host.as_bytes())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?
        else {
            return Ok(false);
        };
        if decode(row, host)?.revision != expected_revision {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE a_auth.branding SET revision=$2::TEXT::NUMERIC,record=$3 \
             WHERE deployment_host=$1",
        )
        .bind(host.as_bytes())
        .bind(record.revision.to_string())
        .bind(text)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}
