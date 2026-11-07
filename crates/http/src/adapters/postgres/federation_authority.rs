use super::{db_error, federation::validate_config_identity, PostgresStore};
use crate::{
    federation_attributes::{MappingChange, MappingChangeOutcome},
    ports::StoreError,
};
use agent_auth_authn::federation::FederationConfig;
use sqlx::{types::Json, Postgres, Transaction};

async fn lock_config(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    idp: &str,
) -> Result<Option<FederationConfig>, StoreError> {
    let record: Option<Json<FederationConfig>> = sqlx::query_scalar(
        "SELECT record FROM a_auth.federation_configs \
         WHERE tenant = $1 AND upstream_idp_id = $2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(idp)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?;
    record
        .map(|Json(config)| {
            validate_config_identity(&config, tenant, idp)?;
            Ok(config)
        })
        .transpose()
}

impl PostgresStore {
    pub(crate) async fn change_federation_mapping_authorized(
        &self,
        expected: &FederationConfig,
        change: MappingChange,
    ) -> Result<MappingChangeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mut mappings =
            Self::lock_mapping_catalog(&mut transaction, &expected.tenant_id).await?;
        let current = lock_config(
            &mut transaction,
            &expected.tenant_id,
            &expected.upstream_idp_id,
        )
        .await?;
        if current.as_ref() != Some(expected) {
            return Ok(MappingChangeOutcome::Conflict);
        }
        let outcome = mappings.change(
            &expected.tenant_id,
            &expected.upstream_idp_id,
            &expected.upstream_issuer,
            change,
        )?;
        Self::persist_mapping_catalog(&mut transaction, &expected.tenant_id, &mappings).await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    pub(crate) async fn put_federation_config_authorized(
        &self,
        expected: Option<&FederationConfig>,
        next: FederationConfig,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mappings = Self::lock_mapping_catalog(&mut transaction, &next.tenant_id).await?;
        let current = lock_config(&mut transaction, &next.tenant_id, &next.upstream_idp_id).await?;
        if current.as_ref() != expected {
            return Ok(false);
        }
        let registry = mappings.get_registry(&next.tenant_id, &next.upstream_idp_id)?;
        if registry
            .as_ref()
            .is_some_and(|registry| !registry.mappings.is_empty())
            && current
                .as_ref()
                .is_none_or(|config| config.upstream_issuer != next.upstream_issuer)
        {
            return Ok(false);
        }
        let result = if current.is_some() {
            sqlx::query(
                "UPDATE a_auth.federation_configs SET record = $3 \
                 WHERE tenant = $1 AND upstream_idp_id = $2",
            )
            .bind(&next.tenant_id)
            .bind(&next.upstream_idp_id)
            .bind(Json(&next))
            .execute(&mut *transaction)
            .await
        } else {
            sqlx::query(
                "INSERT INTO a_auth.federation_configs (tenant, upstream_idp_id, record) \
                 VALUES ($1, $2, $3) ON CONFLICT (tenant, upstream_idp_id) DO NOTHING",
            )
            .bind(&next.tenant_id)
            .bind(&next.upstream_idp_id)
            .bind(Json(&next))
            .execute(&mut *transaction)
            .await
        }
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Ok(false);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    pub(crate) async fn delete_federation_config_authorized(
        &self,
        expected: &FederationConfig,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let mappings = Self::lock_mapping_catalog(&mut transaction, &expected.tenant_id).await?;
        let current = lock_config(
            &mut transaction,
            &expected.tenant_id,
            &expected.upstream_idp_id,
        )
        .await?;
        if current.as_ref() != Some(expected)
            || mappings
                .get_registry(&expected.tenant_id, &expected.upstream_idp_id)?
                .is_some_and(|registry| !registry.mappings.is_empty())
        {
            return Ok(false);
        }
        let result = sqlx::query(
            "DELETE FROM a_auth.federation_configs WHERE tenant = $1 AND upstream_idp_id = $2",
        )
        .bind(&expected.tenant_id)
        .bind(&expected.upstream_idp_id)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Ok(false);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}
