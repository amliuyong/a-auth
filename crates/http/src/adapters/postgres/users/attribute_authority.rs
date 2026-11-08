use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::{
    attribute_namespace::{AttributeWriteAuthority, AttributeWriteResolution},
    ports::{NamespaceAttrs, PutAttrOutcome, StoreError, UserStatus, ATTRIBUTES_MAX_BYTES},
};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;

impl PostgresUsersStore {
    pub(crate) async fn put_attributes_authorized(
        &self,
        tenant: &str,
        user_id: &str,
        requested_namespace: &str,
        expected_authority: &AttributeWriteAuthority,
        kv: BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<PutAttrOutcome, StoreError> {
        let mut transaction = self.base.pool.begin().await.map_err(db_error)?;
        // Namespace authority is locked before the user, including unbound names.
        let namespaces = PostgresStore::lock_namespace_catalog(&mut transaction, tenant).await?;
        if namespaces.resolve_write_authority(tenant, requested_namespace)?
            != AttributeWriteResolution::Authorized(expected_authority.clone())
        {
            return Ok(PutAttrOutcome::NamespaceBlocked);
        }
        let outcome = Self::put_attributes_in_transaction(
            &mut transaction,
            tenant,
            user_id,
            expected_authority.canonical_namespace(),
            kv,
            expected_revision,
        )
        .await?;
        transaction.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    pub(super) async fn put_attributes_in_transaction(
        transaction: &mut Transaction<'_, Postgres>,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<PutAttrOutcome, StoreError> {
        let Some(mut user) = Self::lock_user(transaction, tenant, user_id).await? else {
            return Ok(PutAttrOutcome::NotFound);
        };
        if user.record.status == UserStatus::Tombstoned {
            return Ok(PutAttrOutcome::Tombstoned);
        }
        let current = user
            .record
            .attributes
            .get(namespace)
            .map_or(0, |attrs| attrs.revision);
        if current != expected_revision {
            if expected_revision.checked_add(1) == Some(current)
                && user
                    .record
                    .attributes
                    .get(namespace)
                    .is_some_and(|attrs| attrs.kv == kv)
            {
                return Ok(PutAttrOutcome::Ok { revision: current });
            }
            return Ok(PutAttrOutcome::RevisionConflict { current });
        }
        let owners = user
            .record
            .attributes
            .get(namespace)
            .map(|attrs| attrs.federation_owners.clone())
            .unwrap_or_default();
        if owners.keys().any(|key| {
            user.record
                .attributes
                .get(namespace)
                .and_then(|attrs| attrs.kv.get(key))
                != kv.get(key)
        }) {
            return Ok(PutAttrOutcome::OwnershipConflict);
        }
        let generation = user
            .record
            .attributes_generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("User attribute generation exhausted".into()))?;
        let revision = current
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("User attribute revision exhausted".into()))?;
        let mut attributes = user.record.attributes.clone();
        attributes.insert(
            namespace.into(),
            NamespaceAttrs {
                revision,
                kv,
                federation_owners: owners,
            },
        );
        if crate::user_attributes::attributes_serialized_len(&attributes) > ATTRIBUTES_MAX_BYTES {
            return Ok(PutAttrOutcome::TooLarge);
        }
        user.record.attributes = attributes;
        user.record.attributes_generation = generation;
        Self::write_user(transaction, tenant, &user, false).await?;
        Ok(PutAttrOutcome::Ok { revision })
    }
}
