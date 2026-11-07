use super::super::db_error;
use crate::ports::{FederatedAttributeOwner, NamespaceAttrs, StoreError, UserRecord, UserStatus};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Row};
use std::collections::BTreeMap;

pub(super) use super::super::serialization::required_option;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredStatus {
    Active,
    Disabled,
    Tombstoned,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNamespace {
    revision: u64,
    kv: BTreeMap<String, String>,
    federation_owners: BTreeMap<String, FederatedAttributeOwner>,
}

// Persistence stays private: UserRecord and NamespaceAttrs intentionally have
// no public Serialize implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    user_id: String,
    email: String,
    created_at: i64,
    updated_at: i64,
    #[serde(deserialize_with = "required_option")]
    last_login_at: Option<i64>,
    status: StoredStatus,
    credential_epoch: u64,
    revocation_pending: bool,
    #[serde(deserialize_with = "required_option")]
    scim_external_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    scim_user_name: Option<String>,
    #[serde(deserialize_with = "required_option")]
    scim_display_name: Option<String>,
    attributes_generation: u64,
    attributes: BTreeMap<String, StoredNamespace>,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid canonical user authority".into())
}

pub(super) fn status_name(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
        UserStatus::Tombstoned => "tombstoned",
    }
}

pub(super) fn encode(record: &UserRecord) -> Result<String, StoreError> {
    let status = match record.status {
        UserStatus::Active => StoredStatus::Active,
        UserStatus::Disabled => StoredStatus::Disabled,
        UserStatus::Tombstoned => StoredStatus::Tombstoned,
    };
    serde_json::to_string(&StoredRecord {
        user_id: record.user_id.clone(),
        email: record.email.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        last_login_at: record.last_login_at,
        status,
        credential_epoch: record.credential_epoch,
        revocation_pending: record.revocation_pending,
        scim_external_id: record.scim_external_id.clone(),
        scim_user_name: record.scim_user_name.clone(),
        scim_display_name: record.scim_display_name.clone(),
        attributes_generation: record.attributes_generation,
        attributes: record
            .attributes
            .iter()
            .map(|(namespace, attrs)| {
                (
                    namespace.clone(),
                    StoredNamespace {
                        revision: attrs.revision,
                        kv: attrs.kv.clone(),
                        federation_owners: attrs.federation_owners.clone(),
                    },
                )
            })
            .collect(),
    })
    .map_err(|_| StoreError::Permanent("Canonical user encoding failed".into()))
}

pub(super) struct LockedUser {
    pub(super) record: UserRecord,
    pub(super) operation_id: Option<String>,
}

pub(super) const COLUMNS: &str = "user_id, user_id_folded, email, status, \
    scim_external_id, scim_user_name, credential_change_id, record";

pub(super) fn decode(row: PgRow) -> Result<LockedUser, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredRecord = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let record = UserRecord {
        user_id: stored.user_id,
        email: stored.email,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
        last_login_at: stored.last_login_at,
        status: match stored.status {
            StoredStatus::Active => UserStatus::Active,
            StoredStatus::Disabled => UserStatus::Disabled,
            StoredStatus::Tombstoned => UserStatus::Tombstoned,
        },
        credential_epoch: stored.credential_epoch,
        revocation_pending: stored.revocation_pending,
        scim_external_id: stored.scim_external_id,
        scim_user_name: stored.scim_user_name,
        scim_display_name: stored.scim_display_name,
        attributes_generation: stored.attributes_generation,
        attributes: stored
            .attributes
            .into_iter()
            .map(|(namespace, attrs)| {
                (
                    namespace,
                    NamespaceAttrs {
                        revision: attrs.revision,
                        kv: attrs.kv,
                        federation_owners: attrs.federation_owners,
                    },
                )
            })
            .collect(),
    };
    let id: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let folded: Vec<u8> = row.try_get("user_id_folded").map_err(db_error)?;
    let email: Vec<u8> = row.try_get("email").map_err(db_error)?;
    let status: String = row.try_get("status").map_err(db_error)?;
    let external: Option<Vec<u8>> = row.try_get("scim_external_id").map_err(db_error)?;
    let name: Option<Vec<u8>> = row.try_get("scim_user_name").map_err(db_error)?;
    if id != record.user_id.as_bytes()
        || folded != record.user_id.to_lowercase().as_bytes()
        || email != record.email.as_bytes()
        || status != status_name(record.status)
        || external.as_deref() != record.scim_external_id.as_deref().map(str::as_bytes)
        || name.as_deref() != record.scim_user_name.as_deref().map(str::as_bytes)
        || crate::user_attributes::attributes_serialized_len(&record.attributes)
            > crate::ports::ATTRIBUTES_MAX_BYTES
    {
        return Err(invalid());
    }
    let operation: Option<Vec<u8>> = row.try_get("credential_change_id").map_err(db_error)?;
    Ok(LockedUser {
        record,
        operation_id: operation
            .map(String::from_utf8)
            .transpose()
            .map_err(|_| invalid())?,
    })
}
