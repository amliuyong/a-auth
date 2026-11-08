use super::super::db_error;
use crate::ports::{RecoveryCodeEntry, RecoveryRecord, RecoverySuccessResult, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Row};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCode {
    hash_b64: String,
    consumed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    user_lookup: String,
    user_id: String,
    activation_id: String,
    code_hashes: Vec<StoredCode>,
    attempt_count: u32,
    locked_until: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResult {
    operation_key: String,
    user_lookup: String,
    user_id: String,
    presented_hash: String,
    credential_epoch: u64,
    session_id: String,
    created_at: i64,
    expires_at: i64,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid recovery authority".into())
}

pub(super) fn encode(record: &RecoveryRecord) -> Result<String, StoreError> {
    serde_json::to_string(&StoredRecord {
        user_lookup: record.user_lookup.clone(),
        user_id: record.user_id.clone(),
        activation_id: record.activation_id.clone(),
        code_hashes: record
            .code_hashes
            .iter()
            .map(|entry| StoredCode {
                hash_b64: entry.hash_b64.clone(),
                consumed: entry.consumed,
            })
            .collect(),
        attempt_count: record.attempt_count,
        locked_until: record.locked_until,
    })
    .map_err(|_| StoreError::Permanent("Recovery authority encoding failed".into()))
}

pub(super) fn decode(row: PgRow) -> Result<RecoveryRecord, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredRecord = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let lookup: Vec<u8> = row.try_get("user_lookup").map_err(db_error)?;
    let user: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let activation: Vec<u8> = row.try_get("activation_id").map_err(db_error)?;
    if lookup != stored.user_lookup.as_bytes()
        || user != stored.user_id.as_bytes()
        || activation != stored.activation_id.as_bytes()
    {
        return Err(invalid());
    }
    Ok(RecoveryRecord {
        user_lookup: stored.user_lookup,
        user_id: stored.user_id,
        activation_id: stored.activation_id,
        code_hashes: stored
            .code_hashes
            .into_iter()
            .map(|entry| RecoveryCodeEntry {
                hash_b64: entry.hash_b64,
                consumed: entry.consumed,
            })
            .collect(),
        attempt_count: stored.attempt_count,
        locked_until: stored.locked_until,
    })
}

pub(super) fn decode_result(row: PgRow) -> Result<RecoverySuccessResult, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredResult = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let operation: Vec<u8> = row.try_get("operation_key").map_err(db_error)?;
    let lookup: Vec<u8> = row.try_get("user_lookup").map_err(db_error)?;
    let user: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let epoch: String = row.try_get("credential_epoch").map_err(db_error)?;
    let session: Vec<u8> = row.try_get("session_id").map_err(db_error)?;
    let created: i64 = row.try_get("created_at").map_err(db_error)?;
    let expires: i64 = row.try_get("expires_at").map_err(db_error)?;
    if operation != stored.operation_key.as_bytes()
        || lookup != stored.user_lookup.as_bytes()
        || user != stored.user_id.as_bytes()
        || epoch.parse::<u64>().map_err(|_| invalid())? != stored.credential_epoch
        || session != stored.session_id.as_bytes()
        || created != stored.created_at
        || expires != stored.expires_at
        || expires <= created
    {
        return Err(invalid());
    }
    Ok(RecoverySuccessResult {
        operation_key: stored.operation_key,
        user_lookup: stored.user_lookup,
        user_id: stored.user_id,
        presented_hash: stored.presented_hash,
        credential_epoch: stored.credential_epoch,
        session_id: stored.session_id,
        created_at: stored.created_at,
        expires_at: stored.expires_at,
    })
}

pub(super) fn encode_result(result: &RecoverySuccessResult) -> Result<String, StoreError> {
    if result.expires_at <= result.created_at {
        return Err(invalid());
    }
    serde_json::to_string(&StoredResult {
        operation_key: result.operation_key.clone(),
        user_lookup: result.user_lookup.clone(),
        user_id: result.user_id.clone(),
        presented_hash: result.presented_hash.clone(),
        credential_epoch: result.credential_epoch,
        session_id: result.session_id.clone(),
        created_at: result.created_at,
        expires_at: result.expires_at,
    })
    .map_err(|_| StoreError::Permanent("Recovery result encoding failed".into()))
}
