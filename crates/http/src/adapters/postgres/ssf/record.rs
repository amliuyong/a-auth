use super::super::{db_error, serialization::required_option};
use crate::{
    adapters::mounted_crypto::{EncryptionKeyring, SealedRecord},
    ports::StoreError,
    ssf::{
        validate_delivery_record, validate_stream_configuration, validate_stream_identity,
        SsfDelivery, SsfDeliveryAttempt, SsfDeliveryAttemptOutcome, SsfDeliveryStatus, SsfStream,
        SUPPORTED_EVENT_TYPES,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use zeroize::Zeroizing;

pub(super) const STREAM_COLUMNS: &str =
    "tenant, stream_id, revision::TEXT AS revision, status, record";
pub(super) const DELIVERY_COLUMNS: &str =
    "tenant, stream_id, stream_revision::TEXT AS stream_revision, event_id, created_at, \
     next_attempt_at, expires_at, status, lease_id, lease_expires_at, \
     kid, key_nonce, encrypted_key, nonce, ciphertext";

pub(super) fn invalid() -> StoreError {
    StoreError::Permanent("Invalid SSF authority".into())
}

fn identity(row: &PgRow, column: &str) -> Result<String, StoreError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(db_error)?;
    String::from_utf8(bytes).map_err(|_| invalid())
}

pub(super) fn decode_stream(row: PgRow) -> Result<SsfStream, StoreError> {
    let text: String = row.try_get("record").map_err(db_error)?;
    // Deserialize the original text first so duplicate known fields fail.
    // The complete canonical comparison also rejects unknown and absent fields.
    let stream: SsfStream = serde_json::from_str(&text).map_err(|_| invalid())?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    if serde_json::to_value(&stream).map_err(|_| invalid())? != value
        || stream.tenant_id != identity(&row, "tenant")?
        || stream.stream_id != identity(&row, "stream_id")?
        || stream.revision.to_string() != row.try_get::<String, _>("revision").map_err(db_error)?
        || stream.status.as_str() != row.try_get::<String, _>("status").map_err(db_error)?
    {
        return Err(invalid());
    }
    validate_stream(&stream)?;
    Ok(stream)
}

fn validate_stream(stream: &SsfStream) -> Result<(), StoreError> {
    validate_stream_identity(&stream.tenant_id, &stream.stream_id).map_err(|_| invalid())?;
    validate_stream_configuration(&stream.endpoint, &stream.audience, &stream.requested_events)
        .map_err(|_| invalid())?;
    let expected: Vec<_> = stream
        .requested_events
        .iter()
        .filter(|uri| SUPPORTED_EVENT_TYPES.contains(&uri.as_str()))
        .cloned()
        .collect();
    if expected.is_empty() || stream.delivered_events != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) async fn write_stream(
    tx: &mut Transaction<'_, Postgres>,
    stream: &SsfStream,
) -> Result<(), StoreError> {
    validate_stream(stream)?;
    let text = serde_json::to_string(stream).map_err(|_| invalid())?;
    sqlx::query(
        "INSERT INTO a_auth.ssf_streams (tenant, stream_id, revision, status, record) \
         VALUES ($1, $2, $3::TEXT::NUMERIC, $4, $5) \
         ON CONFLICT (tenant, stream_id) DO UPDATE SET \
         revision = EXCLUDED.revision, status = EXCLUDED.status, record = EXCLUDED.record",
    )
    .bind(stream.tenant_id.as_bytes())
    .bind(stream.stream_id.as_bytes())
    .bind(stream.revision.to_string())
    .bind(stream.status.as_str())
    .bind(text)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttempt {
    attempted_at: i64,
    outcome: SsfDeliveryAttemptOutcome,
    #[serde(deserialize_with = "required_option")]
    status_code: Option<u16>,
    #[serde(deserialize_with = "required_option")]
    error_class: Option<String>,
    #[serde(deserialize_with = "required_option")]
    set_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    signing_kid: Option<String>,
}

impl From<&SsfDeliveryAttempt> for StoredAttempt {
    fn from(value: &SsfDeliveryAttempt) -> Self {
        Self {
            attempted_at: value.attempted_at,
            outcome: value.outcome.clone(),
            status_code: value.status_code,
            error_class: value.error_class.clone(),
            set_sha256: value.set_sha256.clone(),
            signing_kid: value.signing_kid.clone(),
        }
    }
}

impl From<StoredAttempt> for SsfDeliveryAttempt {
    fn from(value: StoredAttempt) -> Self {
        Self {
            attempted_at: value.attempted_at,
            outcome: value.outcome,
            status_code: value.status_code,
            error_class: value.error_class,
            set_sha256: value.set_sha256,
            signing_kid: value.signing_kid,
        }
    }
}

// Public delivery JSON intentionally hides signed SETs and lease credentials.
// Persistent authority must retain every field, including explicit nulls.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDelivery {
    tenant_id: String,
    stream_id: String,
    stream_revision: u64,
    event_id: String,
    issuer: String,
    endpoint: String,
    audience: String,
    event_uri: String,
    subject: serde_json::Value,
    payload: serde_json::Value,
    status: SsfDeliveryStatus,
    attempts: u32,
    cycle_attempts: u32,
    redrive_count: u32,
    attempt_history: Vec<StoredAttempt>,
    event_occurred_at: i64,
    created_at: i64,
    updated_at: i64,
    cycle_started_at: i64,
    next_attempt_at: i64,
    expires_at: i64,
    #[serde(deserialize_with = "required_option")]
    compact_set: Option<String>,
    #[serde(deserialize_with = "required_option")]
    jti: Option<String>,
    #[serde(deserialize_with = "required_option")]
    signing_kid: Option<String>,
    #[serde(deserialize_with = "required_option")]
    issued_at: Option<i64>,
    #[serde(deserialize_with = "required_option")]
    lease_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    lease_expires_at: Option<i64>,
}

impl From<&SsfDelivery> for StoredDelivery {
    fn from(value: &SsfDelivery) -> Self {
        Self {
            tenant_id: value.tenant_id.clone(),
            stream_id: value.stream_id.clone(),
            stream_revision: value.stream_revision,
            event_id: value.event_id.clone(),
            issuer: value.issuer.clone(),
            endpoint: value.endpoint.clone(),
            audience: value.audience.clone(),
            event_uri: value.event_uri.clone(),
            subject: value.subject.clone(),
            payload: value.payload.clone(),
            status: value.status,
            attempts: value.attempts,
            cycle_attempts: value.cycle_attempts,
            redrive_count: value.redrive_count,
            attempt_history: value
                .attempt_history
                .iter()
                .map(StoredAttempt::from)
                .collect(),
            event_occurred_at: value.event_occurred_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            cycle_started_at: value.cycle_started_at,
            next_attempt_at: value.next_attempt_at,
            expires_at: value.expires_at,
            compact_set: value.compact_set.clone(),
            jti: value.jti.clone(),
            signing_kid: value.signing_kid.clone(),
            issued_at: value.issued_at,
            lease_id: value.lease_id.clone(),
            lease_expires_at: value.lease_expires_at,
        }
    }
}

impl From<StoredDelivery> for SsfDelivery {
    fn from(value: StoredDelivery) -> Self {
        Self {
            tenant_id: value.tenant_id,
            stream_id: value.stream_id,
            stream_revision: value.stream_revision,
            event_id: value.event_id,
            issuer: value.issuer,
            endpoint: value.endpoint,
            audience: value.audience,
            event_uri: value.event_uri,
            subject: value.subject,
            payload: value.payload,
            status: value.status,
            attempts: value.attempts,
            cycle_attempts: value.cycle_attempts,
            redrive_count: value.redrive_count,
            attempt_history: value
                .attempt_history
                .into_iter()
                .map(SsfDeliveryAttempt::from)
                .collect(),
            event_occurred_at: value.event_occurred_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            cycle_started_at: value.cycle_started_at,
            next_attempt_at: value.next_attempt_at,
            expires_at: value.expires_at,
            compact_set: value.compact_set,
            jti: value.jti,
            signing_kid: value.signing_kid,
            issued_at: value.issued_at,
            lease_id: value.lease_id,
            lease_expires_at: value.lease_expires_at,
        }
    }
}

pub(super) fn context(delivery: &SsfDelivery) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&(
        "ssf-delivery",
        &delivery.tenant_id,
        &delivery.stream_id,
        delivery.stream_revision,
        &delivery.event_id,
        delivery.created_at,
        delivery.next_attempt_at,
        delivery.expires_at,
        delivery.status,
        &delivery.lease_id,
        delivery.lease_expires_at,
    ))
    .map_err(|_| invalid())
}

pub(super) fn decode_delivery(
    row: PgRow,
    keys: &EncryptionKeyring,
) -> Result<SsfDelivery, StoreError> {
    let nonce = |column: &str| -> Result<[u8; 12], StoreError> {
        let bytes: Vec<u8> = row.try_get(column).map_err(db_error)?;
        bytes.try_into().map_err(|_| invalid())
    };
    let lease: Option<Vec<u8>> = row.try_get("lease_id").map_err(db_error)?;
    let metadata = SsfDelivery {
        tenant_id: identity(&row, "tenant")?,
        stream_id: identity(&row, "stream_id")?,
        stream_revision: row
            .try_get::<String, _>("stream_revision")
            .map_err(db_error)?
            .parse()
            .map_err(|_| invalid())?,
        event_id: identity(&row, "event_id")?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        next_attempt_at: row.try_get("next_attempt_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        status: SsfDeliveryStatus::parse(&row.try_get::<String, _>("status").map_err(db_error)?)?,
        lease_id: lease
            .map(|bytes| String::from_utf8(bytes).map_err(|_| invalid()))
            .transpose()?,
        lease_expires_at: row.try_get("lease_expires_at").map_err(db_error)?,
        issuer: String::new(),
        endpoint: String::new(),
        audience: String::new(),
        event_uri: String::new(),
        subject: serde_json::Value::Null,
        payload: serde_json::Value::Null,
        attempts: 0,
        cycle_attempts: 0,
        redrive_count: 0,
        attempt_history: vec![],
        event_occurred_at: 0,
        updated_at: 0,
        cycle_started_at: 0,
        compact_set: None,
        jti: None,
        signing_kid: None,
        issued_at: None,
    };
    let sealed = SealedRecord {
        kid: row.try_get("kid").map_err(db_error)?,
        key_nonce: nonce("key_nonce")?,
        encrypted_key: row.try_get("encrypted_key").map_err(db_error)?,
        nonce: nonce("nonce")?,
        ciphertext: row.try_get("ciphertext").map_err(db_error)?,
    };
    let plaintext = keys.open(&context(&metadata)?, &sealed)?;
    let record: SsfDelivery = serde_json::from_slice::<StoredDelivery>(&plaintext)
        .map_err(|_| invalid())?
        .into();
    if context(&record)? != context(&metadata)? {
        return Err(invalid());
    }
    validate_delivery_record(&record)?;
    Ok(record)
}

pub(super) async fn write_delivery(
    tx: &mut Transaction<'_, Postgres>,
    keys: &EncryptionKeyring,
    record: &SsfDelivery,
) -> Result<(), StoreError> {
    validate_delivery_record(record)?;
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&StoredDelivery::from(record)).map_err(|_| invalid())?);
    let sealed = keys.seal(&context(record)?, &plaintext)?;
    sqlx::query(
        "INSERT INTO a_auth.ssf_deliveries \
         (tenant, stream_id, stream_revision, event_id, created_at, next_attempt_at, expires_at, \
          status, lease_id, lease_expires_at, kid, key_nonce, encrypted_key, nonce, ciphertext) \
         VALUES ($1, $2, $3::TEXT::NUMERIC, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (tenant, stream_id, stream_revision, event_id) DO UPDATE SET \
         created_at = EXCLUDED.created_at, next_attempt_at = EXCLUDED.next_attempt_at, \
         expires_at = EXCLUDED.expires_at, status = EXCLUDED.status, lease_id = EXCLUDED.lease_id, \
         lease_expires_at = EXCLUDED.lease_expires_at, kid = EXCLUDED.kid, \
         key_nonce = EXCLUDED.key_nonce, encrypted_key = EXCLUDED.encrypted_key, \
         nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext",
    )
    .bind(record.tenant_id.as_bytes())
    .bind(record.stream_id.as_bytes())
    .bind(record.stream_revision.to_string())
    .bind(record.event_id.as_bytes())
    .bind(record.created_at)
    .bind(record.next_attempt_at)
    .bind(record.expires_at)
    .bind(record.status.as_str())
    .bind(record.lease_id.as_ref().map(|value| value.as_bytes()))
    .bind(record.lease_expires_at)
    .bind(&sealed.kid)
    .bind(sealed.key_nonce.as_slice())
    .bind(&sealed.encrypted_key)
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}
