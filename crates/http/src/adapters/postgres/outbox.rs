use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::{
    adapters::mounted_crypto::{EncryptionKeyring, SealedRecord},
    ports::{MessageOutbox, SentMessage, StoreError},
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Row};
use zeroize::Zeroizing;

/// Encrypted delivery observations. This storage adapter does not send mail.
/// A delivery adapter supplies the immutable message it actually delivered.
#[derive(Clone)]
pub struct PostgresMessageOutbox {
    store: PostgresStore,
    keys: Option<EncryptionKeyring>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMessage {
    message_id: String,
    tenant: String,
    kind: String,
    recipient: String,
    body: String,
    created_at: i64,
    ttl: i64,
}

const COLUMNS: &str = "tenant, message_id, kind, recipient, created_at, ttl, \
    kid, key_nonce, encrypted_key, nonce, ciphertext";

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid encrypted notification authority".into())
}

fn context(message: &SentMessage) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&(
        "notification-outbox",
        &message.tenant,
        &message.message_id,
        &message.kind,
        &message.recipient,
        message.created_at,
        message.ttl,
    ))
    .map_err(|_| invalid())
}

fn encode(message: &SentMessage) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    serde_json::to_vec(&StoredMessage {
        message_id: message.message_id.clone(),
        tenant: message.tenant.clone(),
        kind: message.kind.clone(),
        recipient: message.recipient.clone(),
        body: message.body.clone(),
        created_at: message.created_at,
        ttl: message.ttl,
    })
    .map(Zeroizing::new)
    .map_err(|_| StoreError::Permanent("Notification encoding failed".into()))
}

fn decode(row: PgRow, keys: &EncryptionKeyring) -> Result<SentMessage, StoreError> {
    let identity = |column: &str| -> Result<String, StoreError> {
        let value: Vec<u8> = row.try_get(column).map_err(db_error)?;
        String::from_utf8(value).map_err(|_| invalid())
    };
    let nonce = |column: &str| -> Result<[u8; 12], StoreError> {
        let value: Vec<u8> = row.try_get(column).map_err(db_error)?;
        value.try_into().map_err(|_| invalid())
    };
    let metadata = SentMessage {
        message_id: identity("message_id")?,
        tenant: identity("tenant")?,
        kind: identity("kind")?,
        recipient: identity("recipient")?,
        body: String::new(),
        created_at: row.try_get("created_at").map_err(db_error)?,
        ttl: row.try_get("ttl").map_err(db_error)?,
    };
    let sealed = SealedRecord {
        kid: row.try_get("kid").map_err(db_error)?,
        key_nonce: nonce("key_nonce")?,
        encrypted_key: row.try_get("encrypted_key").map_err(db_error)?,
        nonce: nonce("nonce")?,
        ciphertext: row.try_get("ciphertext").map_err(db_error)?,
    };
    let plaintext = keys.open(&context(&metadata)?, &sealed)?;
    let stored: StoredMessage = serde_json::from_slice(&plaintext).map_err(|_| invalid())?;
    if stored.message_id != metadata.message_id
        || stored.tenant != metadata.tenant
        || stored.kind != metadata.kind
        || stored.recipient != metadata.recipient
        || stored.created_at != metadata.created_at
        || stored.ttl != metadata.ttl
    {
        return Err(invalid());
    }
    Ok(SentMessage {
        body: stored.body,
        ..metadata
    })
}

impl PostgresMessageOutbox {
    pub(crate) fn belongs_to(&self, store: &PostgresStore) -> bool {
        self.store.shares_pool_with(store)
    }

    pub fn new(store: PostgresStore, keys: EncryptionKeyring) -> Self {
        Self {
            store,
            keys: Some(keys),
        }
    }

    /// Erasure workers need no ability to decrypt notification bodies.
    pub fn new_delete_only(store: PostgresStore) -> Self {
        Self { store, keys: None }
    }

    fn keys(&self) -> Result<&EncryptionKeyring, StoreError> {
        self.keys.as_ref().ok_or_else(|| {
            StoreError::Permanent(
                "Notification delete-only runtime cannot read or write encrypted state".into(),
            )
        })
    }

    /// Create an immutable delivery observation. An exact retry returns false;
    /// a captured ID cannot be rebound to another recipient or notification.
    pub async fn record_delivered(&self, message: SentMessage) -> Result<bool, StoreError> {
        let keys = self.keys()?;
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, &message.tenant).await?;
        let existing = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.message_outbox \
             WHERE tenant = $1 AND message_id = $2 FOR UPDATE"
        ))
        .bind(message.tenant.as_bytes())
        .bind(message.message_id.as_bytes())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?;
        if let Some(existing) = existing {
            if decode(existing, keys)? != message {
                return Err(StoreError::Permanent(
                    "Notification identity is already bound".into(),
                ));
            }
            transaction.commit().await.map_err(db_error)?;
            return Ok(false);
        }
        let sealed = keys.seal(&context(&message)?, &encode(&message)?)?;
        sqlx::query(
            "INSERT INTO a_auth.message_outbox \
             (tenant, message_id, kind, recipient, created_at, ttl, \
              kid, key_nonce, encrypted_key, nonce, ciphertext) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(message.tenant.as_bytes())
        .bind(message.message_id.as_bytes())
        .bind(message.kind.as_bytes())
        .bind(message.recipient.as_bytes())
        .bind(message.created_at)
        .bind(message.ttl)
        .bind(&sealed.kid)
        .bind(sealed.key_nonce.as_slice())
        .bind(&sealed.encrypted_key)
        .bind(sealed.nonce.as_slice())
        .bind(&sealed.ciphertext)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }
}

impl MessageOutbox for PostgresMessageOutbox {
    async fn list_recent(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<SentMessage>, StoreError> {
        let keys = self.keys()?;
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.message_outbox WHERE tenant = $1 \
             ORDER BY created_at DESC, message_id DESC LIMIT $2"
        ))
        .bind(tenant.as_bytes())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.store.pool)
        .await
        .map_err(db_error)?;
        rows.into_iter().map(|row| decode(row, keys)).collect()
    }

    async fn delete_by_recipients(
        &self,
        tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        if recipients.is_empty() {
            return Ok(0);
        }
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = sqlx::query(
            "DELETE FROM a_auth.message_outbox WHERE tenant = $1 \
             AND recipient = ANY($2::BYTEA[])",
        )
        .bind(tenant.as_bytes())
        .bind(
            recipients
                .iter()
                .map(|recipient| recipient.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let result = sqlx::query("DELETE FROM a_auth.message_outbox WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(result.rows_affected() as usize)
    }
}
