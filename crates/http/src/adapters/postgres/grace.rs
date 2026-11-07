use super::{db_error, PostgresStore};
use crate::{
    adapters::mounted_crypto::{EncryptionKeyring, SealedRecord},
    ports::{GraceCacheEntry, GraceCachedResponse, GraceStore, StoreError},
};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Construction requires explicit external encryption authority. Pool clones
/// share database state; separate instances can read it with the same key ring.
#[derive(Clone)]
pub struct PostgresGraceStore {
    store: PostgresStore,
    keys: Option<EncryptionKeyring>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Payload {
    fingerprint: [u8; 32],
    client_id: String,
    dpop_jkt: Option<String>,
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
    scope: Option<String>,
    expires_in: i64,
}

pub(super) struct PreparedGrace {
    family_id: String,
    version: u64,
    expires_at: i64,
    sealed: SealedRecord,
}

fn context(family_id: &str, version: u64, expires_at: i64) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&("refresh-grace", family_id, version, expires_at))
        .map_err(|_| StoreError::Permanent("Grace record context encoding failed".into()))
}

impl PostgresGraceStore {
    pub fn new(store: PostgresStore, keys: EncryptionKeyring) -> Self {
        Self {
            store,
            keys: Some(keys),
        }
    }

    /// Other runtime paths can invalidate grace state without possessing
    /// encryption keys or acquiring the ability to replay cached tokens.
    pub fn new_delete_only(store: PostgresStore) -> Self {
        Self { store, keys: None }
    }

    fn keys(&self) -> Result<&EncryptionKeyring, StoreError> {
        self.keys.as_ref().ok_or_else(|| {
            StoreError::Permanent(
                "Grace delete-only runtime cannot read or write encrypted state".into(),
            )
        })
    }

    pub(crate) fn belongs_to(&self, store: &PostgresStore) -> bool {
        Arc::ptr_eq(&self.store.identity, &store.identity)
    }

    pub(super) fn prepare(&self, entry: GraceCacheEntry) -> Result<PreparedGrace, StoreError> {
        let keys = self.keys()?;
        let context = context(&entry.family_id, entry.version, entry.expires_at)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&Payload {
                fingerprint: entry.fingerprint,
                client_id: entry.client_id,
                dpop_jkt: entry.dpop_jkt,
                access_token: entry.response.access_token,
                refresh_token: entry.response.refresh_token,
                id_token: entry.response.id_token,
                scope: entry.response.scope,
                expires_in: entry.response.expires_in,
            })
            .map_err(|_| StoreError::Permanent("Grace payload encoding failed".into()))?,
        );
        let sealed = keys.seal(&context, &plaintext)?;
        Ok(PreparedGrace {
            family_id: entry.family_id,
            version: entry.version,
            expires_at: entry.expires_at,
            sealed,
        })
    }

    pub(super) async fn persist(
        connection: &mut PgConnection,
        prepared: &PreparedGrace,
    ) -> Result<(), StoreError> {
        let sealed = &prepared.sealed;
        sqlx::query(
            "INSERT INTO a_auth.grace_responses \
             (family_id, version, expires_at, kid, key_nonce, encrypted_key, nonce, ciphertext) \
             VALUES ($1, $2::TEXT::NUMERIC, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (family_id, version) DO UPDATE \
             SET expires_at = EXCLUDED.expires_at, kid = EXCLUDED.kid, \
                 key_nonce = EXCLUDED.key_nonce, encrypted_key = EXCLUDED.encrypted_key, \
                 nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext",
        )
        .bind(prepared.family_id.as_bytes())
        .bind(prepared.version.to_string())
        .bind(prepared.expires_at)
        .bind(&sealed.kid)
        .bind(sealed.key_nonce.as_slice())
        .bind(&sealed.encrypted_key)
        .bind(sealed.nonce.as_slice())
        .bind(&sealed.ciphertext)
        .execute(connection)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

impl GraceStore for PostgresGraceStore {
    async fn put(&self, entry: GraceCacheEntry) -> Result<(), StoreError> {
        let prepared = self.prepare(entry)?;
        let mut connection = self.store.pool.acquire().await.map_err(db_error)?;
        Self::persist(&mut connection, &prepared).await
    }

    async fn get(
        &self,
        family_id: &str,
        version: u64,
    ) -> Result<Option<GraceCacheEntry>, StoreError> {
        let keys = self.keys()?;
        let row = sqlx::query(
            "SELECT expires_at, kid, key_nonce, encrypted_key, nonce, ciphertext \
             FROM a_auth.grace_responses WHERE family_id = $1 AND version = $2::TEXT::NUMERIC",
        )
        .bind(family_id.as_bytes())
        .bind(version.to_string())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else { return Ok(None) };
        let expires_at = row.try_get("expires_at").map_err(db_error)?;
        let nonce = |field: &str| -> Result<[u8; 12], StoreError> {
            let value: Vec<u8> = row.try_get(field).map_err(db_error)?;
            value
                .try_into()
                .map_err(|_| StoreError::Permanent("Invalid encrypted grace record".into()))
        };
        let sealed = SealedRecord {
            kid: row.try_get("kid").map_err(db_error)?,
            key_nonce: nonce("key_nonce")?,
            encrypted_key: row.try_get("encrypted_key").map_err(db_error)?,
            nonce: nonce("nonce")?,
            ciphertext: row.try_get("ciphertext").map_err(db_error)?,
        };
        let plaintext = keys.open(&context(family_id, version, expires_at)?, &sealed)?;
        let payload: Payload = serde_json::from_slice(&plaintext)
            .map_err(|_| StoreError::Permanent("Invalid encrypted grace payload".into()))?;
        Ok(Some(GraceCacheEntry {
            family_id: family_id.into(),
            version,
            fingerprint: payload.fingerprint,
            client_id: payload.client_id,
            dpop_jkt: payload.dpop_jkt,
            response: GraceCachedResponse {
                access_token: payload.access_token,
                refresh_token: payload.refresh_token,
                id_token: payload.id_token,
                scope: payload.scope,
                expires_in: payload.expires_in,
            },
            expires_at,
        }))
    }

    async fn delete_family(&self, family_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.grace_responses WHERE family_id = $1")
            .bind(family_id.as_bytes())
            .execute(&self.store.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
