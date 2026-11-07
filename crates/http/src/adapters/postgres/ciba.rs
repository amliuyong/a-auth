use super::{db_error, serialization::required_option, PostgresStore, PostgresUsersStore};
use crate::{
    adapters::mounted_crypto::{EncryptionKeyring, SealedRecord},
    ports::{CibaAuthRequest, CibaStore, StoreError},
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct PostgresCibaStore {
    store: PostgresStore,
    keys: Option<EncryptionKeyring>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRequest {
    auth_req_id: String,
    tenant: String,
    client_id: String,
    user_id: String,
    #[serde(deserialize_with = "required_option")]
    authz_session_id: Option<String>,
    scope: Vec<String>,
    resources: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    binding_message: Option<String>,
    interval: i64,
    #[serde(deserialize_with = "required_option")]
    last_poll_at: Option<i64>,
    expires_at: i64,
    status: String,
    consumed: bool,
    #[serde(deserialize_with = "required_option")]
    delivery_mode: Option<String>,
    #[serde(deserialize_with = "required_option")]
    notification_endpoint: Option<String>,
    #[serde(deserialize_with = "required_option")]
    client_notification_token: Option<String>,
    #[serde(deserialize_with = "required_option")]
    password_credential_version: Option<u64>,
}

impl From<&CibaAuthRequest> for StoredRequest {
    fn from(record: &CibaAuthRequest) -> Self {
        Self {
            auth_req_id: record.auth_req_id.clone(),
            tenant: record.tenant.clone(),
            client_id: record.client_id.clone(),
            user_id: record.user_id.clone(),
            authz_session_id: record.authz_session_id.clone(),
            scope: record.scope.clone(),
            resources: record.resources.clone(),
            binding_message: record.binding_message.clone(),
            interval: record.interval,
            last_poll_at: record.last_poll_at,
            expires_at: record.expires_at,
            status: record.status.clone(),
            consumed: record.consumed,
            delivery_mode: record.delivery_mode.clone(),
            notification_endpoint: record.notification_endpoint.clone(),
            client_notification_token: record.client_notification_token.clone(),
            password_credential_version: record.password_credential_version,
        }
    }
}

impl From<StoredRequest> for CibaAuthRequest {
    fn from(record: StoredRequest) -> Self {
        Self {
            auth_req_id: record.auth_req_id,
            tenant: record.tenant,
            client_id: record.client_id,
            user_id: record.user_id,
            authz_session_id: record.authz_session_id,
            scope: record.scope,
            resources: record.resources,
            binding_message: record.binding_message,
            interval: record.interval,
            last_poll_at: record.last_poll_at,
            expires_at: record.expires_at,
            status: record.status,
            consumed: record.consumed,
            delivery_mode: record.delivery_mode,
            notification_endpoint: record.notification_endpoint,
            client_notification_token: record.client_notification_token,
            password_credential_version: record.password_credential_version,
        }
    }
}

const COLUMNS: &str = "tenant, auth_req_id, client_id, user_id, expires_at, status, consumed, \
    last_poll_at, kid, key_nonce, encrypted_key, nonce, ciphertext";

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid encrypted CIBA authority".into())
}

fn context(record: &CibaAuthRequest) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&(
        "ciba-request",
        &record.tenant,
        &record.auth_req_id,
        &record.client_id,
        &record.user_id,
        record.expires_at,
        &record.status,
        record.consumed,
        record.last_poll_at,
    ))
    .map_err(|_| invalid())
}

fn decode(row: PgRow, keys: &EncryptionKeyring) -> Result<CibaAuthRequest, StoreError> {
    let identity = |column: &str| -> Result<String, StoreError> {
        let bytes: Vec<u8> = row.try_get(column).map_err(db_error)?;
        String::from_utf8(bytes).map_err(|_| invalid())
    };
    let nonce = |column: &str| -> Result<[u8; 12], StoreError> {
        let bytes: Vec<u8> = row.try_get(column).map_err(db_error)?;
        bytes.try_into().map_err(|_| invalid())
    };
    let metadata = CibaAuthRequest {
        tenant: identity("tenant")?,
        auth_req_id: identity("auth_req_id")?,
        client_id: identity("client_id")?,
        user_id: identity("user_id")?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        status: identity("status")?,
        consumed: row.try_get("consumed").map_err(db_error)?,
        last_poll_at: row.try_get("last_poll_at").map_err(db_error)?,
        authz_session_id: None,
        scope: vec![],
        resources: vec![],
        binding_message: None,
        interval: 0,
        delivery_mode: None,
        notification_endpoint: None,
        client_notification_token: None,
        password_credential_version: None,
    };
    let sealed = SealedRecord {
        kid: row.try_get("kid").map_err(db_error)?,
        key_nonce: nonce("key_nonce")?,
        encrypted_key: row.try_get("encrypted_key").map_err(db_error)?,
        nonce: nonce("nonce")?,
        ciphertext: row.try_get("ciphertext").map_err(db_error)?,
    };
    let bytes = keys.open(&context(&metadata)?, &sealed)?;
    let record: CibaAuthRequest = serde_json::from_slice::<StoredRequest>(&bytes)
        .map_err(|_| invalid())?
        .into();
    if context(&record)? != context(&metadata)? {
        return Err(invalid());
    }
    Ok(record)
}

async fn write(
    transaction: &mut Transaction<'_, Postgres>,
    keys: &EncryptionKeyring,
    record: &CibaAuthRequest,
) -> Result<(), StoreError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&StoredRequest::from(record))
            .map_err(|_| StoreError::Permanent("CIBA encoding failed".into()))?,
    );
    let sealed = keys.seal(&context(record)?, &plaintext)?;
    sqlx::query(
        "INSERT INTO a_auth.ciba_requests \
         (tenant, auth_req_id, client_id, user_id, expires_at, status, consumed, last_poll_at, \
          kid, key_nonce, encrypted_key, nonce, ciphertext) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (tenant, auth_req_id) DO UPDATE SET \
         client_id = EXCLUDED.client_id, user_id = EXCLUDED.user_id, \
         expires_at = EXCLUDED.expires_at, status = EXCLUDED.status, \
         consumed = EXCLUDED.consumed, last_poll_at = EXCLUDED.last_poll_at, \
         kid = EXCLUDED.kid, key_nonce = EXCLUDED.key_nonce, \
         encrypted_key = EXCLUDED.encrypted_key, nonce = EXCLUDED.nonce, \
         ciphertext = EXCLUDED.ciphertext",
    )
    .bind(record.tenant.as_bytes())
    .bind(record.auth_req_id.as_bytes())
    .bind(record.client_id.as_bytes())
    .bind(record.user_id.as_bytes())
    .bind(record.expires_at)
    .bind(record.status.as_bytes())
    .bind(record.consumed)
    .bind(record.last_poll_at)
    .bind(&sealed.kid)
    .bind(sealed.key_nonce.as_slice())
    .bind(&sealed.encrypted_key)
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(db_error)?;
    Ok(())
}

impl PostgresCibaStore {
    pub fn new(store: PostgresStore, keys: EncryptionKeyring) -> Self {
        Self {
            store,
            keys: Some(keys),
        }
    }

    pub fn new_delete_only(store: PostgresStore) -> Self {
        Self { store, keys: None }
    }

    fn keys(&self) -> Result<&EncryptionKeyring, StoreError> {
        self.keys.as_ref().ok_or_else(|| {
            StoreError::Permanent(
                "CIBA delete-only runtime cannot read or write encrypted state".into(),
            )
        })
    }

    async fn locked(
        transaction: &mut Transaction<'_, Postgres>,
        keys: &EncryptionKeyring,
        tenant: &str,
        id: &str,
    ) -> Result<Option<CibaAuthRequest>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.ciba_requests \
            WHERE tenant = $1 AND auth_req_id = $2 FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(|row| decode(row, keys))
        .transpose()
    }

    async fn mutate<T>(
        &self,
        tenant: &str,
        id: &str,
        operation: impl FnOnce(&mut Option<CibaAuthRequest>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let keys = self.keys()?;
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let mut record = Self::locked(&mut transaction, keys, tenant, id).await?;
        let before = record.clone();
        let result = operation(&mut record)?;
        if record != before {
            let next = record.as_ref().ok_or_else(invalid)?;
            if next.tenant != tenant || next.auth_req_id != id {
                return Err(invalid());
            }
            write(&mut transaction, keys, next).await?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(result)
    }
}

impl CibaStore for PostgresCibaStore {
    async fn put(&self, tenant: &str, record: CibaAuthRequest) -> Result<(), StoreError> {
        let id = record.auth_req_id.clone();
        self.mutate(tenant, &id, move |current| {
            if record.tenant != tenant {
                return Err(invalid());
            }
            *current = Some(record);
            Ok(())
        })
        .await
    }

    async fn get(&self, tenant: &str, id: &str) -> Result<Option<CibaAuthRequest>, StoreError> {
        let keys = self.keys()?;
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM a_auth.ciba_requests \
            WHERE tenant = $1 AND auth_req_id = $2"
        ))
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db_error)?
        .map(|row| decode(row, keys))
        .transpose()
    }

    async fn update(&self, tenant: &str, record: CibaAuthRequest) -> Result<(), StoreError> {
        self.put(tenant, record).await
    }

    async fn consume(&self, tenant: &str, id: &str) -> Result<bool, StoreError> {
        self.mutate(tenant, id, |record| {
            let Some(record) = record.as_mut().filter(|r| !r.consumed) else {
                return Ok(false);
            };
            record.consumed = true;
            Ok(true)
        })
        .await
    }

    async fn claim_poll(
        &self,
        tenant: &str,
        id: &str,
        observed: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.mutate(tenant, id, |record| {
            let Some(record) = record.as_mut().filter(|r| r.last_poll_at == observed) else {
                return Ok(false);
            };
            record.last_poll_at = Some(now);
            Ok(true)
        })
        .await
    }

    async fn decide(
        &self,
        tenant: &str,
        id: &str,
        version: Option<u64>,
        approve: bool,
    ) -> Result<bool, StoreError> {
        self.mutate(tenant, id, |record| {
            let Some(record) = record.as_mut().filter(|r| r.status == "pending") else {
                return Ok(false);
            };
            record.status = if approve { "approved" } else { "denied" }.into();
            record.password_credential_version = version;
            Ok(true)
        })
        .await
    }

    async fn release_consume(&self, tenant: &str, id: &str) -> Result<(), StoreError> {
        self.mutate(tenant, id, |record| {
            if let Some(record) = record {
                record.consumed = false;
            }
            Ok(())
        })
        .await
    }

    async fn try_arm_throttle(
        &self,
        tenant: &str,
        user: &str,
        now: i64,
        window: i64,
    ) -> Result<bool, StoreError> {
        self.keys()?;
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let armed = sqlx::query(
            "INSERT INTO a_auth.ciba_throttle (tenant, user_id, last_authorize_at) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant, user_id) DO UPDATE SET last_authorize_at = EXCLUDED.last_authorize_at \
             WHERE a_auth.ciba_throttle.last_authorize_at::NUMERIC <= $3::BIGINT::NUMERIC - $4::BIGINT::NUMERIC",
        ).bind(tenant.as_bytes()).bind(user.as_bytes()).bind(now).bind(window)
            .execute(&mut *transaction).await.map_err(db_error)?.rows_affected() == 1;
        transaction.commit().await.map_err(db_error)?;
        Ok(armed)
    }

    async fn delete_by_user(&self, tenant: &str, user: &str) -> Result<usize, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let removed =
            sqlx::query("DELETE FROM a_auth.ciba_requests WHERE tenant = $1 AND user_id = $2")
                .bind(tenant.as_bytes())
                .bind(user.as_bytes())
                .execute(&mut *transaction)
                .await
                .map_err(db_error)?
                .rows_affected();
        sqlx::query("DELETE FROM a_auth.ciba_throttle WHERE tenant = $1 AND user_id = $2")
            .bind(tenant.as_bytes())
            .bind(user.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(removed as usize)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        let requests = sqlx::query("DELETE FROM a_auth.ciba_requests WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?
            .rows_affected();
        let throttle = sqlx::query("DELETE FROM a_auth.ciba_throttle WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?
            .rows_affected();
        transaction.commit().await.map_err(db_error)?;
        Ok((requests + throttle) as usize)
    }
}
