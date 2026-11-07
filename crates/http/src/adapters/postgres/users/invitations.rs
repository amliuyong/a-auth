use super::super::{db_error, sessions};
use super::PostgresUsersStore;
use crate::ports::{
    InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome, InvitationRecord,
    InvitationStore, SessionRecord, StoreError, UserRecord, UserStatus,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

/// Invitation authority shares the configured user authority and its pool.
#[derive(Clone)]
pub struct PostgresInvitationStore {
    users: PostgresUsersStore,
}

impl PostgresInvitationStore {
    pub fn new(users: PostgresUsersStore) -> Self {
        Self { users }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInvitation {
    locator: String,
    activation_id: String,
    user_id: String,
    email: String,
    verifier_hash: String,
    credential_epoch: u64,
    issued_at: i64,
    expires_at: i64,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid invitation authority".into())
}

fn encode(record: &InvitationRecord) -> Result<String, StoreError> {
    serde_json::to_string(&StoredInvitation {
        locator: record.locator.clone(),
        activation_id: record.activation_id.clone(),
        user_id: record.user_id.clone(),
        email: record.email.clone(),
        verifier_hash: record.verifier_hash.clone(),
        credential_epoch: record.credential_epoch,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
    })
    .map_err(|_| StoreError::Permanent("Invitation encoding failed".into()))
}

fn decode(row: PgRow) -> Result<InvitationRecord, StoreError> {
    let payload: String = row.try_get("record").map_err(db_error)?;
    let stored: StoredInvitation = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let locator: Vec<u8> = row.try_get("locator").map_err(db_error)?;
    let user: Vec<u8> = row.try_get("user_id").map_err(db_error)?;
    let email: Vec<u8> = row.try_get("email").map_err(db_error)?;
    let activation: Vec<u8> = row.try_get("activation_id").map_err(db_error)?;
    let epoch: String = row.try_get("credential_epoch").map_err(db_error)?;
    let expiry: i64 = row.try_get("expires_at").map_err(db_error)?;
    if locator != stored.locator.as_bytes()
        || user != stored.user_id.as_bytes()
        || email != stored.email.as_bytes()
        || activation != stored.activation_id.as_bytes()
        || epoch.parse::<u64>().map_err(|_| invalid())? != stored.credential_epoch
        || expiry != stored.expires_at
    {
        return Err(invalid());
    }
    Ok(InvitationRecord {
        locator: stored.locator,
        activation_id: stored.activation_id,
        user_id: stored.user_id,
        email: stored.email,
        verifier_hash: stored.verifier_hash,
        credential_epoch: stored.credential_epoch,
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
    })
}

async fn get_locked(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    locator: &str,
) -> Result<Option<InvitationRecord>, StoreError> {
    sqlx::query(
        "SELECT locator, user_id, email, activation_id, credential_epoch::TEXT AS credential_epoch, \
         expires_at, record FROM a_auth.invitations WHERE tenant = $1 AND locator = $2 FOR UPDATE",
    )
    .bind(tenant.as_bytes())
    .bind(locator.as_bytes())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db_error)?
    .map(decode)
    .transpose()
}

fn eligible(user: &UserRecord, record: &InvitationRecord) -> bool {
    user.status == UserStatus::Active
        && !user.revocation_pending
        && user.user_id == record.user_id
        && user.email == record.email
        && user.credential_epoch == record.credential_epoch
        && crate::local_identity::is_valid_email(&user.email)
        && crate::local_identity::is_password_capable_user_id(&user.user_id)
}

async fn has_password(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &str,
    user: &str,
) -> Result<bool, StoreError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM a_auth.password_credentials WHERE tenant = $1 AND user_id = $2)",
    )
    .bind(tenant)
    .bind(user)
    .fetch_one(&mut **transaction)
    .await
    .map_err(db_error)
}

impl InvitationStore for PostgresInvitationStore {
    async fn issue(
        &self,
        tenant: &str,
        record: InvitationRecord,
    ) -> Result<InvitationIssueOutcome, StoreError> {
        let mut transaction = self.users.base.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        self.users.bind_authority(&mut transaction).await?;
        let Some(user) =
            PostgresUsersStore::lock_user(&mut transaction, tenant, &record.user_id).await?
        else {
            return Ok(InvitationIssueOutcome::Ineligible);
        };
        if !eligible(&user.record, &record) {
            return Ok(InvitationIssueOutcome::Ineligible);
        }
        if has_password(&mut transaction, tenant, &record.user_id).await? {
            return Ok(InvitationIssueOutcome::PasswordConfigured);
        }
        get_locked(&mut transaction, tenant, &record.locator).await?;
        sqlx::query(
            "INSERT INTO a_auth.invitations \
             (tenant, locator, user_id, email, activation_id, credential_epoch, expires_at, record) \
             VALUES ($1, $2, $3, $4, $5, $6::TEXT::NUMERIC, $7, $8) \
             ON CONFLICT (tenant, locator) DO UPDATE SET user_id = EXCLUDED.user_id, \
             email = EXCLUDED.email, activation_id = EXCLUDED.activation_id, \
             credential_epoch = EXCLUDED.credential_epoch, expires_at = EXCLUDED.expires_at, \
             record = EXCLUDED.record",
        )
        .bind(tenant.as_bytes())
        .bind(record.locator.as_bytes())
        .bind(record.user_id.as_bytes())
        .bind(record.email.as_bytes())
        .bind(record.activation_id.as_bytes())
        .bind(record.credential_epoch.to_string())
        .bind(record.expires_at)
        .bind(encode(&record)?)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(InvitationIssueOutcome::Issued)
    }

    async fn accept(
        &self,
        tenant: &str,
        request: InvitationAcceptRequest,
    ) -> Result<InvitationAcceptOutcome, StoreError> {
        let mut transaction = self.users.base.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        self.users.bind_authority(&mut transaction).await?;
        let Some(record) = get_locked(&mut transaction, tenant, &request.locator).await? else {
            return Ok(InvitationAcceptOutcome::Invalid);
        };
        if !crate::invitation::verifier_matches(&record.verifier_hash, &request.verifier_hash)
            || record.activation_id != request.activation_id
        {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        if record.expires_at <= request.now {
            return Ok(InvitationAcceptOutcome::Expired {
                user_id: record.user_id,
            });
        }
        let Some(user) =
            PostgresUsersStore::lock_user(&mut transaction, tenant, &record.user_id).await?
        else {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: record.user_id,
            });
        };
        if !eligible(&user.record, &record)
            || has_password(&mut transaction, tenant, &record.user_id).await?
        {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: record.user_id,
            });
        }
        let expires_at = request
            .now
            .checked_add(crate::login::SESSION_TTL_SECS)
            .ok_or_else(|| StoreError::Permanent("Invited session lifetime exhausted".into()))?;
        let session = SessionRecord {
            session_id: request.session_id.clone(),
            user_id: record.user_id.clone(),
            credential_epoch: record.credential_epoch,
            auth_time: request.now,
            created_at: request.now,
            last_used_at: request.now,
            device: request.device,
            expires_at,
            acr: None,
            amr: vec!["invite".into()],
        };
        sessions::create_in_transaction(&mut transaction, tenant, session).await?;
        sqlx::query("DELETE FROM a_auth.invitations WHERE tenant = $1 AND locator = $2")
            .bind(tenant.as_bytes())
            .bind(request.locator.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(InvitationAcceptOutcome::Accepted {
            user_id: record.user_id,
            session_id: request.session_id,
        })
    }

    async fn invalidate(&self, tenant: &str, locator: &str) -> Result<(), StoreError> {
        let mut transaction = self.users.base.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        sqlx::query("DELETE FROM a_auth.invitations WHERE tenant = $1 AND locator = $2")
            .bind(tenant.as_bytes())
            .bind(locator.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)
    }
}
