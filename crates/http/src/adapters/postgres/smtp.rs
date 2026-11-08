//! Durable notification admission and single-submission SMTP authority.
//! A process can reclaim an expired lease before submission admission. Once
//! admitted, an unknown external result never reopens automatic submission.

use super::{db_error, outbox, PostgresMessageOutbox, PostgresStore, PostgresUsersStore};
use crate::{
    adapters::{mounted_crypto::EncryptionKeyring, smtp::SmtpRelay},
    governance::GovernanceAliasKind,
    ports::{Notifier, SentMessage, StoreError},
};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

#[derive(Clone)]
pub struct PostgresSmtpNotifier {
    store: PostgresStore,
    users: PostgresUsersStore,
    keys: EncryptionKeyring,
    relay: SmtpRelay,
}

#[derive(Clone)]
pub struct PostgresSmtpLease {
    message: SentMessage,
    nonce: Vec<u8>,
    deadline: i64,
}

/// An immutable admission capability, with no Debug/serialization or public
/// mutable message/nonce fields.
pub struct PostgresSmtpSend {
    message: SentMessage,
    nonce: Vec<u8>,
}

#[derive(Default, serde::Serialize)]
pub struct PostgresSmtpBatch {
    pub claimed: usize,
    pub accepted: usize,
    pub uncertain: usize,
    pub authority_lost: usize,
}

struct Record {
    message: SentMessage,
    status: String,
    nonce: Option<Vec<u8>>,
    deadline: Option<i64>,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL SMTP authority".into())
}

fn clock(now: i64) -> i64 {
    now.max(crate::current_unix_secs())
}

fn columns() -> String {
    format!("{}, status, lease_id, lease_until", outbox::COLUMNS)
}

fn decode(row: PgRow, keys: &EncryptionKeyring) -> Result<Record, StoreError> {
    let status: String = row.try_get("status").map_err(db_error)?;
    let nonce: Option<Vec<u8>> = row.try_get("lease_id").map_err(db_error)?;
    let deadline: Option<i64> = row.try_get("lease_until").map_err(db_error)?;
    let message = outbox::decode(row, keys)?;
    if !matches!(
        status.as_str(),
        "pending" | "leased" | "sending" | "accepted" | "uncertain"
    ) || (status == "pending") != nonce.is_none()
        || (status == "leased") != deadline.is_some()
        || nonce.as_ref().is_some_and(|value| {
            value.len() != 35
                || !value.starts_with(b"sn_")
                || !value[3..].iter().all(u8::is_ascii_hexdigit)
        })
        || !matches!(message.kind.as_str(), "magic_link" | "recovery")
        || message.message_id.is_empty()
        || message.message_id.len() > 1024
        || message.tenant.len() > 1024
        || message.recipient.len() > 1024
        || message.recipient.chars().any(char::is_control)
        || message.recipient.parse::<lettre::Address>().is_err()
        || message.body.len() > 65_536
        || message.body.contains('\0')
        || message.created_at >= message.ttl
    {
        return Err(invalid());
    }
    Ok(Record {
        message,
        status,
        nonce,
        deadline,
    })
}

impl PostgresSmtpNotifier {
    pub fn new(
        store: PostgresStore,
        users: PostgresUsersStore,
        keys: EncryptionKeyring,
        relay: SmtpRelay,
    ) -> Result<Self, StoreError> {
        if !users.belongs_to(&store) {
            return Err(invalid());
        }
        Ok(Self {
            store,
            users,
            keys,
            relay,
        })
    }

    async fn locked(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        message: &SentMessage,
    ) -> Result<Option<Record>, StoreError> {
        sqlx::query(&format!(
            "SELECT {} FROM a_auth.smtp_notifications \
             WHERE tenant = $1 AND message_id = $2 FOR UPDATE",
            columns()
        ))
        .bind(message.tenant.as_bytes())
        .bind(message.message_id.as_bytes())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(db_error)?
        .map(|row| decode(row, &self.keys))
        .transpose()
    }

    async fn admit(
        &self,
        tenant: &str,
        id: String,
        kind: &str,
        recipient: &str,
        body: String,
    ) -> Result<(), StoreError> {
        let recipient = recipient.trim().to_lowercase();
        if tenant.len() > 1024
            || id.is_empty()
            || id.len() > 1024
            || recipient.len() > 1024
            || recipient.chars().any(char::is_control)
            || recipient.parse::<lettre::Address>().is_err()
            || body.len() > 65_536
            || body.contains('\0')
        {
            return Err(invalid());
        }
        let now = crate::current_unix_secs();
        let message = SentMessage {
            message_id: id,
            tenant: tenant.into(),
            kind: kind.into(),
            recipient,
            body,
            created_at: now,
            ttl: now.checked_add(86_400).ok_or_else(invalid)?,
        };
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, tenant).await?;
        self.users
            .admit_aliases(
                &mut transaction,
                tenant,
                &[(GovernanceAliasKind::Email, &message.recipient)],
            )
            .await?;
        if let Some(existing) = self.locked(&mut transaction, &message).await? {
            // The first admission owns time/expiry. Repeated recovery calls
            // preserve that record instead of manufacturing a new delivery.
            if existing.message.kind != message.kind
                || existing.message.recipient != message.recipient
                || existing.message.body != message.body
            {
                return Err(invalid());
            }
            transaction.commit().await.map_err(db_error)?;
            return Ok(());
        }
        let sealed = self
            .keys
            .seal(&outbox::context(&message)?, &outbox::encode(&message)?)?;
        sqlx::query(
            "INSERT INTO a_auth.smtp_notifications \
             (tenant, message_id, kind, recipient, created_at, ttl, \
              kid, key_nonce, encrypted_key, nonce, ciphertext, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')",
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
        transaction.commit().await.map_err(db_error)
    }

    pub async fn claim(
        &self,
        now: i64,
        lease_seconds: i64,
        limit: usize,
    ) -> Result<Vec<PostgresSmtpLease>, StoreError> {
        if !(1..=360).contains(&lease_seconds) || !(1..=16).contains(&limit) {
            return Err(invalid());
        }
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        let rows = sqlx::query(&format!(
            "SELECT {} FROM a_auth.smtp_notifications WHERE ttl > $1 AND \
             (status = 'pending' OR (status = 'leased' AND lease_until <= $1)) \
             ORDER BY created_at, tenant, message_id LIMIT $2 FOR UPDATE SKIP LOCKED",
            columns()
        ))
        .bind(clock(now))
        .bind(limit as i64)
        .fetch_all(&mut *transaction)
        .await
        .map_err(db_error)?;
        let records = rows
            .into_iter()
            .map(|row| decode(row, &self.keys))
            .collect::<Result<Vec<_>, _>>()?;
        let deadline = clock(now).checked_add(lease_seconds).ok_or_else(invalid)?;
        let mut leases = Vec::with_capacity(records.len());
        for record in records {
            let nonce = format!("sn_{:032x}", rand::random::<u128>()).into_bytes();
            sqlx::query(
                "UPDATE a_auth.smtp_notifications SET status = 'leased', \
                 lease_id = $3, lease_until = $4 WHERE tenant = $1 AND message_id = $2",
            )
            .bind(record.message.tenant.as_bytes())
            .bind(record.message.message_id.as_bytes())
            .bind(&nonce)
            .bind(deadline)
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
            leases.push(PostgresSmtpLease {
                message: record.message,
                nonce,
                deadline,
            });
        }
        if clock(now) >= deadline {
            return Err(StoreError::Transient("SMTP claim expired".into()));
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(leases)
    }

    /// Commit the irreversible single-submission admission before network I/O.
    /// Expired/replaced claims cannot admit a send.
    pub async fn prepare_send(
        &self,
        lease: &PostgresSmtpLease,
        now: i64,
    ) -> Result<Option<PostgresSmtpSend>, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, &lease.message.tenant).await?;
        let Some(record) = self.locked(&mut transaction, &lease.message).await? else {
            return Ok(None);
        };
        if record.status != "leased"
            || record.nonce.as_deref() != Some(lease.nonce.as_slice())
            || record.deadline != Some(lease.deadline)
            || record.message != lease.message
            || clock(now) >= lease.deadline
            || clock(now) >= lease.message.ttl
        {
            return Ok(None);
        }
        self.users
            .admit_aliases(
                &mut transaction,
                &lease.message.tenant,
                &[(GovernanceAliasKind::Email, &lease.message.recipient)],
            )
            .await?;
        sqlx::query(
            "UPDATE a_auth.smtp_notifications SET status = 'sending', lease_until = NULL \
             WHERE tenant = $1 AND message_id = $2",
        )
        .bind(lease.message.tenant.as_bytes())
        .bind(lease.message.message_id.as_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if clock(now) >= lease.deadline || clock(now) >= lease.message.ttl {
            return Ok(None);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(PostgresSmtpSend {
            message: lease.message.clone(),
            nonce: lease.nonce.clone(),
        }))
    }

    /// A positive SMTP receipt and its encrypted observation commit together.
    /// Retrying this transaction never resubmits the mail.
    pub async fn record_acceptance(&self, permit: &PostgresSmtpSend) -> Result<bool, StoreError> {
        self.finish(permit, true).await
    }

    pub async fn record_uncertainty(&self, permit: &PostgresSmtpSend) -> Result<bool, StoreError> {
        self.finish(permit, false).await
    }

    async fn finish(&self, permit: &PostgresSmtpSend, accepted: bool) -> Result<bool, StoreError> {
        let mut transaction = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut transaction, &permit.message.tenant).await?;
        let Some(record) = self.locked(&mut transaction, &permit.message).await? else {
            return Ok(false);
        };
        if record.message != permit.message
            || record.nonce.as_deref() != Some(permit.nonce.as_slice())
            || !(record.status == "sending" || (accepted && record.status == "uncertain"))
        {
            return Ok(false);
        }
        if accepted {
            self.users
                .admit_aliases(
                    &mut transaction,
                    &permit.message.tenant,
                    &[(GovernanceAliasKind::Email, &permit.message.recipient)],
                )
                .await?;
            PostgresMessageOutbox::new(self.store.clone(), self.keys.clone())
                .record_delivered_in(&mut transaction, &permit.message)
                .await?;
        }
        sqlx::query(
            "UPDATE a_auth.smtp_notifications SET status = $3 \
             WHERE tenant = $1 AND message_id = $2",
        )
        .bind(permit.message.tenant.as_bytes())
        .bind(permit.message.message_id.as_bytes())
        .bind(if accepted { "accepted" } else { "uncertain" })
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    pub async fn run_once(&self, now: i64, limit: usize) -> Result<PostgresSmtpBatch, StoreError> {
        let leases = self.claim(now, 360, limit).await?;
        let mut report = PostgresSmtpBatch {
            claimed: leases.len(),
            ..Default::default()
        };
        for lease in leases {
            let Some(permit) = self.prepare_send(&lease, clock(now)).await? else {
                report.authority_lost += 1;
                continue;
            };
            if self.relay.deliver(&permit.message).await.is_ok() {
                if self.record_acceptance(&permit).await? {
                    report.accepted += 1;
                } else {
                    report.authority_lost += 1;
                }
            } else if self.record_uncertainty(&permit).await? {
                report.uncertain += 1;
            } else {
                report.authority_lost += 1;
            }
        }
        Ok(report)
    }
}

impl Notifier for PostgresSmtpNotifier {
    async fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        // Hashing the credential avoids retaining it in the physical identifier
        // and coalesces retries of the same notification.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};
        let id = format!("magic#{}", URL_SAFE_NO_PAD.encode(Sha256::digest(link_url)));
        self.admit(tenant, id, "magic_link", email, link_url.into())
            .await
    }

    async fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        if notification_id.is_empty() || notification_id.len() > 1000 {
            return Err(invalid());
        }
        self.admit(
            tenant,
            format!("recovery#{notification_id}"),
            "recovery",
            recipient_email,
            format!(
                "account recovered at={recovered_at} ip={}",
                client_ip.unwrap_or("-")
            ),
        )
        .await
    }
}
