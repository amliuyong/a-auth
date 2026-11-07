use super::{db_error, PostgresStore, PostgresUsersStore};
use crate::{
    adapters::mounted_crypto::EncryptionKeyring, ports::StoreError, security_event::SecurityEvent,
    ssf::*,
};
use sqlx::{Postgres, Transaction};

mod record;
use record::*;

type DueCursor = (i64, i64, Vec<u8>, Vec<u8>, u64, Vec<u8>);

/// Persistent SSF streams and encrypted, generation-bound delivery authority.
/// Directory locks fence stream changes and queue writes in the same order as
/// governance revocation. Workers additionally use SKIP LOCKED on due rows.
#[derive(Clone)]
pub struct PostgresSsfStore {
    store: PostgresStore,
    keys: EncryptionKeyring,
}

impl PostgresSsfStore {
    pub fn new(store: PostgresStore, keys: EncryptionKeyring) -> Self {
        Self { store, keys }
    }

    pub(crate) fn belongs_to(&self, store: &PostgresStore) -> bool {
        self.store.shares_pool_with(store)
    }

    pub(super) async fn governance_inventory(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<[u64; 5], StoreError> {
        let mut counts = [0; 5];
        for stream in Self::streams(tx, tenant).await? {
            counts[usize::from(stream.status == SsfStreamStatus::Revoked)] += 1;
        }
        let rows = sqlx::query(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries WHERE tenant = $1 \
             ORDER BY stream_id, stream_revision, event_id FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        for row in rows {
            let delivery = decode_delivery(row, &self.keys)?;
            let category = match delivery.status {
                SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait => 2,
                SsfDeliveryStatus::Suppressed => 3,
                SsfDeliveryStatus::Delivered
                | SsfDeliveryStatus::Terminal
                | SsfDeliveryStatus::DeadLettered => 4,
            };
            counts[category] += 1;
        }
        Ok(counts)
    }

    pub(super) async fn revoke_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        timestamp(now)?;
        let mut changed = 0;
        for mut stream in Self::streams(tx, tenant_id).await? {
            if stream.status == SsfStreamStatus::Revoked {
                continue;
            }
            stream.revision = stream
                .revision
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("stream revision exhausted".into()))?;
            stream.status = SsfStreamStatus::Revoked;
            stream.updated_at = now;
            write_stream(tx, &stream).await?;
            changed += 1;
        }
        let rows = sqlx::query(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries WHERE tenant = $1 \
             AND status IN ('pending', 'retry_wait') ORDER BY stream_id, stream_revision, event_id FOR UPDATE"
        )).bind(tenant_id.as_bytes()).fetch_all(&mut **tx).await.map_err(db_error)?;
        for row in rows {
            let mut delivery = decode_delivery(row, &self.keys)?;
            delivery.status = SsfDeliveryStatus::Suppressed;
            delivery.updated_at = now;
            delivery.lease_id = None;
            delivery.lease_expires_at = None;
            write_delivery(tx, &self.keys, &delivery).await?;
            changed += 1;
        }
        Ok(changed)
    }

    async fn transaction(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.store.pool.begin().await.map_err(db_error)?;
        PostgresUsersStore::lock_directory(&mut tx, tenant).await?;
        Ok(tx)
    }

    async fn stream(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        stream: &str,
    ) -> Result<Option<SsfStream>, StoreError> {
        sqlx::query(&format!(
            "SELECT {STREAM_COLUMNS} FROM a_auth.ssf_streams \
             WHERE tenant = $1 AND stream_id = $2 FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .bind(stream.as_bytes())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .map(decode_stream)
        .transpose()
    }

    async fn streams(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<Vec<SsfStream>, StoreError> {
        sqlx::query(&format!(
            "SELECT {STREAM_COLUMNS} FROM a_auth.ssf_streams \
             WHERE tenant = $1 ORDER BY stream_id FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(decode_stream)
        .collect()
    }

    async fn delivery(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        stream: &str,
        revision: u64,
        event: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        sqlx::query(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries \
             WHERE tenant = $1 AND stream_id = $2 AND stream_revision = $3::TEXT::NUMERIC \
             AND event_id = $4 FOR UPDATE"
        ))
        .bind(tenant.as_bytes())
        .bind(stream.as_bytes())
        .bind(revision.to_string())
        .bind(event.as_bytes())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .map(|row| decode_delivery(row, &self.keys))
        .transpose()
    }
}

fn timestamp(now: i64) -> Result<(), StoreError> {
    if now <= 0 {
        return Err(StoreError::Permanent(
            "SSF timestamp must be positive".into(),
        ));
    }
    Ok(())
}

fn fresh_delivery(
    stream: &SsfStream,
    event_id: &str,
    issuer: &str,
    projection: SsfEventProjection,
    occurred_at: i64,
    now: i64,
) -> SsfDelivery {
    SsfDelivery {
        tenant_id: stream.tenant_id.clone(),
        stream_id: stream.stream_id.clone(),
        stream_revision: stream.revision,
        event_id: event_id.into(),
        issuer: issuer.into(),
        endpoint: stream.endpoint.clone(),
        audience: stream.audience.clone(),
        event_uri: projection.event_uri.into(),
        subject: projection.subject,
        payload: projection.payload,
        status: SsfDeliveryStatus::Pending,
        attempts: 0,
        cycle_attempts: 0,
        redrive_count: 0,
        attempt_history: vec![],
        event_occurred_at: occurred_at,
        created_at: now,
        updated_at: now,
        cycle_started_at: now,
        next_attempt_at: now,
        expires_at: now.saturating_add(SSF_DELIVERY_RETENTION_SECS),
        compact_set: None,
        jti: None,
        signing_kid: None,
        issued_at: None,
        lease_id: None,
        lease_expires_at: None,
    }
}

fn current(stream: Option<&SsfStream>, revision: u64) -> bool {
    stream.is_some_and(|stream| {
        stream.status == SsfStreamStatus::Enabled && stream.revision == revision
    })
}

impl SsfStore for PostgresSsfStore {
    async fn create_stream(&self, stream: SsfStream) -> Result<SsfStreamCreateOutcome, StoreError> {
        let mut tx = self.transaction(&stream.tenant_id).await?;
        let streams = Self::streams(&mut tx, &stream.tenant_id).await?;
        let result = if streams
            .iter()
            .any(|existing| existing.stream_id == stream.stream_id)
        {
            SsfStreamCreateOutcome::AlreadyExists
        } else if streams.len() >= SSF_MAX_REGISTERED_STREAMS_PER_TENANT {
            SsfStreamCreateOutcome::QuotaExceeded {
                limit: SSF_MAX_REGISTERED_STREAMS_PER_TENANT,
            }
        } else {
            write_stream(&mut tx, &stream).await?;
            SsfStreamCreateOutcome::Created(stream)
        };
        tx.commit().await.map_err(db_error)?;
        Ok(result)
    }

    async fn get_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<SsfStream>, StoreError> {
        sqlx::query(&format!(
            "SELECT {STREAM_COLUMNS} FROM a_auth.ssf_streams WHERE tenant = $1 AND stream_id = $2"
        ))
        .bind(tenant_id.as_bytes())
        .bind(stream_id.as_bytes())
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db_error)?
        .map(decode_stream)
        .transpose()
    }

    async fn list_streams(&self, tenant_id: &str) -> Result<Vec<SsfStream>, StoreError> {
        sqlx::query(&format!(
            "SELECT {STREAM_COLUMNS} FROM a_auth.ssf_streams WHERE tenant = $1 ORDER BY stream_id"
        ))
        .bind(tenant_id.as_bytes())
        .fetch_all(&self.store.pool)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(decode_stream)
        .collect()
    }

    async fn mutate_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        mutation: SsfStreamMutation,
        now: i64,
    ) -> Result<SsfStreamMutationOutcome, StoreError> {
        timestamp(now)?;
        let mut tx = self.transaction(tenant_id).await?;
        let outcome = match Self::stream(&mut tx, tenant_id, stream_id).await? {
            None => SsfStreamMutationOutcome::NotFound,
            Some(stream) => {
                let outcome = apply_stream_mutation(&stream, expected_revision, &mutation, now)?;
                if let SsfStreamMutationOutcome::Updated(updated) = &outcome {
                    if updated != &stream {
                        write_stream(&mut tx, updated).await?;
                    }
                }
                outcome
            }
        };
        tx.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn enqueue_event(
        &self,
        event: &SecurityEvent,
        issuer: &str,
        now: i64,
    ) -> Result<Vec<SsfDelivery>, StoreError> {
        timestamp(now)?;
        let Some(projection) = project_security_event(event, issuer) else {
            return Ok(vec![]);
        };
        let mut tx = self.transaction(&event.tenant_id).await?;
        let mut created = vec![];
        for stream in Self::streams(&mut tx, &event.tenant_id).await? {
            if stream.status != SsfStreamStatus::Enabled
                || event.occurred_at < stream.activation_at
                || !stream
                    .delivered_events
                    .iter()
                    .any(|uri| uri == projection.event_uri)
            {
                continue;
            }
            if self
                .delivery(
                    &mut tx,
                    &event.tenant_id,
                    &stream.stream_id,
                    stream.revision,
                    &event.event_id,
                )
                .await?
                .is_some()
            {
                continue;
            }
            let delivery = fresh_delivery(
                &stream,
                &event.event_id,
                issuer,
                SsfEventProjection {
                    event_uri: projection.event_uri,
                    subject: projection.subject.clone(),
                    payload: projection.payload.clone(),
                },
                event.occurred_at,
                now,
            );
            write_delivery(&mut tx, &self.keys, &delivery).await?;
            created.push(delivery);
        }
        tx.commit().await.map_err(db_error)?;
        Ok(created)
    }

    async fn enqueue_verification(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        event_id: &str,
        issuer: &str,
        state: Option<&str>,
        now: i64,
    ) -> Result<SsfVerificationOutcome, StoreError> {
        validate_verification_request(event_id, state, now)
            .map_err(|error| StoreError::Permanent(error.into()))?;
        let mut tx = self.transaction(tenant_id).await?;
        let result = match Self::stream(&mut tx, tenant_id, stream_id).await? {
            None => SsfVerificationOutcome::NotFound,
            Some(stream) if stream.revision != expected_revision => {
                SsfVerificationOutcome::RevisionConflict {
                    current_revision: stream.revision,
                }
            }
            Some(stream) if stream.status != SsfStreamStatus::Enabled => {
                SsfVerificationOutcome::NotEnabled
            }
            Some(stream) => {
                if self
                    .delivery(&mut tx, tenant_id, stream_id, stream.revision, event_id)
                    .await?
                    .is_some()
                {
                    return Err(StoreError::Permanent(
                        "verification event id already exists".into(),
                    ));
                }
                let mut payload = serde_json::Map::new();
                if let Some(state) = state {
                    payload.insert("state".into(), state.into());
                }
                let delivery = fresh_delivery(
                    &stream,
                    event_id,
                    issuer,
                    SsfEventProjection {
                        event_uri: SSF_VERIFICATION_EVENT,
                        subject: serde_json::json!({"format": "opaque", "id": stream_id}),
                        payload: serde_json::Value::Object(payload),
                    },
                    now,
                    now,
                );
                write_delivery(&mut tx, &self.keys, &delivery).await?;
                SsfVerificationOutcome::Enqueued(delivery)
            }
        };
        tx.commit().await.map_err(db_error)?;
        Ok(result)
    }

    async fn get_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        sqlx::query(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries \
             WHERE tenant = $1 AND stream_id = $2 AND stream_revision = $3::TEXT::NUMERIC AND event_id = $4"
        ))
        .bind(tenant_id.as_bytes()).bind(stream_id.as_bytes()).bind(stream_revision.to_string())
        .bind(event_id.as_bytes()).fetch_optional(&self.store.pool).await.map_err(db_error)?
        .map(|row| decode_delivery(row, &self.keys)).transpose()
    }

    async fn list_deliveries(
        &self,
        tenant_id: &str,
        stream_id: &str,
        limit: usize,
        cursor: Option<&SsfDeliveryCursor>,
    ) -> Result<SsfDeliveryPage, StoreError> {
        if !(1..=SSF_MAX_DELIVERY_PAGE_SIZE).contains(&limit)
            || cursor.is_some_and(|cursor| {
                cursor.tenant_id != tenant_id || cursor.stream_id != stream_id
            })
        {
            return Err(StoreError::Permanent(
                "invalid SSF delivery page request".into(),
            ));
        }
        let rows = sqlx::query(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries WHERE tenant = $1 AND stream_id = $2 \
             AND ($3 OR (created_at, stream_revision, event_id) < ($4, $5::TEXT::NUMERIC, $6)) \
             ORDER BY created_at DESC, stream_revision DESC, event_id DESC LIMIT $7"
        ))
        .bind(tenant_id.as_bytes()).bind(stream_id.as_bytes()).bind(cursor.is_none())
        .bind(cursor.map_or(0, |value| value.created_at))
        .bind(cursor.map_or(0, |value| value.stream_revision).to_string())
        .bind(cursor.map_or(&[][..], |value| value.event_id.as_bytes()))
        .bind((limit + 1) as i64).fetch_all(&self.store.pool).await.map_err(db_error)?;
        let mut deliveries = rows
            .into_iter()
            .map(|row| decode_delivery(row, &self.keys))
            .collect::<Result<Vec<_>, _>>()?;
        let more = deliveries.len() > limit;
        deliveries.truncate(limit);
        let next_cursor = if more {
            deliveries
                .last()
                .map(|row| SsfDeliveryCursor::new(row).encode())
        } else {
            None
        };
        Ok(SsfDeliveryPage {
            deliveries,
            next_cursor,
        })
    }

    async fn acquire_due(
        &self,
        now: i64,
        lease_duration_secs: i64,
        limit: usize,
    ) -> Result<Vec<SsfDeliveryLease>, StoreError> {
        if now <= 0 || !(1..=300).contains(&lease_duration_secs) || !(1..=100).contains(&limit) {
            return Err(StoreError::Permanent(
                "invalid delivery lease request".into(),
            ));
        }
        let mut tx = self.store.pool.begin().await.map_err(db_error)?;
        // Lock tenant fences in byte order before any delivery row. This avoids
        // reversal with stream revocation and bounds claims to fenced tenants.
        let tenants: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT DISTINCT tenant FROM a_auth.ssf_deliveries \
             WHERE status IN ('pending', 'retry_wait') AND next_attempt_at <= $1 \
             AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY tenant",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        for tenant in &tenants {
            let tenant = std::str::from_utf8(tenant).map_err(|_| invalid())?;
            PostgresUsersStore::lock_directory(&mut tx, tenant).await?;
        }
        let mut leases = vec![];
        let mut after: Option<DueCursor> = None;
        loop {
            let rows = sqlx::query(&format!(
                "SELECT {DELIVERY_COLUMNS} FROM a_auth.ssf_deliveries \
                 WHERE tenant = ANY($2::BYTEA[]) AND status IN ('pending', 'retry_wait') \
                 AND next_attempt_at <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1) \
                 AND ($3 OR (next_attempt_at, created_at, tenant, stream_id, stream_revision, event_id) \
                  > ($4, $5, $6, $7, $8::TEXT::NUMERIC, $9)) \
                 ORDER BY next_attempt_at, created_at, tenant, stream_id, stream_revision, event_id \
                 LIMIT $10 FOR UPDATE SKIP LOCKED"
            ))
            .bind(now).bind(&tenants).bind(after.is_none())
            .bind(after.as_ref().map_or(0, |value| value.0))
            .bind(after.as_ref().map_or(0, |value| value.1))
            .bind(after.as_ref().map_or(&[][..], |value| value.2.as_slice()))
            .bind(after.as_ref().map_or(&[][..], |value| value.3.as_slice()))
            .bind(after.as_ref().map_or(0, |value| value.4).to_string())
            .bind(after.as_ref().map_or(&[][..], |value| value.5.as_slice()))
            .bind((limit - leases.len()) as i64)
            .fetch_all(&mut *tx).await.map_err(db_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let mut delivery = decode_delivery(row, &self.keys)?;
                after = Some((
                    delivery.next_attempt_at,
                    delivery.created_at,
                    delivery.tenant_id.as_bytes().to_vec(),
                    delivery.stream_id.as_bytes().to_vec(),
                    delivery.stream_revision,
                    delivery.event_id.as_bytes().to_vec(),
                ));
                let stream =
                    Self::stream(&mut tx, &delivery.tenant_id, &delivery.stream_id).await?;
                if !current(stream.as_ref(), delivery.stream_revision) {
                    delivery.status = SsfDeliveryStatus::Suppressed;
                } else if delivery.expires_at <= now
                    || delivery_retry_window_expired(&delivery, now)
                    || now.saturating_sub(delivery.cycle_started_at) >= SSF_MAX_RETRY_AGE_SECS
                    || delivery.cycle_attempts >= SSF_MAX_ATTEMPTS_PER_CYCLE
                    || delivery.attempts >= SSF_MAX_TOTAL_ATTEMPTS
                {
                    delivery.status = SsfDeliveryStatus::DeadLettered;
                } else {
                    let lease_id = format!("lease_{}", crate::security_event::new_event_id());
                    let lease_expires_at = now.saturating_add(lease_duration_secs);
                    delivery.lease_id = Some(lease_id.clone());
                    delivery.lease_expires_at = Some(lease_expires_at);
                    write_delivery(&mut tx, &self.keys, &delivery).await?;
                    leases.push(SsfDeliveryLease {
                        delivery,
                        lease_id,
                        lease_expires_at,
                    });
                    continue;
                }
                delivery.updated_at = now;
                delivery.lease_id = None;
                delivery.lease_expires_at = None;
                write_delivery(&mut tx, &self.keys, &delivery).await?;
            }
            if leases.len() == limit {
                break;
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok(leases)
    }

    async fn persist_signed_set(
        &self,
        lease: &SsfDeliveryLease,
        signed: &SignedSet,
        issued_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let identity = &lease.delivery;
        let mut tx = self.transaction(&identity.tenant_id).await?;
        let stream = Self::stream(&mut tx, &identity.tenant_id, &identity.stream_id).await?;
        let mut changed = false;
        if current(stream.as_ref(), identity.stream_revision) {
            if let Some(mut record) = self
                .delivery(
                    &mut tx,
                    &identity.tenant_id,
                    &identity.stream_id,
                    identity.stream_revision,
                    &identity.event_id,
                )
                .await?
            {
                if lease_is_current(&record, lease, now) && record.compact_set.is_none() {
                    record.compact_set = Some(signed.compact_jws.clone());
                    record.jti = Some(signed.jti.clone());
                    record.signing_kid = Some(signed.kid.clone());
                    record.issued_at = Some(issued_at);
                    record.updated_at = now;
                    write_delivery(&mut tx, &self.keys, &record).await?;
                    changed = true;
                }
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok(changed)
    }

    async fn finish_attempt(
        &self,
        lease: &SsfDeliveryLease,
        result: SsfAttemptResult,
        now: i64,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        let identity = &lease.delivery;
        let mut tx = self.transaction(&identity.tenant_id).await?;
        let mut outcome = None;
        if let Some(mut record) = self
            .delivery(
                &mut tx,
                &identity.tenant_id,
                &identity.stream_id,
                identity.stream_revision,
                &identity.event_id,
            )
            .await?
        {
            if lease_is_current(&record, lease, now) {
                apply_attempt_result(&mut record, result, now);
                write_delivery(&mut tx, &self.keys, &record).await?;
                outcome = Some(record);
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn redrive_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
        now: i64,
    ) -> Result<SsfRedriveOutcome, StoreError> {
        let mut tx = self.transaction(tenant_id).await?;
        let stream = Self::stream(&mut tx, tenant_id, stream_id).await?;
        let outcome = if !current(stream.as_ref(), stream_revision) {
            SsfRedriveOutcome::StreamNotCurrent
        } else {
            match self
                .delivery(&mut tx, tenant_id, stream_id, stream_revision, event_id)
                .await?
            {
                None => SsfRedriveOutcome::NotFound,
                Some(record) if !delivery_is_redriveable(&record, now) => {
                    SsfRedriveOutcome::Expired
                }
                Some(record)
                    if !matches!(
                        record.status,
                        SsfDeliveryStatus::Terminal | SsfDeliveryStatus::DeadLettered
                    ) =>
                {
                    SsfRedriveOutcome::NotTerminal
                }
                Some(mut record) => {
                    record.status = SsfDeliveryStatus::Pending;
                    record.cycle_attempts = 0;
                    record.redrive_count = record.redrive_count.saturating_add(1);
                    record.cycle_started_at = now;
                    record.next_attempt_at = now;
                    record.updated_at = now;
                    record.lease_id = None;
                    record.lease_expires_at = None;
                    write_delivery(&mut tx, &self.keys, &record).await?;
                    SsfRedriveOutcome::Redriven(record)
                }
            }
        };
        tx.commit().await.map_err(db_error)?;
        Ok(outcome)
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &str, now: i64) -> Result<usize, StoreError> {
        let mut tx = self.transaction(tenant_id).await?;
        let changed = self.revoke_in_transaction(&mut tx, tenant_id, now).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(changed)
    }
}
