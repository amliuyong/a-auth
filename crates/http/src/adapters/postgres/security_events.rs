use super::{db_error, PostgresStore};
use crate::{
    ports::StoreError,
    security_event::{
        reconcile_source_delivery, SecurityEvent, SecurityEventCursor, SecurityEventDelivery,
        SecurityEventPage, SecurityEventStore, StoredSecurityEvent,
        SECURITY_EVENT_HOT_RETENTION_DAYS, SECURITY_EVENT_SCHEMA_VERSION,
    },
};
use sqlx::{postgres::PgRow, types::Json, Row};

fn invalid_event() -> StoreError {
    StoreError::Permanent("Invalid security event authority record".into())
}

fn validate(event: &SecurityEvent) -> Result<(), StoreError> {
    let canonical = SecurityEvent::new_at(
        &event.event_id,
        event.occurred_at,
        &event.tenant_id,
        event.actor.clone(),
        Some(event.subject.clone()),
        event.category,
        &event.action,
        event.outcome,
        event.correlation.clone(),
    )
    .map_err(|_| invalid_event())?;
    if event.schema_version != SECURITY_EVENT_SCHEMA_VERSION || *event != canonical {
        return Err(invalid_event());
    }
    Ok(())
}

fn decode(row: PgRow) -> Result<StoredSecurityEvent, StoreError> {
    let Json(event): Json<SecurityEvent> = row.try_get("event").map_err(db_error)?;
    validate(&event)?;
    let id: String = row.try_get("event_id").map_err(db_error)?;
    let tenant: String = row.try_get("tenant").map_err(db_error)?;
    let at: i64 = row.try_get("occurred_at").map_err(db_error)?;
    if id != event.event_id || tenant != event.tenant_id || at != event.occurred_at {
        return Err(invalid_event());
    }
    let Json(delivery) = row.try_get("delivery").map_err(db_error)?;
    Ok(StoredSecurityEvent { event, delivery })
}

impl PostgresStore {
    async fn security_event_page(
        &self,
        tenant: &str,
        from: i64,
        through: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> Result<SecurityEventPage, StoreError> {
        let tenant = if tenant.is_empty() { "default" } else { tenant };
        if cursor.is_some_and(|cursor| cursor.tenant_id() != tenant) {
            return Err(StoreError::Permanent(
                "Security event cursor tenant mismatch".into(),
            ));
        }
        let limit = limit.clamp(1, 1000);
        let mut position =
            cursor.map(|cursor| (cursor.occurred_at(), cursor.event_id().to_owned()));
        let mut events = Vec::with_capacity(limit + 1);
        while events.len() <= limit {
            let rows = sqlx::query(
                "SELECT event_id, tenant, occurred_at, event, delivery \
                 FROM a_auth.security_events WHERE tenant = $1 \
                 AND occurred_at BETWEEN $2 AND $3 \
                 AND ($4::BIGINT IS NULL OR (occurred_at, event_id COLLATE \"C\") \
                     < ($4, $5::TEXT COLLATE \"C\")) \
                 ORDER BY occurred_at DESC, event_id COLLATE \"C\" DESC LIMIT $6",
            )
            .bind(tenant)
            .bind(from)
            .bind(through)
            .bind(position.as_ref().map(|(at, _)| *at))
            .bind(position.as_ref().map(|(_, id)| id.as_str()))
            .bind((limit + 1) as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?;
            let exhausted = rows.len() < limit + 1;
            for row in rows {
                // Advance past invalid rows internally; only validated events
                // can produce the public continuation cursor.
                position = Some((
                    row.try_get("occurred_at").map_err(db_error)?,
                    row.try_get("event_id").map_err(db_error)?,
                ));
                match decode(row) {
                    Ok(event) => events.push(event),
                    Err(error) => eprintln!(
                        "SECURITY_EVENT_INVALID source=tenant_export backend=postgres error={error:?}"
                    ),
                }
                if events.len() > limit {
                    break;
                }
            }
            if exhausted {
                break;
            }
        }
        let more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if more {
            events
                .last()
                .map(|stored| SecurityEventCursor::new(&stored.event).encode())
                .transpose()?
        } else {
            None
        };
        Ok(SecurityEventPage {
            events,
            next_cursor,
        })
    }
}

impl SecurityEventStore for PostgresStore {
    async fn put(&self, event: &SecurityEvent) -> Result<bool, StoreError> {
        self.put_with_delivery(event, &SecurityEventDelivery::pending(event.occurred_at))
            .await
    }

    async fn put_with_delivery(
        &self,
        event: &SecurityEvent,
        delivery: &SecurityEventDelivery,
    ) -> Result<bool, StoreError> {
        validate(event)?;
        let expires_at = event
            .occurred_at
            .checked_add(i64::from(SECURITY_EVENT_HOT_RETENTION_DAYS) * 86_400)
            .ok_or_else(invalid_event)?;
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO a_auth.security_events \
             (event_id, tenant, occurred_at, expires_at, event, delivery, source_delivery) \
             VALUES ($1, $2, $3, $4, $5, $6, $6) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(&event.event_id)
        .bind(&event.tenant_id)
        .bind(event.occurred_at)
        .bind(expires_at)
        .bind(Json(event))
        .bind(Json(delivery))
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 1 {
            transaction.commit().await.map_err(db_error)?;
            return Ok(true);
        }
        let row = sqlx::query(
            "SELECT event_id, tenant, occurred_at, event, delivery, source_delivery \
             FROM a_auth.security_events WHERE event_id = $1 FOR UPDATE",
        )
        .bind(&event.event_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db_error)?
        .ok_or_else(|| StoreError::Transient("Security event admission changed".into()))?;
        let Json(source): Json<SecurityEventDelivery> =
            row.try_get("source_delivery").map_err(db_error)?;
        let stored = decode(row)?;
        if stored.event != *event {
            return Err(StoreError::Permanent(
                "security event id collision has a different envelope".into(),
            ));
        }
        if let Some(next) = reconcile_source_delivery(
            &stored.delivery,
            &source,
            delivery,
            crate::current_unix_secs(),
        )? {
            sqlx::query(
                "UPDATE a_auth.security_events SET delivery = $2, source_delivery = $3 \
                 WHERE event_id = $1",
            )
            .bind(&event.event_id)
            .bind(Json(next))
            .bind(Json(delivery))
            .execute(&mut *transaction)
            .await
            .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(false)
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
    ) -> Result<Vec<StoredSecurityEvent>, StoreError> {
        Ok(self
            .security_event_page(tenant_id, from_inclusive, through_inclusive, limit, None)
            .await?
            .events)
    }

    async fn list_by_tenant_page(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> Result<SecurityEventPage, StoreError> {
        self.security_event_page(tenant_id, from_inclusive, through_inclusive, limit, cursor)
            .await
    }
}
