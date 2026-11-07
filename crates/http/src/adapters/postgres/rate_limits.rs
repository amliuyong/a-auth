use super::{db_error, PostgresStore};
use crate::ports::{RateLimitDecision, RateLimitStore, StoreError};
use agent_auth_infra_core::{retry_after_secs, try_acquire, BucketConfig, BucketState};

fn config(capacity: f64, refill_per_sec: f64, cost: f64) -> Result<BucketConfig, StoreError> {
    if [capacity, refill_per_sec, cost]
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err(StoreError::Permanent(
            "invalid rate-limit configuration".into(),
        ));
    }
    Ok(BucketConfig::new(capacity, refill_per_sec))
}

fn decision(
    config: &BucketConfig,
    state: BucketState,
    now: i64,
    cost: f64,
) -> (BucketState, RateLimitDecision) {
    let result = try_acquire(config, state, now as f64, cost);
    let retry_after_secs = if result.allowed {
        None
    } else {
        retry_after_secs(config, result.state, cost).map(|seconds| seconds.ceil() as i64)
    };
    (
        result.state,
        RateLimitDecision {
            allowed: result.allowed,
            retry_after_secs,
        },
    )
}

impl RateLimitStore for PostgresStore {
    async fn check_available(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<RateLimitDecision, StoreError> {
        let config = config(capacity, refill_per_sec, cost)?;
        let stored: Option<(f64, f64)> = sqlx::query_as(
            "SELECT tokens, last_refill FROM a_auth.rate_limits WHERE bucket_key = $1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let state = stored.map_or_else(
            || BucketState::full(&config, now as f64),
            |(tokens, last_refill)| BucketState {
                tokens,
                last_refill,
            },
        );
        Ok(decision(&config, state, now, cost).1)
    }

    async fn try_consume(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<RateLimitDecision, StoreError> {
        let config = config(capacity, refill_per_sec, cost)?;
        let mut transaction = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO a_auth.rate_limits (bucket_key, tokens, last_refill) VALUES ($1, $2, $3) \
             ON CONFLICT (bucket_key) DO NOTHING",
        )
        .bind(key)
        .bind(capacity)
        .bind(now as f64)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        let (tokens, last_refill): (f64, f64) = sqlx::query_as(
            "SELECT tokens, last_refill FROM a_auth.rate_limits WHERE bucket_key = $1 FOR UPDATE",
        )
        .bind(key)
        .fetch_one(&mut *transaction)
        .await
        .map_err(db_error)?;
        let (next, decision) = decision(
            &config,
            BucketState {
                tokens,
                last_refill,
            },
            now,
            cost,
        );
        sqlx::query(
            "UPDATE a_auth.rate_limits SET tokens = $2, last_refill = $3 WHERE bucket_key = $1",
        )
        .bind(key)
        .bind(next.tokens)
        .bind(next.last_refill)
        .execute(&mut *transaction)
        .await
        .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(decision)
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM a_auth.rate_limits WHERE bucket_key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
