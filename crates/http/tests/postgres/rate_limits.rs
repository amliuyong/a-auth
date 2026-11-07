use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryRateLimitStore,
    ports::{RateLimitDecision, RateLimitStore, StoreError},
};
use std::sync::Arc;
use tokio::sync::Barrier;

async fn rate_limit_contract(store: impl RateLimitStore + Clone + 'static) {
    let key = tenant();
    let allowed = RateLimitDecision {
        allowed: true,
        retry_after_secs: None,
    };
    let denied = RateLimitDecision {
        allowed: false,
        retry_after_secs: Some(1),
    };
    // Availability checks do not debit the bucket.
    for _ in 0..3 {
        assert_eq!(
            store
                .check_available(&key, 100, 1.0, 1.0, 1.0)
                .await
                .unwrap(),
            allowed
        );
    }
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, key, barrier) = (store.clone(), key.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..5 {
                match store.try_consume(&key, 100, 1.0, 1.0, 1.0).await {
                    Ok(decision) => return decision.allowed,
                    Err(StoreError::Transient(_)) => continue,
                    Err(error) => panic!("rate-limit contract failed: {error:?}"),
                }
            }
            panic!("rate-limit contention did not converge after bounded retries");
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1, "a bucket cannot over-admit under contention");
    assert_eq!(
        store
            .check_available(&key, 100, 1.0, 1.0, 1.0)
            .await
            .unwrap(),
        denied
    );
    assert_eq!(
        store.try_consume(&key, 100, 1.0, 1.0, 1.0).await.unwrap(),
        denied
    );
    assert_eq!(
        store.try_consume(&key, 101, 1.0, 1.0, 1.0).await.unwrap(),
        allowed
    );
    assert!(
        !store
            .try_consume(&key, 100, 1.0, 1.0, 1.0)
            .await
            .unwrap()
            .allowed,
        "clock rewind must not refill consumed tokens"
    );
    assert_eq!(
        store
            .try_consume("other", 100, 1.0, 1.0, 1.0)
            .await
            .unwrap(),
        allowed
    );
    store.delete(&key).await.unwrap();
    assert_eq!(
        store.try_consume(&key, 100, 1.0, 1.0, 1.0).await.unwrap(),
        allowed
    );
    store.delete(&key).await.unwrap();
    store.delete("other").await.unwrap();
}

#[tokio::test]
async fn memory_rate_limit_contract() {
    rate_limit_contract(MemoryRateLimitStore::default()).await;
}

#[tokio::test]
async fn postgres_rate_limit_contract() {
    rate_limit_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_rate_limit_contract() {
    let (db, table) = super::aws_contract_database::table("key", vec![], vec![]).await;
    rate_limit_contract(agent_auth_http::adapters::aws::DynamoRateLimitStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
