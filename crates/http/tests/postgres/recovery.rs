use super::{database, tenant};
use agent_auth_authn::recovery::{code_hash, LOCKOUT_SECS, MAX_ATTEMPTS};
use agent_auth_http::{
    adapters::memory::MemoryRecoveryStore,
    ports::{RecoveryCodeEntry, RecoveryConsume, RecoveryRecord, RecoveryStore},
};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Barrier;

fn hash(label: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(code_hash(b"contract-test-only", label))
}

pub(super) fn record(lookup: &str) -> RecoveryRecord {
    RecoveryRecord {
        user_lookup: lookup.into(),
        user_id: "canonical-user".into(),
        activation_id: "single-region".into(),
        code_hashes: vec![
            RecoveryCodeEntry {
                hash_b64: hash("one"),
                consumed: false,
            },
            RecoveryCodeEntry {
                hash_b64: hash("two"),
                consumed: false,
            },
        ],
        attempt_count: 0,
        locked_until: 0,
    }
}

async fn recovery_contract(store: impl RecoveryStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    assert_eq!(
        store
            .get_success_result(&tenant, "missing-operation")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "missing", "wrong", 100)
            .await
            .unwrap(),
        RecoveryConsume::NotFound,
    );
    let initial = record("lookup");
    store.put(&tenant, initial.clone()).await.unwrap();
    store.put(&foreign, initial.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(store.get(&foreign, "missing").await.unwrap(), None);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..32 {
                match store
                    .verify_and_consume(&tenant, "lookup", &hash("one"), 100)
                    .await
                {
                    Ok(outcome) => return outcome,
                    Err(agent_auth_http::ports::StoreError::Transient(_)) => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("unexpected recovery admission error: {error:?}"),
                }
            }
            panic!("recovery admission contention did not converge");
        }));
    }
    let mut valid = 0;
    for task in tasks {
        match task.await.unwrap() {
            RecoveryConsume::Valid => valid += 1,
            RecoveryConsume::Invalid | RecoveryConsume::Locked { .. } => {}
            other => panic!("unexpected recovery admission: {other:?}"),
        }
    }
    assert_eq!(valid, 1);
    let consumed = store.get(&tenant, "lookup").await.unwrap().unwrap();
    assert!(consumed.code_hashes[0].consumed);
    assert!(!consumed.code_hashes[1].consumed);
    assert_eq!(
        store.get(&foreign, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("two"), 100)
            .await
            .unwrap(),
        RecoveryConsume::Locked {
            retry_after_secs: LOCKOUT_SECS
        },
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("two"), 100 + LOCKOUT_SECS)
            .await
            .unwrap(),
        RecoveryConsume::Valid,
    );
    let unlocked = store.get(&tenant, "lookup").await.unwrap().unwrap();
    assert_eq!(unlocked.attempt_count, 0);
    assert_eq!(unlocked.locked_until, 0);
    store.put(&tenant, initial.clone()).await.unwrap();
    for attempt in 1..=MAX_ATTEMPTS {
        let outcome = store
            .verify_and_consume(&tenant, "lookup", "wrong", 200)
            .await
            .unwrap();
        if attempt < MAX_ATTEMPTS {
            assert_eq!(outcome, RecoveryConsume::Invalid);
        } else {
            assert_eq!(
                outcome,
                RecoveryConsume::Locked {
                    retry_after_secs: LOCKOUT_SECS
                }
            );
        }
    }
    let locked = store.get(&tenant, "lookup").await.unwrap();
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("one"), 201)
            .await
            .unwrap(),
        RecoveryConsume::Locked {
            retry_after_secs: LOCKOUT_SECS - 1
        },
    );
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), locked);
    store.put(&tenant, initial).await.unwrap();
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("one"), 200)
            .await
            .unwrap(),
        RecoveryConsume::Valid,
    );
    store.delete_by_lookup(&tenant, "lookup").await.unwrap();
    store.delete_by_lookup(&tenant, "lookup").await.unwrap();
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    store.put(&tenant, record("cleanup")).await.unwrap();
    assert!(store.delete_all_by_tenant(&tenant).await.unwrap() > 0);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert!(store.get(&foreign, "lookup").await.unwrap().is_some());
    assert!(store.delete_all_by_tenant(&foreign).await.unwrap() > 0);
}

#[tokio::test]
async fn memory_recovery_contract() {
    recovery_contract(MemoryRecoveryStore::default()).await;
}

#[tokio::test]
async fn postgres_recovery_contract() {
    recovery_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_recovery_contract() {
    use agent_auth_http::adapters::aws::DynamoRecoveryStore;
    let (db, table) = super::aws_contract_database::table("user_lookup", vec![], vec![]).await;
    recovery_contract(DynamoRecoveryStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
