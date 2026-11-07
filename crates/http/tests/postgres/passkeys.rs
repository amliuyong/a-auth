use super::{database, tenant};
use agent_auth_authn::passkey::PasskeyCredential;
use agent_auth_http::{adapters::memory::MemoryPasskeyStore, ports::PasskeyStore};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn record(id: &str, user: &str) -> PasskeyCredential {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
    PasskeyCredential {
        credential_id: id.into(),
        user_id: user.into(),
        rp_id: "auth.example.test".into(),
        public_key_sec1: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        sign_count: 0,
        name: "Security key".into(),
        created_at: 100,
    }
}

async fn passkey_contract(store: impl PasskeyStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get(&tenant, "key").await.unwrap(), None);
    assert!(store
        .list_by_user(&tenant, "user")
        .await
        .unwrap()
        .is_empty());
    assert!(!store.update_sign_count(&tenant, "key", 1, 0).await.unwrap());
    assert!(!store
        .rename_owned(&tenant, "user", "key", "New")
        .await
        .unwrap());
    assert!(!store.delete_owned(&tenant, "user", "key").await.unwrap());
    let initial = record("key", "user");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier, initial) = (
            store.clone(),
            tenant.clone(),
            barrier.clone(),
            initial.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.put_new(&tenant, initial).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert!(store.put_new(&foreign, initial.clone()).await.unwrap());
    assert!(!store
        .put_new(&tenant, record("key", "attacker"))
        .await
        .unwrap());
    assert_eq!(
        store.get(&tenant, "key").await.unwrap(),
        Some(initial.clone())
    );
    assert!(!store
        .rename_owned(&tenant, "attacker", "key", "Wrong")
        .await
        .unwrap());
    assert!(!store
        .delete_owned(&tenant, "attacker", "key")
        .await
        .unwrap());
    assert!(store
        .rename_owned(&tenant, "user", "key", "Renamed")
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.update_sign_count(&tenant, "key", 7, 0).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert!(!store.update_sign_count(&tenant, "key", 8, 0).await.unwrap());
    assert!(!store.update_sign_count(&tenant, "key", 6, 7).await.unwrap());
    assert!(!store.update_sign_count(&tenant, "key", 7, 7).await.unwrap());
    let current = store.get(&tenant, "key").await.unwrap().unwrap();
    assert_eq!(current.sign_count, 7);
    assert_eq!(current.name, "Renamed");
    assert_eq!(
        store.get(&foreign, "key").await.unwrap(),
        Some(initial.clone())
    );
    let barrier = Arc::new(Barrier::new(32));
    let mut counters = Vec::new();
    let mut renames = Vec::new();
    for _ in 0..16 {
        let (counter_store, counter_tenant, counter_barrier) =
            (store.clone(), tenant.clone(), barrier.clone());
        counters.push(tokio::spawn(async move {
            counter_barrier.wait().await;
            for _ in 0..32 {
                if counter_store
                    .update_sign_count(&counter_tenant, "key", 8, 7)
                    .await
                    .unwrap()
                {
                    return true;
                }
                if counter_store
                    .get(&counter_tenant, "key")
                    .await
                    .unwrap()
                    .unwrap()
                    .sign_count
                    != 7
                {
                    return false;
                }
                tokio::task::yield_now().await;
            }
            panic!("counter contention did not converge");
        }));
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        renames.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..32 {
                if store
                    .rename_owned(&tenant, "user", "key", "Race renamed")
                    .await
                    .unwrap()
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("rename contention did not converge");
        }));
    }
    let mut winners = 0;
    for task in counters {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    for task in renames {
        task.await.unwrap();
    }
    assert_eq!(winners, 1);
    let current = store.get(&tenant, "key").await.unwrap().unwrap();
    let mut expected = initial;
    expected.sign_count = 8;
    expected.name = "Race renamed".into();
    assert_eq!(
        current, expected,
        "rename and counter CAS must preserve credential material"
    );
    assert!(store
        .put_new(&tenant, record("zero", "user"))
        .await
        .unwrap());
    assert!(store
        .update_sign_count(&tenant, "zero", 0, 0)
        .await
        .unwrap());
    let mut max = record("max", "user");
    max.sign_count = u32::MAX;
    assert!(store.put_new(&tenant, max.clone()).await.unwrap());
    assert!(!store
        .update_sign_count(&tenant, "max", 0, u32::MAX)
        .await
        .unwrap());
    assert_eq!(store.get(&tenant, "max").await.unwrap(), Some(max));
    let list = store.list_by_user(&tenant, "user").await.unwrap();
    assert_eq!(list.len(), 3);
    assert!(list.iter().all(|entry| entry.user_id == "user"));
    assert!(store
        .put_new(&tenant, record("other", "other-user"))
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.delete_owned(&tenant, "user", "key").await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 2);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 0);
    assert!(store.get(&tenant, "other").await.unwrap().is_some());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.list_by_user(&foreign, "user").await.unwrap().len(), 1);
    assert_eq!(store.delete_all_by_tenant(&foreign).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_passkey_contract() {
    passkey_contract(MemoryPasskeyStore::default()).await;
}

#[tokio::test]
async fn postgres_passkey_contract() {
    passkey_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_passkey_contract() {
    use agent_auth_http::adapters::aws::DynamoPasskeyStore;
    let (db, table) = super::aws_contract_database::table_with_string_index(
        "credential_id",
        "user_id-index",
        "user_id",
    )
    .await;
    passkey_contract(DynamoPasskeyStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
