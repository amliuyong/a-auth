use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryDeviceStore,
    ports::{DeviceAuthGrant, DeviceStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn grant(key: &str, user_code: &str, now: i64) -> DeviceAuthGrant {
    DeviceAuthGrant {
        device_code: key.into(),
        user_code: user_code.into(),
        client_id: "client".into(),
        user_id: None,
        authz_session_id: Some("authorization-session".into()),
        scope: vec!["openid".into(), "offline_access".into()],
        resources: vec!["https://resource.example.test".into()],
        interval: 5,
        last_poll_at: None,
        expires_at: now + 600,
        status: "pending".into(),
        consumed: false,
        password_credential_version: None,
    }
}

async fn device_contract(store: impl DeviceStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let now = agent_auth_http::current_unix_secs();
    let original = grant("device", "BCDFGHJK", now);
    store.put(&tenant, original.clone()).await.unwrap();
    assert_eq!(store.get(&other, "device").await.unwrap(), None);
    assert_eq!(
        store.get_by_user_code(&other, "BCDFGHJK").await.unwrap(),
        None
    );
    assert_eq!(
        store.get_by_user_code(&tenant, "BCDFGHJK").await.unwrap(),
        Some(original.clone())
    );
    let foreign = grant("device", "BCDFGHJK", now);
    store.put(&other, foreign.clone()).await.unwrap();

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .claim_poll(&tenant, "device", None, now)
                .await
                .unwrap()
        }));
    }
    let mut poll_winners = 0;
    for task in tasks {
        poll_winners += usize::from(task.await.unwrap());
    }
    assert_eq!(
        poll_winners, 1,
        "one caller can claim an observed poll slot"
    );

    let barrier = Arc::new(Barrier::new(32));
    let mut consumes = Vec::new();
    let mut decisions = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        consumes.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(&tenant, "device", now + 1).await.unwrap()
        }));
    }
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        decisions.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .decide(&tenant, "device", "user", Some(u64::MAX), true, now + 1)
                .await
                .unwrap()
        }));
    }
    let mut consume_winners = 0;
    let mut decision_winners = 0;
    for task in consumes {
        consume_winners += usize::from(task.await.unwrap());
    }
    for task in decisions {
        decision_winners += usize::from(task.await.unwrap());
    }
    assert_eq!(consume_winners, 1);
    assert_eq!(decision_winners, 1);
    let mut expected = original;
    expected.last_poll_at = Some(now);
    expected.consumed = true;
    expected.status = "approved".into();
    expected.user_id = Some("user".into());
    expected.password_credential_version = Some(u64::MAX);
    assert_eq!(
        store.get(&tenant, "device").await.unwrap(),
        Some(expected.clone()),
        "independent field CAS operations must preserve each other's authority"
    );
    assert!(!store
        .decide(&tenant, "device", "attacker", None, false, now + 2)
        .await
        .unwrap());
    assert!(!store
        .claim_poll(&tenant, "device", None, now + 2)
        .await
        .unwrap());
    assert!(store
        .claim_poll(&tenant, "device", Some(now), now + 2)
        .await
        .unwrap());
    store
        .release_consume(&tenant, "device", now + 2)
        .await
        .unwrap();
    expected.consumed = false;
    expected.last_poll_at = Some(now + 2);
    assert_eq!(store.get(&tenant, "device").await.unwrap(), Some(expected));
    assert!(store.consume(&tenant, "device", now + 3).await.unwrap());
    store
        .release_consume(&tenant, "device", now + 600)
        .await
        .unwrap();
    assert!(
        store
            .get(&tenant, "device")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
    assert!(!store.consume(&tenant, "device", now + 600).await.unwrap());
    assert!(!store
        .claim_poll(&tenant, "device", Some(now + 2), now + 600)
        .await
        .unwrap());
    assert!(!store
        .decide(&tenant, "missing", "user", None, true, now)
        .await
        .unwrap());
    store
        .put(&tenant, grant("expired", "LMNPQRST", now - 600))
        .await
        .unwrap();
    assert!(!store.consume(&tenant, "expired", now).await.unwrap());
    assert!(!store
        .decide(&tenant, "expired", "user", None, true, now)
        .await
        .unwrap());
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 1);
    assert_eq!(store.get(&tenant, "device").await.unwrap(), None);
    assert_eq!(store.get(&other, "device").await.unwrap(), Some(foreign));
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
}

#[tokio::test]
async fn memory_device_contract() {
    device_contract(MemoryDeviceStore::default()).await;
}

#[tokio::test]
async fn postgres_device_contract() {
    device_contract(agent_auth_http::state::DeviceStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_device_contract() {
    let (db, table) = super::aws_contract_database::table_with_string_index(
        "device_code",
        "user_code-index",
        "user_code",
    )
    .await;
    device_contract(agent_auth_http::adapters::aws::DynamoDeviceStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
