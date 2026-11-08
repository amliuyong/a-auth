use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        memory::MemoryCibaStore, mounted_crypto::EncryptionKeyring, postgres::PostgresCibaStore,
    },
    ports::{CibaAuthRequest, CibaStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn record(tenant: &str, id: &str, user: &str) -> CibaAuthRequest {
    CibaAuthRequest {
        auth_req_id: id.into(),
        tenant: tenant.into(),
        client_id: "client".into(),
        user_id: user.into(),
        authz_session_id: Some("session".into()),
        scope: vec!["openid".into(), "profile".into()],
        resources: vec!["resource-a".into()],
        binding_message: Some("approve fixture operation".into()),
        interval: 5,
        last_poll_at: None,
        expires_at: 1_000,
        status: "pending".into(),
        consumed: false,
        delivery_mode: Some("push".into()),
        notification_endpoint: Some("https://client.example.test/callback".into()),
        client_notification_token: Some("private-callback-token-fixture-32-bytes".into()),
        password_credential_version: None,
    }
}

async fn ciba_contract(store: impl CibaStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get(&tenant, "missing").await.unwrap(), None);
    let original = record(&tenant, "request", "user");
    store.put(&tenant, original.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "request").await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(store.get(&foreign, "request").await.unwrap(), None);
    let mut foreign_record = record(&foreign, "request", "foreign-user");
    foreign_record.delivery_mode = None;
    foreign_record.notification_endpoint = None;
    foreign_record.client_notification_token = None;
    store.put(&foreign, foreign_record.clone()).await.unwrap();

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .claim_poll(&tenant, "request", None, 100)
                .await
                .unwrap()
        }));
    }
    let mut claimed = 0;
    for task in tasks {
        claimed += usize::from(task.await.unwrap());
    }
    assert_eq!(claimed, 1);
    assert!(!store
        .claim_poll(&tenant, "request", None, 101)
        .await
        .unwrap());
    assert!(store
        .claim_poll(&tenant, "request", Some(100), 105)
        .await
        .unwrap());

    let barrier = Arc::new(Barrier::new(32));
    let mut decisions = Vec::new();
    let mut consumers = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        decisions.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .decide(&tenant, "request", Some(u64::MAX), true)
                .await
                .unwrap()
        }));
    }
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        consumers.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(&tenant, "request").await.unwrap()
        }));
    }
    let mut decided = 0;
    let mut consumed = 0;
    for task in decisions {
        decided += usize::from(task.await.unwrap());
    }
    for task in consumers {
        consumed += usize::from(task.await.unwrap());
    }
    assert_eq!((decided, consumed), (1, 1));
    let mut expected = original;
    expected.status = "approved".into();
    expected.password_credential_version = Some(u64::MAX);
    expected.consumed = true;
    expected.last_poll_at = Some(105);
    assert_eq!(
        store.get(&tenant, "request").await.unwrap(),
        Some(expected.clone())
    );
    assert!(!store.decide(&tenant, "request", None, false).await.unwrap());
    store.release_consume(&tenant, "request").await.unwrap();
    expected.consumed = false;
    assert_eq!(store.get(&tenant, "request").await.unwrap(), Some(expected));
    assert!(store.consume(&tenant, "request").await.unwrap());
    assert!(!store.consume(&tenant, "request").await.unwrap());
    assert!(!store.consume(&tenant, "missing").await.unwrap());
    assert!(!store.decide(&tenant, "missing", None, false).await.unwrap());
    assert!(!store
        .claim_poll(&tenant, "missing", None, 100)
        .await
        .unwrap());
    store.release_consume(&tenant, "missing").await.unwrap();

    let mut updated = record(&tenant, "maintenance", "other-user");
    store.put(&tenant, updated.clone()).await.unwrap();
    updated.binding_message = None;
    updated.resources.clear();
    updated.authz_session_id = None;
    updated.delivery_mode = None;
    updated.notification_endpoint = None;
    updated.client_notification_token = None;
    store.update(&tenant, updated.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "maintenance").await.unwrap(),
        Some(updated)
    );

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .try_arm_throttle(&tenant, "user", 100, 60)
                .await
                .unwrap()
        }));
    }
    let mut armed = 0;
    for task in tasks {
        armed += usize::from(task.await.unwrap());
    }
    assert_eq!(armed, 1);
    assert!(!store
        .try_arm_throttle(&tenant, "user", 150, 60)
        .await
        .unwrap());
    assert!(!store
        .try_arm_throttle(&tenant, "user", 159, 60)
        .await
        .unwrap());
    assert!(store
        .try_arm_throttle(&tenant, "user", 160, 60)
        .await
        .unwrap());
    assert!(store
        .try_arm_throttle(&foreign, "user", 100, 60)
        .await
        .unwrap());

    for id in 0..16 {
        store
            .put(
                &tenant,
                record(&tenant, &format!("erase-{id}"), "erase-user"),
            )
            .await
            .unwrap();
    }
    assert!(store
        .try_arm_throttle(&tenant, "erase-user", 100, 60)
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.delete_by_user(&tenant, "erase-user").await.unwrap()
        }));
    }
    let mut removed = 0;
    for task in tasks {
        removed += task.await.unwrap();
    }
    assert_eq!(
        removed, 16,
        "user cleanup counts requests and also removes throttle authority"
    );
    assert!(store
        .try_arm_throttle(&tenant, "erase-user", 101, 60)
        .await
        .unwrap());
    assert_eq!(
        store.get(&foreign, "request").await.unwrap(),
        Some(foreign_record.clone())
    );
    assert!(store.get(&tenant, "request").await.unwrap().is_some());

    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 4);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.get(&tenant, "request").await.unwrap(), None);
    assert_eq!(store.get(&tenant, "maintenance").await.unwrap(), None);
    assert!(store
        .try_arm_throttle(&tenant, "user", 161, 60)
        .await
        .unwrap());
    assert_eq!(
        store.get(&foreign, "request").await.unwrap(),
        Some(foreign_record)
    );
    let single = record("", "single-request", "shared-owner");
    let named = record(&foreign, "named-request", "shared-owner");
    store.put("", single).await.unwrap();
    store.put(&foreign, named.clone()).await.unwrap();
    assert_eq!(store.delete_by_user("", "shared-owner").await.unwrap(), 1);
    assert_eq!(store.get("", "single-request").await.unwrap(), None);
    assert_eq!(
        store.get(&foreign, "named-request").await.unwrap(),
        Some(named)
    );
    let boundary = format!("{tenant}-arithmetic");
    assert!(store
        .try_arm_throttle(&boundary, "high", i64::MAX - 1, i64::MAX)
        .await
        .unwrap());
    assert!(!store
        .try_arm_throttle(&boundary, "high", i64::MAX, i64::MAX)
        .await
        .unwrap());
    assert!(store
        .try_arm_throttle(&boundary, "low", i64::MIN, i64::MAX)
        .await
        .unwrap());
    assert!(!store
        .try_arm_throttle(&boundary, "low", i64::MIN + 1, i64::MAX)
        .await
        .unwrap());
    assert!(store
        .try_arm_throttle(&boundary, "low", -1, i64::MAX)
        .await
        .unwrap());
    assert_eq!(store.delete_all_by_tenant(&boundary).await.unwrap(), 2);
}

#[tokio::test]
async fn memory_ciba_contract() {
    ciba_contract(MemoryCibaStore::default()).await;
}

#[tokio::test]
async fn postgres_ciba_contract() {
    let keys = EncryptionKeyring::new(
        "fixture-ciba-v1",
        vec![("fixture-ciba-v1".into(), [31; 32])],
    )
    .unwrap();
    ciba_contract(agent_auth_http::state::CibaStoreImpl::Postgres(
        PostgresCibaStore::new(database().await, keys),
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_ciba_contract() {
    use agent_auth_http::adapters::aws::DynamoCibaStore;
    use base64::Engine;
    let (db, table) = super::aws_contract_database::table("auth_req_id", vec![], vec![]).await;
    // The real AWS adapter uses a loopback KMS response fixture. This provides
    // adapter/envelope contracts, never native KMS acceptance.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let kms_router = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "KeyId": "fixture-key",
                "Plaintext": base64::engine::general_purpose::STANDARD.encode([23; 32]),
                "CiphertextBlob": base64::engine::general_purpose::STANDARD.encode([29; 48]),
            }))
        }),
    );
    let fixture = tokio::spawn(async move {
        axum::serve(listener, kms_router).await.unwrap();
    });
    let kms = aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_kms::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
            .endpoint_url(format!("http://{address}"))
            .build(),
    );
    ciba_contract(DynamoCibaStore::new(db.clone(), kms, &table, "fixture-key")).await;
    fixture.abort();
    db.delete_table().table_name(table).send().await.unwrap();
}
