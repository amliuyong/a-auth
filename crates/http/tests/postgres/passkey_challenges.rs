use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryPasskeyChallengeStore,
    ports::{PasskeyCeremony, PasskeyChallenge, PasskeyChallengeStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn challenge(tenant: &str, key: &str, user: Option<&str>) -> PasskeyChallenge {
    PasskeyChallenge {
        challenge_b64url: key.into(),
        tenant: tenant.into(),
        user_id: user.map(str::to_owned),
        ceremony: if user.is_some() {
            PasskeyCeremony::Registration
        } else {
            PasskeyCeremony::Authentication
        },
        rp_id: "auth.example.test".into(),
        origin: "https://auth.example.test".into(),
        expires_at: agent_auth_http::current_unix_secs() + 300,
    }
}

async fn challenge_contract(store: impl PasskeyChallengeStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let key = format!("challenge-{tenant}");
    let original = challenge(&tenant, &key, Some("user"));
    store.put(original.clone()).await.unwrap();
    assert_eq!(store.consume(&other, &key).await.unwrap(), None);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, tenant, key) =
            (store.clone(), barrier.clone(), tenant.clone(), key.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(&tenant, &key).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(
        winners,
        vec![original],
        "one ceremony receives its complete RP binding"
    );
    assert_eq!(store.consume(&tenant, &key).await.unwrap(), None);
    let mut expired = challenge(&tenant, &format!("{key}-expired"), None);
    expired.expires_at = agent_auth_http::current_unix_secs() - 1;
    store.put(expired.clone()).await.unwrap();
    assert_eq!(
        store
            .consume(&tenant, &expired.challenge_b64url)
            .await
            .unwrap(),
        None
    );
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);

    let registration = challenge(&tenant, &format!("{key}-register"), Some("user"));
    let authentication = challenge(&tenant, &format!("{key}-authn"), None);
    let foreign = challenge(&other, &format!("{key}-foreign"), Some("user"));
    store.put(registration.clone()).await.unwrap();
    store.put(authentication.clone()).await.unwrap();
    store.put(foreign.clone()).await.unwrap();
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 1);
    assert_eq!(
        store
            .consume(&tenant, &registration.challenge_b64url)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .consume(&other, &foreign.challenge_b64url)
            .await
            .unwrap(),
        Some(foreign)
    );
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(
        store
            .consume(&tenant, &authentication.challenge_b64url)
            .await
            .unwrap(),
        None
    );
    let single = challenge("", &format!("{key}-single"), None);
    store.put(single.clone()).await.unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, barrier, key) = (
            store.clone(),
            barrier.clone(),
            single.challenge_b64url.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume("", &key).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            winners.push(record);
        }
    }
    assert_eq!(
        winners,
        vec![single],
        "self-hosted challenges remain one-time"
    );
}

#[tokio::test]
async fn memory_passkey_challenge_contract() {
    challenge_contract(MemoryPasskeyChallengeStore::default()).await;
}

#[tokio::test]
async fn postgres_passkey_challenge_contract() {
    challenge_contract(agent_auth_http::state::PasskeyChallengeStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_passkey_challenge_contract() {
    let (db, table) = super::aws_contract_database::table("challenge", vec![], vec![]).await;
    challenge_contract(
        agent_auth_http::adapters::aws::DynamoPasskeyChallengeStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
