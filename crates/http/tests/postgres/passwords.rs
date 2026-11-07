use super::{database, tenant};
use agent_auth_authn::password::{dummy_hash, hash_password};
use agent_auth_http::{
    adapters::memory::MemoryPasswordStore,
    ports::{PasswordCredential, PasswordStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

fn credential(user_id: &str) -> PasswordCredential {
    PasswordCredential {
        user_id: user_id.into(),
        password_hash: dummy_hash().clone(),
        must_change: true,
        revocation_pending: false,
        credential_change_id: Some("provisioning\0owner".into()),
        version: 7,
        updated_at: 100,
    }
}

fn assert_credential(actual: &PasswordCredential, expected: &PasswordCredential) {
    assert_eq!(actual.user_id, expected.user_id);
    assert!(
        actual.password_hash == expected.password_hash,
        "persisted password hash changed unexpectedly"
    );
    assert_eq!(actual.must_change, expected.must_change);
    assert_eq!(actual.revocation_pending, expected.revocation_pending);
    assert_eq!(actual.credential_change_id, expected.credential_change_id);
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.updated_at, expected.updated_at);
}

async fn exhausted_versions_preserve_credentials(store: &impl PasswordStore) {
    let tenant = tenant();
    let replacement = hash_password("replacement for exhausted version").unwrap();
    for reset in [true, false] {
        let user_id = if reset { "reset-user" } else { "change-user" };
        let original = PasswordCredential {
            version: u64::MAX,
            ..credential(user_id)
        };
        assert!(store
            .create_if_absent(&tenant, original.clone())
            .await
            .unwrap());
        let result = if reset {
            store
                .reset_temporary(&tenant, user_id, replacement.clone(), Some(u64::MAX), 600)
                .await
                .map(|next| next.is_some())
        } else {
            store
                .replace_if_version_and_temporary(
                    &tenant,
                    user_id,
                    replacement.clone(),
                    u64::MAX,
                    600,
                )
                .await
        };
        assert!(
            matches!(
                result,
                Err(agent_auth_http::ports::StoreError::Permanent(_))
            ),
            "exhausted password version must reject mutation: {result:?}"
        );
        assert_credential(
            &store.get(&tenant, user_id).await.unwrap().unwrap(),
            &original,
        );
    }
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
}

async fn password_contract(store: impl PasswordStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let user_id = "canonical-user";
    let initial = credential(user_id);
    let replacement = hash_password("replacement password for contract").unwrap();
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
            store.create_if_absent(&tenant, initial).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(
        winners, 1,
        "one provisioning attempt creates the credential"
    );
    assert_credential(
        &store.get(&tenant, user_id).await.unwrap().unwrap(),
        &initial,
    );
    assert!(store.get(&other, user_id).await.unwrap().is_none());
    let mut overwrite = initial.clone();
    overwrite.password_hash = replacement.clone();
    overwrite.version = 900;
    overwrite.must_change = false;
    assert!(!store.create_if_absent(&tenant, overwrite).await.unwrap());
    assert_credential(
        &store.get(&tenant, user_id).await.unwrap().unwrap(),
        &initial,
    );
    assert!(!store.delete_if_version(&tenant, user_id, 6).await.unwrap());

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier, replacement) = (
            store.clone(),
            tenant.clone(),
            barrier.clone(),
            replacement.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .replace_if_version_and_temporary(&tenant, user_id, replacement, 7, 200)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1, "one first-login change owns the next version");
    let active = PasswordCredential {
        password_hash: replacement.clone(),
        must_change: false,
        credential_change_id: None,
        version: 8,
        updated_at: 200,
        ..initial.clone()
    };
    assert_credential(
        &store.get(&tenant, user_id).await.unwrap().unwrap(),
        &active,
    );
    assert!(!store
        .replace_if_version_and_temporary(&tenant, user_id, dummy_hash().clone(), 8, 201)
        .await
        .unwrap());
    assert_eq!(
        store
            .reset_temporary(&tenant, user_id, dummy_hash().clone(), Some(7), 250)
            .await
            .unwrap(),
        None
    );
    assert_credential(
        &store.get(&tenant, user_id).await.unwrap().unwrap(),
        &active,
    );

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .reset_temporary(&tenant, user_id, dummy_hash().clone(), Some(8), 300)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            Some(9) => winners += 1,
            None => {}
            unexpected => panic!("unexpected reset version: {unexpected:?}"),
        }
    }
    assert_eq!(winners, 1, "one reset owns its pending revocation version");
    let pending = PasswordCredential {
        password_hash: dummy_hash().clone(),
        must_change: true,
        revocation_pending: true,
        credential_change_id: None,
        version: 9,
        updated_at: 300,
        ..initial.clone()
    };
    assert_credential(
        &store.get(&tenant, user_id).await.unwrap().unwrap(),
        &pending,
    );
    assert!(!store
        .replace_if_version_and_temporary(&tenant, user_id, replacement.clone(), 9, 301)
        .await
        .unwrap());
    assert!(!store
        .complete_reset_revocation(&tenant, user_id, 8)
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .complete_reset_revocation(&tenant, user_id, 9)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1, "only the pending reset can complete revocation");
    let ready = PasswordCredential {
        revocation_pending: false,
        ..pending
    };
    assert_credential(&store.get(&tenant, user_id).await.unwrap().unwrap(), &ready);
    assert!(store
        .replace_if_version_and_temporary(&tenant, user_id, replacement, 9, 400)
        .await
        .unwrap());
    assert!(!store.delete_if_version(&tenant, user_id, 9).await.unwrap());
    assert!(store.delete_if_version(&tenant, user_id, 10).await.unwrap());
    assert!(!store.delete_if_version(&tenant, user_id, 10).await.unwrap());

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .reset_temporary(&tenant, user_id, dummy_hash().clone(), None, 500)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            Some(1) => winners += 1,
            None => {}
            unexpected => panic!("unexpected initial reset version: {unexpected:?}"),
        }
    }
    assert_eq!(winners, 1, "a missing credential has one initial reset");
    assert!(store.create_if_absent(&other, initial).await.unwrap());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert!(store.get(&tenant, user_id).await.unwrap().is_none());
    assert!(store.get(&other, user_id).await.unwrap().is_some());
    store.delete(&other, user_id).await.unwrap();
    store.delete(&other, user_id).await.unwrap();
    assert!(store.get(&other, user_id).await.unwrap().is_none());
    exhausted_versions_preserve_credentials(&store).await;
}

#[tokio::test]
async fn memory_password_contract() {
    password_contract(MemoryPasswordStore::default()).await;
}

#[tokio::test]
async fn postgres_password_contract() {
    password_contract(agent_auth_http::state::PasswordStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_password_contract() {
    let (db, table) =
        super::aws_contract_database::table_with_range("user_id", None, vec![], vec![]).await;
    password_contract(agent_auth_http::adapters::aws::DynamoPasswordStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
