use super::{database, passkey_contracts::record, tenant};
use agent_auth_http::ports::{PasskeyStore, StoreError};
use serde_json::Value;

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str) -> String {
    sqlx::query_scalar(
        "SELECT record FROM a_auth.passkey_credentials WHERE tenant = $1 AND credential_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"key".as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn replace_payload(pool: &sqlx::PgPool, tenant: &str, value: &str) {
    sqlx::query(
        "UPDATE a_auth.passkey_credentials SET record = $3 \
         WHERE tenant = $1 AND credential_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"key".as_slice())
    .bind(value)
    .execute(pool)
    .await
    .unwrap();
}

fn assert_private_failure(result: Result<(), StoreError>) {
    let error = result.expect_err("corrupt or rejected authority must fail");
    assert!(matches!(error, StoreError::Permanent(_)), "{error:?}");
    assert!(!format!("{error:?}").contains("private-passkey-sentinel"));
}

#[tokio::test]
async fn postgres_passkey_admission_counter_and_rename_failure_preserve_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let constraint = format!("contract_passkey_{:032x}", rand::random::<u128>());
    let reject = format!(
        "ALTER TABLE a_auth.passkey_credentials ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    );
    let drop = format!("ALTER TABLE a_auth.passkey_credentials DROP CONSTRAINT {constraint}");
    let initial = record("key", "user");
    sqlx::query(&reject).execute(&pool).await.unwrap();
    let failed = store.put_new(&tenant, initial.clone()).await;
    sqlx::query(&drop).execute(&pool).await.unwrap();
    assert_private_failure(failed.map(|_| ()));
    assert_eq!(store.get(&tenant, "key").await.unwrap(), None);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.user_directories WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "failed admission must roll back its directory fence"
    );
    assert!(store.put_new(&tenant, initial.clone()).await.unwrap());
    sqlx::query(&reject).execute(&pool).await.unwrap();
    let counter = store.update_sign_count(&tenant, "key", 7, 0).await;
    let rename = store
        .rename_owned(&tenant, "user", "key", "private-passkey-sentinel")
        .await;
    sqlx::query(&drop).execute(&pool).await.unwrap();
    assert_private_failure(counter.map(|_| ()));
    assert_private_failure(rename.map(|_| ()));
    assert_eq!(
        store.get(&tenant, "key").await.unwrap(),
        Some(initial.clone())
    );
    assert!(store.update_sign_count(&tenant, "key", 7, 0).await.unwrap());
    assert!(store
        .rename_owned(&tenant, "user", "key", "Renamed")
        .await
        .unwrap());
    let mut expected = initial;
    expected.sign_count = 7;
    expected.name = "Renamed".into();
    assert_eq!(store.get(&tenant, "key").await.unwrap(), Some(expected));
    pool.close().await;
}

#[tokio::test]
async fn postgres_passkeys_reject_truncated_or_rebound_authority_without_overwrite() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let initial = record("key", "user");
    assert!(store.put_new(&tenant, initial.clone()).await.unwrap());
    let baseline = payload(&pool, &tenant).await;
    let value: Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".into(), "private-passkey-sentinel".into()];
    for field in [
        "credential_id",
        "user_id",
        "rp_id",
        "public_key_sec1",
        "sign_count",
        "name",
        "created_at",
    ] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(changed.to_string());
    }
    for field in ["credential_id", "user_id", "sign_count", "created_at"] {
        let mut changed = value.clone();
        changed[field] = if changed[field].is_string() {
            "private-passkey-sentinel-other".into()
        } else {
            1.into()
        };
        corruptions.push(changed.to_string());
    }
    let mut unknown = value.clone();
    unknown["unexpected"] = "private-passkey-sentinel".into();
    corruptions.push(unknown.to_string());
    for corrupt in corruptions {
        replace_payload(&pool, &tenant, &corrupt).await;
        for result in [
            store.get(&tenant, "key").await.map(|_| ()),
            store.list_by_user(&tenant, "user").await.map(|_| ()),
            store.put_new(&tenant, initial.clone()).await.map(|_| ()),
            store
                .update_sign_count(&tenant, "key", 1, 0)
                .await
                .map(|_| ()),
            store
                .rename_owned(&tenant, "user", "key", "New")
                .await
                .map(|_| ()),
            store.delete_owned(&tenant, "user", "key").await.map(|_| ()),
        ] {
            assert_private_failure(result);
        }
        assert_eq!(payload(&pool, &tenant).await, corrupt);
    }
    replace_payload(&pool, &tenant, &baseline).await;
    assert_eq!(store.get(&tenant, "key").await.unwrap(), Some(initial));
    let mut nul = record("key\0tail", "user\0tail");
    nul.rp_id.push('\0');
    nul.name.push('\0');
    nul.sign_count = u32::MAX;
    nul.created_at = i64::MAX;
    assert!(store.put_new(&tenant, nul.clone()).await.unwrap());
    assert_eq!(
        store.get(&tenant, &nul.credential_id).await.unwrap(),
        Some(nul)
    );
    pool.close().await;
}
