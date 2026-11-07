use super::{database, recovery_contracts::record, tenant};
use agent_auth_http::ports::{RecoveryStore, StoreError};
use serde_json::{json, Value};

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str) -> String {
    sqlx::query_scalar(
        "SELECT record FROM a_auth.recovery_codes WHERE tenant = $1 AND user_lookup = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"lookup".as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn replace_payload(pool: &sqlx::PgPool, tenant: &str, value: &str) {
    sqlx::query(
        "UPDATE a_auth.recovery_codes SET record = $3 WHERE tenant = $1 AND user_lookup = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"lookup".as_slice())
    .bind(value)
    .execute(pool)
    .await
    .unwrap();
}

fn assert_private_failure(result: Result<(), StoreError>) {
    let error = result.expect_err("corrupt or rejected authority must fail");
    assert!(matches!(error, StoreError::Permanent(_)), "{error:?}");
    assert!(!format!("{error:?}").contains("private-recovery-sentinel"));
}

#[tokio::test]
async fn postgres_recovery_admission_and_consumption_failures_preserve_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let constraint = format!("contract_recovery_{:032x}", rand::random::<u128>());
    let reject = format!(
        "ALTER TABLE a_auth.recovery_codes ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    );
    let drop = format!("ALTER TABLE a_auth.recovery_codes DROP CONSTRAINT {constraint}");
    sqlx::query(&reject).execute(&pool).await.unwrap();
    let failed = store.put(&tenant, record("lookup")).await;
    sqlx::query(&drop).execute(&pool).await.unwrap();
    assert_private_failure(failed);
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.user_directories WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "failed admission must also roll back its directory fence"
    );
    let initial = record("lookup");
    store.put(&tenant, initial.clone()).await.unwrap();
    sqlx::query(&reject).execute(&pool).await.unwrap();
    let failed = store
        .verify_and_consume(&tenant, "lookup", &initial.code_hashes[0].hash_b64, 100)
        .await;
    sqlx::query(&drop).execute(&pool).await.unwrap();
    assert_private_failure(failed.map(|_| ()));
    assert_eq!(
        store.get(&tenant, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &initial.code_hashes[0].hash_b64, 100)
            .await
            .unwrap(),
        agent_auth_http::ports::RecoveryConsume::Valid
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_recovery_rejects_incomplete_or_rebound_code_sets_without_overwriting() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let initial = record("lookup");
    store.put(&tenant, initial.clone()).await.unwrap();
    let baseline = payload(&pool, &tenant).await;
    let value: Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".into(), "private-recovery-sentinel".into()];
    for field in [
        "user_lookup",
        "user_id",
        "activation_id",
        "code_hashes",
        "attempt_count",
        "locked_until",
    ] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(changed.to_string());
    }
    for field in ["hash_b64", "consumed"] {
        let mut changed = value.clone();
        changed["code_hashes"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        corruptions.push(changed.to_string());
    }
    for field in ["user_lookup", "user_id", "activation_id"] {
        let mut changed = value.clone();
        changed[field] = "private-recovery-sentinel".into();
        corruptions.push(changed.to_string());
    }
    let mut unknown = value.clone();
    unknown["unexpected"] = "private-recovery-sentinel".into();
    corruptions.push(unknown.to_string());
    for corrupt in corruptions {
        replace_payload(&pool, &tenant, &corrupt).await;
        assert_private_failure(store.get(&tenant, "lookup").await.map(|_| ()));
        assert_private_failure(store.put(&tenant, initial.clone()).await);
        assert_private_failure(
            store
                .verify_and_consume(&tenant, "lookup", &initial.code_hashes[0].hash_b64, 100)
                .await
                .map(|_| ()),
        );
        assert_eq!(payload(&pool, &tenant).await, corrupt);
    }
    replace_payload(&pool, &tenant, &baseline).await;
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), Some(initial));
    let mut nul = record("lookup\0tail");
    nul.user_id.push('\0');
    nul.activation_id.push('\0');
    nul.attempt_count = u32::MAX;
    store.put(&tenant, nul.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, &nul.user_lookup).await.unwrap(),
        Some(nul)
    );
    pool.close().await;
}

async fn receipt(pool: &sqlx::PgPool, tenant: &str) -> Value {
    let value = json!({
        "operation_key": "private-recovery-sentinel\0operation",
        "user_lookup": "lookup",
        "user_id": "canonical-user",
        "presented_hash": "private-recovery-sentinel-verifier",
        "credential_epoch": u64::MAX,
        "session_id": "private-recovery-sentinel-session",
        "created_at": 100,
        "expires_at": 200
    });
    sqlx::query(
        "INSERT INTO a_auth.recovery_success_results \
         (tenant, operation_key, user_lookup, user_id, credential_epoch, session_id, \
          created_at, expires_at, record) VALUES ($1, $2, $3, $4, $5::NUMERIC, $6, 100, 200, $7)",
    )
    .bind(tenant.as_bytes())
    .bind(value["operation_key"].as_str().unwrap().as_bytes())
    .bind(b"lookup".as_slice())
    .bind(b"canonical-user".as_slice())
    .bind(u64::MAX.to_string())
    .bind(value["session_id"].as_str().unwrap().as_bytes())
    .bind(value.to_string())
    .execute(pool)
    .await
    .unwrap();
    value
}

#[tokio::test]
async fn postgres_recovery_receipts_require_complete_matching_private_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let value = receipt(&pool, &tenant).await;
    let operation = value["operation_key"].as_str().unwrap();
    let result = store
        .get_success_result(&tenant, operation)
        .await
        .unwrap()
        .unwrap();
    let debug = format!("{result:?}");
    assert!(debug.contains("18446744073709551615"));
    assert!(!debug.contains("private-recovery-sentinel"));
    assert_eq!(
        store
            .get_success_result("another-tenant", operation)
            .await
            .unwrap(),
        None
    );
    let mut corruptions = vec!["{}".to_string(), "private-recovery-sentinel".into()];
    for field in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(changed.to_string());
    }
    for field in [
        "operation_key",
        "user_lookup",
        "user_id",
        "session_id",
        "credential_epoch",
        "created_at",
        "expires_at",
    ] {
        let mut changed = value.clone();
        changed[field] = if changed[field].is_string() {
            "private-recovery-sentinel-other".into()
        } else {
            0.into()
        };
        corruptions.push(changed.to_string());
    }
    for corrupt in corruptions {
        sqlx::query(
            "UPDATE a_auth.recovery_success_results SET record = $3 \
             WHERE tenant = $1 AND operation_key = $2",
        )
        .bind(tenant.as_bytes())
        .bind(operation.as_bytes())
        .bind(&corrupt)
        .execute(&pool)
        .await
        .unwrap();
        assert_private_failure(
            store
                .get_success_result(&tenant, operation)
                .await
                .map(|_| ()),
        );
    }
    pool.close().await;
}

#[tokio::test]
async fn postgres_recovery_tenant_cleanup_second_delete_failure_rolls_back_code_sets() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let foreign = super::tenant();
    let initial = record("lookup");
    store.put(&tenant, initial.clone()).await.unwrap();
    store.put(&foreign, initial.clone()).await.unwrap();
    let value = receipt(&pool, &tenant).await;
    let operation = value["operation_key"].as_str().unwrap();
    let trigger = format!("contract_recovery_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF OLD.tenant = convert_to('{tenant}', 'UTF8') THEN \
         RAISE EXCEPTION 'private-recovery-sentinel' USING ERRCODE = '23514'; \
         END IF; RETURN OLD; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON a_auth.recovery_success_results \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.delete_all_by_tenant(&tenant).await;
    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON a_auth.recovery_success_results"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert_private_failure(failed.map(|_| ()));
    assert_eq!(
        store.get(&tenant, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert!(store
        .get_success_result(&tenant, operation)
        .await
        .unwrap()
        .is_some());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    assert_eq!(
        store.get_success_result(&tenant, operation).await.unwrap(),
        None
    );
    assert_eq!(store.get(&foreign, "lookup").await.unwrap(), Some(initial));
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    pool.close().await;
}
