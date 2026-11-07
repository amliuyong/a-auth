use super::{database, login_session_contracts::record, tenant};
use agent_auth_http::ports::{SessionStore, StoreError};

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str, id: &str) -> String {
    sqlx::query_scalar(
        "SELECT record FROM a_auth.login_sessions WHERE tenant = $1 AND session_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn replace_payload(pool: &sqlx::PgPool, tenant: &str, id: &str, value: &str) {
    sqlx::query(
        "UPDATE a_auth.login_sessions SET record = $3 WHERE tenant = $1 AND session_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .bind(value)
    .execute(pool)
    .await
    .unwrap();
}

async fn generation(pool: &sqlx::PgPool, tenant: &str, user: &str) -> String {
    sqlx::query_scalar(
        "SELECT generation::TEXT FROM a_auth.login_session_generations \
         WHERE tenant = $1 AND user_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn postgres_login_session_admission_and_retained_fence_failure_roll_back() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let constraint = format!("contract_login_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.login_sessions ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.create(&tenant, record("actor", "user", 0)).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.login_sessions DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(store.get(&tenant, "actor").await.unwrap(), None);
    for table in ["user_directories", "login_session_generations"] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM a_auth.{table} WHERE tenant = $1"
        ))
        .bind(tenant.as_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }
    let actor = record("actor", "user", 0);
    let other = record("other", "user", 0);
    store.create(&tenant, actor.clone()).await.unwrap();
    store.create(&tenant, other.clone()).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE a_auth.login_sessions ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8') OR session_generation = 0) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.delete_others_by_user(&tenant, "user", "actor").await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.login_sessions DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(generation(&pool, &tenant, "user").await, "0");
    assert_eq!(store.get(&tenant, "actor").await.unwrap(), Some(actor));
    assert_eq!(store.get(&tenant, "other").await.unwrap(), Some(other));
    assert_eq!(
        store
            .delete_others_by_user(&tenant, "user", "actor")
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(store.get(&tenant, "other").await.unwrap(), None);
    pool.close().await;
}

#[tokio::test]
async fn postgres_login_session_actor_delete_failure_rolls_back_generation() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let actor = record("actor", "user", 0);
    let other = record("other", "user", 0);
    store.create(&tenant, actor.clone()).await.unwrap();
    store.create(&tenant, other.clone()).await.unwrap();
    let trigger = format!("contract_session_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF OLD.tenant = convert_to('{tenant}', 'UTF8') \
         AND OLD.session_id = convert_to('actor', 'UTF8') THEN \
         RAISE EXCEPTION 'contract rejection' USING ERRCODE = '23514'; \
         END IF; RETURN OLD; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON a_auth.login_sessions \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.revoke_all_by_actor(&tenant, "user", "actor").await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.login_sessions"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(generation(&pool, &tenant, "user").await, "0");
    assert_eq!(store.get(&tenant, "actor").await.unwrap(), Some(actor));
    assert_eq!(store.get(&tenant, "other").await.unwrap(), Some(other));
    assert!(store
        .revoke_all_by_actor(&tenant, "user", "actor")
        .await
        .unwrap());
    assert_eq!(store.get(&tenant, "other").await.unwrap(), None);
    pool.close().await;
}

#[tokio::test]
async fn postgres_login_sessions_reject_truncated_or_inconsistent_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    store
        .create(&tenant, record("actor", "user", 0))
        .await
        .unwrap();
    let baseline = payload(&pool, &tenant, "actor").await;
    let value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".to_owned(), "private-session-sentinel".to_owned()];
    for field in ["record", "generation"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&changed).unwrap());
    }
    for field in [
        "session_id",
        "user_id",
        "credential_epoch",
        "auth_time",
        "created_at",
        "last_used_at",
        "device",
        "expires_at",
        "acr",
        "amr",
    ] {
        let mut changed = value.clone();
        changed["record"].as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&changed).unwrap());
    }
    for mutation in 0..6 {
        let mut changed = value.clone();
        match mutation {
            0 => changed["generation"] = 1.into(),
            1 => changed["record"]["session_id"] = "private-other-session".into(),
            2 => changed["record"]["user_id"] = "private-other-user".into(),
            3 => changed["record"]["credential_epoch"] = 1.into(),
            4 => changed["record"]["expires_at"] = 201.into(),
            5 => changed["record"]["last_used_at"] = 101.into(),
            _ => unreachable!(),
        }
        corruptions.push(serde_json::to_string(&changed).unwrap());
    }
    for corrupt in corruptions {
        replace_payload(&pool, &tenant, "actor", &corrupt).await;
        let attempts = [
            store.get(&tenant, "actor").await.map(|_| ()),
            store.list_by_user(&tenant, "user", 100).await.map(|_| ()),
            store.count_by_user(&tenant, "user", 100).await.map(|_| ()),
            store
                .touch_last_used(&tenant, "actor", 150)
                .await
                .map(|_| ()),
            store
                .delete_owned(&tenant, "user", "actor", "actor")
                .await
                .map(|_| ()),
            store
                .delete_others_by_user(&tenant, "user", "actor")
                .await
                .map(|_| ()),
            store
                .revoke_all_by_actor(&tenant, "user", "actor")
                .await
                .map(|_| ()),
        ];
        let retained = payload(&pool, &tenant, "actor").await;
        replace_payload(&pool, &tenant, "actor", &baseline).await;
        for attempt in attempts {
            let Err(StoreError::Permanent(message)) = attempt else {
                panic!("corrupt session authority must fail closed: {attempt:?}");
            };
            assert!(!message.contains("private-"));
        }
        assert_eq!(retained, corrupt);
        assert_eq!(generation(&pool, &tenant, "user").await, "0");
    }
    pool.close().await;
}

#[tokio::test]
async fn postgres_login_session_nul_and_generation_exhaustion_preserve_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = format!("{}\0tenant", tenant());
    let user = "user\0id";
    let id = "session\0id";
    let mut actor = record(id, user, u64::MAX);
    actor.device = "Contract\0browser".into();
    actor.acr = None;
    actor.amr = vec!["amr\0value".into()];
    store.create(&tenant, actor.clone()).await.unwrap();
    assert_eq!(store.get(&tenant, id).await.unwrap(), Some(actor.clone()));
    assert_eq!(
        store
            .delete_by_user_before_epoch(&tenant, user, u64::MAX)
            .await
            .unwrap(),
        0
    );
    sqlx::query(
        "UPDATE a_auth.login_session_generations SET generation = $3::TEXT::NUMERIC \
         WHERE tenant = $1 AND user_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .bind(u64::MAX.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let baseline = payload(&pool, &tenant, id).await;
    let mut value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    value["generation"] = u64::MAX.into();
    let maximum = serde_json::to_string(&value).unwrap();
    sqlx::query(
        "UPDATE a_auth.login_sessions SET session_generation = $3::TEXT::NUMERIC, record = $4 \
         WHERE tenant = $1 AND session_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .bind(u64::MAX.to_string())
    .bind(&maximum)
    .execute(&pool)
    .await
    .unwrap();
    for attempt in [
        store
            .delete_others_by_user(&tenant, user, id)
            .await
            .map(|_| ()),
        store
            .revoke_all_by_actor(&tenant, user, id)
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(attempt, Err(StoreError::Permanent(_))));
    }
    assert_eq!(store.get(&tenant, id).await.unwrap(), Some(actor));
    assert_eq!(payload(&pool, &tenant, id).await, maximum);
    assert_eq!(generation(&pool, &tenant, user).await, u64::MAX.to_string());
    pool.close().await;
}
