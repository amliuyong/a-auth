use agent_auth_http::{
    adapters::postgres::PostgresStore,
    ports::{ParRecord, ParStore, StoreError},
};
use sqlx::{migrate::Migrate, Connection};
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

/// Cold boot is different from rerunning migrations on a warm contract database.
/// Give competing migrators an actual held advisory lock, then release it after
/// the ordinary business-query lock budget. Runtime writes keep that budget.
#[tokio::test]
async fn postgres_cold_migration_waits_without_relaxing_runtime_or_leaking_locks() {
    let base_url = std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&base_url).await.unwrap();
    let name = format!("contract_bootstrap_{:032x}", rand::random::<u128>());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let mut fresh_url = url::Url::parse(&base_url).unwrap();
    fresh_url.set_path(&format!("/{name}"));
    let fresh_url = fresh_url.as_str();
    let mut stores = Vec::new();
    for _ in 0..12 {
        stores.push(PostgresStore::connect(fresh_url, 2).await.unwrap());
    }
    let mut holder = sqlx::PgConnection::connect(fresh_url).await.unwrap();
    holder.lock().await.unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(6)).await;
        holder.unlock().await.unwrap();
        holder.close().await.unwrap();
    });
    let barrier = Arc::new(Barrier::new(stores.len()));
    let mut tasks = Vec::new();
    for store in &stores {
        let (store, barrier) = (store.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.migrate().await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    release.await.unwrap();
    let mut runtime_result = None;
    let mut bounded_result = None;
    let mut repair_result = None;
    if results.iter().all(Result::is_ok) {
        let store = &stores[0];
        let record = ParRecord {
            request_uri: "request".into(),
            client_id: "client".into(),
            raw_params: "client_id=client".into(),
            expires_at: agent_auth_http::current_unix_secs() + 600,
        };
        ParStore::put(store, "", record.clone()).await.unwrap();
        let mut fixture = sqlx::PgConnection::connect(fresh_url).await.unwrap();
        sqlx::query("BEGIN").execute(&mut fixture).await.unwrap();
        sqlx::query("SELECT request_uri FROM a_auth.par WHERE tenant = '' FOR UPDATE")
            .execute(&mut fixture)
            .await
            .unwrap();
        runtime_result = Some(
            tokio::time::timeout(Duration::from_secs(8), ParStore::put(store, "", record)).await,
        );
        sqlx::query("ROLLBACK").execute(&mut fixture).await.unwrap();

        // A migration session must still consume its configured pool permit.
        // Observe the actual advisory wait before asking a one-connection pool
        // for another authority write; no scheduler delay stands in for proof.
        let application_name = format!("bounded_{name}");
        let mut bounded_url = url::Url::parse(fresh_url).unwrap();
        bounded_url
            .query_pairs_mut()
            .append_pair("application_name", &application_name);
        let bounded = PostgresStore::connect(bounded_url.as_str(), 1)
            .await
            .unwrap();
        fixture.lock().await.unwrap();
        let migrator = bounded.clone();
        let migrating = tokio::spawn(async move { migrator.migrate().await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let observed = loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity AS activity \
                 JOIN pg_locks AS locks ON locks.pid = activity.pid \
                 WHERE activity.application_name = $1 \
                 AND locks.locktype = 'advisory' AND NOT locks.granted)",
            )
            .bind(&application_name)
            .fetch_one(&mut fixture)
            .await
            .unwrap();
            if waiting || tokio::time::Instant::now() >= deadline {
                break waiting;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let write = tokio::time::timeout(
            Duration::from_secs(8),
            ParStore::put(
                &bounded,
                "",
                ParRecord {
                    request_uri: "bounded-request".into(),
                    client_id: "client".into(),
                    raw_params: "client_id=client".into(),
                    expires_at: agent_auth_http::current_unix_secs() + 600,
                },
            ),
        )
        .await;
        fixture.unlock().await.unwrap();
        let migration = migrating.await.unwrap();
        bounded_result = Some((observed, write, migration));
        drop(bounded);

        // A checksum failure must close its migration session. Otherwise the
        // SQLx migrator's early error leaves its session-level advisory lock in
        // the shared pool and poisons a subsequent repaired migration.
        let checksum: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 1")
                .fetch_one(&mut fixture)
                .await
                .unwrap();
        sqlx::query("UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = 1")
            .execute(&mut fixture)
            .await
            .unwrap();
        let mismatch = store.migrate().await;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
            .bind(checksum)
            .execute(&mut fixture)
            .await
            .unwrap();
        let repaired = tokio::time::timeout(Duration::from_secs(3), stores[1].migrate()).await;
        repair_result = Some((mismatch, repaired));
        fixture.close().await.unwrap();
    }
    drop(stores);
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    assert!(
        results.iter().all(Result::is_ok),
        "all cold migrators must converge after release of the database lock: {results:?}"
    );
    assert!(
        matches!(runtime_result, Some(Ok(Err(StoreError::Transient(_))))),
        "ordinary authority writes must retain their shorter lock timeout"
    );
    assert!(
        matches!(
            bounded_result,
            Some((true, Ok(Err(StoreError::Transient(_))), Ok(())))
        ),
        "migration must retain its pool permit until the connection closes"
    );
    let (mismatch, repaired) = repair_result.unwrap();
    assert!(matches!(mismatch, Err(StoreError::Permanent(_))));
    assert!(matches!(repaired, Ok(Ok(()))));
}
