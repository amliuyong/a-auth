use super::{code_record, database, tenant};
use agent_auth_http::adapters::postgres::ExchangeFailureRequest;
use agent_auth_http::ports::{
    AuthzSessionRecord, AuthzSessionStore, ClientRecord, ClientStore, CodeStore, LeaseAcquire,
};

#[tokio::test]
async fn postgres_exchange_failure_consumes_code_and_transitions_session_atomically() {
    let tenant = tenant();
    let store = database().await;
    let now = agent_auth_http::current_unix_secs();
    ClientStore::put(
        &store,
        &tenant,
        ClientRecord {
            client_id: "client".into(),
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let session = AuthzSessionRecord {
        session_id: "session".into(),
        client_id: "client".into(),
        user_id: Some("user".into()),
        state: "code_issued_awaiting_exchange".into(),
        session_token_hash: "opaque-hash".into(),
        sequence: 3,
        last_error: None,
        expires_at: now + 600,
    };
    AuthzSessionStore::create(&store, &tenant, session.clone())
        .await
        .unwrap();
    let mut code = code_record();
    code.expires_at = now + 600;
    code.authz_session_id = Some("session".into());
    CodeStore::put(&store, &tenant, code.clone()).await.unwrap();
    let failure = || ExchangeFailureRequest {
        tenant: &tenant,
        code: "code",
        client_id: "client",
        expires_at: code.expires_at,
        now,
        lease_owner: "owner",
        authz_session_id: Some("session"),
        last_error: "failed".into(),
    };
    assert!(matches!(
        CodeStore::acquire_lease(&store, &tenant, "code", "owner", now, now + 60)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    // Identity and session-binding failures cannot consume either authority.
    for (client, expiry, owner, bound_session) in [
        ("other", code.expires_at, "owner", Some("session")),
        ("client", code.expires_at - 1, "owner", Some("session")),
        ("client", code.expires_at, "old-owner", Some("session")),
        ("client", code.expires_at, "owner", Some("other-session")),
        ("client", code.expires_at, "owner", None),
    ] {
        let mut request = failure();
        request.client_id = client;
        request.expires_at = expiry;
        request.lease_owner = owner;
        request.authz_session_id = bound_session;
        assert!(store.finalize_exchange_failure(request).await.is_err());
    }
    assert_eq!(
        AuthzSessionStore::get(&store, &tenant, "session")
            .await
            .unwrap(),
        Some(session.clone())
    );
    assert_eq!(
        CodeStore::acquire_lease(&store, &tenant, "code", "other-owner", now, now + 60)
            .await
            .unwrap(),
        LeaseAcquire::Locked
    );

    // Fail the second table write after the code UPDATE. The transaction must
    // roll back code consumption as well as the session update.
    let fixture_pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let fixture_id = format!("exchange_failure_{:032x}", rand::random::<u128>());
    let function_sql = format!(
        "CREATE FUNCTION a_auth.{fixture_id}() RETURNS TRIGGER LANGUAGE plpgsql AS \
         $$ BEGIN IF NEW.tenant = '{}' THEN RAISE EXCEPTION 'contract failure'; \
         END IF; RETURN NEW; END $$",
        tenant
    );
    sqlx::query(&function_sql)
        .execute(&fixture_pool)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {fixture_id} BEFORE UPDATE ON a_auth.authz_sessions \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{fixture_id}()"
    ))
    .execute(&fixture_pool)
    .await
    .unwrap();
    let result = store.finalize_exchange_failure(failure()).await;
    sqlx::query(&format!(
        "DROP TRIGGER {fixture_id} ON a_auth.authz_sessions"
    ))
    .execute(&fixture_pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{fixture_id}()"))
        .execute(&fixture_pool)
        .await
        .unwrap();
    assert!(result.is_err());
    assert_eq!(
        AuthzSessionStore::get(&store, &tenant, "session")
            .await
            .unwrap(),
        Some(session)
    );
    assert_eq!(
        CodeStore::acquire_lease(&store, &tenant, "code", "other-owner", now, now + 60)
            .await
            .unwrap(),
        LeaseAcquire::Locked
    );
    let failed = store
        .finalize_exchange_failure(failure())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.state, "exchange_failed");
    assert_eq!(failed.sequence, 4);
    assert_eq!(failed.last_error.as_deref(), Some("failed"));
    let reconnected = database().await;
    assert_eq!(
        AuthzSessionStore::get(&reconnected, &tenant, "session")
            .await
            .unwrap(),
        Some(failed)
    );
    assert!(matches!(
        CodeStore::acquire_lease(&reconnected, &tenant, "code", "other-owner", now, now + 60)
            .await
            .unwrap(),
        LeaseAcquire::AlreadyConsumed {
            issued_grant_id: None,
            ..
        }
    ));
    assert!(store.finalize_exchange_failure(failure()).await.is_err());

    // Flows without an authorization-session pointer still consume once.
    let mut detached = code_record();
    detached.code = "detached".into();
    detached.expires_at = now + 600;
    CodeStore::put(&store, &tenant, detached.clone())
        .await
        .unwrap();
    CodeStore::acquire_lease(&store, &tenant, "detached", "owner", now, now + 60)
        .await
        .unwrap();
    assert_eq!(
        store
            .finalize_exchange_failure(ExchangeFailureRequest {
                code: "detached",
                expires_at: detached.expires_at,
                authz_session_id: None,
                ..failure()
            })
            .await
            .unwrap(),
        None
    );
    // A caller's old timestamp cannot authorize an expired code at commit.
    let mut expired = code_record();
    expired.code = "expired".into();
    expired.expires_at = now - 1;
    CodeStore::put(&store, &tenant, expired.clone())
        .await
        .unwrap();
    assert!(matches!(
        CodeStore::acquire_lease(&store, &tenant, "expired", "owner", now - 20, now + 60)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    assert!(
        store
            .finalize_exchange_failure(ExchangeFailureRequest {
                code: "expired",
                expires_at: expired.expires_at,
                now: now - 20,
                authz_session_id: None,
                ..failure()
            })
            .await
            .is_err(),
        "expiry must be checked with the commit-time clock"
    );
    assert_eq!(
        AuthzSessionStore::delete_all_by_tenant(&store, &tenant)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        CodeStore::delete_all_by_tenant(&store, &tenant)
            .await
            .unwrap(),
        3
    );
    ClientStore::delete(&store, &tenant, "client")
        .await
        .unwrap();
    fixture_pool.close().await;
}
