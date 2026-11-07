use super::{database, tenant};
use agent_auth_authn::recovery::{code_hash, LOCKOUT_SECS, MAX_ATTEMPTS};
use agent_auth_http::{
    adapters::memory::MemoryRecoveryStore,
    ports::{RecoveryCodeEntry, RecoveryConsume, RecoveryRecord, RecoveryStore},
};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Barrier;

fn hash(label: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(code_hash(b"contract-test-only", label))
}

pub(super) fn record(lookup: &str) -> RecoveryRecord {
    RecoveryRecord {
        user_lookup: lookup.into(),
        user_id: "canonical-user".into(),
        activation_id: "single-region".into(),
        code_hashes: vec![
            RecoveryCodeEntry {
                hash_b64: hash("one"),
                consumed: false,
            },
            RecoveryCodeEntry {
                hash_b64: hash("two"),
                consumed: false,
            },
        ],
        attempt_count: 0,
        locked_until: 0,
    }
}

async fn recovery_contract(store: impl RecoveryStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    assert_eq!(
        store
            .get_success_result(&tenant, "missing-operation")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "missing", "wrong", 100)
            .await
            .unwrap(),
        RecoveryConsume::NotFound,
    );
    let initial = record("lookup");
    store.put(&tenant, initial.clone()).await.unwrap();
    store.put(&foreign, initial.clone()).await.unwrap();
    assert_eq!(
        store.get(&tenant, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(store.get(&foreign, "missing").await.unwrap(), None);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..32 {
                match store
                    .verify_and_consume(&tenant, "lookup", &hash("one"), 100)
                    .await
                {
                    Ok(outcome) => return outcome,
                    Err(agent_auth_http::ports::StoreError::Transient(_)) => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("unexpected recovery admission error: {error:?}"),
                }
            }
            panic!("recovery admission contention did not converge");
        }));
    }
    let mut valid = 0;
    for task in tasks {
        match task.await.unwrap() {
            RecoveryConsume::Valid => valid += 1,
            RecoveryConsume::Invalid | RecoveryConsume::Locked { .. } => {}
            other => panic!("unexpected recovery admission: {other:?}"),
        }
    }
    assert_eq!(valid, 1);
    let consumed = store.get(&tenant, "lookup").await.unwrap().unwrap();
    assert!(consumed.code_hashes[0].consumed);
    assert!(!consumed.code_hashes[1].consumed);
    assert_eq!(
        store.get(&foreign, "lookup").await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("two"), 100)
            .await
            .unwrap(),
        RecoveryConsume::Locked {
            retry_after_secs: LOCKOUT_SECS
        },
    );
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("two"), 100 + LOCKOUT_SECS)
            .await
            .unwrap(),
        RecoveryConsume::Valid,
    );
    let unlocked = store.get(&tenant, "lookup").await.unwrap().unwrap();
    assert_eq!(unlocked.attempt_count, 0);
    assert_eq!(unlocked.locked_until, 0);
    store.put(&tenant, initial.clone()).await.unwrap();
    for attempt in 1..=MAX_ATTEMPTS {
        let outcome = store
            .verify_and_consume(&tenant, "lookup", "wrong", 200)
            .await
            .unwrap();
        if attempt < MAX_ATTEMPTS {
            assert_eq!(outcome, RecoveryConsume::Invalid);
        } else {
            assert_eq!(
                outcome,
                RecoveryConsume::Locked {
                    retry_after_secs: LOCKOUT_SECS
                }
            );
        }
    }
    let locked = store.get(&tenant, "lookup").await.unwrap();
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("one"), 201)
            .await
            .unwrap(),
        RecoveryConsume::Locked {
            retry_after_secs: LOCKOUT_SECS - 1
        },
    );
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), locked);
    store.put(&tenant, initial).await.unwrap();
    assert_eq!(
        store
            .verify_and_consume(&tenant, "lookup", &hash("one"), 200)
            .await
            .unwrap(),
        RecoveryConsume::Valid,
    );
    store.delete_by_lookup(&tenant, "lookup").await.unwrap();
    store.delete_by_lookup(&tenant, "lookup").await.unwrap();
    assert_eq!(store.get(&tenant, "lookup").await.unwrap(), None);
    store.put(&tenant, record("cleanup")).await.unwrap();
    assert!(store.delete_all_by_tenant(&tenant).await.unwrap() > 0);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert!(store.get(&foreign, "lookup").await.unwrap().is_some());
    assert!(store.delete_all_by_tenant(&foreign).await.unwrap() > 0);
}

#[tokio::test]
async fn memory_recovery_contract() {
    recovery_contract(MemoryRecoveryStore::default()).await;
}

#[tokio::test]
async fn postgres_recovery_contract() {
    recovery_contract(agent_auth_http::state::RecoveryStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_recovery_contract() {
    use agent_auth_http::adapters::aws::DynamoRecoveryStore;
    let (db, table) = super::aws_contract_database::table("user_lookup", vec![], vec![]).await;
    recovery_contract(DynamoRecoveryStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}

fn recovery_authority_state(
    base: agent_auth_http::adapters::postgres::PostgresStore,
) -> agent_auth_http::AppState {
    use agent_auth_http::{
        adapters::postgres::{PostgresUsersStore, UserAuthorityKey},
        state::{PasswordStoreImpl, RecoveryStoreImpl, SessionStoreImpl, UsersStoreImpl},
    };
    let mut state = agent_auth_http::AppState::dev("localhost");
    state.users = Arc::new(UsersStoreImpl::Postgres(PostgresUsersStore::new(
        base.clone(),
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    )));
    state.passwords = Arc::new(PasswordStoreImpl::Postgres(base.clone()));
    state.sessions = Arc::new(SessionStoreImpl::Postgres(base.clone()));
    state.recovery = Arc::new(RecoveryStoreImpl::Postgres(base));
    state
}

async fn recovery_authority_seed(state: &agent_auth_http::AppState) {
    use agent_auth_http::ports::{
        PasswordCredential, PasswordStore, SessionRecord, SessionStore, UsersStore,
    };
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "alice@example.com", "user:alice@example.com", now)
        .await
        .unwrap();
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: "user:alice@example.com".into(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 7,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: "prior-login".into(),
                user_id: "user:alice@example.com".into(),
                credential_epoch: 0,
                auth_time: now,
                created_at: now,
                last_used_at: now,
                device: "contract".into(),
                expires_at: now + 3600,
                acr: None,
                amr: vec!["email".into()],
            },
        )
        .await
        .unwrap();
}

async fn recovery_authority_request(
    router: &axum::Router,
    path: &str,
    session_id: Option<&str>,
    body: serde_json::Value,
) -> axum::response::Response {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(id) = session_id {
        request = request.header("cookie", format!("__Host-agent_auth_session={id}"));
    }
    router
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

fn recovery_authority_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .strip_prefix("__Host-agent_auth_session=")
                .map(|rest| rest.split(';').next().unwrap().to_string())
        })
        .expect("recovery must return its durable session")
}

#[tokio::test]
async fn postgres_recovery_authority_http_rotation_and_same_operation_race_use_one_session() {
    use agent_auth_http::ports::{SessionStore, UsersStore};
    use axum::{body::to_bytes, http::StatusCode};
    use serde_json::json;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = recovery_authority_state(base);
    let other = recovery_authority_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    recovery_authority_seed(&state).await;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    let response = recovery_authority_request(
        &router,
        "/recovery/generate",
        Some("prior-login"),
        json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let code = body["recovery_codes"][0].as_str().unwrap().to_string();
    let user = other
        .users
        .get_by_id("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.credential_epoch, 1);
    assert!(!user.revocation_pending);
    assert!(other
        .sessions
        .get("", "prior-login")
        .await
        .unwrap()
        .is_none());
    let operation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
    let barrier = Arc::new(Barrier::new(16));
    let mut actors = Vec::new();
    for i in 0..16 {
        let router = if i % 2 == 0 {
            router.clone()
        } else {
            other_router.clone()
        };
        let (barrier, code, operation) = (barrier.clone(), code.clone(), operation.clone());
        actors.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = recovery_authority_request(
                &router,
                "/recovery/verify",
                None,
                json!({"code":code,"operation_id":operation}),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            recovery_authority_cookie(&response)
        }));
    }
    let mut ids = std::collections::BTreeSet::new();
    for actor in actors {
        ids.insert(actor.await.unwrap());
    }
    assert_eq!(
        ids.len(),
        1,
        "all retries must return one committed session"
    );
    let id = ids.first().unwrap();
    let session = other.sessions.get("", id).await.unwrap().unwrap();
    assert_eq!(session.credential_epoch, 2);
    let user = other
        .users
        .get_by_id("", "user:alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.credential_epoch, 2);
    assert!(!user.revocation_pending);
    let results: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.recovery_success_results")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(results, 1);
    assert_eq!(
        other
            .sessions
            .count_by_user(
                "",
                "user:alice@example.com",
                agent_auth_http::current_unix_secs()
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(recovery_authority_request(&other_router, "/recovery/verify", None,
        json!({"code":code,"operation_id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x43;32])}))
        .await.status(), StatusCode::BAD_REQUEST);
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn postgres_recovery_authority_http_failed_receipt_preserves_code_user_and_old_session() {
    use agent_auth_http::ports::{SessionStore, UserStatus, UsersStore};
    use axum::http::StatusCode;
    use serde_json::json;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = recovery_authority_state(base);
    let other = recovery_authority_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    recovery_authority_seed(&state).await;
    let user_id = "user:alice@example.com";
    let lookup = "contract-user-lookup";
    let code = agent_auth_authn::recovery::format_code(
        lookup,
        &[0x35; agent_auth_authn::recovery::SECRET_BYTES],
    );
    let record = RecoveryRecord {
        user_lookup: lookup.into(),
        user_id: user_id.into(),
        activation_id: state.region.issue_id("recovery"),
        code_hashes: vec![RecoveryCodeEntry {
            hash_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(code_hash(&state.server_secret, &code)),
            consumed: false,
        }],
        attempt_count: 0,
        locked_until: 0,
    };
    state.recovery.put("", record.clone()).await.unwrap();
    let operation = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x51; 32]);
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    sqlx::query("ALTER TABLE a_auth.recovery_success_results ADD CONSTRAINT contract_no_receipt CHECK (false)")
        .execute(&pool).await.unwrap();
    assert_eq!(
        recovery_authority_request(
            &router,
            "/recovery/verify",
            None,
            json!({"code":code,"operation_id":operation})
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(other.recovery.get("", lookup).await.unwrap(), Some(record));
    let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 0);
    assert!(!user.revocation_pending);
    assert!(other
        .sessions
        .get("", "prior-login")
        .await
        .unwrap()
        .is_some());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.recovery_success_results")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("ALTER TABLE a_auth.recovery_success_results DROP CONSTRAINT contract_no_receipt")
        .execute(&pool)
        .await
        .unwrap();
    let response = recovery_authority_request(
        &other_router,
        "/recovery/verify",
        None,
        json!({"code":code,"operation_id":operation}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let id = recovery_authority_cookie(&response);
    assert!(state
        .sessions
        .get("", "prior-login")
        .await
        .unwrap()
        .is_none());
    assert!(state.sessions.get("", &id).await.unwrap().is_some());
    assert!(
        state
            .recovery
            .get("", lookup)
            .await
            .unwrap()
            .unwrap()
            .code_hashes[0]
            .consumed
    );
    state
        .users
        .set_status(
            "",
            user_id,
            UserStatus::Disabled,
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    let denied = recovery_authority_request(
        &router,
        "/recovery/verify",
        None,
        json!({"code":code,"operation_id":operation}),
    )
    .await;
    // Existing receipt replay hides blocked-account state as an invalid code.
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert!(denied.headers().get("set-cookie").is_none());
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
