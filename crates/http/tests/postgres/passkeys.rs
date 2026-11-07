use super::{database, tenant};
use agent_auth_authn::passkey::PasskeyCredential;
use agent_auth_http::{adapters::memory::MemoryPasskeyStore, ports::PasskeyStore};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn record(id: &str, user: &str) -> PasskeyCredential {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
    PasskeyCredential {
        credential_id: id.into(),
        user_id: user.into(),
        rp_id: "auth.example.test".into(),
        public_key_sec1: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        sign_count: 0,
        name: "Security key".into(),
        created_at: 100,
    }
}

async fn passkey_contract(store: impl PasskeyStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get(&tenant, "key").await.unwrap(), None);
    assert!(store
        .list_by_user(&tenant, "user")
        .await
        .unwrap()
        .is_empty());
    assert!(!store.update_sign_count(&tenant, "key", 1, 0).await.unwrap());
    assert!(!store
        .rename_owned(&tenant, "user", "key", "New")
        .await
        .unwrap());
    assert!(!store.delete_owned(&tenant, "user", "key").await.unwrap());
    let initial = record("key", "user");
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
            store.put_new(&tenant, initial).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert!(store.put_new(&foreign, initial.clone()).await.unwrap());
    assert!(!store
        .put_new(&tenant, record("key", "attacker"))
        .await
        .unwrap());
    assert_eq!(
        store.get(&tenant, "key").await.unwrap(),
        Some(initial.clone())
    );
    assert!(!store
        .rename_owned(&tenant, "attacker", "key", "Wrong")
        .await
        .unwrap());
    assert!(!store
        .delete_owned(&tenant, "attacker", "key")
        .await
        .unwrap());
    assert!(store
        .rename_owned(&tenant, "user", "key", "Renamed")
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.update_sign_count(&tenant, "key", 7, 0).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert!(!store.update_sign_count(&tenant, "key", 8, 0).await.unwrap());
    assert!(!store.update_sign_count(&tenant, "key", 6, 7).await.unwrap());
    assert!(!store.update_sign_count(&tenant, "key", 7, 7).await.unwrap());
    let current = store.get(&tenant, "key").await.unwrap().unwrap();
    assert_eq!(current.sign_count, 7);
    assert_eq!(current.name, "Renamed");
    assert_eq!(
        store.get(&foreign, "key").await.unwrap(),
        Some(initial.clone())
    );
    let barrier = Arc::new(Barrier::new(32));
    let mut counters = Vec::new();
    let mut renames = Vec::new();
    for _ in 0..16 {
        let (counter_store, counter_tenant, counter_barrier) =
            (store.clone(), tenant.clone(), barrier.clone());
        counters.push(tokio::spawn(async move {
            counter_barrier.wait().await;
            for _ in 0..32 {
                if counter_store
                    .update_sign_count(&counter_tenant, "key", 8, 7)
                    .await
                    .unwrap()
                {
                    return true;
                }
                if counter_store
                    .get(&counter_tenant, "key")
                    .await
                    .unwrap()
                    .unwrap()
                    .sign_count
                    != 7
                {
                    return false;
                }
                tokio::task::yield_now().await;
            }
            panic!("counter contention did not converge");
        }));
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        renames.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..32 {
                if store
                    .rename_owned(&tenant, "user", "key", "Race renamed")
                    .await
                    .unwrap()
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("rename contention did not converge");
        }));
    }
    let mut winners = 0;
    for task in counters {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    for task in renames {
        task.await.unwrap();
    }
    assert_eq!(winners, 1);
    let current = store.get(&tenant, "key").await.unwrap().unwrap();
    let mut expected = initial;
    expected.sign_count = 8;
    expected.name = "Race renamed".into();
    assert_eq!(
        current, expected,
        "rename and counter CAS must preserve credential material"
    );
    assert!(store
        .put_new(&tenant, record("zero", "user"))
        .await
        .unwrap());
    assert!(store
        .update_sign_count(&tenant, "zero", 0, 0)
        .await
        .unwrap());
    let mut max = record("max", "user");
    max.sign_count = u32::MAX;
    assert!(store.put_new(&tenant, max.clone()).await.unwrap());
    assert!(!store
        .update_sign_count(&tenant, "max", 0, u32::MAX)
        .await
        .unwrap());
    assert_eq!(store.get(&tenant, "max").await.unwrap(), Some(max));
    let list = store.list_by_user(&tenant, "user").await.unwrap();
    assert_eq!(list.len(), 3);
    assert!(list.iter().all(|entry| entry.user_id == "user"));
    assert!(store
        .put_new(&tenant, record("other", "other-user"))
        .await
        .unwrap());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.delete_owned(&tenant, "user", "key").await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 2);
    assert_eq!(store.delete_by_user(&tenant, "user").await.unwrap(), 0);
    assert!(store.get(&tenant, "other").await.unwrap().is_some());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.list_by_user(&foreign, "user").await.unwrap().len(), 1);
    assert_eq!(store.delete_all_by_tenant(&foreign).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_passkey_contract() {
    passkey_contract(MemoryPasskeyStore::default()).await;
}

#[tokio::test]
async fn postgres_passkey_contract() {
    passkey_contract(agent_auth_http::state::PasskeyStoreImpl::Postgres(
        database().await,
    ))
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_passkey_contract() {
    use agent_auth_http::adapters::aws::DynamoPasskeyStore;
    let (db, table) = super::aws_contract_database::table_with_string_index(
        "credential_id",
        "user_id-index",
        "user_id",
    )
    .await;
    passkey_contract(DynamoPasskeyStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}

fn passkey_authority_state(
    base: agent_auth_http::adapters::postgres::PostgresStore,
) -> agent_auth_http::AppState {
    use agent_auth_http::{
        adapters::postgres::{PostgresUsersStore, UserAuthorityKey},
        state::{
            PasskeyChallengeStoreImpl, PasskeyStoreImpl, PasswordStoreImpl, SessionStoreImpl,
            UsersStoreImpl,
        },
    };
    let mut state = agent_auth_http::AppState::dev("localhost");
    state.passkey_enabled = true;
    state.users = Arc::new(UsersStoreImpl::Postgres(PostgresUsersStore::new(
        base.clone(),
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    )));
    state.passwords = Arc::new(PasswordStoreImpl::Postgres(base.clone()));
    state.sessions = Arc::new(SessionStoreImpl::Postgres(base.clone()));
    state.passkey_challenges = Arc::new(PasskeyChallengeStoreImpl::Postgres(base.clone()));
    state.passkeys = Arc::new(PasskeyStoreImpl::Postgres(base));
    state
}

async fn passkey_authority_session(state: &agent_auth_http::AppState, id: &str, epoch: u64) {
    use agent_auth_http::ports::{SessionRecord, SessionStore};
    let now = agent_auth_http::current_unix_secs();
    state
        .sessions
        .create(
            "",
            SessionRecord {
                session_id: id.into(),
                user_id: "user:alice@example.com".into(),
                credential_epoch: epoch,
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

async fn passkey_authority_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    session: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "localhost")
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-agent_auth_session={session}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn passkey_authority_attestation(credential_id: &[u8]) -> String {
    use base64::Engine;
    use ciborium::value::Value as Cbor;
    use sha2::{Digest, Sha256};
    // A deterministic test authenticator supplies fmt=none attestation; this
    // verifies the real ceremony parser, not hardware authenticator acceptance.
    let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let cose = Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(point.x().unwrap().to_vec()),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(point.y().unwrap().to_vec()),
        ),
    ]);
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(0x45); // UP, UV and attested credential data.
    data.extend_from_slice(&0_u32.to_be_bytes());
    data.extend_from_slice(&[0_u8; 16]);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    ciborium::ser::into_writer(&cose, &mut data).unwrap();
    let object = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(data)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&object, &mut bytes).unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn passkey_authority_registration(
    router: &axum::Router,
    session: &str,
    credential_id: &[u8],
) -> serde_json::Value {
    use axum::{body::to_bytes, http::StatusCode};
    use base64::Engine;
    use serde_json::json;
    let response = passkey_authority_request(
        router,
        "POST",
        "/passkey/register/begin",
        session,
        json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let options: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let challenge = options["challenge"].as_str().unwrap();
    let client_data = serde_json::to_vec(&json!({
        "type":"webauthn.create","challenge":challenge,"origin":"https://localhost",
    }))
    .unwrap();
    json!({
        "challenge":challenge,
        "client_data_json":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data),
        "attestation_object":passkey_authority_attestation(credential_id),
    })
}

#[tokio::test]
async fn postgres_passkey_authority_http_registration_rechecks_user_and_session_after_lock_wait() {
    use agent_auth_http::ports::{UserStatus, UsersStore};
    use axum::http::StatusCode;
    use base64::Engine;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = passkey_authority_state(base);
    let other = passkey_authority_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let user_id = "user:alice@example.com";
    state
        .users
        .create_or_get_by_email("", "alice@example.com", user_id, 100)
        .await
        .unwrap();
    passkey_authority_session(&state, "registration", 0).await;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    let barrier = Arc::new(Barrier::new(16));
    let mut actors = Vec::new();
    for i in 0..16_u8 {
        let raw_id = vec![i + 1; 32];
        let router = if i % 2 == 0 {
            router.clone()
        } else {
            other_router.clone()
        };
        let body = passkey_authority_registration(&router, "registration", &raw_id).await;
        let barrier = barrier.clone();
        actors.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = passkey_authority_request(
                &router,
                "POST",
                "/passkey/register/finish",
                "registration",
                body,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_id)
        }));
    }
    for actor in actors {
        let id = actor.await.unwrap();
        let stored = other.passkeys.get("", &id).await.unwrap().unwrap();
        assert_eq!(stored.user_id, user_id);
        assert_eq!(stored.rp_id, "localhost");
        assert_eq!(
            stored.public_key_sec1,
            record("expected", user_id).public_key_sec1
        );
    }
    assert_eq!(
        other
            .passkeys
            .list_by_user("", user_id)
            .await
            .unwrap()
            .len(),
        16
    );

    for lock_user in [true, false] {
        let session_id = if lock_user {
            "late-user"
        } else {
            "late-generation"
        };
        let raw_id = if lock_user {
            vec![0x71; 32]
        } else {
            vec![0x72; 32]
        };
        passkey_authority_session(&state, session_id, 0).await;
        let body = passkey_authority_registration(&other_router, session_id, &raw_id).await;
        let table = if lock_user {
            "a_auth.users"
        } else {
            "a_auth.login_session_generations"
        };
        let mut held = pool.begin().await.unwrap();
        sqlx::query(&format!(
            "SELECT 1 FROM {table} WHERE tenant = $1 AND user_id = $2 FOR UPDATE"
        ))
        .bind(b"".as_slice())
        .bind(user_id.as_bytes())
        .fetch_one(&mut *held)
        .await
        .unwrap();
        let finish_router = other_router.clone();
        let actor = tokio::spawn(async move {
            passkey_authority_request(
                &finish_router,
                "POST",
                "/passkey/register/finish",
                session_id,
                body,
            )
            .await
        });
        let mut blocked = false;
        for _ in 0..100 {
            let query_pattern = format!("%{table}%FOR UPDATE%");
            blocked = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname = current_database() AND state = 'active' \
                 AND wait_event_type = 'Lock' AND query LIKE $1)",
            )
            .bind(query_pattern)
            .fetch_one(&pool)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            blocked,
            "registration must reach the authority row lock after preflight"
        );
        if lock_user {
            sqlx::query(
                r#"UPDATE a_auth.users SET status = 'disabled',
                   record = jsonb_set(record::jsonb, '{status}', '"disabled"')::text
                   WHERE tenant = $1 AND user_id = $2"#,
            )
            .bind(b"".as_slice())
            .bind(user_id.as_bytes())
            .execute(&mut *held)
            .await
            .unwrap();
        } else {
            sqlx::query(
                "UPDATE a_auth.login_session_generations SET generation = generation + 1 \
                 WHERE tenant = $1 AND user_id = $2",
            )
            .bind(b"".as_slice())
            .bind(user_id.as_bytes())
            .execute(&mut *held)
            .await
            .unwrap();
        }
        held.commit().await.unwrap();
        assert_eq!(actor.await.unwrap().status(), StatusCode::CONFLICT);
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_id);
        assert!(state.passkeys.get("", &id).await.unwrap().is_none());
        if lock_user {
            state
                .users
                .set_status(
                    "",
                    user_id,
                    UserStatus::Active,
                    agent_auth_http::current_unix_secs(),
                )
                .await
                .unwrap();
        }
    }
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn passkey_authority_handle(router: &axum::Router, session: &str) -> String {
    use axum::{body::to_bytes, http::StatusCode};
    let response = passkey_authority_request(
        router,
        "GET",
        "/account/credentials",
        session,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    body["passkeys"][0]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn postgres_passkey_authority_http_delete_rolls_back_key_when_user_completion_fails() {
    use agent_auth_http::ports::{PasswordCredential, PasswordStore, SessionStore, UsersStore};
    use axum::http::StatusCode;
    use serde_json::json;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = passkey_authority_state(base);
    let other = passkey_authority_state(
        agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap(),
    );
    let user_id = "user:alice@example.com";
    state
        .users
        .create_or_get_by_email("", "alice@example.com", user_id, 100)
        .await
        .unwrap();
    state
        .passwords
        .create_if_absent(
            "",
            PasswordCredential {
                user_id: user_id.into(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: false,
                revocation_pending: false,
                credential_change_id: None,
                version: 7,
                updated_at: 100,
            },
        )
        .await
        .unwrap();
    let mut key = record("owned-key", user_id);
    key.rp_id = "localhost".into();
    assert!(state.passkeys.put_new("", key.clone()).await.unwrap());
    passkey_authority_session(&state, "delete-key", 0).await;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    let handle = passkey_authority_handle(&router, "delete-key").await;
    sqlx::query(
        "ALTER TABLE a_auth.users ADD CONSTRAINT contract_pending_only \
         CHECK ((record::jsonb->>'revocation_pending')::boolean) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        passkey_authority_request(
            &router,
            "DELETE",
            &format!("/account/passkeys/{handle}"),
            "delete-key",
            json!({})
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        other.passkeys.get("", "owned-key").await.unwrap(),
        Some(key)
    );
    let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 1);
    assert!(user.revocation_pending);
    assert!(other
        .sessions
        .get("", "delete-key")
        .await
        .unwrap()
        .is_none());
    sqlx::query("ALTER TABLE a_auth.users DROP CONSTRAINT contract_pending_only")
        .execute(&pool)
        .await
        .unwrap();
    // Controlled fixture advances the recovery cutoff to release the failed
    // owner fence; production timeout/admission qualification remains separate.
    let now = agent_auth_http::current_unix_secs();
    assert!(state
        .users
        .recover_expired_credential_change("", user_id, 1, now + 1, now)
        .await
        .unwrap());
    passkey_authority_session(&other, "retry-delete", 1).await;
    let handle = passkey_authority_handle(&other_router, "retry-delete").await;
    assert_eq!(
        passkey_authority_request(
            &other_router,
            "DELETE",
            &format!("/account/passkeys/{handle}"),
            "retry-delete",
            json!({})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(state.passkeys.get("", "owned-key").await.unwrap().is_none());
    let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 2);
    assert!(!user.revocation_pending);
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
