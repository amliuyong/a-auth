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

fn authority_state(
    store: agent_auth_http::adapters::postgres::PostgresStore,
) -> agent_auth_http::AppState {
    use agent_auth_http::{
        adapters::postgres::{PostgresUsersStore, UserAuthorityKey},
        state::{PasswordStoreImpl, SessionStoreImpl, UsersStoreImpl},
    };
    // Deliberately override only the authority under test; this is not a
    // production PostgreSQL AppState or transport qualification.
    let mut state = agent_auth_http::AppState::dev("localhost");
    state.users = Arc::new(UsersStoreImpl::Postgres(PostgresUsersStore::new(
        store.clone(),
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    )));
    state.passwords = Arc::new(PasswordStoreImpl::Postgres(store.clone()));
    state.sessions = Arc::new(SessionStoreImpl::Postgres(store));
    state
}

async fn authority_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    session_id: Option<&str>,
    body: serde_json::Value,
) -> axum::response::Response {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(session_id) = session_id {
        request = request.header("cookie", format!("__Host-agent_auth_session={session_id}"));
    } else {
        request = request.header("authorization", "Bearer dev-admin-token-not-for-prod");
    }
    router
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn authority_session(state: &agent_auth_http::AppState, id: &str, epoch: u64) {
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

#[tokio::test]
async fn postgres_password_enrollment_and_rotation_http_commit_user_fence_atomically() {
    use agent_auth_authn::password::verify_password;
    use agent_auth_http::ports::{SessionStore, UsersStore};
    use axum::http::StatusCode;
    use serde_json::json;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = authority_state(base.clone());
    let other = authority_state(
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
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    for (index, (router, state)) in [(&router, &state), (&other_router, &other)]
        .into_iter()
        .enumerate()
    {
        let session_id = format!("password-session-{index}");
        authority_session(state, &session_id, index as u64).await;
        let new_password = format!("Active contract password {index}!");
        let response = authority_request(
            router,
            "PUT",
            "/account/password",
            Some(&session_id),
            json!({"new_password": new_password}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let credential = other.passwords.get("", user_id).await.unwrap().unwrap();
        assert_eq!(credential.version, index as u64 + 1);
        assert!(!credential.must_change && !credential.revocation_pending);
        assert!(credential.credential_change_id.is_none());
        assert!(verify_password(&new_password, &credential.password_hash).unwrap());
        let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.credential_epoch, index as u64 + 1);
        assert!(!user.revocation_pending);
        assert!(other.sessions.get("", &session_id).await.unwrap().is_none());
    }

    // A real second-write failure must roll back the password while retaining
    // the previously committed user fence, so old authentication stays denied.
    authority_session(&state, "failed-change", 2).await;
    let before = state.passwords.get("", user_id).await.unwrap().unwrap();
    sqlx::query(
        "ALTER TABLE a_auth.users ADD CONSTRAINT contract_pending_only \
         CHECK ((record::jsonb->>'revocation_pending')::boolean) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    let response = authority_request(
        &router,
        "PUT",
        "/account/password",
        Some("failed-change"),
        json!({"new_password": "Rejected third password 123!"}),
    )
    .await;
    // Constraint rejection is a permanent StoreError; the existing account
    // API maps it to 500 rather than the transient-store 503.
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_credential(
        &other.passwords.get("", user_id).await.unwrap().unwrap(),
        &before,
    );
    let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 3);
    assert!(user.revocation_pending);
    assert!(other
        .sessions
        .get("", "failed-change")
        .await
        .unwrap()
        .is_none());
    sqlx::query("ALTER TABLE a_auth.users DROP CONSTRAINT contract_pending_only")
        .execute(&pool)
        .await
        .unwrap();
    drop(base);
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn postgres_admin_password_reset_http_resumes_exact_pending_owner_across_pools() {
    use agent_auth_authn::password::verify_password;
    use agent_auth_http::ports::{SessionStore, UserStatus, UsersStore};
    use axum::http::StatusCode;
    use serde_json::json;
    let (base, pool, admin, name, url) = super::ssf_contracts::isolated_database().await;
    let state = authority_state(base.clone());
    let other = authority_state(
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
    authority_session(&state, "prior-login", 0).await;
    let (router, _) = agent_auth_http::build_router(state.clone());
    let (other_router, _) = agent_auth_http::build_router(other.clone());
    let path = "/admin/users/user:alice@example.com/reset-password";
    let temporary = "Temporary contract password 123!";
    sqlx::query(
        "ALTER TABLE a_auth.users ADD CONSTRAINT contract_pending_only \
         CHECK ((record::jsonb->>'revocation_pending')::boolean) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        authority_request(
            &router,
            "POST",
            path,
            None,
            json!({"temporary_password": temporary})
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let pending = other.passwords.get("", user_id).await.unwrap().unwrap();
    assert_eq!(pending.version, 1);
    assert!(pending.must_change && pending.revocation_pending);
    assert!(pending.credential_change_id.is_some());
    assert!(verify_password(temporary, &pending.password_hash).unwrap());
    let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 1);
    assert!(user.revocation_pending);
    assert!(other
        .sessions
        .get("", "prior-login")
        .await
        .unwrap()
        .is_none());
    sqlx::query("ALTER TABLE a_auth.users DROP CONSTRAINT contract_pending_only")
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            authority_request(
                &other_router,
                "POST",
                path,
                None,
                json!({"temporary_password": temporary}),
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    let complete = state.passwords.get("", user_id).await.unwrap().unwrap();
    assert_eq!(complete.version, 1, "retry must not stage another password");
    assert!(complete.must_change && !complete.revocation_pending);
    assert!(complete.credential_change_id.is_none());
    let user = state.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.credential_epoch, 1);
    assert!(!user.revocation_pending);

    state
        .users
        .set_status("", user_id, UserStatus::Disabled, 200)
        .await
        .unwrap();
    assert_eq!(
        authority_request(
            &router,
            "POST",
            path,
            None,
            json!({"temporary_password": "Disabled user temporary password 456!"}),
        )
        .await
        .status(),
        StatusCode::OK
    );
    let user = other.users.get_by_id("", user_id).await.unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Disabled);
    assert_eq!(user.credential_epoch, 2);
    assert!(!user.revocation_pending);
    assert_eq!(
        other
            .passwords
            .get("", user_id)
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    drop(base);
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
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
