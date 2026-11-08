use super::{
    database,
    invitation_contracts::{record, request},
    tenant,
};
use agent_auth_http::{
    adapters::postgres::{
        PostgresInvitationStore, PostgresStore, PostgresUsersStore, UserAuthorityKey,
    },
    ports::{
        InvitationAcceptOutcome, InvitationStore, PasswordCredential, PasswordStore, SessionStore,
        StoreError, UsersStore,
    },
};
use std::time::Duration;

async fn password_admission_waits_for_invitation_commit(reset: bool) {
    let base = database().await;
    let users = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
    let invites = PostgresInvitationStore::new(users.clone());
    let tenant = tenant();
    let email = format!("person@{tenant}.example.test");
    let user = format!("user:{email}");
    users
        .create_or_get_by_email(&tenant, &email, &user, 100)
        .await
        .unwrap();
    let invitation = record(&user, &email);
    invites.issue(&tenant, invitation.clone()).await.unwrap();
    let hash = agent_auth_authn::password::dummy_hash().clone();
    let database_url = std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut fixture = pool.acquire().await.unwrap();
    let lock = i64::from(rand::random::<u32>() & 0x7fff_ffff);
    sqlx::query("SELECT pg_advisory_lock(142, $1::INT)")
        .bind(lock as i32)
        .execute(&mut *fixture)
        .await
        .unwrap();
    let trigger = format!("contract_invite_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF NEW.tenant = convert_to('{tenant}', 'UTF8') THEN \
         PERFORM pg_advisory_xact_lock(142, {lock}); END IF; RETURN NEW; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON a_auth.login_sessions \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let input = request(&invitation, "actor", 100);
    let (accepting_store, accepting_tenant) = (invites.clone(), tenant.clone());
    let accepting =
        tokio::spawn(async move { accepting_store.accept(&accepting_tenant, input).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let invitation_waiting = loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype = 'advisory' \
             AND classid = 142::OID AND objid::BIGINT = $1 AND NOT granted)",
        )
        .bind(lock)
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting || tokio::time::Instant::now() >= deadline {
            break waiting;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let application = format!("invitation_admission_{:032x}", rand::random::<u128>());
    let mut writer_url = url::Url::parse(&database_url).unwrap();
    writer_url
        .query_pairs_mut()
        .append_pair("application_name", &application);
    let writer_store = PostgresStore::connect(writer_url.as_str(), 1)
        .await
        .unwrap();
    let (writer_tenant, writer_user) = (tenant.clone(), user.clone());
    let writing = tokio::spawn(async move {
        if reset {
            writer_store
                .reset_temporary(&writer_tenant, &writer_user, hash, None, 100)
                .await
                .map(|version| version == Some(1))
        } else {
            writer_store
                .create_if_absent(
                    &writer_tenant,
                    PasswordCredential {
                        user_id: writer_user,
                        password_hash: hash,
                        must_change: true,
                        revocation_pending: false,
                        credential_change_id: None,
                        version: 0,
                        updated_at: 100,
                    },
                )
                .await
        }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let writer_waiting = loop {
        if writing.is_finished() {
            break false;
        }
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
             WHERE application_name = $1 AND wait_event_type = 'Lock')",
        )
        .bind(&application)
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting || tokio::time::Instant::now() >= deadline {
            break waiting;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    sqlx::query("SELECT pg_advisory_unlock(142, $1::INT)")
        .bind(lock as i32)
        .execute(&mut *fixture)
        .await
        .unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    let written = writing.await.unwrap().unwrap();
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.login_sessions"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        invitation_waiting,
        "observe the actual invitation commit pause"
    );
    assert!(
        writer_waiting,
        "a password cannot appear after the invitation's absence check"
    );
    assert_eq!(
        accepted,
        InvitationAcceptOutcome::Accepted {
            user_id: user.clone(),
            session_id: "actor".into(),
        }
    );
    assert!(written);
    assert!(PasswordStore::get(&base, &tenant, &user)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        SessionStore::get(&base, &tenant, "actor")
            .await
            .unwrap()
            .unwrap()
            .amr,
        vec!["invite"]
    );
    drop(fixture);
    pool.close().await;
}

#[tokio::test]
async fn postgres_invitation_password_creation_waits_for_atomic_acceptance() {
    password_admission_waits_for_invitation_commit(false).await;
}

#[tokio::test]
async fn postgres_invitation_missing_password_reset_waits_for_atomic_acceptance() {
    password_admission_waits_for_invitation_commit(true).await;
}

#[tokio::test]
async fn postgres_invitation_failed_consumption_rolls_back_session_and_generation() {
    let base = database().await;
    let users = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
    let invites = PostgresInvitationStore::new(users.clone());
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let tenant = tenant();
    let email = format!("person@{tenant}.example.test");
    let user = format!("user:{email}");
    users
        .create_or_get_by_email(&tenant, &email, &user, 100)
        .await
        .unwrap();
    let initial = record(&user, &email);
    invites.issue(&tenant, initial.clone()).await.unwrap();
    let trigger = format!("contract_invite_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF OLD.tenant = convert_to('{tenant}', 'UTF8') THEN \
         RAISE EXCEPTION 'private-invitation-sentinel' USING ERRCODE = '23514'; \
         END IF; RETURN OLD; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON a_auth.invitations \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = invites
        .accept(&tenant, request(&initial, "atomic-session", 100))
        .await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.invitations"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    let error = failed.unwrap_err();
    assert!(matches!(error, StoreError::Permanent(_)));
    assert!(!format!("{error:?}").contains("private-invitation-sentinel"));
    assert_eq!(
        SessionStore::get(&base, &tenant, "atomic-session")
            .await
            .unwrap(),
        None
    );
    let generations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM a_auth.login_session_generations \
         WHERE tenant = $1 AND user_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(user.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(generations, 0, "the first write also rolls back");
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "atomic-session", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Accepted {
            user_id: user,
            session_id: "atomic-session".into()
        }
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_invitation_complete_codec_and_failed_resend_preserve_authority() {
    use agent_auth_http::ports::InvitationIssueOutcome;
    use serde_json::Value;
    let base = database().await;
    let users = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
    let invites = PostgresInvitationStore::new(users.clone());
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let tenant = tenant();
    let email = format!("person@{tenant}.example.test");
    let user = format!("user:{email}");
    users
        .create_or_get_by_email(&tenant, &email, &user, 100)
        .await
        .unwrap();
    let mut initial = record(&user, &email);
    initial.locator.push('\0');
    initial.activation_id.push('\0');
    initial.issued_at = i64::MIN;
    initial.expires_at = i64::MAX;
    invites.issue(&tenant, initial.clone()).await.unwrap();
    let baseline: String = sqlx::query_scalar(
        "SELECT record FROM a_auth.invitations WHERE tenant = $1 AND locator = $2",
    )
    .bind(tenant.as_bytes())
    .bind(initial.locator.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    let value: Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".into(), "private-invitation-sentinel".into()];
    for field in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        corruptions.push(missing.to_string());
    }
    for field in [
        "locator",
        "user_id",
        "email",
        "activation_id",
        "credential_epoch",
        "expires_at",
    ] {
        let mut rebound = value.clone();
        rebound[field] = if rebound[field].is_string() {
            "private-invitation-sentinel".into()
        } else {
            1.into()
        };
        corruptions.push(rebound.to_string());
    }
    let mut unknown = value.clone();
    unknown["unexpected"] = true.into();
    corruptions.push(unknown.to_string());
    for corrupt in corruptions {
        sqlx::query("UPDATE a_auth.invitations SET record = $3 WHERE tenant = $1 AND locator = $2")
            .bind(tenant.as_bytes())
            .bind(initial.locator.as_bytes())
            .bind(&corrupt)
            .execute(&pool)
            .await
            .unwrap();
        let issued = invites.issue(&tenant, initial.clone()).await.unwrap_err();
        let accepted = invites
            .accept(&tenant, request(&initial, "corrupt-session", 100))
            .await
            .unwrap_err();
        for error in [issued, accepted] {
            assert!(matches!(error, StoreError::Permanent(_)));
            assert!(!format!("{error:?}").contains("private-invitation-sentinel"));
        }
        let stored: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.invitations WHERE tenant = $1 AND locator = $2",
        )
        .bind(tenant.as_bytes())
        .bind(initial.locator.as_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, corrupt);
        assert_eq!(
            SessionStore::get(&base, &tenant, "corrupt-session")
                .await
                .unwrap(),
            None
        );
    }
    sqlx::query("UPDATE a_auth.invitations SET record = $3 WHERE tenant = $1 AND locator = $2")
        .bind(tenant.as_bytes())
        .bind(initial.locator.as_bytes())
        .bind(&baseline)
        .execute(&pool)
        .await
        .unwrap();
    let constraint = format!("contract_invite_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.invitations ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let mut renewed = initial.clone();
    renewed.verifier_hash = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [9_u8; 32],
    );
    let failed = invites.issue(&tenant, renewed).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.invitations DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    let wrong_key = PostgresInvitationStore::new(PostgresUsersStore::new(
        base.clone(),
        UserAuthorityKey::new([0x58; 32]).unwrap(),
    ));
    assert!(matches!(
        wrong_key.issue(&tenant, initial.clone()).await,
        Err(StoreError::Permanent(_))
    ));
    assert!(matches!(
        wrong_key
            .accept(&tenant, request(&initial, "wrong-key", 100))
            .await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "restored-session", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Accepted {
            user_id: user,
            session_id: "restored-session".into()
        }
    );
    pool.close().await;
}
