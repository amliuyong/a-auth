use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        memory::{
            MemoryInvitationStore, MemoryPasswordStore, MemorySessionStore, MemoryUsersStore,
        },
        postgres::{PostgresInvitationStore, PostgresUsersStore, UserAuthorityKey},
    },
    ports::{
        InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome, InvitationRecord,
        InvitationStore, PasswordCredential, PasswordStore, SessionRecord, SessionStore,
        UsersStore,
    },
};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn record(user: &str, email: &str) -> InvitationRecord {
    InvitationRecord {
        locator: "lookup".into(),
        activation_id: "single-region".into(),
        user_id: user.into(),
        email: email.into(),
        verifier_hash: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]),
        credential_epoch: 0,
        issued_at: 100,
        expires_at: 200,
    }
}

pub(super) fn request(
    record: &InvitationRecord,
    session: &str,
    now: i64,
) -> InvitationAcceptRequest {
    InvitationAcceptRequest {
        locator: record.locator.clone(),
        activation_id: record.activation_id.clone(),
        verifier_hash: record.verifier_hash.clone(),
        session_id: session.into(),
        device: "Test browser".into(),
        now,
    }
}

async fn invitation_contract(
    invites: impl InvitationStore + Clone + 'static,
    users: impl UsersStore,
    passwords: impl PasswordStore,
    sessions: impl SessionStore,
) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    let email = format!("person@{tenant}.example.test");
    let user = format!("user:{email}");
    let initial = record(&user, &email);
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Ineligible
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "missing", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    users
        .create_or_get_by_email(&tenant, &email, &user, 100)
        .await
        .unwrap();
    users
        .create_or_get_by_email(&foreign, &email, &user, 100)
        .await
        .unwrap();
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert_eq!(
        invites.issue(&foreign, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    let mut bad = request(&initial, "bad", 100);
    bad.activation_id = "wrong-region".into();
    assert_eq!(
        invites.accept(&tenant, bad).await.unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    let mut bad = request(&initial, "bad", 100);
    bad.verifier_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8_u8; 32]);
    assert_eq!(
        invites.accept(&tenant, bad).await.unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    assert_eq!(sessions.get(&tenant, "bad").await.unwrap(), None);
    let mut renewed = initial.clone();
    renewed.verifier_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]);
    assert_eq!(
        invites.issue(&tenant, renewed.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "superseded", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for actor in 0..16 {
        let (invites, tenant, barrier, input) = (
            invites.clone(),
            tenant.clone(),
            barrier.clone(),
            request(&renewed, &format!("actor-{actor}"), 100),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            invites.accept(&tenant, input).await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        match task.await.unwrap() {
            InvitationAcceptOutcome::Accepted {
                user_id,
                session_id,
            } => {
                assert_eq!(user_id, user);
                winners.push(session_id);
            }
            InvitationAcceptOutcome::Invalid => {}
            outcome => panic!("unexpected invitation outcome: {outcome:?}"),
        }
    }
    assert_eq!(winners.len(), 1);
    let session = sessions.get(&tenant, &winners[0]).await.unwrap().unwrap();
    assert_eq!(session.user_id, user);
    assert_eq!(session.credential_epoch, 0);
    assert_eq!(session.amr, vec!["invite"]);
    assert_eq!(session.device, "Test browser");
    assert_eq!(session.created_at, 100);
    assert_eq!(session.expires_at, 3700);
    assert_eq!(
        sessions
            .list_by_user(&tenant, &user, 100)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&renewed, "replay", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    assert_eq!(
        invites
            .accept(&foreign, request(&initial, "foreign", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Accepted {
            user_id: user.clone(),
            session_id: "foreign".into()
        }
    );
    assert_eq!(sessions.get(&tenant, "foreign").await.unwrap(), None);
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "expired", 200))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Expired {
            user_id: user.clone()
        }
    );
    assert_eq!(sessions.get(&tenant, "expired").await.unwrap(), None);
    invites.invalidate(&tenant, &initial.locator).await.unwrap();
    invites.invalidate(&tenant, &initial.locator).await.unwrap();
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "invalidated", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Invalid
    );
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    sessions
        .create(
            &tenant,
            SessionRecord {
                session_id: "collision".into(),
                user_id: "other-user".into(),
                credential_epoch: 0,
                auth_time: 100,
                created_at: 100,
                last_used_at: 100,
                device: "Existing browser".into(),
                expires_at: 3700,
                acr: None,
                amr: vec!["email".into()],
            },
        )
        .await
        .unwrap();
    assert!(invites
        .accept(&tenant, request(&initial, "collision", 100))
        .await
        .is_err());
    assert_eq!(
        sessions
            .get(&tenant, "collision")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        "other-user"
    );
    sessions.delete(&tenant, "collision").await.unwrap();
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "after-collision", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Accepted {
            user_id: user.clone(),
            session_id: "after-collision".into()
        }
    );
    let mut overflow = initial.clone();
    overflow.expires_at = i64::MAX;
    assert_eq!(
        invites.issue(&tenant, overflow.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert!(invites
        .accept(&tenant, request(&overflow, "overflow", i64::MAX - 1))
        .await
        .is_err());
    assert_eq!(sessions.get(&tenant, "overflow").await.unwrap(), None);
    assert_eq!(
        invites
            .accept(&tenant, request(&overflow, "after-overflow", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Accepted {
            user_id: user.clone(),
            session_id: "after-overflow".into()
        }
    );
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    assert!(passwords
        .create_if_absent(
            &tenant,
            PasswordCredential {
                user_id: user.clone(),
                password_hash: agent_auth_authn::password::dummy_hash().clone(),
                must_change: true,
                revocation_pending: false,
                credential_change_id: None,
                version: 0,
                updated_at: 100
            }
        )
        .await
        .unwrap());
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::PasswordConfigured
    );
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "password-configured", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Ineligible {
            user_id: user.clone()
        }
    );
    passwords.delete(&tenant, &user).await.unwrap();
    assert_eq!(
        invites.issue(&tenant, initial.clone()).await.unwrap(),
        InvitationIssueOutcome::Issued
    );
    users
        .begin_credential_change(&tenant, &user, 0, "owner", 100)
        .await
        .unwrap();
    assert_eq!(
        invites
            .accept(&tenant, request(&initial, "authority-moved", 100))
            .await
            .unwrap(),
        InvitationAcceptOutcome::Ineligible {
            user_id: user.clone()
        }
    );
    assert_eq!(
        sessions.get(&tenant, "authority-moved").await.unwrap(),
        None
    );
    assert_eq!(
        invites.issue(&tenant, initial).await.unwrap(),
        InvitationIssueOutcome::Ineligible
    );
}

#[tokio::test]
async fn memory_invitation_contract() {
    let users = MemoryUsersStore::default();
    let passwords = MemoryPasswordStore::default();
    let sessions = MemorySessionStore::default();
    invitation_contract(
        MemoryInvitationStore::new(users.clone(), passwords.clone(), sessions.clone()),
        users,
        passwords,
        sessions,
    )
    .await;
}

#[tokio::test]
async fn postgres_invitation_contract() {
    let base = database().await;
    let users = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
    invitation_contract(
        agent_auth_http::state::InvitationStoreImpl::Postgres(PostgresInvitationStore::new(
            users.clone(),
        )),
        agent_auth_http::state::UsersStoreImpl::Postgres(users),
        agent_auth_http::state::PasswordStoreImpl::Postgres(base.clone()),
        agent_auth_http::state::SessionStoreImpl::Postgres(base),
    )
    .await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_invitation_contract() {
    use agent_auth_http::adapters::aws::{
        DynamoInvitationStore, DynamoPasswordStore, DynamoSessionStore, DynamoUsersStore,
    };
    let (db, user_table) =
        super::aws_contract_database::table_with_string_index("user_id", "email-index", "email")
            .await;
    let (_, password_table) = super::aws_contract_database::table("user_id", vec![], vec![]).await;
    let (_, session_table) = super::aws_contract_database::table_with_string_index(
        "session_id",
        "user_id-index",
        "user_id",
    )
    .await;
    let (_, invite_table) = super::aws_contract_database::table("locator", vec![], vec![]).await;
    invitation_contract(
        DynamoInvitationStore::new(
            db.clone(),
            &invite_table,
            &user_table,
            &password_table,
            &session_table,
        ),
        DynamoUsersStore::new(db.clone(), &user_table),
        DynamoPasswordStore::new(db.clone(), &password_table),
        DynamoSessionStore::new(db.clone(), &session_table),
    )
    .await;
    for table in [user_table, password_table, session_table, invite_table] {
        db.delete_table().table_name(table).send().await.unwrap();
    }
}
