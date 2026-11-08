use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::{
        mounted_crypto::EncryptionKeyring,
        postgres::{
            PostgresMessageOutbox, PostgresSmtpNotifier, PostgresStore, PostgresUsersStore,
            UserAuthorityKey,
        },
        smtp::{SmtpRelay, SmtpRelayConfig, SmtpTlsMode},
    },
    ports::{MessageOutbox, Notifier, StoreError},
};
use std::sync::Arc;
use tokio::sync::Barrier;

struct Fixture {
    stores: [PostgresStore; 2],
    notifiers: [PostgresSmtpNotifier; 2],
    outbox: PostgresMessageOutbox,
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    name: String,
}

impl Fixture {
    async fn new() -> Self {
        let (first, pool, admin, name, url) = isolated_database().await;
        let second = PostgresStore::connect(&url, 8).await.unwrap();
        let keys =
            EncryptionKeyring::new("smtp-test", vec![("smtp-test".into(), [0x71; 32])]).unwrap();
        let relay = SmtpRelay::new(SmtpRelayConfig {
            host: "smtp.example.invalid".into(),
            port: 465,
            tls: SmtpTlsMode::Implicit,
            from: "sender@example.com".into(),
            root_ca_pem: None,
            credentials: None,
        })
        .unwrap();
        let notifier = |store: PostgresStore| {
            let users =
                PostgresUsersStore::new(store.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
            PostgresSmtpNotifier::new(store, users, keys.clone(), relay.clone()).unwrap()
        };
        Self {
            stores: [first.clone(), second.clone()],
            notifiers: [notifier(first.clone()), notifier(second)],
            outbox: PostgresMessageOutbox::new(first, keys),
            pool,
            admin,
            name,
        }
    }

    async fn passed(self) {
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .unwrap();
    }
}

fn now() -> i64 {
    agent_auth_http::current_unix_secs()
}

#[tokio::test]
async fn postgres_smtp_recovery_operation_coalesces_across_pools_and_cannot_be_rebound() {
    let fixture = Fixture::new().await;
    let at = now();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let notifier = fixture.notifiers[index % 2].clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            notifier
                .notify_recovery("", "opaque-operation", "person@example.com", at, None)
                .await
                .unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert!(matches!(
        fixture.notifiers[1]
            .notify_recovery("", "opaque-operation", "different@example.com", at, None)
            .await,
        Err(StoreError::Permanent(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(fixture.outbox.list_recent("", 10).await.unwrap().is_empty());
    let first = fixture.notifiers[0].claim(at, 30, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    assert!(fixture.notifiers[1]
        .claim(at, 30, 1)
        .await
        .unwrap()
        .is_empty());
    let permit = fixture.notifiers[1]
        .prepare_send(&first[0], at)
        .await
        .unwrap()
        .unwrap();
    assert!(fixture.notifiers[0]
        .prepare_send(&first[0], at)
        .await
        .unwrap()
        .is_none());
    // This is a journal/observation fixture, not a claimed SMTP acceptance.
    assert!(fixture.notifiers[0]
        .record_acceptance(&permit)
        .await
        .unwrap());
    assert!(!fixture.notifiers[1]
        .record_acceptance(&permit)
        .await
        .unwrap());
    assert_eq!(fixture.outbox.list_recent("", 10).await.unwrap().len(), 1);
    fixture.notifiers[1]
        .notify_recovery("", "opaque-operation", "person@example.com", at, None)
        .await
        .unwrap();
    assert!(fixture.notifiers[0]
        .claim(at + 60, 30, 1)
        .await
        .unwrap()
        .is_empty());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_reclaims_only_before_submission_and_preserves_uncertain_authority() {
    let fixture = Fixture::new().await;
    let at = now();
    fixture.notifiers[0]
        .notify_recovery("", "operation", "person@example.com", at, None)
        .await
        .unwrap();
    let first = fixture.notifiers[0].claim(at, 2, 1).await.unwrap();
    let second = fixture.notifiers[1].claim(at + 3, 2, 1).await.unwrap();
    assert_eq!(second.len(), 1);
    assert!(fixture.notifiers[0]
        .prepare_send(&first[0], at + 3)
        .await
        .unwrap()
        .is_none());
    let permit = fixture.notifiers[1]
        .prepare_send(&second[0], at + 3)
        .await
        .unwrap()
        .unwrap();
    // A crash after submission admission never causes an automatic second
    // submission. Neither expired leases nor repeated calls reopen it.
    assert!(fixture.notifiers[0]
        .claim(at + 1000, 30, 1)
        .await
        .unwrap()
        .is_empty());
    assert!(fixture.notifiers[0]
        .record_uncertainty(&permit)
        .await
        .unwrap());
    fixture.notifiers[1]
        .notify_recovery("", "operation", "person@example.com", at, None)
        .await
        .unwrap();
    assert!(fixture.notifiers[1]
        .claim(at + 1001, 30, 1)
        .await
        .unwrap()
        .is_empty());
    assert!(fixture.outbox.list_recent("", 10).await.unwrap().is_empty());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_acceptance_and_observation_roll_back_together() {
    let fixture = Fixture::new().await;
    let at = now();
    fixture.notifiers[0]
        .notify_recovery("", "operation", "person@example.com", at, None)
        .await
        .unwrap();
    let lease = fixture.notifiers[0].claim(at, 30, 1).await.unwrap();
    let permit = fixture.notifiers[0]
        .prepare_send(&lease[0], at)
        .await
        .unwrap()
        .unwrap();
    sqlx::query("ALTER TABLE a_auth.message_outbox ADD CONSTRAINT smtp_fault CHECK (FALSE)")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(fixture.notifiers[1]
        .record_acceptance(&permit)
        .await
        .is_err());
    let status: String = sqlx::query_scalar("SELECT status FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "sending");
    assert!(fixture.outbox.list_recent("", 10).await.unwrap().is_empty());
    sqlx::query("ALTER TABLE a_auth.message_outbox DROP CONSTRAINT smtp_fault")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(fixture.notifiers[1]
        .record_acceptance(&permit)
        .await
        .unwrap());
    assert_eq!(fixture.outbox.list_recent("", 10).await.unwrap().len(), 1);
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_recipient_erasure_removes_pending_and_inflight_authority() {
    let fixture = Fixture::new().await;
    let at = now();
    for operation in ["first", "second"] {
        fixture.notifiers[0]
            .notify_recovery("", operation, "person@example.com", at, None)
            .await
            .unwrap();
    }
    let lease = fixture.notifiers[0].claim(at, 30, 1).await.unwrap();
    let permit = fixture.notifiers[0]
        .prepare_send(&lease[0], at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture
            .outbox
            .delete_by_recipients("", &["person@example.com".into()])
            .await
            .unwrap(),
        2
    );
    assert!(!fixture.notifiers[1]
        .record_acceptance(&permit)
        .await
        .unwrap());
    assert!(fixture.notifiers[0]
        .claim(at, 30, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(fixture.outbox.list_recent("", 10).await.unwrap().is_empty());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_corrupt_encrypted_authority_is_not_overwritten_or_claimed() {
    let fixture = Fixture::new().await;
    let at = now();
    fixture.notifiers[0]
        .notify_recovery("", "operation", "person@example.com", at, None)
        .await
        .unwrap();
    sqlx::query("UPDATE a_auth.smtp_notifications SET kid = 'unknown-key'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let before: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert!(matches!(
        fixture.notifiers[1]
            .notify_recovery("", "operation", "person@example.com", at, None)
            .await,
        Err(StoreError::Permanent(_))
    ));
    // SQLx queues rollback when the failed admission's transaction is dropped.
    // Wait for that actual row lock to clear before testing a different pool's
    // SKIP LOCKED claim; otherwise a valid skip looks like a decode success.
    let released: String =
        sqlx::query_scalar("SELECT status FROM a_auth.smtp_notifications FOR UPDATE")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(released, "pending");
    assert!(matches!(
        fixture.notifiers[0].claim(at, 30, 1).await,
        Err(StoreError::Permanent(_))
    ));
    let after: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    let status: String = sqlx::query_scalar("SELECT status FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "pending");
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_submission_rechecks_expiry_after_an_actual_row_lock_wait() {
    use std::time::Duration;
    let fixture = Fixture::new().await;
    let at = now();
    fixture.notifiers[0]
        .notify_recovery("", "operation", "person@example.com", at, None)
        .await
        .unwrap();
    let lease = fixture.notifiers[0]
        .claim(at, 2, 1)
        .await
        .unwrap()
        .remove(0);
    let deadline: i64 = sqlx::query_scalar("SELECT lease_until FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT status FROM a_auth.smtp_notifications FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let notifier = fixture.notifiers[1].clone();
    let task = tokio::spawn(async move { notifier.prepare_send(&lease, at).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock' \
                 AND query LIKE '%a_auth.smtp_notifications%' AND pid <> pg_backend_pid())",
            )
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("submission admission must reach the locked notification row");
    while now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    blocker.rollback().await.unwrap();
    assert!(task.await.unwrap().unwrap().is_none());
    assert_eq!(
        fixture.notifiers[0]
            .claim(now(), 30, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_smtp_governance_erasure_removes_jobs_and_fences_late_observations() {
    use super::governance_contracts::{
        attach_resource_backend, start_user_erasure, user_data_state,
    };
    use agent_auth_http::{
        governance::GovernanceJobState,
        governance_worker::advance_user_erasure_once,
        ports::{GovernanceStore, UsersStore},
    };
    let fixture = Fixture::new().await;
    // Explicit development control/transports and complete PostgreSQL user
    // data authority; this is not a production factory or cluster receipt.
    let mut state = user_data_state(fixture.stores[0].clone());
    let resource_root = attach_resource_backend(&mut state, fixture.stores[0].clone());
    let at = now();
    let email = "smtp-erasure@example.com";
    let user_id = "user:smtp-erasure@example.com";
    state
        .users
        .create_or_get_by_email("", email, user_id, at)
        .await
        .unwrap();
    fixture.notifiers[0]
        .notify_recovery("", "erasure-operation", email, at, None)
        .await
        .unwrap();
    fixture.notifiers[1]
        .send_magic_link("", email, "https://issuer.example.com/login?secret=fixture")
        .await
        .unwrap();
    let lease = fixture.notifiers[0]
        .claim(at, 30, 1)
        .await
        .unwrap()
        .remove(0);
    let permit = fixture.notifiers[0]
        .prepare_send(&lease, at)
        .await
        .unwrap()
        .unwrap();
    let job_id = start_user_erasure(&state, user_id).await;
    for index in 0..12 {
        advance_user_erasure_once(&state, "default", &job_id, at + index)
            .await
            .unwrap();
        if state
            .governance
            .get_job("default", &job_id)
            .await
            .unwrap()
            .unwrap()
            .state
            == GovernanceJobState::RetentionPending
        {
            break;
        }
    }
    assert_eq!(
        state
            .governance
            .get_job("default", &job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        GovernanceJobState::RetentionPending
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.smtp_notifications")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    assert!(!fixture.notifiers[1]
        .record_acceptance(&permit)
        .await
        .unwrap());
    assert!(fixture.outbox.list_recent("", 10).await.unwrap().is_empty());
    assert!(matches!(
        fixture.notifiers[1]
            .notify_recovery("", "erasure-operation", email, at, None)
            .await,
        Err(StoreError::Permanent(_))
    ));
    fixture.passed().await;
    std::fs::remove_dir_all(resource_root).unwrap();
}
