use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::postgres::{PostgresGovernanceQueue, PostgresStore},
    governance::GovernanceJobCommand,
    ports::{GovernanceJobQueue, StoreError},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

struct Fixture {
    stores: [PostgresStore; 2],
    queues: [PostgresGovernanceQueue; 2],
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    name: String,
}

impl Fixture {
    async fn new() -> Self {
        let (store, pool, admin, name, url) = isolated_database().await;
        let second = PostgresStore::connect(&url, 8).await.unwrap();
        Self {
            queues: [
                PostgresGovernanceQueue::new(store.clone()),
                PostgresGovernanceQueue::new(second.clone()),
            ],
            stores: [store, second],
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

fn command(job: &str) -> GovernanceJobCommand {
    GovernanceJobCommand {
        tenant_id: "queue\0tenant".into(),
        job_id: job.into(),
        expected_revision: u64::MAX,
        failure_attempt: u8::MAX,
    }
}

fn now() -> i64 {
    agent_auth_http::current_unix_secs()
}

#[tokio::test]
async fn postgres_governance_queue_coalesces_and_claims_once_across_pools() {
    let fixture = Fixture::new().await;
    let original = command("job\0one");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let queue = fixture.queues[index % 2].clone();
        let command = original.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            queue.enqueue(command).await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.governance_queue")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let queue = fixture.queues[index % 2].clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            queue.claim(now(), 30, 1).await.unwrap()
        }));
    }
    let mut leases = Vec::new();
    for task in tasks {
        leases.extend(task.await.unwrap());
    }
    assert_eq!(leases.len(), 1);
    let lease = leases.pop().unwrap();
    assert_eq!(lease.command(), &original);
    assert!(fixture.queues[1].acknowledge(&lease, now()).await.unwrap());
    assert!(!fixture.queues[0].acknowledge(&lease, now()).await.unwrap());
    assert!(fixture.queues[0]
        .claim(now(), 30, 1)
        .await
        .unwrap()
        .is_empty());
    // A later explicit wake-up can reactivate the same command. The durable
    // job revision, rather than an infinite broker dedup window, owns effects.
    fixture.queues[0].enqueue(original.clone()).await.unwrap();
    let next = fixture.queues[1].claim(now(), 30, 1).await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].command(), &original);
    assert!(!fixture.queues[0].acknowledge(&lease, now()).await.unwrap());
    assert!(fixture.queues[0]
        .acknowledge(&next[0], now())
        .await
        .unwrap());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_skips_a_locked_head() {
    let fixture = Fixture::new().await;
    for id in ["01-head", "02-next"] {
        fixture.queues[0].enqueue(command(id)).await.unwrap();
    }
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query(
        "SELECT record FROM a_auth.governance_queue \
         WHERE tenant = $1 AND job_id = $2 FOR UPDATE",
    )
    .bind(command("01-head").tenant_id.as_bytes())
    .bind(b"01-head".as_slice())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let leases = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.queues[1].claim(now(), 30, 2),
    )
    .await
    .expect("a locked head must not serialize independent workers")
    .unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].command().job_id, "02-next");
    assert!(fixture.queues[1]
        .acknowledge(&leases[0], now())
        .await
        .unwrap());
    blocker.rollback().await.unwrap();
    let head = fixture.queues[0].claim(now(), 30, 1).await.unwrap();
    assert_eq!(head[0].command().job_id, "01-head");
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_redelivers_and_preserves_inflight_wakeups() {
    let fixture = Fixture::new().await;
    let original = command("redelivery");
    fixture.queues[0].enqueue(original.clone()).await.unwrap();
    let start = now();
    let first = fixture.queues[0]
        .claim(start, 10, 1)
        .await
        .unwrap()
        .remove(0);
    assert!(fixture.queues[1]
        .claim(start + 9, 10, 1)
        .await
        .unwrap()
        .is_empty());
    let second = fixture.queues[1]
        .claim(start + 10, 10, 1)
        .await
        .unwrap()
        .remove(0);
    assert!(!fixture.queues[0]
        .acknowledge(&first, start + 10)
        .await
        .unwrap());
    assert!(!fixture.queues[0]
        .retry(&first, start + 10, 5)
        .await
        .unwrap());
    assert!(fixture.queues[1]
        .retry(&second, start + 10, 5)
        .await
        .unwrap());
    assert!(fixture.queues[0]
        .claim(start + 14, 10, 1)
        .await
        .unwrap()
        .is_empty());
    let third = fixture.queues[0]
        .claim(start + 15, 10, 1)
        .await
        .unwrap()
        .remove(0);
    fixture.queues[1].enqueue(original.clone()).await.unwrap();
    assert!(fixture.queues[0]
        .acknowledge(&third, start + 15)
        .await
        .unwrap());
    let preserved = fixture.queues[1].claim(start + 15, 10, 1).await.unwrap();
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].command(), &original);
    assert!(!fixture.queues[0]
        .acknowledge(&third, start + 15)
        .await
        .unwrap());
    assert!(fixture.queues[1]
        .acknowledge(&preserved[0], start + 15)
        .await
        .unwrap());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_rolls_back_failed_claims_and_rejects_damaged_commands() {
    let fixture = Fixture::new().await;
    fixture.queues[0].enqueue(command("01-good")).await.unwrap();
    fixture.queues[0]
        .enqueue(command("02-fault"))
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE a_auth.governance_queue ADD CONSTRAINT contract_no_second_lease \
         CHECK (job_id <> decode('30322d6661756c74', 'hex') OR status <> 'leased') NOT VALID",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert!(matches!(
        fixture.queues[1].claim(now(), 30, 2).await,
        Err(StoreError::Permanent(_))
    ));
    let leased: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.governance_queue WHERE status = 'leased'")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(leased, 0);
    sqlx::query("ALTER TABLE a_auth.governance_queue DROP CONSTRAINT contract_no_second_lease")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let original: String =
        sqlx::query_scalar("SELECT record FROM a_auth.governance_queue WHERE job_id = $1")
            .bind(b"02-fault".as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    let mut damaged: serde_json::Value = serde_json::from_str(&original).unwrap();
    damaged.as_object_mut().unwrap().remove("failure_attempt");
    let damaged = damaged.to_string();
    sqlx::query("UPDATE a_auth.governance_queue SET record = $1 WHERE job_id = $2")
        .bind(&damaged)
        .bind(b"02-fault".as_slice())
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(matches!(
        fixture.queues[0].claim(now(), 30, 2).await,
        Err(StoreError::Permanent(_))
    ));
    let after: String =
        sqlx::query_scalar("SELECT record FROM a_auth.governance_queue WHERE job_id = $1")
            .bind(b"02-fault".as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(after, damaged);
    sqlx::query("UPDATE a_auth.governance_queue SET record = $1 WHERE job_id = $2")
        .bind(&original)
        .bind(b"02-fault".as_slice())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let repaired = fixture.queues[1].claim(now(), 30, 2).await.unwrap();
    assert_eq!(repaired.len(), 2);
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_ack_rechecks_expiry_after_a_real_row_lock_wait() {
    let fixture = Fixture::new().await;
    fixture.queues[0].enqueue(command("expiry")).await.unwrap();
    let start = now();
    let lease = fixture.queues[0]
        .claim(start, 2, 1)
        .await
        .unwrap()
        .remove(0);
    let deadline: i64 = sqlx::query_scalar("SELECT lease_until FROM a_auth.governance_queue")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT record FROM a_auth.governance_queue FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let queue = fixture.queues[1].clone();
    let task = tokio::spawn(async move { queue.acknowledge(&lease, start).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock' \
                 AND query LIKE '%a_auth.governance_queue%' AND pid <> pg_backend_pid())",
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
    .expect("acknowledgment must reach the actual locked queue row");
    while now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    blocker.rollback().await.unwrap();
    assert!(!task.await.unwrap().unwrap());
    let replacement = fixture.queues[0].claim(now(), 30, 1).await.unwrap();
    assert_eq!(replacement.len(), 1);
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_worker_repairs_crash_without_repeating_a_phase() {
    use super::governance_contracts::{start_user_erasure, user_data_state};
    use agent_auth_http::{
        governance::{GovernanceJobPhase, GovernanceJobQueueImpl, GovernanceJobState},
        governance_worker::{process_command_once, run_postgres_queue_once},
        ports::{GovernanceStore, ScimUserInput, UsersStore},
    };
    let fixture = Fixture::new().await;
    let mut first = user_data_state(fixture.stores[0].clone());
    first.governance_jobs = Arc::new(GovernanceJobQueueImpl::Postgres(fixture.queues[0].clone()));
    let mut second = user_data_state(fixture.stores[1].clone());
    second.governance_jobs = Arc::new(GovernanceJobQueueImpl::Postgres(fixture.queues[1].clone()));
    let start = now();
    let user_id = "user:queue-worker@example.com";
    first
        .users
        .create_scim(
            "",
            ScimUserInput {
                user_id: user_id.into(),
                external_id: "queue-worker-external".into(),
                user_name: "queue-worker@example.com".into(),
                display_name: None,
                active: true,
                now: start,
            },
        )
        .await
        .unwrap();
    let job_id = start_user_erasure(&first, user_id).await;
    let abandoned = fixture.queues[0]
        .claim(start, 30, 1)
        .await
        .unwrap()
        .remove(0);
    // The process dies after the phase and its next wake-up commit, before ack.
    process_command_once(&first, abandoned.command().clone(), start + 1)
        .await
        .unwrap();
    let committed = first
        .governance
        .get_job("default", &job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.phase, GovernanceJobPhase::MutationFenced);
    assert_eq!(
        first
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        1
    );
    let report = run_postgres_queue_once(&second, start + 40, 1)
        .await
        .unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(report.requeued, 1);
    let repaired = second
        .governance
        .get_job("default", &job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repaired.revision, committed.revision);
    assert_eq!(repaired.phase, committed.phase);
    assert_eq!(
        second
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .credential_epoch,
        1
    );
    for index in 0..10 {
        let state = if index % 2 == 0 { &first } else { &second };
        run_postgres_queue_once(state, start + 41 + index, 8)
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
        first
            .governance
            .get_job("default", &job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        GovernanceJobState::RetentionPending
    );
    assert!(first.users.get_by_id("", user_id).await.unwrap().is_none());
    assert!(!fixture.queues[1]
        .acknowledge(&abandoned, start + 60)
        .await
        .unwrap());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_queue_worker_refuses_foreign_pool_before_claiming() {
    use super::governance_contracts::user_data_state;
    use agent_auth_http::{
        governance::GovernanceJobQueueImpl, governance_worker::run_postgres_queue_once,
    };
    let fixture = Fixture::new().await;
    fixture.queues[0]
        .enqueue(command("unclaimed"))
        .await
        .unwrap();
    let mut state = user_data_state(fixture.stores[0].clone());
    state.governance_jobs = Arc::new(GovernanceJobQueueImpl::Postgres(fixture.queues[1].clone()));
    assert!(matches!(
        run_postgres_queue_once(&state, now(), 1).await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(
        fixture.queues[0].claim(now(), 30, 1).await.unwrap().len(),
        1
    );
    fixture.passed().await;
}
