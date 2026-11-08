use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::postgres::{PostgresSecurityEventFallback, PostgresStore},
    ports::StoreError,
    security_event::{
        SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
        SecurityEventDeliveryStatus, SecurityEventFallback, SecurityEventFallbackOutcome,
        SecurityEventIngress, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
    },
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

struct Fixture {
    stores: [PostgresStore; 2],
    queues: [PostgresSecurityEventFallback; 2],
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    name: String,
}

impl Fixture {
    async fn new() -> Self {
        let (first, pool, admin, name, url) = isolated_database().await;
        let second = PostgresStore::connect(&url, 8).await.unwrap();
        Self {
            queues: [
                PostgresSecurityEventFallback::new(first.clone()),
                PostgresSecurityEventFallback::new(second.clone()),
            ],
            stores: [first, second],
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

fn ingress(id: &str) -> SecurityEventIngress {
    SecurityEventIngress::new(
        SecurityEvent::new_at(
            id,
            100,
            "default",
            SecurityActor::admin("administrator"),
            Some(SecuritySubject::user("canonical-user")),
            SecurityEventCategory::UserLifecycle,
            "user.disable",
            SecurityEventOutcome::Success,
            SecurityEventCorrelation::default(),
        )
        .unwrap(),
    )
}

fn now() -> i64 {
    agent_auth_http::current_unix_secs()
}

#[tokio::test]
async fn postgres_security_fallback_coalesces_claims_and_fences_event_identity() {
    let fixture = Fixture::new().await;
    let original = ingress("evt_fallback_one");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let queue = fixture.queues[index % 2].clone();
        let original = original.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            queue.enqueue(&original).await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM a_auth.security_event_fallback")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut rebound = original.clone();
    rebound.event.outcome = SecurityEventOutcome::Denied;
    assert!(matches!(
        fixture.queues[1].enqueue(&rebound).await,
        Err(StoreError::Permanent(_))
    ));
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
    assert_eq!(leases[0].ingress().event, original.event);
    assert!(fixture.queues[1]
        .acknowledge(&leases[0], now())
        .await
        .unwrap());
    assert!(!fixture.queues[0]
        .acknowledge(&leases[0], now())
        .await
        .unwrap());
    fixture.queues[0].enqueue(&original).await.unwrap();
    assert!(fixture.queues[1]
        .claim(now(), 30, 1)
        .await
        .unwrap()
        .is_empty());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_redelivery_preserves_one_event_and_source_history() {
    let fixture = Fixture::new().await;
    let original = ingress("evt_fallback_crash");
    let at = now();
    fixture.queues[0].enqueue(&original).await.unwrap();
    let first = fixture.queues[0].claim(at, 2, 1).await.unwrap().remove(0);
    // The hot-ledger insert commits, then the process exits before queue ack.
    fixture.stores[0]
        .put_with_delivery(&first.ingress().event, &first.ingress().delivery)
        .await
        .unwrap();
    let report = fixture.queues[1].run_once(at + 3, 1).await.unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(report.persisted, 1);
    assert_eq!(report.acknowledged, 1);
    assert!(!fixture.queues[0].acknowledge(&first, at + 3).await.unwrap());
    let events = fixture.stores[1]
        .list_by_tenant("default", 100, 100, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, original.event);
    assert!(
        events[0].delivery.attempts > first.ingress().delivery.attempts,
        "redelivery extends source attempt evidence without another event"
    );
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_failed_claim_rolls_back_and_rejects_missing_counters() {
    let fixture = Fixture::new().await;
    for id in ["evt_fallback_01", "evt_fallback_02"] {
        fixture.queues[0].enqueue(&ingress(id)).await.unwrap();
    }
    sqlx::query(
        "ALTER TABLE a_auth.security_event_fallback ADD CONSTRAINT fallback_fault \
         CHECK (event_id <> 'evt_fallback_02' OR status <> 'leased')",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert!(fixture.queues[1].claim(now(), 30, 2).await.is_err());
    let leased: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM a_auth.security_event_fallback WHERE status='leased'",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(leased, 0);
    sqlx::query("ALTER TABLE a_auth.security_event_fallback DROP CONSTRAINT fallback_fault")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let record: String = sqlx::query_scalar(
        "SELECT record FROM a_auth.security_event_fallback WHERE event_id='evt_fallback_02'",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    let mut damaged: serde_json::Value = serde_json::from_str(&record).unwrap();
    damaged.as_object_mut().unwrap().remove("ingress_attempts");
    let damaged = serde_json::to_string(&damaged).unwrap();
    sqlx::query(
        "UPDATE a_auth.security_event_fallback SET record=$1 WHERE event_id='evt_fallback_02'",
    )
    .bind(&damaged)
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert!(matches!(
        fixture.queues[0].claim(now(), 30, 2).await,
        Err(StoreError::Permanent(_))
    ));
    let after: String = sqlx::query_scalar(
        "SELECT record FROM a_auth.security_event_fallback WHERE event_id='evt_fallback_02'",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(after, damaged);
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_batch_reports_each_outcome_without_losing_valid_entries() {
    let fixture = Fixture::new().await;
    let mut invalid = ingress("evt_fallback_invalid");
    invalid.event.event_id.clear();
    let outcomes = fixture.queues[0]
        .enqueue_batch(&[
            ingress("evt_fallback_valid_1"),
            invalid,
            ingress("evt_fallback_valid_2"),
        ])
        .await
        .unwrap();
    assert!(matches!(
        outcomes[0],
        SecurityEventFallbackOutcome::Enqueued
    ));
    assert!(matches!(
        outcomes[1],
        SecurityEventFallbackOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcomes[2],
        SecurityEventFallbackOutcome::Enqueued
    ));
    let report = fixture.queues[1].run_once(now(), 10).await.unwrap();
    assert_eq!(
        (report.claimed, report.persisted, report.acknowledged),
        (2, 2, 2)
    );
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_skips_locked_head_and_retains_a_new_source_during_lease() {
    let fixture = Fixture::new().await;
    let original = ingress("evt_fallback_01");
    fixture.queues[0].enqueue(&original).await.unwrap();
    fixture.queues[0]
        .enqueue(&ingress("evt_fallback_02"))
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query(
        "SELECT record FROM a_auth.security_event_fallback \
         WHERE event_id='evt_fallback_01' FOR UPDATE",
    )
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.queues[1].claim(now(), 30, 1),
    )
    .await
    .expect("locked head must not block another due row")
    .unwrap()
    .remove(0);
    assert_eq!(second.ingress().event.event_id, "evt_fallback_02");
    assert!(fixture.queues[1].acknowledge(&second, now()).await.unwrap());
    blocker.rollback().await.unwrap();
    let first = fixture.queues[0]
        .claim(now(), 30, 1)
        .await
        .unwrap()
        .remove(0);
    fixture.stores[0]
        .put_with_delivery(&first.ingress().event, &first.ingress().delivery)
        .await
        .unwrap();
    let mut newer = first.ingress().clone();
    newer
        .delivery
        .record(SecurityEventDeliveryStatus::Failed, now());
    fixture.queues[1].enqueue(&newer).await.unwrap();
    assert!(fixture.queues[1].acknowledge(&first, now()).await.unwrap());
    let report = fixture.queues[0].run_once(now(), 1).await.unwrap();
    assert_eq!(
        (report.claimed, report.persisted, report.acknowledged),
        (1, 1, 1)
    );
    let events = fixture.stores[1]
        .list_by_tenant("default", 100, 100, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].delivery.attempts > first.ingress().delivery.attempts);
    assert!(fixture.queues[1]
        .claim(now(), 30, 10)
        .await
        .unwrap()
        .is_empty());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_ack_rechecks_expiry_after_observed_database_lock_wait() {
    let fixture = Fixture::new().await;
    fixture.queues[0]
        .enqueue(&ingress("evt_fallback_expiry"))
        .await
        .unwrap();
    let at = now();
    let lease = fixture.queues[0].claim(at, 2, 1).await.unwrap().remove(0);
    let old = lease.clone();
    let deadline: i64 =
        sqlx::query_scalar("SELECT lease_until FROM a_auth.security_event_fallback")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT record FROM a_auth.security_event_fallback FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let queue = fixture.queues[1].clone();
    let task = tokio::spawn(async move { queue.acknowledge(&lease, at).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event_type='Lock' \
                 AND query LIKE '%a_auth.security_event_fallback%' \
                 AND pid<>pg_backend_pid())",
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
    let replacement = fixture.queues[1]
        .claim(now(), 30, 1)
        .await
        .unwrap()
        .remove(0);
    assert!(!fixture.queues[0].acknowledge(&old, now()).await.unwrap());
    assert!(fixture.queues[0]
        .acknowledge(&replacement, now())
        .await
        .unwrap());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_security_fallback_worker_retries_real_faults_and_retains_dead_letters() {
    let fixture = Fixture::new().await;
    let original = ingress("evt_fallback_transient");
    fixture.queues[0].enqueue(&original).await.unwrap();
    sqlx::query(
        "CREATE FUNCTION a_auth.contract_fallback_transient() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
         RAISE EXCEPTION 'contract-only' USING ERRCODE='40001'; END $$",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER contract_fallback_transient BEFORE INSERT \
         ON a_auth.security_events FOR EACH ROW \
         EXECUTE FUNCTION a_auth.contract_fallback_transient()",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    let at = now();
    for index in 0..4 {
        let report = fixture.queues[index % 2]
            .run_once(at + index as i64 * 6, 1)
            .await
            .unwrap();
        assert_eq!(
            (report.claimed, report.persisted, report.acknowledged),
            (1, 0, 0)
        );
        assert_eq!(report.retried, usize::from(index < 3));
        assert_eq!(report.dead_lettered, usize::from(index == 3));
        assert_eq!(report.authority_lost, 0);
    }
    let status: String = sqlx::query_scalar("SELECT status FROM a_auth.security_event_fallback")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "dead_lettered");
    sqlx::query("DROP TRIGGER contract_fallback_transient ON a_auth.security_events")
        .execute(&fixture.pool)
        .await
        .unwrap();
    fixture.queues[0].enqueue(&original).await.unwrap();
    assert!(fixture.queues[1]
        .claim(at + 30, 30, 1)
        .await
        .unwrap()
        .is_empty());
    // A different immutable source is admitted without reopening the old one.
    let mut repaired = original.clone();
    repaired.delivery.start_attempt(at + 30);
    repaired
        .delivery
        .record(SecurityEventDeliveryStatus::Failed, at + 30);
    repaired.ingress_attempts = 1;
    fixture.queues[1].enqueue(&repaired).await.unwrap();
    assert_eq!(
        fixture.queues[0]
            .run_once(at + 30, 1)
            .await
            .unwrap()
            .persisted,
        1
    );
    let mut collision = ingress("evt_fallback_collision");
    fixture.queues[0].enqueue(&collision).await.unwrap();
    collision.event.outcome = SecurityEventOutcome::Denied;
    fixture.stores[1].put(&collision.event).await.unwrap();
    let report = fixture.queues[1].run_once(at + 30, 1).await.unwrap();
    assert_eq!(
        (report.claimed, report.persisted, report.dead_lettered),
        (1, 0, 1)
    );
    fixture.passed().await;
}
