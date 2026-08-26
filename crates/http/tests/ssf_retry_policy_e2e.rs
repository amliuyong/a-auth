use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex},
};

use agent_auth_http::{
    adapters::memory::MemorySigner,
    security_event::{
        SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
        SecurityEventOutcome, SecuritySubject,
    },
    ssf::{
        MemorySsfStore, SignedSet, SsfDeliveryStatus, SsfRedriveOutcome, SsfStore, SsfStream,
        SsfStreamMutation, SsfStreamMutationOutcome, RISC_ACCOUNT_DISABLED_EVENT,
        SSF_MAX_ATTEMPTS_PER_CYCLE,
    },
    ssf_worker::{process_due_deliveries, SsfPushClient, SsfPushRequest, SsfPushResult},
};

#[derive(Clone)]
struct ControlledReceiver {
    outcomes: Arc<Mutex<VecDeque<SsfPushResult>>>,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl ControlledReceiver {
    fn new(outcomes: impl IntoIterator<Item = SsfPushResult>) -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            bodies: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SsfPushClient for ControlledReceiver {
    fn push(&self, request: SsfPushRequest) -> impl Future<Output = SsfPushResult> + Send {
        let outcomes = self.outcomes.clone();
        let bodies = self.bodies.clone();
        async move {
            bodies.lock().unwrap().push(request.body);
            outcomes.lock().unwrap().pop_front().unwrap()
        }
    }
}

fn event(event_id: &str) -> SecurityEvent {
    SecurityEvent::new_at(
        event_id,
        101,
        "t1",
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap()
}

async fn store() -> MemorySsfStore {
    let store = MemorySsfStore::default();
    store
        .create_stream(
            SsfStream::new(
                "t1",
                "receiver-1",
                "https://receiver.example.net/events",
                "https://receiver.example.net",
                vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                100,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    store
        .enqueue_event(
            &event("evt-retry-exhaustion"),
            "https://t1.example.com",
            110,
        )
        .await
        .unwrap();
    store
}

#[tokio::test]
async fn retryable_failures_exhaust_once_and_keep_one_stable_set() {
    let store = store().await;
    let signer = MemorySigner::from_seed([44; 32]);
    let receiver = ControlledReceiver::new(
        (0..SSF_MAX_ATTEMPTS_PER_CYCLE).map(|_| SsfPushResult::Response(503)),
    );
    let mut now = 110;
    for attempt in 1..=SSF_MAX_ATTEMPTS_PER_CYCLE {
        let stats = process_due_deliveries(&store, &signer, &receiver, now)
            .await
            .unwrap();
        if attempt == SSF_MAX_ATTEMPTS_PER_CYCLE {
            assert_eq!(stats.dead_lettered, 1);
        } else {
            assert_eq!(stats.retrying, 1);
        }
        now = store
            .list_deliveries("t1", "receiver-1", 100, None)
            .await
            .unwrap()
            .deliveries[0]
            .next_attempt_at;
    }

    let delivery = store
        .list_deliveries("t1", "receiver-1", 100, None)
        .await
        .unwrap()
        .deliveries
        .pop()
        .unwrap();
    assert_eq!(delivery.status, SsfDeliveryStatus::DeadLettered);
    assert_eq!(delivery.attempts, SSF_MAX_ATTEMPTS_PER_CYCLE);
    assert_eq!(
        delivery.attempt_history.len(),
        SSF_MAX_ATTEMPTS_PER_CYCLE as usize
    );
    assert!(store
        .acquire_due(i64::MAX / 2, 30, 10)
        .await
        .unwrap()
        .is_empty());
    let bodies = receiver.bodies.lock().unwrap();
    assert_eq!(bodies.len(), SSF_MAX_ATTEMPTS_PER_CYCLE as usize);
    assert!(bodies.iter().all(|body| body == &bodies[0]));
}

#[tokio::test]
async fn redrive_cannot_exceed_the_audited_attempt_history() {
    const MAX_AUDITED_ATTEMPTS: u32 = 64;

    let store = store().await;
    let signer = MemorySigner::from_seed([45; 32]);
    let receiver =
        ControlledReceiver::new((0..MAX_AUDITED_ATTEMPTS).map(|_| SsfPushResult::Response(503)));
    let mut now = 110;

    for cycle in 0..(MAX_AUDITED_ATTEMPTS / SSF_MAX_ATTEMPTS_PER_CYCLE) {
        for _ in 0..SSF_MAX_ATTEMPTS_PER_CYCLE {
            process_due_deliveries(&store, &signer, &receiver, now)
                .await
                .unwrap();
            now = store
                .list_deliveries("t1", "receiver-1", 100, None)
                .await
                .unwrap()
                .deliveries[0]
                .next_attempt_at;
        }
        if cycle + 1 < MAX_AUDITED_ATTEMPTS / SSF_MAX_ATTEMPTS_PER_CYCLE {
            assert!(matches!(
                store
                    .redrive_delivery("t1", "receiver-1", 1, "evt-retry-exhaustion", now,)
                    .await
                    .unwrap(),
                SsfRedriveOutcome::Redriven(_)
            ));
        }
    }

    let delivery = store
        .list_deliveries("t1", "receiver-1", 100, None)
        .await
        .unwrap()
        .deliveries
        .pop()
        .unwrap();
    assert_eq!(delivery.attempts, MAX_AUDITED_ATTEMPTS);
    assert_eq!(
        delivery.attempt_history.len(),
        MAX_AUDITED_ATTEMPTS as usize
    );
    assert_eq!(
        store
            .redrive_delivery("t1", "receiver-1", 1, "evt-retry-exhaustion", now,)
            .await
            .unwrap(),
        SsfRedriveOutcome::Expired
    );
}

#[tokio::test]
async fn concurrent_revision_mutations_have_one_winner() {
    let store = store().await;
    let left = store.mutate_stream("t1", "receiver-1", 1, SsfStreamMutation::Pause, 120);
    let right = store.mutate_stream(
        "t1",
        "receiver-1",
        1,
        SsfStreamMutation::Replace {
            endpoint: "https://replacement.example.net/events".to_string(),
            audience: "https://replacement.example.net".to_string(),
            requested_events: vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
        },
        121,
    );
    let (left, right) = tokio::join!(left, right);
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SsfStreamMutationOutcome::Updated(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                SsfStreamMutationOutcome::RevisionConflict {
                    current_revision: 2
                }
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn revocation_after_lease_fences_signing_and_suppresses_the_delivery() {
    let store = store().await;
    let lease = store.acquire_due(110, 300, 1).await.unwrap().pop().unwrap();
    store
        .mutate_stream("t1", "receiver-1", 1, SsfStreamMutation::Revoke, 111)
        .await
        .unwrap();
    assert!(!store
        .persist_signed_set(
            &lease,
            &SignedSet {
                compact_jws: "must.not.persist".to_string(),
                jti: "set-revoked".to_string(),
                kid: "kid-revoked".to_string(),
            },
            112,
            112,
        )
        .await
        .unwrap());
    assert!(store.acquire_due(411, 300, 1).await.unwrap().is_empty());
    let delivery = store
        .list_deliveries("t1", "receiver-1", 100, None)
        .await
        .unwrap()
        .deliveries
        .pop()
        .unwrap();
    assert_eq!(delivery.status, SsfDeliveryStatus::Suppressed);
    assert!(delivery.compact_set.is_none());
}
