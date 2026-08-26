use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex},
};

use agent_auth_http::{
    adapters::memory::MemorySigner,
    ports::Signer,
    security_event::{
        SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
        SecurityEventOutcome, SecuritySubject,
    },
    ssf::{MemorySsfStore, SsfDeliveryStatus, SsfStore, SsfStream, RISC_ACCOUNT_DISABLED_EVENT},
    ssf_worker::{process_due_deliveries, SsfPushClient, SsfPushRequest, SsfPushResult},
    tenant_keys::{TenantKeyRegistry, TenantKeyRegistryImpl, TenantKeyService},
};
use agent_auth_infra_core::{EcPublicJwk, RsaPublicJwk, TenantKeyAlgorithm, TenantKeyRecord};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone)]
struct ControlledReceiver {
    outcomes: Arc<Mutex<VecDeque<SsfPushResult>>>,
    requests: Arc<Mutex<Vec<SsfPushRequest>>>,
}

impl ControlledReceiver {
    fn new(outcomes: impl IntoIterator<Item = SsfPushResult>) -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SsfPushClient for ControlledReceiver {
    fn push(&self, request: SsfPushRequest) -> impl Future<Output = SsfPushResult> + Send {
        let outcomes = self.outcomes.clone();
        let requests = self.requests.clone();
        async move {
            requests.lock().unwrap().push(request);
            outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("configured receiver outcome")
        }
    }
}

fn account_disabled(event_id: &str, occurred_at: i64) -> SecurityEvent {
    account_disabled_for_tenant("t1", event_id, occurred_at)
}

fn account_disabled_for_tenant(tenant_id: &str, event_id: &str, occurred_at: i64) -> SecurityEvent {
    SecurityEvent::new_at(
        event_id,
        occurred_at,
        tenant_id,
        SecurityActor::admin("admin:operator"),
        Some(SecuritySubject::user("user:alice@example.com")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap()
}

async fn store_with_delivery(event_id: &str) -> MemorySsfStore {
    let store = MemorySsfStore::default();
    store
        .create_stream(
            SsfStream::new(
                "t1",
                "stream-worker",
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
            &account_disabled(event_id, 101),
            "https://t1.example.com",
            110,
        )
        .await
        .unwrap();
    store
}

async fn install_tenant_signer(service: &TenantKeyService, tenant: &str, seed: u8) -> String {
    let signer = MemorySigner::from_seed([seed; 32]);
    let ec = signer.public_jwks().await.unwrap().remove(0);
    let rsa = signer.public_rsa_jwks().await.unwrap().remove(0);
    let expected_kid = ec.kid.clone();
    let operation = format!("onboard-{tenant}");
    let mut record = TenantKeyRecord::begin_onboarding(tenant, &operation, 1).unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Es256,
            format!("arn:{tenant}:ec"),
            2,
        )
        .unwrap();
    record
        .record_verified_ec(
            &operation,
            EcPublicJwk {
                x: ec.x,
                y: ec.y,
                kid: ec.kid,
            },
            3,
        )
        .unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Rs256,
            format!("arn:{tenant}:rsa"),
            4,
        )
        .unwrap();
    record
        .record_verified_rsa(
            &operation,
            RsaPublicJwk {
                n: rsa.n,
                e: rsa.e,
                kid: rsa.kid,
            },
            5,
        )
        .unwrap();
    record.publish_candidate(&operation, 6).unwrap();
    match service.registry() {
        TenantKeyRegistryImpl::Memory(registry) => {
            assert!(registry.create(record).await.unwrap());
        }
        #[cfg(feature = "aws")]
        TenantKeyRegistryImpl::Dynamo(_) => panic!("expected memory registry"),
    }
    service
        .install_memory_signer(&format!("arn:{tenant}:ec"), signer)
        .await;
    expected_kid
}

#[tokio::test]
async fn timeout_retry_reuses_the_exact_compact_set_until_202() {
    let store = store_with_delivery("evt_worker_retry").await;
    let signer = MemorySigner::from_seed([27; 32]);
    let receiver = ControlledReceiver::new([
        SsfPushResult::NetworkError("timeout".to_string()),
        SsfPushResult::Response(202),
    ]);

    let first = process_due_deliveries(&store, &signer, &receiver, 110)
        .await
        .unwrap();
    assert_eq!(first.retrying, 1);
    let retry_at = store
        .list_deliveries("t1", "stream-worker", 100, None)
        .await
        .unwrap()
        .deliveries[0]
        .next_attempt_at;
    let second = process_due_deliveries(&store, &signer, &receiver, retry_at)
        .await
        .unwrap();
    assert_eq!(second.delivered, 1);

    let requests = receiver.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].content_type, "application/secevent+jwt");
    assert_eq!(requests[0].endpoint, "https://receiver.example.net/events");
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(
        store
            .list_deliveries("t1", "stream-worker", 100, None)
            .await
            .unwrap()
            .deliveries[0]
            .status,
        SsfDeliveryStatus::Delivered
    );
}

#[tokio::test]
async fn receiver_400_is_terminal_and_not_automatically_retried() {
    let store = store_with_delivery("evt_worker_terminal").await;
    let signer = MemorySigner::from_seed([28; 32]);
    let receiver = ControlledReceiver::new([SsfPushResult::Response(400)]);

    let stats = process_due_deliveries(&store, &signer, &receiver, 110)
        .await
        .unwrap();
    assert_eq!(stats.terminal, 1);
    assert!(process_due_deliveries(&store, &signer, &receiver, 10_000)
        .await
        .unwrap()
        .is_idle());
}

#[tokio::test]
async fn one_pass_drains_a_full_tenant_stream_fanout_without_starving_another_tenant() {
    let store = MemorySsfStore::default();
    for index in 0..32 {
        store
            .create_stream(
                SsfStream::new(
                    "t1",
                    format!("t1-stream-{index:02}"),
                    format!("https://receiver-{index:02}.example.net/events"),
                    format!("urn:receiver:t1:{index}"),
                    vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    store
        .create_stream(
            SsfStream::new(
                "t2",
                "t2-stream",
                "https://receiver-t2.example.net/events",
                "urn:receiver:t2",
                vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                100,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .enqueue_event(
                &account_disabled_for_tenant("t1", "evt-t1-fanout", 101),
                "https://t1.example.com",
                110,
            )
            .await
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        store
            .enqueue_event(
                &account_disabled_for_tenant("t2", "evt-t2-fanout", 101),
                "https://t2.example.com",
                110,
            )
            .await
            .unwrap()
            .len(),
        1
    );

    let signer = MemorySigner::from_seed([29; 32]);
    let receiver = ControlledReceiver::new((0..33).map(|_| SsfPushResult::Response(202)));
    let stats = process_due_deliveries(&store, &signer, &receiver, 110)
        .await
        .unwrap();
    assert_eq!(stats.acquired, 33);
    assert_eq!(stats.delivered, 33);
    assert!(receiver
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|request| request.endpoint == "https://receiver-t2.example.net/events"));
}

#[tokio::test]
async fn saas_worker_signs_each_delivery_with_its_tenant_key() {
    let store = MemorySsfStore::default();
    for tenant in ["t1", "t2"] {
        store
            .create_stream(
                SsfStream::new(
                    tenant,
                    format!("{tenant}-stream"),
                    format!("https://receiver-{tenant}.example.net/events"),
                    format!("urn:receiver:{tenant}"),
                    vec![RISC_ACCOUNT_DISABLED_EVENT.to_string()],
                    100,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        store
            .enqueue_event(
                &account_disabled_for_tenant(tenant, &format!("evt-{tenant}"), 101),
                &format!("https://{tenant}.example.com"),
                110,
            )
            .await
            .unwrap();
    }
    let service = TenantKeyService::memory();
    let t1_kid = install_tenant_signer(&service, "t1", 51).await;
    let t2_kid = install_tenant_signer(&service, "t2", 52).await;
    let receiver =
        ControlledReceiver::new([SsfPushResult::Response(202), SsfPushResult::Response(202)]);

    let stats = process_due_deliveries(&store, &service, &receiver, 110)
        .await
        .unwrap();
    assert_eq!(stats.delivered, 2);
    let requests = receiver.requests.lock().unwrap();
    for request in requests.iter() {
        let header = request.body.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let expected = if request.endpoint.contains("receiver-t1") {
            &t1_kid
        } else {
            &t2_kid
        };
        assert_eq!(header["kid"], expected.as_str());
    }
    assert_ne!(t1_kid, t2_kid);
}
