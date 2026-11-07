use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        memory::MemoryOutboxNotifier, mounted_crypto::EncryptionKeyring,
        postgres::PostgresMessageOutbox,
    },
    ports::{MessageOutbox, Notifier, SentMessage, StoreError},
};
use std::sync::Arc;
use tokio::sync::Barrier;

// The delivery-observation writer is the real public storage seam. This
// fixture supplies notifications without claiming SMTP delivery acceptance.
#[derive(Clone)]
struct ObservedNotificationFixture(PostgresMessageOutbox);

impl Notifier for ObservedNotificationFixture {
    async fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        self.0
            .record_delivered(SentMessage {
                message_id: format!("message-{:032x}", rand::random::<u128>()),
                tenant: tenant.into(),
                kind: "magic_link".into(),
                recipient: email.into(),
                body: link_url.into(),
                created_at: 100,
                ttl: 86_500,
            })
            .await?;
        Ok(())
    }

    async fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        self.0
            .record_delivered(SentMessage {
                message_id: format!("recovery#{notification_id}"),
                tenant: tenant.into(),
                kind: "recovery".into(),
                recipient: recipient_email.into(),
                body: format!(
                    "account recovered at={recovered_at} ip={}",
                    client_ip.unwrap_or("-")
                ),
                created_at: 100,
                ttl: 86_500,
            })
            .await?;
        Ok(())
    }
}

async fn outbox_contract(outbox: impl MessageOutbox + Clone + 'static, notifier: impl Notifier) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(outbox.list_recent(&tenant, 0).await.unwrap(), vec![]);
    for actor in 0..16 {
        notifier
            .send_magic_link(
                &tenant,
                "person@example.test",
                &format!("https://issuer.example.test/login?secret=sentinel-{actor}"),
            )
            .await
            .unwrap();
    }
    for _ in 0..2 {
        notifier
            .notify_recovery(
                &tenant,
                "operation",
                "recovered@example.test",
                100,
                Some("192.0.2.1"),
            )
            .await
            .unwrap();
    }
    notifier
        .send_magic_link(&foreign, "person@example.test", "foreign-secret-sentinel")
        .await
        .unwrap();
    let all = outbox.list_recent(&tenant, 64).await.unwrap();
    assert_eq!(all.len(), 17);
    assert!(all.iter().all(|m| m.tenant == tenant));
    assert_eq!(all.iter().filter(|m| m.kind == "recovery").count(), 1);
    let mut sorted = all.clone();
    sorted.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(b.message_id.cmp(&a.message_id))
    });
    assert_eq!(all, sorted);
    assert_eq!(
        outbox.list_recent(&tenant, 3).await.unwrap(),
        all[..3],
        "apply the limit after sorting the complete tenant selection"
    );
    assert_eq!(outbox.list_recent(&foreign, 64).await.unwrap().len(), 1);
    assert_eq!(outbox.delete_by_recipients(&tenant, &[]).await.unwrap(), 0);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (outbox, tenant, barrier) = (outbox.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            outbox
                .delete_by_recipients(&tenant, &["recovered@example.test".into()])
                .await
                .unwrap()
        }));
    }
    let mut deleted = 0;
    for task in tasks {
        deleted += task.await.unwrap();
    }
    assert_eq!(deleted, 1, "count rows actually removed by each invocation");
    assert_eq!(outbox.list_recent(&tenant, 64).await.unwrap().len(), 16);
    assert_eq!(outbox.list_recent(&foreign, 64).await.unwrap().len(), 1);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (outbox, tenant, barrier) = (outbox.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            outbox.delete_all_by_tenant(&tenant).await.unwrap()
        }));
    }
    let mut deleted = 0;
    for task in tasks {
        deleted += task.await.unwrap();
    }
    assert_eq!(deleted, 16);
    assert_eq!(outbox.list_recent(&tenant, 64).await.unwrap(), vec![]);
    assert_eq!(outbox.list_recent(&foreign, 64).await.unwrap().len(), 1);
    assert_eq!(outbox.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(outbox.delete_all_by_tenant(&foreign).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_outbox_contract() {
    let store = MemoryOutboxNotifier::default();
    outbox_contract(store.clone(), store).await;
}

#[tokio::test]
async fn postgres_outbox_contract() {
    let store = PostgresMessageOutbox::new(
        database().await,
        EncryptionKeyring::new("outbox-key", vec![("outbox-key".into(), [0x61; 32])]).unwrap(),
    );
    outbox_contract(store.clone(), ObservedNotificationFixture(store)).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_outbox_contract() {
    use agent_auth_http::adapters::aws::DynamoNotifier;
    let (db, table) = super::aws_contract_database::table("message_id", vec![], vec![]).await;
    let store = DynamoNotifier::new(db.clone(), &table);
    outbox_contract(store.clone(), store).await;
    db.delete_table().table_name(&table).send().await.unwrap();
}
