use super::{database, tenant};
use agent_auth_http::{adapters::memory::MemoryPolicyArtifactStore, ports::PolicyArtifactStore};
use std::sync::Arc;
use tokio::sync::Barrier;

async fn artifact_contract(store: impl PolicyArtifactStore + Clone + 'static) {
    let tenant = tenant();
    assert_eq!(store.get(&tenant, 1).await.unwrap(), None);
    store
        .put(&tenant, 1, "original".into(), "digest-1".into())
        .await
        .unwrap();
    store
        .put(&tenant, 1, "original".into(), "digest-1".into())
        .await
        .unwrap();
    assert!(
        store
            .put(&tenant, 1, "replacement".into(), "digest-2".into())
            .await
            .is_err(),
        "an activated version must continue to identify the same immutable artifact"
    );
    assert!(store
        .put(&tenant, 1, "original".into(), "changed-digest".into())
        .await
        .is_err());
    assert_eq!(
        store.get(&tenant, 1).await.unwrap(),
        Some(("original".into(), "digest-1".into()))
    );
    assert_eq!(store.get("other", 1).await.unwrap(), None);
    store
        .put("other", 1, "other".into(), "other-digest".into())
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .put(
                    &tenant,
                    2,
                    format!("candidate-{index}"),
                    format!("digest-{index}"),
                )
                .await
                .is_ok()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(
        winners, 1,
        "concurrent conflicting artifacts cannot overwrite"
    );
    let (text, digest) = store.get(&tenant, 2).await.unwrap().unwrap();
    store
        .put(&tenant, 2, text.clone(), digest.clone())
        .await
        .unwrap();
    assert_eq!(store.get(&tenant, 2).await.unwrap(), Some((text, digest)));
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(
        store.get("other", 1).await.unwrap(),
        Some(("other".into(), "other-digest".into()))
    );
    assert_eq!(store.delete_all_by_tenant("other").await.unwrap(), 1);
}

#[tokio::test]
async fn memory_policy_artifact_contract() {
    artifact_contract(MemoryPolicyArtifactStore::default()).await;
}

#[tokio::test]
async fn postgres_policy_artifact_contract() {
    artifact_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_policy_artifact_contract() {
    let (db, table) = super::aws_contract_database::table("grant_id", vec![], vec![]).await;
    artifact_contract(
        agent_auth_http::adapters::aws::DynamoPolicyArtifactStore::new(db.clone(), &table),
    )
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
