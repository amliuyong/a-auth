use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryDomainMapStore,
    ports::{DomainBinding, DomainMapStore},
};
use std::sync::Arc;
use tokio::sync::Barrier;

async fn domain_map_contract(store: impl DomainMapStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let domain = format!("{tenant}.example.test");
    let binding = DomainBinding {
        domain: domain.to_ascii_uppercase(),
        resource_id: "https://resource.example.test".into(),
        tenant_id: tenant.clone(),
        client_id: format!("client-{tenant}"),
    };
    assert!(store.put_if_absent(binding.clone()).await.unwrap());
    let mut expected = binding.clone();
    expected.domain = domain.clone();
    assert_eq!(
        store.get(&domain.to_ascii_uppercase()).await.unwrap(),
        Some(expected.clone()),
        "the authoritative domain is normalized independently of caller case"
    );
    let mut challenger = expected.clone();
    challenger.tenant_id = other.clone();
    challenger.client_id = format!("client-{other}");
    assert!(!store.put_if_absent(challenger.clone()).await.unwrap());
    assert!(!store
        .delete_if_owner(&domain, &challenger.client_id)
        .await
        .unwrap());
    assert_eq!(
        store.list_by_client(&binding.client_id).await.unwrap(),
        vec![expected.clone()]
    );
    assert!(store
        .list_by_client(&challenger.client_id)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .delete_if_owner(&domain.to_ascii_uppercase(), &binding.client_id)
        .await
        .unwrap());
    assert!(!store
        .delete_if_owner(&domain, &binding.client_id)
        .await
        .unwrap());

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, barrier, mut candidate) = (store.clone(), barrier.clone(), expected.clone());
        candidate.tenant_id = format!("{tenant}-{index}");
        candidate.client_id = format!("client-{tenant}-{index}");
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let won = store.put_if_absent(candidate.clone()).await.unwrap();
            (won, candidate)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (won, candidate) = task.await.unwrap();
        if won {
            winners.push(candidate);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "a domain has one global owner across tenants"
    );
    let winner = winners.pop().unwrap();
    assert_eq!(store.get(&domain).await.unwrap(), Some(winner.clone()));
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 0);
    assert_eq!(
        store.delete_all_by_tenant(&winner.tenant_id).await.unwrap(),
        1
    );
    assert_eq!(store.get(&domain).await.unwrap(), None);
    assert!(store.put_if_absent(challenger).await.unwrap());
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_domain_map_contract() {
    domain_map_contract(MemoryDomainMapStore::default()).await;
}

#[tokio::test]
async fn postgres_domain_map_contract() {
    domain_map_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_domain_map_contract() {
    let (db, table) = super::aws_contract_database::table_with_string_index(
        "domain",
        "client_id-index",
        "client_id",
    )
    .await;
    domain_map_contract(agent_auth_http::adapters::aws::DynamoDomainMapStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
