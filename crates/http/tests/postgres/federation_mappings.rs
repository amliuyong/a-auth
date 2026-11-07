use super::{database, tenant};
use agent_auth_http::{
    adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore,
    federation_attributes::{
        FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome, MappingMode,
        MappingRegistry, MappingSpec, MappingValidationError, MAPPINGS_MAX_PER_IDP,
    },
};
use std::sync::Arc;
use tokio::sync::Barrier;

const ISSUER: &str = "https://identity.example.test";

fn spec(key: &str) -> MappingSpec {
    MappingSpec {
        source_claim: "department".into(),
        target_namespace: "https://resource.example.test/attributes".into(),
        target_key: key.into(),
        mode: MappingMode::CopyString,
    }
}

fn applied(outcome: MappingChangeOutcome) -> MappingRegistry {
    let MappingChangeOutcome::Applied(registry) = outcome else {
        panic!("expected applied registry, received {outcome:?}");
    };
    registry
}

async fn contract(store: impl FederationAttributeMappingsStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    assert_eq!(store.get_registry(&tenant, "primary").await.unwrap(), None);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        0
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .change(
                    &tenant,
                    "primary",
                    ISSUER,
                    MappingChange::Create {
                        mapping_id: "fm_primary".into(),
                        expected_registry_revision: 0,
                        spec: spec("department"),
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let MappingChangeOutcome::Applied(registry) = task.await.unwrap() {
            winners.push(registry);
        }
    }
    assert_eq!(winners.len(), 1, "one registry admission wins");
    let first = winners.remove(0);
    assert_eq!(first.revision, 1);
    assert_eq!(first.mappings.len(), 1);
    assert_eq!(first.mappings[0].revision, 1);
    assert_eq!(
        store.get_registry(&tenant, "primary").await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(store.get_registry(&other, "primary").await.unwrap(), None);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        3
    );
    assert_eq!(
        store
            .change(
                &tenant,
                "secondary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 0,
                    spec: spec("other"),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::MappingIdRetired,
        "mapping IDs are tenant-wide permanent authority",
    );
    assert_eq!(
        store
            .change(
                &tenant,
                "secondary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_secondary".into(),
                    expected_registry_revision: 0,
                    spec: spec("department"),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::TargetConflict,
    );
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        3
    );
    let invalid = store
        .change(
            &tenant,
            "primary",
            ISSUER,
            MappingChange::Update {
                mapping_id: "fm_primary".into(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: true,
                spec: spec("credential_epoch"),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        invalid,
        MappingChangeOutcome::Invalid(MappingValidationError::ReservedTargetKey)
    );
    assert_eq!(
        store.get_registry(&tenant, "primary").await.unwrap(),
        Some(first)
    );

    let disabled = applied(
        store
            .change(
                &tenant,
                "primary",
                ISSUER,
                MappingChange::SetEnabled {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 1,
                    expected_mapping_revision: 1,
                    enabled: false,
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(disabled.revision, 2);
    assert_eq!(disabled.mappings[0].revision, 2);
    assert!(!disabled.mappings[0].enabled);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        2
    );
    let secondary = applied(
        store
            .change(
                &tenant,
                "secondary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_secondary".into(),
                    expected_registry_revision: 0,
                    spec: spec("department"),
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(secondary.revision, 1);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        5
    );
    let enable = MappingChange::SetEnabled {
        mapping_id: "fm_primary".into(),
        expected_registry_revision: 2,
        expected_mapping_revision: 2,
        enabled: true,
    };
    assert_eq!(
        store
            .change(&tenant, "primary", ISSUER, enable.clone())
            .await
            .unwrap(),
        MappingChangeOutcome::TargetConflict
    );
    assert_eq!(
        store.get_registry(&tenant, "primary").await.unwrap(),
        Some(disabled)
    );
    let empty_secondary = applied(
        store
            .change(
                &tenant,
                "secondary",
                ISSUER,
                MappingChange::Delete {
                    mapping_id: "fm_secondary".into(),
                    expected_registry_revision: 1,
                    expected_mapping_revision: 1,
                },
            )
            .await
            .unwrap(),
    );
    assert!(empty_secondary.mappings.is_empty());
    let enabled = applied(
        store
            .change(&tenant, "primary", ISSUER, enable)
            .await
            .unwrap(),
    );
    assert_eq!(enabled.revision, 3);
    assert_eq!(enabled.mappings[0].revision, 3);
    assert!(enabled.mappings[0].enabled);
    let wrong_issuer = store
        .change(
            &tenant,
            "primary",
            "https://unrelated.example.test",
            MappingChange::Delete {
                mapping_id: "fm_primary".into(),
                expected_registry_revision: 3,
                expected_mapping_revision: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(wrong_issuer, MappingChangeOutcome::Conflict);

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .change(
                    &tenant,
                    "primary",
                    ISSUER,
                    MappingChange::Update {
                        mapping_id: "fm_primary".into(),
                        expected_registry_revision: 3,
                        expected_mapping_revision: 3,
                        enabled: true,
                        spec: spec("cost_center"),
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let MappingChangeOutcome::Applied(registry) = task.await.unwrap() {
            winners.push(registry);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "registry/mapping revisions fence concurrent mutation"
    );
    assert_eq!(winners[0].revision, 4);
    assert_eq!(winners[0].mappings[0].revision, 4);
    assert_eq!(winners[0].mappings[0].target_key, "cost_center");
    let empty = applied(
        store
            .change(
                &tenant,
                "primary",
                ISSUER,
                MappingChange::Delete {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 4,
                    expected_mapping_revision: 4,
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(empty.revision, 5);
    assert!(empty.mappings.is_empty());
    assert_eq!(
        store
            .change(
                &tenant,
                "primary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 5,
                    spec: spec("department"),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::MappingIdRetired,
    );
    let rebound = applied(
        store
            .change(
                &tenant,
                "primary",
                "https://replacement.example.test",
                MappingChange::Create {
                    mapping_id: "fm_replacement".into(),
                    expected_registry_revision: 5,
                    spec: spec("department"),
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(rebound.revision, 6);
    assert_eq!(rebound.upstream_issuer, "https://replacement.example.test");
    let registries = store.list_by_tenant(&tenant).await.unwrap();
    assert_eq!(registries.len(), 2);
    assert_eq!(registries[0], rebound);
    assert_eq!(registries[1], empty_secondary);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        6
    );
    let foreign = applied(
        store
            .change(
                &other,
                "primary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_primary".into(),
                    expected_registry_revision: 0,
                    spec: spec("department"),
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(foreign.tenant_id, other);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 6);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        0
    );
    assert!(store.list_by_tenant(&tenant).await.unwrap().is_empty());
    assert_eq!(
        store.get_registry(&other, "primary").await.unwrap(),
        Some(foreign)
    );
    assert_eq!(store.delete_all_by_tenant(&other).await.unwrap(), 3);

    let owners = format!("{tenant}-owners");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, barrier) = (store.clone(), owners.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .change(
                    &tenant,
                    &format!("provider-{index}"),
                    ISSUER,
                    MappingChange::Create {
                        mapping_id: format!("fm_owner_{index}"),
                        expected_registry_revision: 0,
                        spec: spec("shared-target"),
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            MappingChangeOutcome::Applied(_) => winners += 1,
            MappingChangeOutcome::TargetConflict => {}
            other => panic!("unexpected target admission: {other:?}"),
        }
    }
    assert_eq!(winners, 1, "one IdP owns the tenant-wide target");
    assert_eq!(store.list_by_tenant(&owners).await.unwrap().len(), 1);
    assert_eq!(
        store.governance_count_all_by_tenant(&owners).await.unwrap(),
        3
    );
    assert_eq!(store.delete_all_by_tenant(&owners).await.unwrap(), 3);

    let empty_idp = format!("empty-{tenant}");
    let empty_mapping_id = format!("fm_empty_{tenant}");
    let empty = applied(
        store
            .change(
                "",
                &empty_idp,
                ISSUER,
                MappingChange::Create {
                    mapping_id: empty_mapping_id.clone(),
                    expected_registry_revision: 0,
                    spec: spec(&format!("empty_{tenant}")),
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(empty.tenant_id, "");
    assert_eq!(
        store.get_registry("", &empty_idp).await.unwrap(),
        Some(empty)
    );
    assert_eq!(store.get_registry(&other, &empty_idp).await.unwrap(), None);
    assert!(applied(
        store
            .change(
                "",
                &empty_idp,
                ISSUER,
                MappingChange::Delete {
                    mapping_id: empty_mapping_id,
                    expected_registry_revision: 1,
                    expected_mapping_revision: 1,
                },
            )
            .await
            .unwrap()
    )
    .mappings
    .is_empty());

    let bounded = format!("{tenant}-bounded");
    for index in 0..MAPPINGS_MAX_PER_IDP {
        let next = applied(
            store
                .change(
                    &bounded,
                    "primary",
                    ISSUER,
                    MappingChange::Create {
                        mapping_id: format!("fm_{index:02}"),
                        expected_registry_revision: index as u64,
                        spec: spec(&format!("key_{index:02}")),
                    },
                )
                .await
                .unwrap(),
        );
        assert_eq!(next.mappings.len(), index + 1);
    }
    let before = store.get_registry(&bounded, "primary").await.unwrap();
    assert_eq!(
        store
            .change(
                &bounded,
                "primary",
                ISSUER,
                MappingChange::Create {
                    mapping_id: "fm_over_limit".into(),
                    expected_registry_revision: MAPPINGS_MAX_PER_IDP as u64,
                    spec: spec("extra"),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::LimitExceeded,
    );
    assert_eq!(
        store.get_registry(&bounded, "primary").await.unwrap(),
        before
    );
    assert_eq!(
        store.delete_all_by_tenant(&bounded).await.unwrap(),
        1 + 2 * MAPPINGS_MAX_PER_IDP
    );
}

#[tokio::test]
async fn memory_federation_mapping_contract() {
    contract(MemoryFederationAttributeMappingsStore::default()).await;
}

#[tokio::test]
async fn postgres_federation_mapping_contract() {
    contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_federation_mapping_contract() {
    use agent_auth_http::adapters::aws::DynamoFederationAttributeMappingsStore;
    let (db, table) = super::aws_contract_database::table_with_range(
        "tenant_id",
        Some("lookup_key"),
        vec![],
        vec![],
    )
    .await;
    contract(DynamoFederationAttributeMappingsStore::new(
        db.clone(),
        &table,
    ))
    .await;
    db.delete_table().table_name(table).send().await.unwrap();
}
#[tokio::test]
async fn postgres_mapping_catalog_rolls_back_and_rejects_invalid_authority() {
    use agent_auth_http::ports::StoreError;
    let store = database().await;
    let tenant = tenant();
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let create = MappingChange::Create {
        mapping_id: "fm_primary".into(),
        expected_registry_revision: 0,
        spec: spec("department"),
    };
    let constraint = format!("contract_mapping_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.federation_mapping_catalogs ADD CONSTRAINT {constraint} \
         CHECK (tenant <> '{tenant}' OR NOT ((record::JSONB->'registries') ? 'primary')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store
        .change(&tenant, "primary", ISSUER, create.clone())
        .await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.federation_mapping_catalogs DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(store.get_registry(&tenant, "primary").await.unwrap(), None);
    let physical_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM a_auth.federation_mapping_catalogs WHERE tenant = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        physical_rows, 0,
        "the failed second write must roll back its root admission"
    );
    let registry = applied(
        store
            .change(&tenant, "primary", ISSUER, create.clone())
            .await
            .unwrap(),
    );
    assert_eq!(registry.revision, 1);
    assert_eq!(
        store.governance_count_all_by_tenant(&tenant).await.unwrap(),
        3
    );
    let baseline: String = sqlx::query_scalar(
        "SELECT record FROM a_auth.federation_mapping_catalogs WHERE tenant = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    let baseline_json: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".to_owned(), "private-record-sentinel".to_owned()];
    for mutation in 0..6 {
        let mut value = baseline_json.clone();
        match mutation {
            0 => {
                value.as_object_mut().unwrap().remove("retired_mapping_ids");
            }
            1 => value["target_owners"] = serde_json::json!([]),
            2 => value["retired_mapping_ids"] = serde_json::json!([]),
            3 => value["registries"]["primary"]["tenant_id"] = "another-tenant".into(),
            4 => {
                value["registries"]["primary"]["mappings"][0]["target_key"] =
                    "credential_epoch".into()
            }
            5 => value["target_owners"][0][2]["mapping_revision"] = 2.into(),
            _ => unreachable!(),
        }
        corruptions.push(serde_json::to_string(&value).unwrap());
    }
    for corrupt in corruptions {
        sqlx::query("UPDATE a_auth.federation_mapping_catalogs SET record = $2 WHERE tenant = $1")
            .bind(&tenant)
            .bind(&corrupt)
            .execute(&pool)
            .await
            .unwrap();
        let attempts = [
            store.get_registry(&tenant, "primary").await.map(|_| ()),
            store.list_by_tenant(&tenant).await.map(|_| ()),
            store
                .governance_count_all_by_tenant(&tenant)
                .await
                .map(|_| ()),
            store
                .change(&tenant, "primary", ISSUER, create.clone())
                .await
                .map(|_| ()),
            store.delete_all_by_tenant(&tenant).await.map(|_| ()),
        ];
        for result in attempts {
            let Err(StoreError::Permanent(message)) = result else {
                panic!("a corrupt mapping snapshot must reject every read and mutation");
            };
            assert!(!message.contains("private-record-sentinel"));
        }
        let retained: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.federation_mapping_catalogs WHERE tenant = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            retained, corrupt,
            "rejection must not overwrite authority with empty defaults"
        );
    }
    let mut exhausted = baseline_json;
    exhausted["registries"]["primary"]["revision"] = u64::MAX.into();
    exhausted["registries"]["primary"]["mappings"][0]["revision"] = u64::MAX.into();
    exhausted["target_owners"][0][2]["mapping_revision"] = u64::MAX.into();
    let exhausted = serde_json::to_string(&exhausted).unwrap();
    sqlx::query("UPDATE a_auth.federation_mapping_catalogs SET record = $2 WHERE tenant = $1")
        .bind(&tenant)
        .bind(&exhausted)
        .execute(&pool)
        .await
        .unwrap();
    for change in [
        MappingChange::SetEnabled {
            mapping_id: "fm_primary".into(),
            expected_registry_revision: u64::MAX,
            expected_mapping_revision: u64::MAX,
            enabled: false,
        },
        MappingChange::Delete {
            mapping_id: "fm_primary".into(),
            expected_registry_revision: u64::MAX,
            expected_mapping_revision: u64::MAX,
        },
    ] {
        assert!(matches!(
            store.change(&tenant, "primary", ISSUER, change).await,
            Err(StoreError::Permanent(_))
        ));
        assert_eq!(
            store.governance_count_all_by_tenant(&tenant).await.unwrap(),
            3
        );
        let retained: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.federation_mapping_catalogs WHERE tenant = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            retained, exhausted,
            "exhaustion must preserve target ownership"
        );
    }
    sqlx::query("UPDATE a_auth.federation_mapping_catalogs SET record = $2 WHERE tenant = $1")
        .bind(&tenant)
        .bind(&baseline)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.get_registry(&tenant, "primary").await.unwrap(),
        Some(registry)
    );
    sqlx::query("DELETE FROM a_auth.federation_mapping_catalogs WHERE tenant = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
