use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        memory::MemoryUsersStore,
        postgres::{PostgresUsersStore, UserAuthorityKey},
    },
    ports::{
        AttributeMigrationOutcome, CredentialChangeOwner, CredentialChangeStart, DisableStart,
        EnableOutcome, PutAttrOutcome, ScimCreateLifecycleStart, ScimCreateOutcome,
        ScimReplaceInput, ScimReplaceOutcome, ScimUserInput, UserListStatusFilter, UserStatus,
        UsersStore,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio::sync::Barrier;

async fn user_contract(store: impl UsersStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    let email = format!("person@{tenant}.example.test");
    let id = format!("user:{email}");
    assert_eq!(store.get_by_email(&tenant, &email).await.unwrap(), None);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, email, id, barrier) = (
            store.clone(),
            tenant.clone(),
            email.clone(),
            id.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .create_or_get_by_email(&tenant, &email, &id, 100)
                .await
                .unwrap()
        }));
    }
    let first = tasks.remove(0).await.unwrap();
    for task in tasks {
        assert_eq!(task.await.unwrap(), first);
    }
    assert_eq!(first.user_id, id);
    assert_eq!(first.email, email);
    assert_eq!(first.created_at, 100);
    assert_eq!(first.status, UserStatus::Active);
    assert_eq!(
        store
            .create_or_get_by_email(&tenant, &email, "another-id", 200)
            .await
            .unwrap(),
        first,
        "email retries preserve the canonical identity and creation time",
    );
    assert_eq!(store.get_by_id(&other, &id).await.unwrap(), None);
    assert_eq!(store.get_by_email(&other, &email).await.unwrap(), None);
    assert!(store
        .create_or_get_by_email(&tenant, "another@example.test", &id, 200)
        .await
        .is_err());
    store.touch_last_login(&tenant, &id, 110).await.unwrap();
    store.touch_last_login(&tenant, &id, 105).await.unwrap();
    assert_eq!(
        store
            .get_by_id(&tenant, &id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at,
        Some(110)
    );

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, id, barrier) =
            (store.clone(), tenant.clone(), id.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            let operation = format!("credential-{index}");
            barrier.wait().await;
            let outcome = store
                .begin_credential_change(&tenant, &id, 0, &operation, 120)
                .await
                .unwrap();
            (operation, outcome)
        }));
    }
    let mut owners = Vec::new();
    for task in tasks {
        let (owner, outcome) = task.await.unwrap();
        match outcome {
            CredentialChangeStart::Started { epoch: 1 } => owners.push(owner),
            CredentialChangeStart::ConcurrentChange => {}
            other => panic!("unexpected credential admission: {other:?}"),
        }
    }
    assert_eq!(owners.len(), 1);
    let owner = owners.remove(0);
    assert_eq!(
        store
            .begin_credential_change(&tenant, &id, 0, &owner, 121)
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );
    assert!(!store
        .complete_credential_change(
            &tenant,
            &id,
            CredentialChangeOwner {
                epoch: 1,
                operation_id: "wrong-owner"
            },
            122,
        )
        .await
        .unwrap());
    assert!(!store
        .recover_expired_credential_change(&tenant, &id, 1, 119, 122)
        .await
        .unwrap());
    assert!(store
        .complete_credential_change(
            &tenant,
            &id,
            CredentialChangeOwner {
                epoch: 1,
                operation_id: &owner
            },
            123,
        )
        .await
        .unwrap());
    assert!(!store
        .complete_credential_change(
            &tenant,
            &id,
            CredentialChangeOwner {
                epoch: 1,
                operation_id: &owner
            },
            124,
        )
        .await
        .unwrap());

    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, id, barrier) =
            (store.clone(), tenant.clone(), id.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.begin_disable(&tenant, &id, 130).await.unwrap()
        }));
    }
    for task in tasks {
        let DisableStart::Ready { epoch: 2, record } = task.await.unwrap() else {
            panic!("disable retries must share one generation");
        };
        assert_eq!(record.status, UserStatus::Disabled);
        assert!(record.revocation_pending);
    }
    assert_eq!(
        store.enable_completed(&tenant, &id, 2, 131).await.unwrap(),
        EnableOutcome::RevocationPending
    );
    assert!(!store.complete_disable(&tenant, &id, 1, 132).await.unwrap());
    assert!(store.complete_disable(&tenant, &id, 2, 133).await.unwrap());
    assert_eq!(
        store.enable_completed(&tenant, &id, 1, 134).await.unwrap(),
        EnableOutcome::ConcurrentChange
    );
    assert!(matches!(
        store.enable_completed(&tenant, &id, 2, 135).await.unwrap(),
        EnableOutcome::Enabled(_)
    ));

    let namespace = "https://resource.example.test/attributes";
    let alias = "https://resource.example.test/alias";
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, id, barrier) =
            (store.clone(), tenant.clone(), id.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            let values = BTreeMap::from([("role".into(), format!("role-{index}"))]);
            barrier.wait().await;
            let outcome = store
                .put_attributes(&tenant, &id, namespace, values.clone(), 0)
                .await
                .unwrap();
            (values, outcome)
        }));
    }
    let mut values = Vec::new();
    for task in tasks {
        let (value, outcome) = task.await.unwrap();
        match outcome {
            PutAttrOutcome::Ok { revision: 1 } => values.push(value),
            PutAttrOutcome::RevisionConflict { current: 1 } => {}
            other => panic!("unexpected attribute admission: {other:?}"),
        }
    }
    assert_eq!(values.len(), 1);
    let value = values.remove(0);
    assert_eq!(
        store
            .put_attributes(&tenant, &id, namespace, value.clone(), 0)
            .await
            .unwrap(),
        PutAttrOutcome::Ok { revision: 1 }
    );
    let snapshot = store.get_by_id(&tenant, &id).await.unwrap().unwrap();
    assert_eq!(snapshot.attributes_generation, 1);
    assert_eq!(
        store
            .put_attributes(
                &tenant,
                &id,
                namespace,
                BTreeMap::from([("large".into(), "x".repeat(4097))]),
                1
            )
            .await
            .unwrap(),
        PutAttrOutcome::TooLarge,
    );
    assert_eq!(
        store.get_by_id(&tenant, &id).await.unwrap().unwrap(),
        snapshot
    );
    assert_eq!(
        store
            .put_attributes(&tenant, &id, alias, value.clone(), 0)
            .await
            .unwrap(),
        PutAttrOutcome::Ok { revision: 1 }
    );
    let sources = BTreeSet::from([alias.into()]);
    assert_eq!(
        store
            .migrate_attributes(&tenant, &id, namespace, &sources)
            .await
            .unwrap(),
        AttributeMigrationOutcome::Migrated { generation: 3 }
    );
    assert_eq!(
        store
            .migrate_attributes(&tenant, &id, namespace, &sources)
            .await
            .unwrap(),
        AttributeMigrationOutcome::Noop
    );
    let migrated = store.get_by_id(&tenant, &id).await.unwrap().unwrap();
    assert_eq!(migrated.attributes[namespace].kv, value);
    assert!(!migrated.attributes.contains_key(alias));

    let legacy = "legacy-disabled";
    store
        .create_or_get_by_id(&tenant, legacy, 100)
        .await
        .unwrap();
    assert!(store
        .set_status(&tenant, legacy, UserStatus::Disabled, 140)
        .await
        .unwrap());
    let repaired = store
        .begin_legacy_disable_cleanup(&tenant, legacy, 141)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repaired.credential_epoch, 1);
    assert!(repaired.revocation_pending);
    assert!(store
        .begin_legacy_disable_cleanup(&tenant, legacy, 142)
        .await
        .unwrap()
        .is_none());
    assert!(!store.recover_expired_credential_change(&tenant, legacy, 1, 200, 201).await.unwrap(),
        "a pending legacy row without operation ownership cannot be recovered as a credential change");
    assert!(store
        .complete_disable(&tenant, legacy, 1, 143)
        .await
        .unwrap());
    assert!(matches!(
        store
            .enable_completed(&tenant, legacy, 1, 144)
            .await
            .unwrap(),
        EnableOutcome::Enabled(_)
    ));

    let federation_id = "user:fed:opaque-subject";
    let federation = store
        .create_or_get_by_id(&tenant, federation_id, 101)
        .await
        .unwrap();
    assert!(federation.email.is_empty());
    assert_eq!(
        store
            .create_or_get_by_id(&tenant, federation_id, 999)
            .await
            .unwrap(),
        federation
    );
    assert!(store
        .delete_erased_identity(&tenant, federation_id, 1)
        .await
        .is_err());
    let fenced = store
        .fence_for_erasure(&tenant, federation_id, 1, 150)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fenced.status, UserStatus::Tombstoned);
    assert_eq!(
        store
            .fence_for_erasure(&tenant, federation_id, 1, 151)
            .await
            .unwrap(),
        Some(fenced)
    );
    assert!(store
        .fence_for_erasure(&tenant, federation_id, 2, 152)
        .await
        .is_err());
    assert!(store
        .delete_erased_identity(&tenant, federation_id, 1)
        .await
        .unwrap());
    assert!(store
        .delete_erased_identity(&tenant, federation_id, 1)
        .await
        .unwrap());
    assert_eq!(store.get_by_id(&tenant, federation_id).await.unwrap(), None);

    assert!(store
        .set_status(&tenant, &id, UserStatus::Tombstoned, 160)
        .await
        .unwrap());
    assert!(!store
        .set_status(&tenant, &id, UserStatus::Active, 161)
        .await
        .unwrap());
    assert!(!store
        .set_status(&tenant, &id, UserStatus::Disabled, 162)
        .await
        .unwrap());
    assert_eq!(
        store.begin_disable(&tenant, &id, 163).await.unwrap(),
        DisableStart::Tombstoned
    );
    assert_eq!(
        store.enable_completed(&tenant, &id, 2, 164).await.unwrap(),
        EnableOutcome::Tombstoned
    );
    let tombstone = store.get_by_id(&tenant, &id).await.unwrap().unwrap();
    assert!(tombstone.attributes.is_empty());
    assert_eq!(
        store
            .create_or_get_by_email(&tenant, &email, "replacement", 165)
            .await
            .unwrap(),
        tombstone
    );
    let (active, _) = store
        .list(&tenant, 100, None, None, UserListStatusFilter::Active)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].user_id, legacy);
    let (deleted, _) = store
        .list(
            &tenant,
            100,
            None,
            Some(&email.to_uppercase()),
            UserListStatusFilter::Tombstoned,
        )
        .await
        .unwrap();
    assert_eq!(deleted, vec![tombstone]);
    assert!(store
        .list(
            &tenant,
            100,
            Some("not-a-cursor"),
            None,
            UserListStatusFilter::All
        )
        .await
        .is_err());

    let scim_tenant = format!("{tenant}-scim");
    let scim_email = format!("directory@{tenant}.example.test");
    let canonical = format!("user:{scim_email}");
    store
        .create_or_get_by_email(&scim_tenant, &scim_email, &canonical, 100)
        .await
        .unwrap();
    let input = ScimUserInput {
        user_id: "requested-new-id".into(),
        external_id: "external-original".into(),
        user_name: scim_email.clone(),
        display_name: Some("Display".into()),
        active: false,
        now: 200,
    };
    let ScimCreateOutcome::Created(adopted) = store
        .create_scim(&scim_tenant, input.clone())
        .await
        .unwrap()
    else {
        panic!("SCIM must adopt the existing local identity");
    };
    assert_eq!(adopted.user_id, canonical);
    assert_eq!(adopted.created_at, 100);
    assert_eq!(adopted.status, UserStatus::Disabled);
    assert_eq!(adopted.credential_epoch, 1);
    assert!(matches!(
        store
            .create_scim(&scim_tenant, input.clone())
            .await
            .unwrap(),
        ScimCreateOutcome::Existing {
            pending_initial_epoch: Some(0),
            ..
        }
    ));
    let ScimCreateLifecycleStart::Ready { epoch: 1, .. } = store
        .begin_scim_create_lifecycle(
            &scim_tenant,
            &input.external_id,
            &input.user_name,
            &canonical,
            201,
        )
        .await
        .unwrap()
    else {
        panic!("inactive POST receipt must resume its initial cleanup");
    };
    assert!(store
        .complete_disable(&scim_tenant, &canonical, 1, 202)
        .await
        .unwrap());
    store
        .complete_scim_create_lifecycle(
            &scim_tenant,
            &input.external_id,
            &input.user_name,
            &canonical,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .begin_scim_create_lifecycle(
                &scim_tenant,
                &input.external_id,
                &input.user_name,
                &canonical,
                203,
            )
            .await
            .unwrap(),
        ScimCreateLifecycleStart::Complete
    );
    assert_eq!(
        store
            .get_scim_by_external_id(&scim_tenant, &input.external_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        canonical
    );
    assert_eq!(
        store
            .get_scim_by_user_name(&scim_tenant, &input.user_name.to_uppercase())
            .await
            .unwrap()
            .unwrap()
            .user_id,
        canonical
    );
    let replacement_name = format!("moved@{tenant}.example.test");
    let ScimReplaceOutcome::Updated(replaced) = store
        .replace_scim(
            &scim_tenant,
            &canonical,
            ScimReplaceInput {
                external_id: "external-moved".into(),
                user_name: replacement_name.clone(),
                display_name: None,
                active: true,
                now: 210,
            },
        )
        .await
        .unwrap()
    else {
        panic!("SCIM aliases must move atomically");
    };
    assert_eq!(replaced.user_id, canonical);
    assert_eq!(
        replaced.status,
        UserStatus::Disabled,
        "enable requires completed generation authority"
    );
    assert_eq!(
        store.get_by_email(&scim_tenant, &scim_email).await.unwrap(),
        None
    );
    assert_eq!(
        store
            .get_scim_by_external_id(&scim_tenant, &input.external_id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_scim_by_user_name(&scim_tenant, &input.user_name)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_by_email(&scim_tenant, &replacement_name)
            .await
            .unwrap(),
        Some(replaced.clone())
    );
    assert!(
        matches!(
            store.create_scim(&scim_tenant, input).await.unwrap(),
            ScimCreateOutcome::Existing { record, pending_initial_epoch: None } if record == replaced
        ),
        "old POST retries must not reinstall moved aliases or old active intent"
    );
    let (page, total) = store.list_scim(&scim_tenant, 0, 1).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(page, vec![replaced]);
    let (page, total) = store.list_scim(&scim_tenant, 1, 1).await.unwrap();
    assert_eq!(total, 1);
    assert!(page.is_empty());

    for round in 0..8 {
        shared_scim_alias_race(store.clone(), &format!("{tenant}-scim-race-{round}")).await;
    }
}

async fn shared_scim_alias_race(store: impl UsersStore + Clone + 'static, tenant: &str) {
    let racing_tenant = tenant.to_string();
    let name = format!("race@{tenant}.example.test");
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, name, barrier) = (
            store.clone(),
            racing_tenant.clone(),
            name.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .create_scim(
                    &tenant,
                    ScimUserInput {
                        user_id: format!("candidate-{index}"),
                        external_id: "shared-external".into(),
                        user_name: name,
                        display_name: None,
                        active: true,
                        now: 300,
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut created = 0;
    let mut admitted = Vec::new();
    for task in tasks {
        match task.await.unwrap() {
            ScimCreateOutcome::Created(record) => {
                created += 1;
                admitted.push(record);
            }
            ScimCreateOutcome::Existing {
                record,
                pending_initial_epoch: None,
            } => admitted.push(record),
            other => panic!("unexpected shared-alias admission: {other:?}"),
        }
    }
    assert_eq!(created, 1);
    assert!(admitted.iter().all(|record| record == &admitted[0]));
    assert_eq!(store.list_scim(&racing_tenant, 0, 100).await.unwrap().1, 1);
}

#[tokio::test]
async fn memory_user_contract() {
    user_contract(MemoryUsersStore::default()).await;
}

#[tokio::test]
async fn postgres_user_contract() {
    let store =
        PostgresUsersStore::new(database().await, UserAuthorityKey::new([0x57; 32]).unwrap());
    user_contract(store).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_user_contract() {
    use agent_auth_http::adapters::aws::DynamoUsersStore;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = ["email", "scim_tenant"]
        .into_iter()
        .map(|name| {
            AttributeDefinition::builder()
                .attribute_name(name)
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap()
        })
        .collect();
    let indexes = [
        ("email-index", "email"),
        ("scim_tenant-index", "scim_tenant"),
    ]
    .into_iter()
    .map(|(name, key)| {
        GlobalSecondaryIndex::builder()
            .index_name(name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(key)
                    .key_type(KeyType::Hash)
                    .build()
                    .unwrap(),
            )
            .projection(
                Projection::builder()
                    .projection_type(ProjectionType::All)
                    .build(),
            )
            .build()
            .unwrap()
    })
    .collect();
    let (db, table) = super::aws_contract_database::table("user_id", attributes, indexes).await;
    user_contract(DynamoUsersStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
