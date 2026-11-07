use super::{database, tenant};
use agent_auth_http::{
    adapters::memory::MemoryScimGroupsStore,
    ports::{
        ScimGroupChange, ScimGroupCreateInput, ScimGroupCreateOutcome, ScimGroupDeleteOutcome,
        ScimGroupMutation, ScimGroupMutationOutcome, ScimGroupsStore, ScimRoleMappingOutcome,
        TenantRole, SCIM_GROUP_MAX_MEMBERS,
    },
};
use std::sync::Arc;
use tokio::sync::Barrier;

async fn group_contract(store: impl ScimGroupsStore + Clone + 'static) {
    let tenant = tenant();
    let other = format!("{tenant}-other");
    assert_eq!(store.get(&tenant, "primary").await.unwrap(), None);
    assert_eq!(store.list(&tenant, 0, 10).await.unwrap(), (vec![], 0));
    let input = ScimGroupCreateInput {
        group_id: "primary".into(),
        external_id: "external-primary".into(),
        display_name: "Primary".into(),
        members: vec!["shared".into(), "member-a".into(), "shared".into()],
        now: 100,
    };
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, mut input, barrier) = (
            store.clone(),
            tenant.clone(),
            input.clone(),
            barrier.clone(),
        );
        input.group_id = format!("candidate-{index:02}");
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.create(&tenant, input).await.unwrap()
        }));
    }
    let mut created = 0;
    let mut records = Vec::new();
    for task in tasks {
        match task.await.unwrap() {
            ScimGroupCreateOutcome::Created(record) => {
                created += 1;
                records.push(record);
            }
            ScimGroupCreateOutcome::Existing(record) => records.push(record),
        }
    }
    assert_eq!(created, 1);
    let first = records[0].clone();
    assert!(records.iter().all(|record| record == &first));
    assert_eq!(first.members, ["member-a", "shared"]);
    assert_eq!(first.version, 1);
    assert_eq!(store.get(&other, &first.group_id).await.unwrap(), None);
    assert_eq!(
        store
            .get_by_external_id(&tenant, &input.external_id)
            .await
            .unwrap(),
        Some(first.clone())
    );
    assert!(store
        .create(
            &tenant,
            ScimGroupCreateInput {
                group_id: first.group_id.clone(),
                external_id: "another-external".into(),
                ..input.clone()
            }
        )
        .await
        .is_err());
    assert_eq!(
        store
            .mapped_role_for_member(&tenant, "shared")
            .await
            .unwrap()
            .role,
        None
    );
    let ScimRoleMappingOutcome::Updated(mapping) = store
        .set_role_mapping(&tenant, &input.external_id, Some(TenantRole::Admin), 110)
        .await
        .unwrap()
    else {
        panic!("mapping an existing group must succeed");
    };
    assert_eq!(mapping.updated_at, 110);
    assert_eq!(
        store
            .get(&tenant, &first.group_id)
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    assert_eq!(
        store
            .set_role_mapping(&tenant, &input.external_id, Some(TenantRole::Admin), 120)
            .await
            .unwrap(),
        ScimRoleMappingOutcome::Updated(mapping.clone())
    );
    assert_eq!(
        store.list_role_mappings(&tenant).await.unwrap(),
        vec![mapping]
    );
    let mapped = store
        .mapped_role_for_member(&tenant, "shared")
        .await
        .unwrap();
    assert_eq!(mapped.role, Some(TenantRole::Admin));
    assert_eq!(mapped.mappings.len(), 1);
    assert_eq!(
        store
            .mapped_role_for_member(&other, "shared")
            .await
            .unwrap()
            .role,
        None
    );
    assert_eq!(
        store
            .set_role_mapping(&tenant, "missing", Some(TenantRole::Owner), 120)
            .await
            .unwrap(),
        ScimRoleMappingOutcome::GroupNotFound
    );
    let before = store.get(&tenant, &first.group_id).await.unwrap().unwrap();
    assert_eq!(
        store
            .mutate(
                &tenant,
                &first.group_id,
                ScimGroupMutation::Replace {
                    display_name: before.display_name.clone(),
                    members: before.members.clone(),
                    now: 130,
                }
            )
            .await
            .unwrap(),
        ScimGroupMutationOutcome::Updated(before.clone())
    );
    assert_eq!(
        store
            .mutate(
                &tenant,
                &first.group_id,
                ScimGroupMutation::Patch {
                    changes: vec![ScimGroupChange::AddMembers(
                        (0..=SCIM_GROUP_MAX_MEMBERS)
                            .map(|index| format!("oversized-{index}"))
                            .collect()
                    )],
                    now: 130,
                }
            )
            .await
            .unwrap(),
        ScimGroupMutationOutcome::TooManyMembers
    );
    assert_eq!(
        store.get(&tenant, &first.group_id).await.unwrap(),
        Some(before.clone())
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let (store, tenant, id, barrier) = (
            store.clone(),
            tenant.clone(),
            first.group_id.clone(),
            barrier.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let mutation = ScimGroupMutation::Patch {
                changes: vec![ScimGroupChange::AddMembers(vec![format!(
                    "member-{index:02}"
                )])],
                now: 140,
            };
            for _ in 0..64 {
                match store.mutate(&tenant, &id, mutation.clone()).await {
                    Ok(ScimGroupMutationOutcome::Updated(_)) => return,
                    Err(agent_auth_http::ports::StoreError::Transient(_)) => {
                        tokio::task::yield_now().await
                    }
                    outcome => panic!("unexpected membership update: {outcome:?}"),
                }
            }
            panic!("membership contention failed to converge");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let after = store.get(&tenant, &first.group_id).await.unwrap().unwrap();
    assert_eq!(after.version, before.version + 16);
    assert_eq!(after.members.len(), 18);
    for index in 0..16 {
        assert!(after.members.contains(&format!("member-{index:02}")));
    }
    let ScimGroupCreateOutcome::Created(owner) = store
        .create(
            &tenant,
            ScimGroupCreateInput {
                group_id: "owner-group".into(),
                external_id: "external-owner".into(),
                display_name: "Owner".into(),
                members: vec!["shared".into()],
                now: 150,
            },
        )
        .await
        .unwrap()
    else {
        panic!("new owner group must be created");
    };
    store
        .set_role_mapping(&tenant, &owner.external_id, Some(TenantRole::Owner), 150)
        .await
        .unwrap();
    let mapped = store
        .mapped_role_for_member(&tenant, "shared")
        .await
        .unwrap();
    assert_eq!(mapped.role, Some(TenantRole::Owner));
    assert_eq!(mapped.mappings.len(), 2);
    assert_eq!(
        store
            .remove_member_from_all(&tenant, "shared", 160)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .remove_member_from_all(&tenant, "shared", 161)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .mapped_role_for_member(&tenant, "shared")
            .await
            .unwrap()
            .role,
        None
    );
    assert_eq!(
        store
            .set_role_mapping(&tenant, &owner.external_id, None, 170)
            .await
            .unwrap(),
        ScimRoleMappingOutcome::Removed
    );
    let before = store.get(&tenant, &owner.group_id).await.unwrap().unwrap();
    assert_eq!(
        store
            .set_role_mapping(&tenant, &owner.external_id, None, 171)
            .await
            .unwrap(),
        ScimRoleMappingOutcome::Removed
    );
    assert_eq!(
        store.get(&tenant, &owner.group_id).await.unwrap(),
        Some(before)
    );
    assert_eq!(
        store.delete(&tenant, &first.group_id, 180).await.unwrap(),
        ScimGroupDeleteOutcome::Deleted
    );
    assert_eq!(
        store.delete(&tenant, &first.group_id, 181).await.unwrap(),
        ScimGroupDeleteOutcome::Deleted
    );
    assert_eq!(store.get(&tenant, &first.group_id).await.unwrap(), None);
    assert_eq!(
        store
            .get_by_external_id(&tenant, &first.external_id)
            .await
            .unwrap(),
        None
    );
    assert!(store
        .create(
            &tenant,
            ScimGroupCreateInput {
                group_id: first.group_id.clone(),
                ..input.clone()
            }
        )
        .await
        .is_err());
    let ScimGroupCreateOutcome::Created(replacement) = store
        .create(
            &tenant,
            ScimGroupCreateInput {
                group_id: "replacement".into(),
                ..input.clone()
            },
        )
        .await
        .unwrap()
    else {
        panic!("the released external alias may bind a new group");
    };
    assert_eq!(replacement.version, 1);
    assert_eq!(
        store.delete(&tenant, "missing", 190).await.unwrap(),
        ScimGroupDeleteOutcome::NotFound
    );
    assert_eq!(
        store
            .mutate(
                &tenant,
                "missing",
                ScimGroupMutation::Patch {
                    changes: vec![],
                    now: 190
                }
            )
            .await
            .unwrap(),
        ScimGroupMutationOutcome::NotFound
    );
    let (page, total) = store.list(&tenant, 0, 1).await.unwrap();
    assert_eq!(total, 2);
    assert_eq!(page.len(), 1);
    assert_eq!(store.list(&tenant, 2, 1).await.unwrap(), (vec![], 2));
    let foreign = store.create(&other, input).await.unwrap();
    assert!(store.delete_all_by_tenant(&tenant).await.unwrap() >= 3);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(store.list(&tenant, 0, 10).await.unwrap(), (vec![], 0));
    assert!(store.list_role_mappings(&tenant).await.unwrap().is_empty());
    let foreign = match foreign {
        ScimGroupCreateOutcome::Created(record) | ScimGroupCreateOutcome::Existing(record) => {
            record
        }
    };
    assert_eq!(
        store.get(&other, &foreign.group_id).await.unwrap(),
        Some(foreign.clone())
    );
    let empty_id = format!("empty-{tenant}");
    store
        .create(
            "",
            ScimGroupCreateInput {
                group_id: empty_id.clone(),
                external_id: empty_id.clone(),
                display_name: "Empty issuer tenant".into(),
                members: vec!["empty-member".into()],
                now: 200,
            },
        )
        .await
        .unwrap();
    assert!(store.delete_all_by_tenant("").await.unwrap() > 0);
    assert_eq!(store.get("", &empty_id).await.unwrap(), None);
    assert_eq!(
        store.get(&other, &foreign.group_id).await.unwrap(),
        Some(foreign),
        "empty issuer cleanup must preserve named-tenant authority",
    );
    assert!(store.delete_all_by_tenant(&other).await.unwrap() > 0);
}

#[tokio::test]
async fn memory_scim_group_contract() {
    group_contract(MemoryScimGroupsStore::default()).await;
}

#[tokio::test]
async fn postgres_scim_group_contract() {
    group_contract(database().await).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_scim_group_contract() {
    use agent_auth_http::adapters::aws::DynamoScimGroupsStore;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
        ProjectionType, ScalarAttributeType,
    };
    let attributes = vec![AttributeDefinition::builder()
        .attribute_name("tenant_kind")
        .attribute_type(ScalarAttributeType::S)
        .build()
        .unwrap()];
    let indexes = vec![GlobalSecondaryIndex::builder()
        .index_name("tenant_kind-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("tenant_kind")
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
        .unwrap()];
    let (db, table) =
        super::aws_contract_database::table_with_range("pk", Some("sk"), attributes, indexes).await;
    group_contract(DynamoScimGroupsStore::new(db.clone(), &table)).await;
    db.delete_table().table_name(table).send().await.unwrap();
}
