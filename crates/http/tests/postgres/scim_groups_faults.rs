use super::{database, tenant};
use agent_auth_http::ports::{
    ScimGroupCreateInput, ScimGroupCreateOutcome, ScimGroupMutation, ScimGroupsStore, StoreError,
    TenantRole,
};

fn input(id: &str) -> ScimGroupCreateInput {
    ScimGroupCreateInput {
        group_id: id.into(),
        external_id: format!("external-{id}"),
        display_name: id.into(),
        members: vec!["shared".into()],
        now: 100,
    }
}

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str, id: &str) -> String {
    sqlx::query_scalar("SELECT record FROM a_auth.scim_groups WHERE tenant = $1 AND group_id = $2")
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn replace_payload(pool: &sqlx::PgPool, tenant: &str, id: &str, value: &str) {
    sqlx::query("UPDATE a_auth.scim_groups SET record = $3 WHERE tenant = $1 AND group_id = $2")
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .bind(value)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_group_admission_and_bulk_membership_failure_roll_back_complete_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    let constraint = format!("contract_group_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_groups ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.create(&tenant, input("group-a")).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_groups DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(store.get(&tenant, "group-a").await.unwrap(), None);
    let roots: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.user_directories WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(roots, 0);
    for id in ["group-a", "group-b"] {
        store.create(&tenant, input(id)).await.unwrap();
        store
            .set_role_mapping(
                &tenant,
                &format!("external-{id}"),
                Some(TenantRole::Owner),
                110,
            )
            .await
            .unwrap();
    }
    let first = store.get(&tenant, "group-a").await.unwrap();
    let second = store.get(&tenant, "group-b").await.unwrap();
    let mappings = store.list_role_mappings(&tenant).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_groups ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8') \
             OR group_id <> convert_to('group-b', 'UTF8') \
             OR convert_to('shared', 'UTF8') = ANY(members)) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.remove_member_from_all(&tenant, "shared", 120).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_groups DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(store.get(&tenant, "group-a").await.unwrap(), first);
    assert_eq!(store.get(&tenant, "group-b").await.unwrap(), second);
    assert_eq!(store.list_role_mappings(&tenant).await.unwrap(), mappings);
    assert_eq!(
        store
            .mapped_role_for_member(&tenant, "shared")
            .await
            .unwrap()
            .mappings
            .len(),
        2
    );
    assert_eq!(
        store
            .remove_member_from_all(&tenant, "shared", 121)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .mapped_role_for_member(&tenant, "shared")
            .await
            .unwrap()
            .role,
        None
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_groups_reject_incomplete_or_inconsistent_membership_and_role_authority() {
    let store = database().await;
    let pool = pool().await;
    let tenant = tenant();
    store.create(&tenant, input("group")).await.unwrap();
    store
        .set_role_mapping(&tenant, "external-group", Some(TenantRole::Owner), 110)
        .await
        .unwrap();
    let baseline = payload(&pool, &tenant, "group").await;
    let value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".to_owned(), "private-group-sentinel".to_owned()];
    for field in ["record", "role", "role_updated_at", "deleted"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&changed).unwrap());
    }
    for mutation in 0..8 {
        let mut changed = value.clone();
        match mutation {
            0 => {
                changed["record"].as_object_mut().unwrap().remove("members");
            }
            1 => changed["record"]["group_id"] = "private-another-group".into(),
            2 => changed["record"]["external_id"] = "private-another-alias".into(),
            3 => changed["record"]["members"] = serde_json::json!(["private-another-member"]),
            4 => changed["role"] = "admin".into(),
            5 => changed["role_updated_at"] = serde_json::Value::Null,
            6 => changed["deleted"] = true.into(),
            7 => changed["record"]["version"] = 0.into(),
            _ => unreachable!(),
        }
        corruptions.push(serde_json::to_string(&changed).unwrap());
    }
    for corrupt in corruptions {
        replace_payload(&pool, &tenant, "group", &corrupt).await;
        let attempts = [
            store.get(&tenant, "group").await.map(|_| ()),
            store
                .get_by_external_id(&tenant, "external-group")
                .await
                .map(|_| ()),
            store.list(&tenant, 0, 10).await.map(|_| ()),
            store.create(&tenant, input("group")).await.map(|_| ()),
            store
                .mutate(
                    &tenant,
                    "group",
                    ScimGroupMutation::Replace {
                        display_name: "changed".into(),
                        members: vec![],
                        now: 120,
                    },
                )
                .await
                .map(|_| ()),
            store.delete(&tenant, "group", 120).await.map(|_| ()),
            store
                .set_role_mapping(&tenant, "external-group", None, 120)
                .await
                .map(|_| ()),
            store.list_role_mappings(&tenant).await.map(|_| ()),
            store
                .mapped_role_for_member(&tenant, "shared")
                .await
                .map(|_| ()),
            store
                .remove_member_from_all(&tenant, "shared", 120)
                .await
                .map(|_| ()),
        ];
        let retained = payload(&pool, &tenant, "group").await;
        replace_payload(&pool, &tenant, "group", &baseline).await;
        for result in attempts {
            let Err(StoreError::Permanent(message)) = result else {
                panic!("invalid group authority must fail closed: {result:?}");
            };
            assert!(!message.contains("private-"));
        }
        assert_eq!(retained, corrupt);
    }
    pool.close().await;
}

#[tokio::test]
async fn postgres_group_nul_and_exhaustion_preserve_members_aliases_and_roles() {
    let store = database().await;
    let pool = pool().await;
    let tenant = format!("{}\0tenant", tenant());
    let id = "group\0id";
    let external = "external\0id";
    let member = "member\0id";
    let ScimGroupCreateOutcome::Created(_) = store
        .create(
            &tenant,
            ScimGroupCreateInput {
                group_id: id.into(),
                external_id: external.into(),
                display_name: "Group\0name".into(),
                members: vec![member.into()],
                now: 100,
            },
        )
        .await
        .unwrap()
    else {
        panic!("NUL identifiers must be persisted");
    };
    store
        .set_role_mapping(&tenant, external, Some(TenantRole::Owner), 110)
        .await
        .unwrap();
    let baseline = payload(&pool, &tenant, id).await;
    let mut value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    value["record"]["version"] = u64::MAX.into();
    let maximum = serde_json::to_string(&value).unwrap();
    replace_payload(&pool, &tenant, id, &maximum).await;
    let before = store.get(&tenant, id).await.unwrap();
    assert_eq!(
        store.get_by_external_id(&tenant, external).await.unwrap(),
        before
    );
    let attempts = [
        store.delete(&tenant, id, 120).await.map(|_| ()),
        store
            .mutate(
                &tenant,
                id,
                ScimGroupMutation::Replace {
                    display_name: "changed".into(),
                    members: vec![],
                    now: 120,
                },
            )
            .await
            .map(|_| ()),
        store
            .set_role_mapping(&tenant, external, Some(TenantRole::Admin), 120)
            .await
            .map(|_| ()),
        store
            .set_role_mapping(&tenant, external, None, 120)
            .await
            .map(|_| ()),
        store
            .remove_member_from_all(&tenant, member, 120)
            .await
            .map(|_| ()),
    ];
    let retained = payload(&pool, &tenant, id).await;
    replace_payload(&pool, &tenant, id, &baseline).await;
    assert!(attempts
        .into_iter()
        .all(|result| matches!(result, Err(StoreError::Permanent(_)))));
    assert_eq!(retained, maximum);
    assert_eq!(
        store
            .mapped_role_for_member(&tenant, member)
            .await
            .unwrap()
            .role,
        Some(TenantRole::Owner)
    );
    pool.close().await;
}
