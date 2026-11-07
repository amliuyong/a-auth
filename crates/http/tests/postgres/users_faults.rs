use super::{database, tenant};
use agent_auth_http::{
    adapters::postgres::{PostgresUsersStore, UserAuthorityKey},
    ports::{
        CredentialChangeOwner, CredentialChangeStart, PutAttrOutcome, ScimCreateOutcome,
        ScimReplaceInput, ScimReplaceOutcome, ScimUserInput, StoreError, UserListStatusFilter,
        UserStatus, UsersStore,
    },
};
use std::collections::BTreeMap;

const KEY: [u8; 32] = [0x57; 32];

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str, id: &str) -> String {
    sqlx::query_scalar("SELECT record FROM a_auth.users WHERE tenant = $1 AND user_id = $2")
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn replace_payload(pool: &sqlx::PgPool, tenant: &str, id: &str, value: &str) {
    sqlx::query("UPDATE a_auth.users SET record = $3 WHERE tenant = $1 AND user_id = $2")
        .bind(tenant.as_bytes())
        .bind(id.as_bytes())
        .bind(value)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_users_reject_incomplete_or_inconsistent_authority_without_overwrite() {
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let pool = pool().await;
    let tenant = tenant();
    let id = "private-identity-sentinel";
    let email = "private-email-sentinel@example.test";
    let record = store
        .create_or_get_by_email(&tenant, email, id, 100)
        .await
        .unwrap();
    let baseline = payload(&pool, &tenant, id).await;
    let value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec!["{}".to_owned(), "private-record-sentinel".to_owned()];
    for field in [
        "user_id",
        "last_login_at",
        "scim_external_id",
        "scim_user_name",
        "scim_display_name",
        "attributes",
        "credential_epoch",
    ] {
        let mut corrupt = value.clone();
        corrupt.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&corrupt).unwrap());
    }
    for (field, change) in [
        ("user_id", serde_json::json!("another-user")),
        ("email", serde_json::json!("another@example.test")),
        ("status", serde_json::json!("disabled")),
        ("scim_user_name", serde_json::json!("another-name")),
        ("credential_epoch", serde_json::json!(-1)),
        ("unknown", serde_json::json!("private-record-sentinel")),
    ] {
        let mut corrupt = value.clone();
        corrupt[field] = change;
        corruptions.push(serde_json::to_string(&corrupt).unwrap());
    }
    for corrupt in corruptions {
        replace_payload(&pool, &tenant, id, &corrupt).await;
        let attempts = [
            store.get_by_id(&tenant, id).await.map(|_| ()),
            store.get_by_email(&tenant, email).await.map(|_| ()),
            store
                .list(&tenant, 10, None, None, UserListStatusFilter::All)
                .await
                .map(|_| ()),
            store
                .create_or_get_by_email(&tenant, email, "new-candidate", 200)
                .await
                .map(|_| ()),
            store
                .begin_credential_change(&tenant, id, 0, "operation", 200)
                .await
                .map(|_| ()),
            store.begin_disable(&tenant, id, 200).await.map(|_| ()),
            store
                .put_attributes(&tenant, id, "namespace", BTreeMap::new(), 0)
                .await
                .map(|_| ()),
            store
                .fence_for_erasure(&tenant, id, 1, 200)
                .await
                .map(|_| ()),
            store
                .delete_erased_identity(&tenant, id, 1)
                .await
                .map(|_| ()),
        ];
        // Restore even on an assertion failure, keeping the owned fixture usable.
        let retained = payload(&pool, &tenant, id).await;
        replace_payload(&pool, &tenant, id, &baseline).await;
        for result in attempts {
            let Err(StoreError::Permanent(message)) = result else {
                panic!("invalid authority must fail closed: {result:?}; row: {corrupt}");
            };
            assert!(!message.contains("private-"));
        }
        assert_eq!(retained, corrupt);
    }
    assert_eq!(store.get_by_id(&tenant, id).await.unwrap(), Some(record));
    pool.close().await;
}

#[tokio::test]
async fn postgres_scim_second_write_failure_rolls_back_identity_and_moved_aliases() {
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let pool = pool().await;
    let tenant = tenant();
    let input = ScimUserInput {
        user_id: "canonical".into(),
        external_id: "external-original".into(),
        user_name: format!("original@{tenant}.example.test"),
        display_name: None,
        active: false,
        now: 100,
    };
    let constraint = format!("contract_scim_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_create_claims ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store.create_scim(&tenant, input.clone()).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.scim_create_claims DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(
        store.get_by_id(&tenant, &input.user_id).await.unwrap(),
        None
    );
    let roots: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.user_directories WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        roots, 0,
        "second-write failure rolls back absent-root admission"
    );
    let ScimCreateOutcome::Created(record) =
        store.create_scim(&tenant, input.clone()).await.unwrap()
    else {
        panic!("retry after rollback creates the complete identity");
    };
    assert_eq!(record.status, UserStatus::Disabled);
    let baseline = payload(&pool, &tenant, &input.user_id).await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.users ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8') \
                OR scim_external_id <> convert_to('external-moved', 'UTF8')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let replacement = ScimReplaceInput {
        external_id: "external-moved".into(),
        user_name: format!("moved@{tenant}.example.test"),
        display_name: None,
        active: true,
        now: 200,
    };
    let failed = store
        .replace_scim(&tenant, &input.user_id, replacement.clone())
        .await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.users DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(failed, Err(StoreError::Permanent(_))));
    assert_eq!(payload(&pool, &tenant, &input.user_id).await, baseline);
    assert_eq!(
        store
            .get_scim_by_external_id(&tenant, &input.external_id)
            .await
            .unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        store
            .get_scim_by_external_id(&tenant, &replacement.external_id)
            .await
            .unwrap(),
        None
    );
    assert!(matches!(
        store.create_scim(&tenant, input).await.unwrap(),
        ScimCreateOutcome::Existing { record: current, pending_initial_epoch: Some(0) }
            if current == record
    ));
    assert!(matches!(
        store
            .replace_scim(&tenant, "canonical", replacement)
            .await
            .unwrap(),
        ScimReplaceOutcome::Updated(_)
    ));
    pool.close().await;
}

#[tokio::test]
async fn postgres_users_preserve_nul_and_u64_and_reject_exhaustion_atomically() {
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let pool = pool().await;
    let tenant = format!("{}\0tenant", tenant());
    let id = "canonical\0identity";
    store.create_or_get_by_id(&tenant, id, 100).await.unwrap();
    assert_eq!(
        store
            .put_attributes(
                &tenant,
                id,
                "namespace\0name",
                BTreeMap::from([("key\0name".into(), "value\0name".into())]),
                0,
            )
            .await
            .unwrap(),
        PutAttrOutcome::Ok { revision: 1 }
    );
    let original = payload(&pool, &tenant, id).await;
    let original_value: serde_json::Value = serde_json::from_str(&original).unwrap();
    for mutation in 0..3 {
        let mut value = original_value.clone();
        match mutation {
            0 => value["credential_epoch"] = u64::MAX.into(),
            1 => value["attributes_generation"] = u64::MAX.into(),
            2 => value["attributes"]["namespace\0name"]["revision"] = u64::MAX.into(),
            _ => unreachable!(),
        }
        let changed = serde_json::to_string(&value).unwrap();
        replace_payload(&pool, &tenant, id, &changed).await;
        let attempts = match mutation {
            0 => vec![
                store
                    .begin_credential_change(&tenant, id, u64::MAX, "owner", 200)
                    .await
                    .map(|_| ()),
                store.begin_disable(&tenant, id, 200).await.map(|_| ()),
                store
                    .fence_for_erasure(&tenant, id, 0, 200)
                    .await
                    .map(|_| ()),
            ],
            _ => vec![store
                .put_attributes(
                    &tenant,
                    id,
                    "namespace\0name",
                    BTreeMap::from([("changed".into(), "value".into())]),
                    if mutation == 1 { 1 } else { u64::MAX },
                )
                .await
                .map(|_| ())],
        };
        let retained = payload(&pool, &tenant, id).await;
        replace_payload(&pool, &tenant, id, &original).await;
        assert!(attempts
            .into_iter()
            .all(|result| matches!(result, Err(StoreError::Permanent(_)))));
        assert_eq!(retained, changed);
    }
    assert_eq!(
        store
            .begin_credential_change(&tenant, id, 0, "owner\0id", 300)
            .await
            .unwrap(),
        CredentialChangeStart::Started { epoch: 1 }
    );
    assert!(store
        .recover_expired_credential_change(&tenant, id, 1, 300, 301)
        .await
        .unwrap());
    assert!(!store
        .complete_credential_change(
            &tenant,
            id,
            CredentialChangeOwner {
                epoch: 1,
                operation_id: "owner\0id"
            },
            302
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .get_by_id(&tenant, id)
            .await
            .unwrap()
            .unwrap()
            .attributes["namespace\0name"]
            .kv["key\0name"],
        "value\0name"
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_user_cursors_bind_tenant_filter_query_and_external_key_across_pools() {
    assert!(UserAuthorityKey::new([0; 32]).is_err());
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let independent =
        PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let changed_key =
        PostgresUsersStore::new(database().await, UserAuthorityKey::new([0x58; 32]).unwrap());
    let tenant = tenant();
    for id in ["identity-a", "identity-b", "identity-c"] {
        store.create_or_get_by_id(&tenant, id, 100).await.unwrap();
    }
    let (first, cursor) = store
        .list(
            &tenant,
            1,
            None,
            Some(" IDENTITY "),
            UserListStatusFilter::Active,
        )
        .await
        .unwrap();
    assert_eq!(first[0].user_id, "identity-a");
    let cursor = cursor.unwrap();
    let (next, _) = independent
        .list(
            &tenant,
            10,
            Some(&cursor),
            Some("identity"),
            UserListStatusFilter::Active,
        )
        .await
        .unwrap();
    assert_eq!(
        next.iter()
            .map(|record| record.user_id.as_str())
            .collect::<Vec<_>>(),
        ["identity-b", "identity-c"]
    );
    for result in [
        independent
            .list(
                "another-tenant",
                10,
                Some(&cursor),
                Some("identity"),
                UserListStatusFilter::Active,
            )
            .await,
        independent
            .list(
                &tenant,
                10,
                Some(&cursor),
                None,
                UserListStatusFilter::Active,
            )
            .await,
        independent
            .list(
                &tenant,
                10,
                Some(&cursor),
                Some("identity"),
                UserListStatusFilter::All,
            )
            .await,
        changed_key
            .list(
                &tenant,
                10,
                Some(&cursor),
                Some("identity"),
                UserListStatusFilter::Active,
            )
            .await,
        store
            .list(
                &tenant,
                10,
                Some(&format!("{cursor}A")),
                Some("identity"),
                UserListStatusFilter::Active,
            )
            .await,
    ] {
        assert!(matches!(result, Err(StoreError::Permanent(_))));
    }
}

#[tokio::test]
async fn postgres_empty_tenant_admission_waits_for_logical_suppression_fence() {
    use agent_auth_http::governance::{
        suppression_digest, GovernanceSuppressionRecord, SUPPRESSION_KEY_VERSION,
        SUPPRESSION_NORMALIZATION_VERSION,
    };
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let pool = pool().await;
    let id = format!("suppression-race-{}", tenant());
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO a_auth.user_directories (tenant) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(b"default".as_slice())
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query("SELECT tenant FROM a_auth.user_directories WHERE tenant = $1 FOR UPDATE")
        .bind(b"default".as_slice())
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let mut admission = tokio::spawn({
        let (store, id) = (store.clone(), id.clone());
        async move {
            started.send(()).unwrap();
            store.create_or_get_by_id("", &id, 100).await
        }
    });
    ready.await.unwrap();
    let early = tokio::time::timeout(std::time::Duration::from_millis(300), &mut admission).await;
    let digest = suppression_digest(
        &KEY,
        "default",
        "user",
        "canonical_id",
        SUPPRESSION_NORMALIZATION_VERSION,
        &id,
    );
    let record = GovernanceSuppressionRecord {
        tenant_id: "default".into(),
        target_class: "user".into(),
        key_version: SUPPRESSION_KEY_VERSION,
        normalization_version: SUPPRESSION_NORMALIZATION_VERSION,
        digest: digest.clone(),
        target_epoch: 1,
        created_at: 100,
    };
    sqlx::query(
        "INSERT INTO a_auth.governance_suppressions \
         (tenant, target_class, digest, epoch, record) VALUES ($1, 'user', $2, 1, $3)",
    )
    .bind(b"default".as_slice())
    .bind(digest)
    .bind(sqlx::types::Json(record))
    .execute(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    let result = match early {
        Ok(result) => result.unwrap(),
        Err(_) => admission.await.unwrap(),
    };
    assert!(
        matches!(result, Err(StoreError::Permanent(_))),
        "admission must observe suppression published by the logical tenant fence: {result:?}",
    );
    assert_eq!(store.get_by_id("", &id).await.unwrap(), None);
    pool.close().await;
}

#[tokio::test]
async fn postgres_scim_adoption_checks_the_selected_canonical_identity_suppression() {
    use agent_auth_http::governance::{
        suppression_digest, GovernanceSuppressionRecord, SUPPRESSION_KEY_VERSION,
        SUPPRESSION_NORMALIZATION_VERSION,
    };
    let store = PostgresUsersStore::new(database().await, UserAuthorityKey::new(KEY).unwrap());
    let pool = pool().await;
    let tenant = tenant();
    let email = format!("adopt@{tenant}.example.test");
    let canonical = store
        .create_or_get_by_email(&tenant, &email, "selected-canonical", 100)
        .await
        .unwrap();
    let digest = suppression_digest(
        &KEY,
        &tenant,
        "user",
        "canonical_id",
        SUPPRESSION_NORMALIZATION_VERSION,
        &canonical.user_id,
    );
    let record = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user".into(),
        key_version: SUPPRESSION_KEY_VERSION,
        normalization_version: SUPPRESSION_NORMALIZATION_VERSION,
        digest: digest.clone(),
        target_epoch: 1,
        created_at: 110,
    };
    sqlx::query(
        "INSERT INTO a_auth.governance_suppressions \
         (tenant, target_class, digest, epoch, record) VALUES ($1, 'user', $2, 1, $3)",
    )
    .bind(tenant.as_bytes())
    .bind(digest)
    .bind(sqlx::types::Json(record))
    .execute(&pool)
    .await
    .unwrap();
    let result = store
        .create_scim(
            &tenant,
            ScimUserInput {
                user_id: "unused-candidate".into(),
                external_id: "new-external".into(),
                user_name: email,
                display_name: None,
                active: true,
                now: 120,
            },
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::Permanent(_))),
        "{result:?}"
    );
    assert_eq!(
        store.get_by_id(&tenant, &canonical.user_id).await.unwrap(),
        Some(canonical)
    );
    assert_eq!(
        store
            .get_scim_by_external_id(&tenant, "new-external")
            .await
            .unwrap(),
        None
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_user_admission_rejects_a_different_external_authority_key() {
    let base = database().await;
    let configured = PostgresUsersStore::new(base.clone(), UserAuthorityKey::new(KEY).unwrap());
    let misconfigured = PostgresUsersStore::new(base, UserAuthorityKey::new([0x58; 32]).unwrap());
    let tenant = tenant();
    configured
        .create_or_get_by_id(&tenant, "original-user", 100)
        .await
        .unwrap();
    configured.verify_authority().await.unwrap();
    assert!(matches!(
        misconfigured.verify_authority().await,
        Err(StoreError::Permanent(_))
    ));
    let result = misconfigured
        .create_or_get_by_id(&tenant, "unbound-user", 110)
        .await;
    assert!(
        matches!(result, Err(StoreError::Permanent(_))),
        "another replica must not silently use a different suppression key: {result:?}",
    );
    assert_eq!(
        configured.get_by_id(&tenant, "unbound-user").await.unwrap(),
        None
    );
    let pool = pool().await;
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT key_check FROM a_auth.user_authority_binding WHERE singleton = TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained.len(), 32);
    assert_ne!(retained, KEY);
    pool.close().await;
}
