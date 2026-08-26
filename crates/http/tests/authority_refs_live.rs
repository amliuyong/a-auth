#![cfg(feature = "aws")]

use agent_auth_http::adapters::aws::{
    AuthorityReferenceMigrationProgress, DynamoAuthorityReferenceMigrator, DynamoClientStore,
    DynamoCodeStore, DynamoRefreshStore,
};
use agent_auth_http::ports::{
    ClientStore, CodeRecord, CodeStore, LeaseAcquire, RefreshFamilyRecord, RefreshStore,
};
use agent_auth_http::tenant::tpk;
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType,
    ScalarAttributeType, TableStatus,
};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type LiveResult<T> = Result<T, String>;

fn error(label: &str, value: impl std::fmt::Debug) -> String {
    format!("{label}: {value:?}")
}

async fn wait_for_table(db: &aws_sdk_dynamodb::Client, table: &str) -> LiveResult<()> {
    for _ in 0..90 {
        let output = db
            .describe_table()
            .table_name(table)
            .send()
            .await
            .map_err(|value| error("describe DynamoDB table", value))?;
        if output
            .table()
            .and_then(|value| value.table_status())
            .is_some_and(|status| status == &TableStatus::Active)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("DynamoDB table {table} did not become ACTIVE"))
}

async fn create_table(
    db: &aws_sdk_dynamodb::Client,
    table: &str,
    partition_key: &str,
    sort_key: Option<&str>,
) -> LiveResult<()> {
    let partition_definition = AttributeDefinition::builder()
        .attribute_name(partition_key)
        .attribute_type(ScalarAttributeType::S)
        .build()
        .map_err(|value| error("build partition attribute", value))?;
    let partition_schema = KeySchemaElement::builder()
        .attribute_name(partition_key)
        .key_type(KeyType::Hash)
        .build()
        .map_err(|value| error("build partition key", value))?;
    let mut request = db
        .create_table()
        .table_name(table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(partition_definition)
        .key_schema(partition_schema);
    if let Some(sort_key) = sort_key {
        request = request
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(sort_key)
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .map_err(|value| error("build sort attribute", value))?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(sort_key)
                    .key_type(KeyType::Range)
                    .build()
                    .map_err(|value| error("build sort key", value))?,
            );
    }
    request
        .send()
        .await
        .map_err(|value| error("create DynamoDB table", value))?;
    wait_for_table(db, table).await
}

async fn delete_tables(db: &aws_sdk_dynamodb::Client, tables: &[String]) -> LiveResult<()> {
    let mut failure = None;
    for table in tables.iter().rev() {
        if let Err(value) = db.delete_table().table_name(table).send().await {
            if value.code() != Some("ResourceNotFoundException") {
                failure = Some(error("delete DynamoDB table", value));
                continue;
            }
        }
        let mut absent = false;
        for _ in 0..90 {
            match db.describe_table().table_name(table).send().await {
                Ok(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(value) if value.code() == Some("ResourceNotFoundException") => {
                    absent = true;
                    break;
                }
                Err(value) => {
                    failure = Some(error("verify DynamoDB table deletion", value));
                    break;
                }
            }
        }
        if !absent && failure.is_none() {
            failure = Some(format!("DynamoDB table {table} still exists after cleanup"));
        }
    }
    failure.map_or(Ok(()), Err)
}

fn code_record(code: &str, client_id: &str, expires_at: i64) -> CodeRecord {
    CodeRecord {
        code: code.to_string(),
        client_id: client_id.to_string(),
        cimd_snapshot: None,
        redirect_uri: "https://client.invalid/callback".to_string(),
        code_challenge: "challenge".to_string(),
        resources: vec!["https://resource.invalid".to_string()],
        user_id: "authority-refs-live".to_string(),
        scope: vec!["openid".to_string()],
        expires_at,
        authz_session_id: None,
        nonce: None,
        auth_time: expires_at - 600,
        authorization_details: Vec::new(),
        acr: None,
        amr: Vec::new(),
        credential_epoch: Some(1),
        password_credential_version: None,
    }
}

fn refresh_record(family_id: &str, client_id: &str) -> RefreshFamilyRecord {
    RefreshFamilyRecord {
        family_id: family_id.to_string(),
        current_version: 0,
        revoked: false,
        client_id: client_id.to_string(),
        cimd_snapshot: None,
        user_id: "authority-refs-live".to_string(),
        credential_epoch: 1,
        resources: vec!["https://resource.invalid".to_string()],
        scope: vec!["openid".to_string()],
        actor_allowlist: Vec::new(),
        max_act_chain: 1,
        dpop_jkt: None,
        pkce_code_challenge: None,
        auth_time: Some(1_700_000_000),
        acr: None,
        password_credential_version: None,
    }
}

async fn seed_legacy_rows(
    db: &aws_sdk_dynamodb::Client,
    codes_table: &str,
    refresh_table: &str,
    refs_table: &str,
    tenant: &str,
    client_id: &str,
    now: i64,
) -> LiveResult<()> {
    db.put_item()
        .table_name(codes_table)
        .set_item(Some(HashMap::from([
            (
                "code".to_string(),
                AttributeValue::S(tpk(tenant, "legacy-code")),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, client_id)),
            ),
            (
                "redirect_uri".to_string(),
                AttributeValue::S("https://client.invalid/callback".to_string()),
            ),
            (
                "code_challenge".to_string(),
                AttributeValue::S("challenge".to_string()),
            ),
            ("resources".to_string(), AttributeValue::L(Vec::new())),
            (
                "user_id".to_string(),
                AttributeValue::S("authority-refs-live".to_string()),
            ),
            ("scope".to_string(), AttributeValue::L(Vec::new())),
            (
                "expires_at".to_string(),
                AttributeValue::N((now + 600).to_string()),
            ),
            ("auth_time".to_string(), AttributeValue::N(now.to_string())),
        ])))
        .send()
        .await
        .map_err(|value| error("seed legacy authorization code", value))?;
    db.put_item()
        .table_name(refresh_table)
        .set_item(Some(HashMap::from([
            (
                "family_id".to_string(),
                AttributeValue::S(tpk(tenant, "legacy-family")),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(tpk(tenant, client_id)),
            ),
            (
                "current_version".to_string(),
                AttributeValue::N("0".to_string()),
            ),
            ("revoked".to_string(), AttributeValue::Bool(false)),
        ])))
        .send()
        .await
        .map_err(|value| error("seed legacy refresh family", value))?;
    db.put_item()
        .table_name(refresh_table)
        .item(
            "family_id",
            AttributeValue::S(tpk(tenant, "terminal-family")),
        )
        .item("client_id", AttributeValue::S(tpk(tenant, client_id)))
        .item("current_version", AttributeValue::N("0".to_string()))
        .item("revoked", AttributeValue::Bool(true))
        .send()
        .await
        .map_err(|value| error("seed terminal legacy refresh family", value))?;
    let client_key = format!(
        "client#{:08x}{}{:08x}{}",
        tenant.len(),
        tenant,
        client_id.len(),
        client_id
    );
    db.put_item()
        .table_name(refs_table)
        .item("client_key", AttributeValue::S(client_key))
        .item(
            "reference_key",
            AttributeValue::S("r#terminal-orphan".to_string()),
        )
        .item(
            "source_id",
            AttributeValue::S(tpk(tenant, "terminal-family")),
        )
        .item("kind", AttributeValue::S("refresh".to_string()))
        .item("tenant_id", AttributeValue::S(tenant.to_string()))
        .item("client_id", AttributeValue::S(client_id.to_string()))
        .send()
        .await
        .map_err(|value| error("seed terminal orphan reference", value))?;
    Ok(())
}

async fn seed_client(
    db: &aws_sdk_dynamodb::Client,
    clients_table: &str,
    tenant: &str,
    client_id: &str,
) -> LiveResult<()> {
    db.put_item()
        .table_name(clients_table)
        .item("client_id", AttributeValue::S(tpk(tenant, client_id)))
        .send()
        .await
        .map_err(|value| error("seed registered client", value))?;
    Ok(())
}

async fn delete_client(
    db: &aws_sdk_dynamodb::Client,
    clients_table: &str,
    tenant: &str,
    client_id: &str,
) -> LiveResult<()> {
    db.delete_item()
        .table_name(clients_table)
        .key("client_id", AttributeValue::S(tpk(tenant, client_id)))
        .send()
        .await
        .map_err(|value| error("delete registered client", value))?;
    Ok(())
}

async fn verify_empty(
    db: &aws_sdk_dynamodb::Client,
    codes_table: &str,
    refresh_table: &str,
    clients_table: &str,
    refs_table: &str,
) -> LiveResult<()> {
    let codes = db
        .scan()
        .table_name(codes_table)
        .consistent_read(true)
        .select(aws_sdk_dynamodb::types::Select::Count)
        .send()
        .await
        .map_err(|value| error("count authorization codes", value))?
        .count();
    let refreshes = db
        .scan()
        .table_name(refresh_table)
        .consistent_read(true)
        .select(aws_sdk_dynamodb::types::Select::Count)
        .send()
        .await
        .map_err(|value| error("count refresh families", value))?
        .count();
    let refs = db
        .scan()
        .table_name(refs_table)
        .consistent_read(true)
        .send()
        .await
        .map_err(|value| error("read authority reference metadata", value))?;
    let clients = db
        .scan()
        .table_name(clients_table)
        .consistent_read(true)
        .select(aws_sdk_dynamodb::types::Select::Count)
        .send()
        .await
        .map_err(|value| error("count registered clients", value))?
        .count();
    let mut metadata = refs
        .items()
        .iter()
        .map(|item| {
            (
                item.get("client_key")
                    .and_then(|value| value.as_s().ok())
                    .cloned()
                    .unwrap_or_default(),
                item.get("reference_key")
                    .and_then(|value| value.as_s().ok())
                    .cloned()
                    .unwrap_or_default(),
                item.get("phase")
                    .and_then(|value| value.as_s().ok())
                    .cloned(),
            )
        })
        .collect::<Vec<_>>();
    metadata.sort();
    let expected_metadata = vec![
        (
            "meta\u{1f}coverage".to_string(),
            "code\u{1f}client-authority-refs-v1".to_string(),
            None,
        ),
        (
            "meta\u{1f}coverage".to_string(),
            "refresh\u{1f}client-authority-refs-v1".to_string(),
            None,
        ),
        (
            "meta\u{1f}migration".to_string(),
            "state\u{1f}client-authority-refs-v1".to_string(),
            Some("complete".to_string()),
        ),
        (
            "meta\u{1f}migration-request".to_string(),
            "request\u{1f}authority-refs-live-create".to_string(),
            None,
        ),
    ];
    if codes != 0 || refreshes != 0 || clients != 0 || metadata != expected_metadata {
        return Err(format!(
            "unexpected post-test counts: codes={codes} refreshes={refreshes} \
             clients={clients} refs={metadata:?}"
        ));
    }
    Ok(())
}

async fn run_scenarios(
    db: aws_sdk_dynamodb::Client,
    codes_table: &str,
    refresh_table: &str,
    clients_table: &str,
    refs_table: &str,
) -> LiveResult<()> {
    let migration_id = "client-authority-refs-v1:live";
    let codes = DynamoCodeStore::new(
        db.clone(),
        codes_table,
        clients_table,
        refs_table,
        migration_id,
    );
    let refresh = DynamoRefreshStore::new(
        db.clone(),
        refresh_table,
        clients_table,
        refs_table,
        migration_id,
    );
    let clients = DynamoClientStore::new(db.clone(), clients_table);
    let migrator =
        DynamoAuthorityReferenceMigrator::new(db.clone(), codes_table, refresh_table, refs_table);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|value| error("read current time", value))?
        .as_secs() as i64;
    let invocation_started_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|value| error("read migration invocation time", value))?
        .as_millis()
        .try_into()
        .map_err(|value| error("convert migration invocation time", value))?;

    let legacy_tenant = "live-legacy";
    seed_legacy_rows(
        &db,
        codes_table,
        refresh_table,
        refs_table,
        legacy_tenant,
        "shared-client",
        now,
    )
    .await?;
    migrator
        .begin(
            migration_id,
            None,
            "authority-refs-live-create",
            invocation_started_at_ms,
            now,
        )
        .await
        .map_err(|value| error("initialize legacy reference migration", value))?;
    let stats = loop {
        match migrator
            .step(migration_id, now)
            .await
            .map_err(|value| error("advance legacy reference migration", value))?
        {
            AuthorityReferenceMigrationProgress::Pending => {}
            AuthorityReferenceMigrationProgress::Complete(stats) => break stats,
        }
    };
    if stats.code_references != 1 || stats.refresh_references != 1 {
        return Err(format!("unexpected migration stats: {stats:?}"));
    }
    let orphan = db
        .get_item()
        .table_name(refs_table)
        .key(
            "client_key",
            AttributeValue::S(format!(
                "client#{:08x}{}{:08x}{}",
                legacy_tenant.len(),
                legacy_tenant,
                "shared-client".len(),
                "shared-client"
            )),
        )
        .key(
            "reference_key",
            AttributeValue::S("r#terminal-orphan".to_string()),
        )
        .consistent_read(true)
        .send()
        .await
        .map_err(|value| error("verify terminal orphan cleanup", value))?;
    if orphan.item().is_some() {
        return Err("terminal orphan reference survived migration".to_string());
    }
    if !codes
        .has_unexpired_by_client(legacy_tenant, "shared-client", now)
        .await
        .map_err(|value| error("query migrated code reference", value))?
        || !refresh
            .has_active_family_by_client(legacy_tenant, "shared-client")
            .await
            .map_err(|value| error("query migrated refresh reference", value))?
        || codes
            .has_unexpired_by_client("other-tenant", "shared-client", now)
            .await
            .map_err(|value| error("query cross-tenant migrated code", value))?
    {
        return Err("legacy migration or tenant partition assertion failed".to_string());
    }
    codes
        .delete_all_by_tenant(legacy_tenant)
        .await
        .map_err(|value| error("clean migrated codes", value))?;
    refresh
        .delete_all_by_tenant(legacy_tenant)
        .await
        .map_err(|value| error("clean migrated refresh families", value))?;

    let code_tenant = "live-codes";
    let code_client = "multiple-client";
    seed_client(&db, clients_table, code_tenant, code_client).await?;
    for code in ["code-a", "code-b"] {
        codes
            .put(code_tenant, code_record(code, code_client, now + 600))
            .await
            .map_err(|value| error("create authorization code and reference", value))?;
    }
    if !codes
        .has_unexpired_by_client(code_tenant, code_client, now)
        .await
        .map_err(|value| error("query multiple code references", value))?
    {
        return Err("multiple code references were not immediately visible".to_string());
    }
    for (index, code) in ["code-a", "code-b"].into_iter().enumerate() {
        let owner = format!("owner-{index}");
        if !matches!(
            codes
                .acquire_lease(code_tenant, code, &owner, now, now + 30)
                .await
                .map_err(|value| error("acquire code lease", value))?,
            LeaseAcquire::Acquired(_)
        ) {
            return Err("authorization code lease was not acquired".to_string());
        }
        codes
            .finalize(code_tenant, code, code_client, now + 600, now, &owner, None)
            .await
            .map_err(|value| error("finalize code and remove reference", value))?;
        let active = codes
            .has_unexpired_by_client(code_tenant, code_client, now)
            .await
            .map_err(|value| error("query code reference after finalize", value))?;
        if active != (index == 0) {
            return Err("multiple-code reference removal was not independent".to_string());
        }
    }
    codes
        .put(code_tenant, code_record("expired-code", code_client, now))
        .await
        .map_err(|value| error("create expired authorization code", value))?;
    if codes
        .has_unexpired_by_client(code_tenant, code_client, now)
        .await
        .map_err(|value| error("query expired code reference", value))?
    {
        return Err("expiry-equal authorization code still blocked reclamation".to_string());
    }
    codes
        .delete_all_by_tenant(code_tenant)
        .await
        .map_err(|value| error("clean runtime authorization codes", value))?;
    delete_client(&db, clients_table, code_tenant, code_client).await?;

    let revision_tenant = "live-revision";
    let revision_client = "same-day-client";
    seed_client(&db, clients_table, revision_tenant, revision_client).await?;
    let today = now.div_euclid(86_400);
    db.update_item()
        .table_name(clients_table)
        .key(
            "client_id",
            AttributeValue::S(tpk(revision_tenant, revision_client)),
        )
        .update_expression("SET last_used_day = :today")
        .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
        .send()
        .await
        .map_err(|value| error("seed same-day reclaim snapshot", value))?;
    let snapshot = clients
        .get(revision_tenant, revision_client)
        .await
        .map_err(|value| error("read same-day reclaim snapshot", value))?
        .ok_or_else(|| "same-day reclaim client is missing".to_string())?;
    if snapshot.authority_revision != 0 || snapshot.last_used_day != Some(today) {
        return Err("unexpected same-day reclaim snapshot".to_string());
    }
    codes
        .put(
            revision_tenant,
            code_record("revision-code", revision_client, now + 600),
        )
        .await
        .map_err(|value| error("create same-day authority", value))?;
    if clients
        .convert_to_tombstone(
            revision_tenant,
            revision_client,
            now,
            snapshot.last_used_day,
            snapshot.authority_revision,
        )
        .await
        .map_err(|value| error("attempt stale-revision tombstone", value))?
    {
        return Err("stale authority revision allowed tombstoning".to_string());
    }
    let after_revision = clients
        .get(revision_tenant, revision_client)
        .await
        .map_err(|value| error("read same-day authority revision", value))?
        .ok_or_else(|| "same-day authority client disappeared".to_string())?;
    if after_revision.tombstoned_at.is_some() || after_revision.authority_revision != 1 {
        return Err("same-day authority revision fence was not preserved".to_string());
    }
    codes
        .delete_all_by_tenant(revision_tenant)
        .await
        .map_err(|value| error("clean same-day authority", value))?;
    delete_client(&db, clients_table, revision_tenant, revision_client).await?;

    let refresh_revision_tenant = "live-refresh-revision";
    let refresh_revision_client = "same-day-refresh-client";
    seed_client(
        &db,
        clients_table,
        refresh_revision_tenant,
        refresh_revision_client,
    )
    .await?;
    db.update_item()
        .table_name(clients_table)
        .key(
            "client_id",
            AttributeValue::S(tpk(refresh_revision_tenant, refresh_revision_client)),
        )
        .update_expression("SET last_used_day = :today")
        .expression_attribute_values(":today", AttributeValue::N(today.to_string()))
        .send()
        .await
        .map_err(|value| error("seed same-day refresh reclaim snapshot", value))?;
    let refresh_snapshot = clients
        .get(refresh_revision_tenant, refresh_revision_client)
        .await
        .map_err(|value| error("read same-day refresh reclaim snapshot", value))?
        .ok_or_else(|| "same-day refresh reclaim client is missing".to_string())?;
    refresh
        .create(
            refresh_revision_tenant,
            refresh_record("revision-family", refresh_revision_client),
        )
        .await
        .map_err(|value| error("create same-day refresh authority", value))?;
    if clients
        .convert_to_tombstone(
            refresh_revision_tenant,
            refresh_revision_client,
            now,
            refresh_snapshot.last_used_day,
            refresh_snapshot.authority_revision,
        )
        .await
        .map_err(|value| error("attempt stale refresh-revision tombstone", value))?
    {
        return Err("stale refresh authority revision allowed tombstoning".to_string());
    }
    let after_refresh_revision = clients
        .get(refresh_revision_tenant, refresh_revision_client)
        .await
        .map_err(|value| error("read same-day refresh authority revision", value))?
        .ok_or_else(|| "same-day refresh authority client disappeared".to_string())?;
    if after_refresh_revision.tombstoned_at.is_some()
        || after_refresh_revision.authority_revision != 1
    {
        return Err("same-day refresh authority revision fence was not preserved".to_string());
    }
    refresh
        .revoke(refresh_revision_tenant, "revision-family")
        .await
        .map_err(|value| error("clean same-day refresh authority", value))?;
    refresh
        .delete_all_by_tenant(refresh_revision_tenant)
        .await
        .map_err(|value| error("delete same-day refresh authority source", value))?;
    delete_client(
        &db,
        clients_table,
        refresh_revision_tenant,
        refresh_revision_client,
    )
    .await?;

    let collision_client = "same-client";
    seed_client(&db, clients_table, "tenant-a", collision_client).await?;
    seed_client(&db, clients_table, "tenant-b", collision_client).await?;
    refresh
        .create(
            "tenant-a",
            refresh_record("collision-family", collision_client),
        )
        .await
        .map_err(|value| error("create tenant-a refresh reference", value))?;
    refresh
        .create(
            "tenant-b",
            refresh_record("collision-family", collision_client),
        )
        .await
        .map_err(|value| error("create tenant-b refresh reference", value))?;
    refresh
        .revoke("tenant-a", "collision-family")
        .await
        .map_err(|value| error("revoke tenant-a refresh family", value))?;
    if refresh
        .has_active_family_by_client("tenant-a", collision_client)
        .await
        .map_err(|value| error("query tenant-a collision", value))?
        || !refresh
            .has_active_family_by_client("tenant-b", collision_client)
            .await
            .map_err(|value| error("query tenant-b collision", value))?
    {
        return Err("cross-tenant client collision isolation failed".to_string());
    }
    refresh
        .revoke("tenant-b", "collision-family")
        .await
        .map_err(|value| error("revoke tenant-b refresh family", value))?;

    let concurrent_tenant = "live-concurrent";
    let concurrent_client = "concurrent-client";
    seed_client(&db, clients_table, concurrent_tenant, concurrent_client).await?;
    refresh
        .create(
            concurrent_tenant,
            refresh_record("family-old", concurrent_client),
        )
        .await
        .map_err(|value| error("create initial concurrent refresh family", value))?;
    let revoke_store = refresh.clone();
    let create_store = refresh.clone();
    let (revoked, created) = tokio::join!(
        revoke_store.revoke(concurrent_tenant, "family-old"),
        create_store.create(
            concurrent_tenant,
            refresh_record("family-new", concurrent_client)
        ),
    );
    revoked.map_err(|value| error("concurrent refresh revoke", value))?;
    created.map_err(|value| error("concurrent refresh create", value))?;
    if !refresh
        .has_active_family_by_client(concurrent_tenant, concurrent_client)
        .await
        .map_err(|value| error("query concurrent refresh reference", value))?
    {
        return Err("concurrent revoke/create lost the active reference".to_string());
    }
    refresh
        .revoke(concurrent_tenant, "family-new")
        .await
        .map_err(|value| error("revoke replacement refresh family", value))?;
    if refresh
        .has_active_family_by_client(concurrent_tenant, concurrent_client)
        .await
        .map_err(|value| error("query fully revoked refresh client", value))?
    {
        return Err("fully revoked refresh client remained active".to_string());
    }

    for tenant in ["tenant-a", "tenant-b", concurrent_tenant] {
        refresh
            .delete_all_by_tenant(tenant)
            .await
            .map_err(|value| error("clean refresh families", value))?;
        delete_client(
            &db,
            clients_table,
            tenant,
            if tenant == concurrent_tenant {
                concurrent_client
            } else {
                collision_client
            },
        )
        .await?;
    }

    let fenced_tenant = "live-fenced";
    let fenced_client = "tombstoned-client";
    seed_client(&db, clients_table, fenced_tenant, fenced_client).await?;
    db.update_item()
        .table_name(clients_table)
        .key(
            "client_id",
            AttributeValue::S(tpk(fenced_tenant, fenced_client)),
        )
        .update_expression("SET tombstoned_at = :now")
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
        .send()
        .await
        .map_err(|value| error("tombstone registered client", value))?;
    if codes
        .put(
            fenced_tenant,
            code_record("fenced-code", fenced_client, now + 600),
        )
        .await
        .is_ok()
        || refresh
            .create(
                fenced_tenant,
                refresh_record("fenced-family", fenced_client),
            )
            .await
            .is_ok()
    {
        return Err("tombstoned client accepted new authority".to_string());
    }
    delete_client(&db, clients_table, fenced_tenant, fenced_client).await?;

    verify_empty(&db, codes_table, refresh_table, clients_table, refs_table).await
}

#[tokio::test]
#[ignore = "creates disposable real AWS DynamoDB tables"]
async fn real_dynamodb_authority_reference_lifecycle() {
    assert_eq!(
        std::env::var("AGENT_AUTH_AUTHORITY_REFS_LIVE").as_deref(),
        Ok("1"),
        "set AGENT_AUTH_AUTHORITY_REFS_LIVE=1 explicitly"
    );
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let db = aws_sdk_dynamodb::Client::new(&config);
    let run = format!(
        "{:x}{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tables = [
        format!("aa162-{run}-codes"),
        format!("aa162-{run}-refresh"),
        format!("aa162-{run}-clients"),
        format!("aa162-{run}-refs"),
    ];
    let cleanup_manifest = std::env::var("AGENT_AUTH_AUTHORITY_REFS_CLEANUP_MANIFEST")
        .expect("AGENT_AUTH_AUTHORITY_REFS_CLEANUP_MANIFEST must name a private cleanup manifest");
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&cleanup_manifest)
        .expect("create authority-reference cleanup manifest");
    manifest
        .write_all(
            serde_json::to_string(&serde_json::json!({ "tables": &tables }))
                .expect("serialize cleanup manifest")
                .as_bytes(),
        )
        .expect("write authority-reference cleanup manifest");
    manifest
        .sync_all()
        .expect("sync authority-reference cleanup manifest");
    let mut created = Vec::new();
    for (table, partition, sort) in [
        (&tables[0], "code", None),
        (&tables[1], "family_id", None),
        (&tables[2], "client_id", None),
        (&tables[3], "client_key", Some("reference_key")),
    ] {
        // Register the intended name before CreateTable. A transport timeout can
        // occur after AWS accepted the request, so cleanup must still probe/delete it.
        created.push(table.clone());
        match create_table(&db, table, partition, sort).await {
            Ok(()) => {}
            Err(value) => {
                let cleanup = delete_tables(&db, &created).await;
                panic!("table setup failed: {value}; cleanup={cleanup:?}");
            }
        }
    }

    let result = run_scenarios(db.clone(), &tables[0], &tables[1], &tables[2], &tables[3]).await;
    let cleanup = delete_tables(&db, &created).await;
    assert!(
        cleanup.is_ok(),
        "temporary table cleanup failed: {cleanup:?}"
    );
    result.expect("real DynamoDB authority-reference scenarios failed");
    println!(
        "AUTHORITY_REFS_LIVE {}",
        serde_json::json!({
            "result": "pass",
            "legacy_backfill": true,
            "immediate_reference_visibility": true,
            "multiple_active_references": true,
            "expiry_exclusion": true,
            "cross_tenant_collision_isolation": true,
            "concurrent_revoke_create": true,
            "tombstone_creation_fence": true,
            "same_day_code_revision_fence": true,
            "same_day_refresh_revision_fence": true,
            "terminal_orphan_cleanup": true,
            "governance_adapter_cleanup": true,
            "temporary_tables_deleted": true
        })
    );
}
