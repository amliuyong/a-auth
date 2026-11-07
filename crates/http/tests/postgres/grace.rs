use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        memory::MemoryGraceStore, mounted_crypto::EncryptionKeyring, postgres::PostgresGraceStore,
    },
    ports::{GraceCacheEntry, GraceCachedResponse, GraceStore},
};

fn entry(family: &str, version: u64) -> GraceCacheEntry {
    GraceCacheEntry {
        family_id: family.into(),
        version,
        fingerprint: [7; 32],
        client_id: "client".into(),
        dpop_jkt: Some("proof-thumbprint".into()),
        response: GraceCachedResponse {
            access_token: "issued-access-token".into(),
            refresh_token: "issued-refresh-token".into(),
            id_token: Some("issued-id-token".into()),
            scope: Some("openid profile".into()),
            expires_in: 300,
        },
        expires_at: 100,
    }
}

async fn grace_contract(store: impl GraceStore + Clone + 'static) {
    let family = tenant();
    let neighbor = format!("{family}.child");
    assert_eq!(store.get(&family, 1).await.unwrap(), None);
    let first = entry(&family, 1);
    store.put(first.clone()).await.unwrap();
    // The endpoint checks the window: the raw port returns an expired entry.
    assert_eq!(store.get(&family, 1).await.unwrap(), Some(first));
    let mut replacement = entry(&family, 1);
    replacement.response.id_token = None;
    replacement.dpop_jkt = None;
    replacement.response.scope = None;
    store.put(replacement.clone()).await.unwrap();
    assert_eq!(store.get(&family, 1).await.unwrap(), Some(replacement));

    let mut tasks = Vec::new();
    for version in 2..18 {
        let (store, family) = (store.clone(), family.clone());
        tasks.push(tokio::spawn(async move {
            let response = entry(&family, version);
            store.put(response.clone()).await.unwrap();
            assert_eq!(store.get(&family, version).await.unwrap(), Some(response));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let largest = entry(&family, u64::MAX);
    store.put(largest.clone()).await.unwrap();
    assert_eq!(store.get(&family, u64::MAX).await.unwrap(), Some(largest));
    let other = entry(&neighbor, 1);
    store.put(other.clone()).await.unwrap();
    store.delete_family(&family).await.unwrap();
    store.delete_family(&family).await.unwrap();
    for version in [1, 2, 17, u64::MAX] {
        assert_eq!(store.get(&family, version).await.unwrap(), None);
    }
    assert_eq!(
        store.get(&neighbor, 1).await.unwrap(),
        Some(other),
        "deleting one family must preserve a distinct family with a shared prefix"
    );
    store.delete_family(&neighbor).await.unwrap();
}

#[tokio::test]
async fn memory_grace_contract() {
    grace_contract(MemoryGraceStore::default()).await;
}

#[tokio::test]
async fn postgres_grace_contract() {
    let keys = EncryptionKeyring::new("fixture-v1", vec![("fixture-v1".into(), [19; 32])]).unwrap();
    grace_contract(PostgresGraceStore::new(database().await, keys)).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_grace_contract() {
    use agent_auth_http::adapters::aws::DynamoGraceStore;
    use aws_sdk_dynamodb::types::ScalarAttributeType;
    use base64::Engine;
    let (db, table) = super::aws_contract_database::table_with_typed_range(
        "family_id",
        Some(("version", ScalarAttributeType::N)),
        vec![],
        vec![],
    )
    .await;
    // The real AWS adapter and DynamoDB emulator run end to end. KMS is a
    // loopback fixture, so this does not establish native KMS qualification.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let kms_router = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "KeyId": "fixture-key",
                "Plaintext": base64::engine::general_purpose::STANDARD.encode([23; 32]),
                "CiphertextBlob": base64::engine::general_purpose::STANDARD.encode([29; 48]),
            }))
        }),
    );
    let fixture = tokio::spawn(async move {
        axum::serve(listener, kms_router).await.unwrap();
    });
    let kms = aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_kms::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
            .endpoint_url(format!("http://{address}"))
            .build(),
    );
    grace_contract(DynamoGraceStore::new(
        db.clone(),
        kms,
        &table,
        "fixture-key",
    ))
    .await;
    fixture.abort();
    db.delete_table().table_name(table).send().await.unwrap();
}

struct KeyFile(std::path::PathBuf);

impl KeyFile {
    fn new() -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        let path =
            std::env::temp_dir().join(format!("a-auth-142-key-{:032x}", rand::random::<u128>()));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        Self(path)
    }

    fn write(&self, active: &str, keys: &[(&str, [u8; 32])]) {
        use base64::Engine;
        let keys: Vec<_> = keys
            .iter()
            .map(|(kid, bytes)| {
                serde_json::json!({
                    "kid": kid,
                    "key_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
                })
            })
            .collect();
        std::fs::write(
            &self.0,
            serde_json::to_vec(&serde_json::json!({"active_kid": active, "keys": keys})).unwrap(),
        )
        .unwrap();
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn postgres_grace_mounted_key_rotation_preserves_overlap_and_rejects_retired_keys() {
    use std::os::unix::fs::PermissionsExt;
    let file = KeyFile::new();
    assert!(
        EncryptionKeyring::from_file(&file.0).is_err(),
        "empty keys fail closed"
    );
    file.write("old", &[("old", [31; 32])]);
    let first = PostgresGraceStore::new(
        database().await,
        EncryptionKeyring::from_file(&file.0).unwrap(),
    );
    let family = tenant();
    let old = entry(&family, 1);
    first.put(old.clone()).await.unwrap();
    file.write("new", &[("old", [31; 32]), ("new", [37; 32])]);
    let overlap = PostgresGraceStore::new(
        database().await,
        EncryptionKeyring::from_file(&file.0).unwrap(),
    );
    let new = entry(&family, 2);
    overlap.put(new.clone()).await.unwrap();
    assert_eq!(overlap.get(&family, 1).await.unwrap(), Some(old));
    assert_eq!(overlap.get(&family, 2).await.unwrap(), Some(new.clone()));
    assert!(
        first.get(&family, 2).await.is_err(),
        "an existing instance retains its immutable key snapshot"
    );
    file.write("new", &[("new", [37; 32])]);
    let retired = PostgresGraceStore::new(
        database().await,
        EncryptionKeyring::from_file(&file.0).unwrap(),
    );
    assert!(retired.get(&family, 1).await.is_err());
    assert_eq!(retired.get(&family, 2).await.unwrap(), Some(new));
    retired.delete_family(&family).await.unwrap();
    assert!(retired.get(&family, 1).await.unwrap().is_none());

    for (active, keys) in [
        ("absent", vec![("old", [31; 32])]),
        ("old", vec![("old", [31; 32]), ("old", [37; 32])]),
        ("old", vec![("old", [0; 32])]),
        ("bad/id", vec![("bad/id", [31; 32])]),
    ] {
        file.write(active, &keys);
        assert!(EncryptionKeyring::from_file(&file.0).is_err());
    }
    file.write("old", &[("old", [31; 32])]);
    std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert!(EncryptionKeyring::from_file(&file.0).is_err());
    // Kubernetes Secret projections can grant read access to the pod's fsGroup.
    std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o440)).unwrap();
    assert!(EncryptionKeyring::from_file(&file.0).is_ok());
    std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o600)).unwrap();
    for invalid in [
        r#"{"active_kid":"old","keys":[{"kid":"old","key_base64":"invalid-secret-material"}]}"#
            .as_bytes()
            .to_vec(),
        r#"{"active_kid":"old","keys":[],"unexpected":"private-config"}"#
            .as_bytes()
            .to_vec(),
        vec![b' '; 65_537],
    ] {
        std::fs::write(&file.0, invalid).unwrap();
        assert!(EncryptionKeyring::from_file(&file.0).is_err());
    }
}

#[tokio::test]
async fn postgres_grace_delete_only_rejects_decryption_and_preserves_cleanup() {
    let database = database().await;
    let writer = PostgresGraceStore::new(
        database.clone(),
        EncryptionKeyring::new("fixture", vec![("fixture".into(), [41; 32])]).unwrap(),
    );
    let family = tenant();
    let response = entry(&family, 1);
    writer.put(response.clone()).await.unwrap();
    let cleanup = PostgresGraceStore::new_delete_only(database);
    assert!(cleanup.get(&family, 1).await.is_err());
    assert!(cleanup.get("absent", 1).await.is_err());
    assert!(cleanup.put(response.clone()).await.is_err());
    assert_eq!(writer.get(&family, 1).await.unwrap(), Some(response));
    cleanup.delete_family(&family).await.unwrap();
    assert_eq!(writer.get(&family, 1).await.unwrap(), None);
}

#[tokio::test]
async fn postgres_grace_rejects_row_substitution_and_tampered_envelopes() {
    use agent_auth_http::ports::StoreError;
    use sqlx::Row;
    let database = database().await;
    let store = PostgresGraceStore::new(
        database,
        EncryptionKeyring::new("fixture", vec![("fixture".into(), [43; 32])]).unwrap(),
    );
    let family = format!("{}\0opaque", tenant());
    let mut response = entry(&family, 1);
    response.client_id = "client\0opaque".into();
    store.put(response.clone()).await.unwrap();
    assert_eq!(store.get(&family, 1).await.unwrap(), Some(response.clone()));
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT encrypted_key, key_nonce, nonce, ciphertext FROM a_auth.grace_responses \
         WHERE family_id = $1 AND version = 1",
    )
    .bind(family.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    // Observe the persistence boundary: tokens and key material must not occur
    // in any stored envelope bytes.
    for column in ["encrypted_key", "key_nonce", "nonce", "ciphertext"] {
        let bytes: Vec<u8> = row.get(column);
        for secret in [
            response.response.access_token.as_bytes(),
            response.response.refresh_token.as_bytes(),
            response.response.id_token.as_deref().unwrap().as_bytes(),
            &[43u8; 32][..],
        ] {
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }
    let moved = format!("{family}-moved");
    for (destination, version) in [(&moved, 1i64), (&family, 2i64)] {
        sqlx::query(
            "INSERT INTO a_auth.grace_responses \
             SELECT $2, $3, expires_at, kid, key_nonce, encrypted_key, nonce, ciphertext \
             FROM a_auth.grace_responses WHERE family_id = $1 AND version = 1",
        )
        .bind(family.as_bytes())
        .bind(destination.as_bytes())
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            store.get(destination, version as u64).await,
            Err(StoreError::Permanent(_))
        ));
    }
    for mutation in [
        "expires_at = expires_at + 1",
        "ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1)",
        "encrypted_key = set_byte(encrypted_key, 0, get_byte(encrypted_key, 0) # 1)",
        "nonce = set_byte(nonce, 0, get_byte(nonce, 0) # 1)",
        "key_nonce = set_byte(key_nonce, 0, get_byte(key_nonce, 0) # 1)",
        "kid = 'unknown'",
    ] {
        sqlx::query(&format!(
            "UPDATE a_auth.grace_responses SET {mutation} WHERE family_id = $1 AND version = 1"
        ))
        .bind(family.as_bytes())
        .execute(&pool)
        .await
        .unwrap();
        let error = store.get(&family, 1).await.unwrap_err();
        let StoreError::Permanent(message) = error else {
            panic!("damaged envelope must fail closed");
        };
        assert_eq!(message, "Encrypted record authentication failed");
        store.put(response.clone()).await.unwrap();
        assert_eq!(store.get(&family, 1).await.unwrap(), Some(response.clone()));
    }
    store.delete_family(&family).await.unwrap();
    store.delete_family(&moved).await.unwrap();
    pool.close().await;
}

#[tokio::test]
async fn postgres_refresh_finalization_commits_encrypted_grace_atomically() {
    use agent_auth_http::{
        adapters::postgres::RefreshRotationRequest,
        ports::{ClientRecord, ClientStore, RefreshLeaseAcquire, RefreshStore},
    };
    let database = database().await;
    let grace = PostgresGraceStore::new(
        database.clone(),
        EncryptionKeyring::new("fixture", vec![("fixture".into(), [47; 32])]).unwrap(),
    );
    let tenant = tenant();
    let family = format!("{tenant}-family");
    let now = agent_auth_http::current_unix_secs();
    ClientStore::put(
        &database,
        &tenant,
        ClientRecord {
            client_id: "client".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let record = super::refresh_record();
    RefreshStore::create(
        &database,
        &tenant,
        agent_auth_http::ports::RefreshFamilyRecord {
            family_id: family.clone(),
            ..record
        },
    )
    .await
    .unwrap();
    assert_eq!(
        database
            .acquire_lease(&tenant, &family, 0, "owner", now, now + 600)
            .await
            .unwrap(),
        RefreshLeaseAcquire::Acquired
    );
    let response = entry(&family, 0);
    // An actual database constraint rejects the second write. The first write
    // must roll back, preserving both the old version and its owner's lease.
    let pool = sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let constraint = format!("contract_grace_{:032x}", rand::random::<u128>());
    let family_hex: String = family.bytes().map(|byte| format!("{byte:02x}")).collect();
    sqlx::query(&format!(
        "ALTER TABLE a_auth.grace_responses ADD CONSTRAINT {constraint} \
         CHECK (family_id <> decode('{family_hex}', 'hex')) NOT VALID"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let result = database
        .finalize_refresh_rotation(
            Some(&grace),
            RefreshRotationRequest {
                tenant: &tenant,
                family_id: &family,
                expected_version: 0,
                lease_owner: "owner",
                now,
                grace_entry: Some(response.clone()),
            },
        )
        .await;
    sqlx::query(&format!(
        "ALTER TABLE a_auth.grace_responses DROP CONSTRAINT {constraint}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(
        RefreshStore::get(&database, &tenant, &family)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        0
    );
    assert_eq!(grace.get(&family, 0).await.unwrap(), None);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (database, grace, tenant, family, response) = (
            database.clone(),
            grace.clone(),
            tenant.clone(),
            family.clone(),
            response.clone(),
        );
        tasks.push(tokio::spawn(async move {
            database
                .finalize_refresh_rotation(
                    Some(&grace),
                    RefreshRotationRequest {
                        tenant: &tenant,
                        family_id: &family,
                        expected_version: 0,
                        lease_owner: "owner",
                        now,
                        grace_entry: Some(response),
                    },
                )
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    assert_eq!(
        RefreshStore::get(&database, &tenant, &family)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        1
    );
    assert_eq!(grace.get(&family, 0).await.unwrap(), Some(response.clone()));
    let mut mismatched = response.clone();
    mismatched.family_id = format!("{family}-wrong");
    assert!(database
        .finalize_refresh_rotation(
            Some(&grace),
            RefreshRotationRequest {
                tenant: &tenant,
                family_id: &family,
                expected_version: 0,
                lease_owner: "owner",
                now,
                grace_entry: Some(mismatched),
            },
        )
        .await
        .is_err());
    // A stale caller clock cannot finalize a lease already expired in reality.
    assert_eq!(
        database
            .acquire_lease(&tenant, &family, 1, "expired", now - 600, now - 1)
            .await
            .unwrap(),
        RefreshLeaseAcquire::Acquired
    );
    assert!(!database
        .finalize_refresh_rotation(
            Some(&grace),
            RefreshRotationRequest {
                tenant: &tenant,
                family_id: &family,
                expected_version: 1,
                lease_owner: "expired",
                now: now - 600,
                grace_entry: Some(entry(&family, 1)),
            },
        )
        .await
        .unwrap());
    assert_eq!(grace.get(&family, 1).await.unwrap(), None);
    let now = agent_auth_http::current_unix_secs();
    assert_eq!(
        database
            .acquire_lease(&tenant, &family, 1, "replacement", now, now + 600)
            .await
            .unwrap(),
        RefreshLeaseAcquire::Acquired
    );
    assert!(database
        .finalize_refresh_rotation(
            None,
            RefreshRotationRequest {
                tenant: &tenant,
                family_id: &family,
                expected_version: 1,
                lease_owner: "replacement",
                now,
                grace_entry: None,
            },
        )
        .await
        .unwrap());
    assert_eq!(
        RefreshStore::get(&database, &tenant, &family)
            .await
            .unwrap()
            .unwrap()
            .current_version,
        2
    );
    let other_pool = PostgresGraceStore::new(
        super::database().await,
        EncryptionKeyring::new("fixture", vec![("fixture".into(), [47; 32])]).unwrap(),
    );
    assert!(database
        .finalize_refresh_rotation(
            Some(&other_pool),
            RefreshRotationRequest {
                tenant: &tenant,
                family_id: &family,
                expected_version: 0,
                lease_owner: "owner",
                now,
                grace_entry: Some(response),
            },
        )
        .await
        .is_err());
    grace.delete_family(&family).await.unwrap();
    RefreshStore::delete_all_by_tenant(&database, &tenant)
        .await
        .unwrap();
    ClientStore::delete(&database, &tenant, "client")
        .await
        .unwrap();
    pool.close().await;
}
