use super::{ciba_contracts::record, database, tenant};
use agent_auth_http::{
    adapters::{
        mounted_crypto::EncryptionKeyring,
        postgres::{PostgresCibaStore, PostgresMessageOutbox},
    },
    ports::{CibaAuthRequest, CibaStore, SentMessage, StoreError},
};
use sqlx::Row;

fn keys(kid: &str, material: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(kid, vec![(kid.into(), [material; 32])]).unwrap()
}

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Envelope {
    kid: String,
    key_nonce: Vec<u8>,
    encrypted_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

async fn envelope(pool: &sqlx::PgPool, tenant: &str, id: &str) -> Envelope {
    let row = sqlx::query(
        "SELECT kid, key_nonce, encrypted_key, nonce, ciphertext \
        FROM a_auth.ciba_requests WHERE tenant = $1 AND auth_req_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .fetch_one(pool)
    .await
    .unwrap();
    Envelope {
        kid: row.get("kid"),
        key_nonce: row.get("key_nonce"),
        encrypted_key: row.get("encrypted_key"),
        nonce: row.get("nonce"),
        ciphertext: row.get("ciphertext"),
    }
}

async fn replace(pool: &sqlx::PgPool, tenant: &str, id: &str, envelope: &Envelope) {
    sqlx::query(
        "UPDATE a_auth.ciba_requests SET kid = $3, key_nonce = $4, encrypted_key = $5, \
        nonce = $6, ciphertext = $7 WHERE tenant = $1 AND auth_req_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(id.as_bytes())
    .bind(&envelope.kid)
    .bind(&envelope.key_nonce)
    .bind(&envelope.encrypted_key)
    .bind(&envelope.nonce)
    .bind(&envelope.ciphertext)
    .execute(pool)
    .await
    .unwrap();
}

// Independent fixture codec: the public secret-bearing request deliberately
// has no Serialize implementation.
fn payload(record: &CibaAuthRequest) -> serde_json::Value {
    serde_json::json!({
        "auth_req_id": record.auth_req_id,
        "tenant": record.tenant,
        "client_id": record.client_id,
        "user_id": record.user_id,
        "authz_session_id": record.authz_session_id,
        "scope": record.scope,
        "resources": record.resources,
        "binding_message": record.binding_message,
        "interval": record.interval,
        "last_poll_at": record.last_poll_at,
        "expires_at": record.expires_at,
        "status": record.status,
        "consumed": record.consumed,
        "delivery_mode": record.delivery_mode,
        "notification_endpoint": record.notification_endpoint,
        "client_notification_token": record.client_notification_token,
        "password_credential_version": record.password_credential_version,
    })
}

fn authenticated_payload(
    envelope: &Envelope,
    record: &CibaAuthRequest,
    plaintext: &[u8],
) -> Envelope {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    let context = serde_json::to_vec(&(
        "ciba-request",
        &record.tenant,
        &record.auth_req_id,
        &record.client_id,
        &record.user_id,
        record.expires_at,
        &record.status,
        record.consumed,
        record.last_poll_at,
    ))
    .unwrap();
    let aad = |purpose: &[u8]| {
        let mut value = b"a-auth-envelope-v1".to_vec();
        for part in [envelope.kid.as_bytes(), &context, purpose] {
            value.extend_from_slice(&(part.len() as u64).to_be_bytes());
            value.extend_from_slice(part);
        }
        value
    };
    let data_key = zeroize::Zeroizing::new(
        Aes256Gcm::new_from_slice(&[0x67; 32])
            .unwrap()
            .decrypt(
                Nonce::from_slice(&envelope.key_nonce),
                Payload {
                    msg: &envelope.encrypted_key,
                    aad: &aad(b"data-key"),
                },
            )
            .unwrap(),
    );
    let mut changed = envelope.clone();
    changed.nonce = rand::random::<[u8; 12]>().to_vec();
    changed.ciphertext = Aes256Gcm::new_from_slice(&data_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&changed.nonce),
            Payload {
                msg: plaintext,
                aad: &aad(b"payload"),
            },
        )
        .unwrap();
    changed
}

#[tokio::test]
async fn postgres_ciba_encryption_rejects_incomplete_rebound_or_wrong_purpose_authority() {
    let base = database().await;
    let store = PostgresCibaStore::new(base.clone(), keys("ciba-key", 0x67));
    let pool = pool().await;
    let tenant = tenant();
    let initial = record(&tenant, "request", "user");
    store.put(&tenant, initial.clone()).await.unwrap();
    let original = envelope(&pool, &tenant, "request").await;
    for secret in [
        initial.client_notification_token.as_ref().unwrap(),
        initial.binding_message.as_ref().unwrap(),
    ] {
        assert!(!original
            .ciphertext
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes()));
    }
    let mut corruptions = Vec::new();
    for field in ["kid", "key_nonce", "encrypted_key", "nonce", "ciphertext"] {
        let mut changed = original.clone();
        match field {
            "kid" => changed.kid = "wrong-key".into(),
            "key_nonce" => changed.key_nonce[0] ^= 1,
            "encrypted_key" => changed.encrypted_key[0] ^= 1,
            "nonce" => changed.nonce[0] ^= 1,
            "ciphertext" => changed.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        corruptions.push(changed);
    }
    let value = payload(&initial);
    for field in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        corruptions.push(authenticated_payload(
            &original,
            &initial,
            &serde_json::to_vec(&changed).unwrap(),
        ));
    }
    for (field, replacement) in [
        ("tenant", serde_json::json!("foreign")),
        ("auth_req_id", serde_json::json!("different-request")),
        ("client_id", serde_json::json!("different-client")),
        ("user_id", serde_json::json!("different-user")),
        ("expires_at", serde_json::json!(999)),
        ("status", serde_json::json!("approved")),
        ("consumed", serde_json::json!(true)),
        ("last_poll_at", serde_json::json!(1)),
        ("unknown", serde_json::json!("private-ciba-sentinel")),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        corruptions.push(authenticated_payload(
            &original,
            &initial,
            &serde_json::to_vec(&changed).unwrap(),
        ));
    }
    for bytes in [
        b"{}".as_slice(),
        b"private-ciba-sentinel".as_slice(),
        br#"{"auth_req_id":"request","auth_req_id":"request"}"#.as_slice(),
    ] {
        corruptions.push(authenticated_payload(&original, &initial, bytes));
    }
    let mut duplicate = serde_json::to_string(&value).unwrap();
    duplicate = duplicate.replacen(
        "\"auth_req_id\":\"request\"",
        "\"auth_req_id\":\"request\",\"auth_req_id\":\"request\"",
        1,
    );
    corruptions.push(authenticated_payload(
        &original,
        &initial,
        duplicate.as_bytes(),
    ));
    for bad in corruptions {
        replace(&pool, &tenant, "request", &bad).await;
        let attempts = [
            store.get(&tenant, "request").await.map(|_| ()),
            store.consume(&tenant, "request").await.map(|_| ()),
            store.put(&tenant, initial.clone()).await,
        ];
        for attempt in attempts {
            assert!(
                matches!(&attempt, Err(StoreError::Permanent(_))),
                "{attempt:?}"
            );
            assert!(!format!("{attempt:?}").contains("private-ciba-sentinel"));
        }
        assert_eq!(envelope(&pool, &tenant, "request").await, bad);
    }
    replace(&pool, &tenant, "request", &original).await;
    sqlx::query("UPDATE a_auth.ciba_requests SET client_id = $2 WHERE tenant = $1")
        .bind(tenant.as_bytes())
        .bind(b"rebound-client".as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.get(&tenant, "request").await,
        Err(StoreError::Permanent(_))
    ));
    sqlx::query("UPDATE a_auth.ciba_requests SET client_id = $2 WHERE tenant = $1")
        .bind(tenant.as_bytes())
        .bind(initial.client_id.as_bytes())
        .execute(&pool)
        .await
        .unwrap();
    let outbox = PostgresMessageOutbox::new(base, keys("ciba-key", 0x67));
    outbox
        .record_delivered(SentMessage {
            message_id: "different-purpose".into(),
            tenant: tenant.clone(),
            kind: "notice".into(),
            recipient: "person@example.test".into(),
            body: "private-ciba-sentinel".into(),
            created_at: 100,
            ttl: 200,
        })
        .await
        .unwrap();
    sqlx::query("UPDATE a_auth.ciba_requests AS c SET \
        (kid, key_nonce, encrypted_key, nonce, ciphertext) = \
        (m.kid, m.key_nonce, m.encrypted_key, m.nonce, m.ciphertext) \
        FROM a_auth.message_outbox AS m WHERE c.tenant = $1 AND m.tenant = $1 AND m.message_id = $2")
        .bind(tenant.as_bytes()).bind(b"different-purpose".as_slice()).execute(&pool).await.unwrap();
    assert!(matches!(
        store.get(&tenant, "request").await,
        Err(StoreError::Permanent(_))
    ));
    replace(&pool, &tenant, "request", &original).await;
    assert_eq!(store.get(&tenant, "request").await.unwrap(), Some(initial));
    pool.close().await;
}

#[tokio::test]
async fn postgres_ciba_failed_writes_and_cleanup_preserve_complete_previous_authority() {
    let base = database().await;
    let store = PostgresCibaStore::new(base, keys("ciba-key", 0x67));
    let pool = pool().await;
    let tenant = tenant();
    let initial = record(&tenant, "request", "user");
    store.put(&tenant, initial.clone()).await.unwrap();
    store
        .try_arm_throttle(&tenant, "user", 100, 60)
        .await
        .unwrap();
    let original = envelope(&pool, &tenant, "request").await;
    let fresh = super::tenant();
    let trigger = format!("contract_ciba_{:032x}", rand::random::<u128>());
    sqlx::query(&format!("CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
        $fixture$ BEGIN IF NEW.tenant IN (convert_to('{tenant}', 'UTF8'), convert_to('{fresh}', 'UTF8')) THEN \
        RAISE EXCEPTION 'private-ciba-sentinel' USING ERRCODE = '23514'; END IF; RETURN NEW; END $fixture$"))
        .execute(&pool).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE ON a_auth.ciba_requests \
        FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let admission = store.put(&fresh, record(&fresh, "initial", "user")).await;
    let consumption = store.consume(&tenant, "request").await;
    let decision = store.decide(&tenant, "request", Some(1), true).await;
    let polling = store.claim_poll(&tenant, "request", None, 100).await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.ciba_requests"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    for attempt in [
        admission,
        consumption.map(|_| ()),
        decision.map(|_| ()),
        polling.map(|_| ()),
    ] {
        assert!(matches!(&attempt, Err(StoreError::Permanent(_))));
        assert!(!format!("{attempt:?}").contains("private-ciba-sentinel"));
    }
    assert_eq!(envelope(&pool, &tenant, "request").await, original);
    assert_eq!(
        store.get(&tenant, "request").await.unwrap(),
        Some(initial.clone())
    );
    let directory: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM a_auth.user_directories WHERE tenant = $1)",
    )
    .bind(fresh.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!directory);
    sqlx::query(&format!("CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
        $fixture$ BEGIN IF OLD.tenant = convert_to('{tenant}', 'UTF8') THEN \
        RAISE EXCEPTION 'private-ciba-sentinel' USING ERRCODE = '23514'; END IF; RETURN OLD; END $fixture$"))
        .execute(&pool).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON a_auth.ciba_throttle \
        FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let by_user = store.delete_by_user(&tenant, "user").await;
    let by_tenant = store.delete_all_by_tenant(&tenant).await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.ciba_throttle"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(by_user, Err(StoreError::Permanent(_))));
    assert!(matches!(by_tenant, Err(StoreError::Permanent(_))));
    assert_eq!(store.get(&tenant, "request").await.unwrap(), Some(initial));
    assert!(!store
        .try_arm_throttle(&tenant, "user", 101, 60)
        .await
        .unwrap());
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    pool.close().await;
}

#[tokio::test]
async fn postgres_ciba_key_overlap_and_delete_only_capability_preserve_confidentiality() {
    let base = database().await;
    let tenant = tenant();
    let old = PostgresCibaStore::new(base.clone(), keys("old", 0x68));
    let first = record(&tenant, "old-request", "user");
    old.put(&tenant, first.clone()).await.unwrap();
    let rotated = PostgresCibaStore::new(
        base.clone(),
        EncryptionKeyring::new(
            "new",
            vec![("old".into(), [0x68; 32]), ("new".into(), [0x69; 32])],
        )
        .unwrap(),
    );
    assert_eq!(
        rotated.get(&tenant, "old-request").await.unwrap(),
        Some(first)
    );
    let second = record(&tenant, "new-request", "user");
    rotated.put(&tenant, second.clone()).await.unwrap();
    let retired = PostgresCibaStore::new(base.clone(), keys("new", 0x69));
    assert!(matches!(
        retired.get(&tenant, "old-request").await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(
        retired.get(&tenant, "new-request").await.unwrap(),
        Some(second)
    );
    let wrong = PostgresCibaStore::new(base.clone(), keys("new", 0x70));
    assert!(matches!(
        wrong.get(&tenant, "new-request").await,
        Err(StoreError::Permanent(_))
    ));
    let erase = PostgresCibaStore::new_delete_only(base);
    let attempts = [
        erase.get(&tenant, "old-request").await.map(|_| ()),
        erase.get(&tenant, "absent").await.map(|_| ()),
        erase.consume(&tenant, "absent").await.map(|_| ()),
        erase
            .claim_poll(&tenant, "absent", None, 100)
            .await
            .map(|_| ()),
        erase
            .decide(&tenant, "absent", None, true)
            .await
            .map(|_| ()),
        erase.release_consume(&tenant, "absent").await,
        erase
            .put(&tenant, record(&tenant, "forbidden", "user"))
            .await,
        erase
            .try_arm_throttle(&tenant, "user", 100, 60)
            .await
            .map(|_| ()),
    ];
    for attempt in attempts {
        assert!(matches!(attempt, Err(StoreError::Permanent(_))));
    }
    assert_eq!(erase.delete_by_user(&tenant, "user").await.unwrap(), 2);
    assert_eq!(erase.delete_all_by_tenant(&tenant).await.unwrap(), 0);
    assert_eq!(rotated.get(&tenant, "old-request").await.unwrap(), None);
}

#[tokio::test]
async fn postgres_ciba_separate_pools_preserve_nul_identifiers_and_full_numeric_domains() {
    let first = PostgresCibaStore::new(database().await, keys("ciba-key", 0x67));
    let second = PostgresCibaStore::new(database().await, keys("ciba-key", 0x67));
    let tenant = format!("{}\0tenant", tenant());
    let mut initial = record(&tenant, "request\0id", "user\0id");
    initial.client_id = "client\0id".into();
    initial.authz_session_id = Some("session\0id".into());
    initial.resources = vec!["resource\0value".into()];
    initial.scope = vec!["scope\0value".into()];
    initial.binding_message = Some("message\0value".into());
    initial.client_notification_token = Some("private-token\0value".into());
    initial.notification_endpoint = Some("opaque\0snapshot".into());
    initial.interval = i64::MIN;
    initial.expires_at = i64::MAX;
    first.put(&tenant, initial.clone()).await.unwrap();
    assert_eq!(
        second.get(&tenant, &initial.auth_req_id).await.unwrap(),
        Some(initial.clone())
    );
    assert!(second
        .claim_poll(&tenant, &initial.auth_req_id, None, i64::MIN)
        .await
        .unwrap());
    assert!(first
        .decide(&tenant, &initial.auth_req_id, Some(u64::MAX), false)
        .await
        .unwrap());
    initial.last_poll_at = Some(i64::MIN);
    initial.status = "denied".into();
    initial.password_credential_version = Some(u64::MAX);
    assert_eq!(
        second.get(&tenant, &initial.auth_req_id).await.unwrap(),
        Some(initial.clone())
    );
    assert!(first.consume(&tenant, &initial.auth_req_id).await.unwrap());
    assert!(!second.consume(&tenant, &initial.auth_req_id).await.unwrap());
    assert!(first
        .try_arm_throttle(&tenant, &initial.user_id, i64::MIN, i64::MAX)
        .await
        .unwrap());
    assert!(!second
        .try_arm_throttle(&tenant, &initial.user_id, i64::MIN + 1, i64::MAX)
        .await
        .unwrap());
    assert!(second
        .try_arm_throttle(&tenant, &initial.user_id, -1, i64::MAX)
        .await
        .unwrap());
    assert_eq!(first.delete_all_by_tenant(&tenant).await.unwrap(), 2);
    assert_eq!(
        second.get(&tenant, &initial.auth_req_id).await.unwrap(),
        None
    );
}
