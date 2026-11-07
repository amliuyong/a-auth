use super::{database, tenant};
use agent_auth_http::{
    adapters::{
        mounted_crypto::EncryptionKeyring,
        postgres::{PostgresGraceStore, PostgresMessageOutbox, PostgresStore},
    },
    ports::{
        GraceCacheEntry, GraceCachedResponse, GraceStore, MessageOutbox, SentMessage, StoreError,
    },
};
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::Barrier;

fn keys(kid: &str, material: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(kid, vec![(kid.into(), [material; 32])]).unwrap()
}

fn message(tenant: &str, id: &str) -> SentMessage {
    SentMessage {
        message_id: id.into(),
        tenant: tenant.into(),
        kind: "magic_link".into(),
        recipient: "person@example.test".into(),
        body: "https://issuer.example.test/private-outbox-body-sentinel".into(),
        created_at: 100,
        ttl: 86_500,
    }
}

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

fn private_failure<T>(result: Result<T, StoreError>) {
    let Err(error) = result else {
        panic!("invalid authority must fail closed")
    };
    assert!(matches!(error, StoreError::Permanent(_)), "{error:?}");
    assert!(!format!("{error:?}").contains("private-outbox-body-sentinel"));
}

#[tokio::test]
async fn postgres_outbox_admission_is_immutable_and_failed_writes_preserve_state() {
    let base = database().await;
    let store = PostgresMessageOutbox::new(base, keys("outbox-key", 0x61));
    let pool = pool().await;
    let tenant = tenant();
    let initial = message(&tenant, "message");
    let constraint = format!("contract_outbox_{:032x}", rand::random::<u128>());
    let reject = format!(
        "ALTER TABLE a_auth.message_outbox ADD CONSTRAINT {constraint} \
         CHECK (tenant <> convert_to('{tenant}', 'UTF8')) NOT VALID"
    );
    let drop = format!("ALTER TABLE a_auth.message_outbox DROP CONSTRAINT {constraint}");
    sqlx::query(&reject).execute(&pool).await.unwrap();
    let failed = store.record_delivered(initial.clone()).await;
    sqlx::query(&drop).execute(&pool).await.unwrap();
    private_failure(failed);
    assert_eq!(store.list_recent(&tenant, 64).await.unwrap(), vec![]);
    let directories: i64 =
        sqlx::query_scalar("SELECT count(*) FROM a_auth.user_directories WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(directories, 0);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, initial, barrier) = (store.clone(), initial.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.record_delivered(initial).await.unwrap()
        }));
    }
    let mut wins = 0;
    for task in tasks {
        wins += usize::from(task.await.unwrap());
    }
    assert_eq!(wins, 1);
    let mut rebound = initial.clone();
    rebound.recipient = "other@example.test".into();
    private_failure(store.record_delivered(rebound).await);
    assert_eq!(
        store.list_recent(&tenant, 64).await.unwrap(),
        vec![initial.clone()]
    );
    let trigger = format!("contract_outbox_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF OLD.tenant = convert_to('{tenant}', 'UTF8') THEN \
         RAISE EXCEPTION 'private-outbox-body-sentinel' USING ERRCODE = '23514'; \
         END IF; RETURN OLD; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON a_auth.message_outbox \
         FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = store
        .delete_by_recipients(&tenant, std::slice::from_ref(&initial.recipient))
        .await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON a_auth.message_outbox"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    private_failure(failed);
    assert_eq!(store.list_recent(&tenant, 64).await.unwrap(), vec![initial]);
    assert_eq!(store.delete_all_by_tenant(&tenant).await.unwrap(), 1);
    pool.close().await;
}

#[derive(Clone)]
struct Envelope {
    kid: String,
    key_nonce: Vec<u8>,
    encrypted_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

async fn envelope(pool: &sqlx::PgPool, tenant: &str) -> Envelope {
    let row = sqlx::query(
        "SELECT kid, key_nonce, encrypted_key, nonce, ciphertext \
         FROM a_auth.message_outbox WHERE tenant = $1 AND message_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"message".as_slice())
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

async fn replace_envelope(pool: &sqlx::PgPool, tenant: &str, e: &Envelope) {
    sqlx::query(
        "UPDATE a_auth.message_outbox SET kid = $3, key_nonce = $4, encrypted_key = $5, \
         nonce = $6, ciphertext = $7 WHERE tenant = $1 AND message_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(b"message".as_slice())
    .bind(&e.kid)
    .bind(&e.key_nonce)
    .bind(&e.encrypted_key)
    .bind(&e.nonce)
    .bind(&e.ciphertext)
    .execute(pool)
    .await
    .unwrap();
}

// This independently produces authenticated malformed payloads. Fresh payload
// nonces isolate codec validation from envelope authentication failures.
fn with_authenticated_payload(e: &Envelope, message: &SentMessage, plaintext: &[u8]) -> Envelope {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    let context = serde_json::to_vec(&(
        "notification-outbox",
        &message.tenant,
        &message.message_id,
        &message.kind,
        &message.recipient,
        message.created_at,
        message.ttl,
    ))
    .unwrap();
    let aad = |purpose: &[u8]| {
        let mut value = b"a-auth-envelope-v1".to_vec();
        for part in [e.kid.as_bytes(), &context, purpose] {
            value.extend_from_slice(&(part.len() as u64).to_be_bytes());
            value.extend_from_slice(part);
        }
        value
    };
    let data_key = zeroize::Zeroizing::new(
        Aes256Gcm::new_from_slice(&[0x61; 32])
            .unwrap()
            .decrypt(
                Nonce::from_slice(&e.key_nonce),
                Payload {
                    msg: &e.encrypted_key,
                    aad: &aad(b"data-key"),
                },
            )
            .unwrap(),
    );
    let mut changed = e.clone();
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
async fn postgres_outbox_encryption_requires_complete_payload_and_bound_envelope() {
    let base = database().await;
    let store = PostgresMessageOutbox::new(base.clone(), keys("outbox-key", 0x61));
    let pool = pool().await;
    let tenant = tenant();
    let initial = message(&tenant, "message");
    assert!(store.record_delivered(initial.clone()).await.unwrap());
    let stored: String = sqlx::query_scalar(
        "SELECT row_to_json(m)::TEXT FROM a_auth.message_outbox m WHERE tenant = $1",
    )
    .bind(tenant.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!stored.contains("private-outbox-body-sentinel"));
    let original = envelope(&pool, &tenant).await;
    let mut corruptions = Vec::new();
    for field in ["kid", "key_nonce", "encrypted_key", "nonce", "ciphertext"] {
        let mut changed = original.clone();
        match field {
            "kid" => changed.kid = "unknown-key".into(),
            "key_nonce" => changed.key_nonce[0] ^= 1,
            "encrypted_key" => changed.encrypted_key[0] ^= 1,
            "nonce" => changed.nonce[0] ^= 1,
            "ciphertext" => changed.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        corruptions.push(changed);
    }
    let payload = serde_json::json!({
        "message_id": initial.message_id, "tenant": initial.tenant, "kind": initial.kind,
        "recipient": initial.recipient, "body": initial.body,
        "created_at": initial.created_at, "ttl": initial.ttl
    });
    let mut plaintexts = vec![b"{}".to_vec(), b"private-outbox-body-sentinel".to_vec()];
    for field in payload.as_object().unwrap().keys() {
        let mut changed = payload.clone();
        changed.as_object_mut().unwrap().remove(field);
        plaintexts.push(serde_json::to_vec(&changed).unwrap());
    }
    for field in [
        "message_id",
        "tenant",
        "kind",
        "recipient",
        "created_at",
        "ttl",
    ] {
        let mut changed = payload.clone();
        changed[field] = if changed[field].is_string() {
            "rebound".into()
        } else {
            1.into()
        };
        plaintexts.push(serde_json::to_vec(&changed).unwrap());
    }
    let mut unknown = payload;
    unknown["unexpected"] = true.into();
    plaintexts.push(serde_json::to_vec(&unknown).unwrap());
    for plaintext in plaintexts {
        corruptions.push(with_authenticated_payload(&original, &initial, &plaintext));
    }
    for changed in corruptions {
        replace_envelope(&pool, &tenant, &changed).await;
        private_failure(store.list_recent(&tenant, 64).await);
        private_failure(store.record_delivered(initial.clone()).await);
        assert_eq!(
            envelope(&pool, &tenant).await.ciphertext,
            changed.ciphertext
        );
    }
    replace_envelope(&pool, &tenant, &original).await;
    for column in ["kind", "recipient"] {
        sqlx::query(&format!(
            "UPDATE a_auth.message_outbox SET {column} = $3 \
             WHERE tenant = $1 AND message_id = $2"
        ))
        .bind(tenant.as_bytes())
        .bind(b"message".as_slice())
        .bind(b"rebound".as_slice())
        .execute(&pool)
        .await
        .unwrap();
        private_failure(store.list_recent(&tenant, 64).await);
        sqlx::query(&format!(
            "UPDATE a_auth.message_outbox SET {column} = $3 \
             WHERE tenant = $1 AND message_id = $2"
        ))
        .bind(tenant.as_bytes())
        .bind(b"message".as_slice())
        .bind(if column == "kind" {
            initial.kind.as_bytes()
        } else {
            initial.recipient.as_bytes()
        })
        .execute(&pool)
        .await
        .unwrap();
    }
    let grace = PostgresGraceStore::new(base, keys("outbox-key", 0x61));
    let family = format!("outbox-purpose-{}", rand::random::<u128>());
    grace
        .put(GraceCacheEntry {
            family_id: family.clone(),
            version: 1,
            fingerprint: [0x61; 32],
            client_id: "client".into(),
            dpop_jkt: None,
            expires_at: 86_500,
            response: GraceCachedResponse {
                access_token: "private-outbox-body-sentinel".into(),
                refresh_token: "refresh".into(),
                id_token: None,
                scope: None,
                expires_in: 300,
            },
        })
        .await
        .unwrap();
    sqlx::query(
        "UPDATE a_auth.message_outbox m SET \
         (kid, key_nonce, encrypted_key, nonce, ciphertext) = \
         (g.kid, g.key_nonce, g.encrypted_key, g.nonce, g.ciphertext) \
         FROM a_auth.grace_responses g WHERE m.tenant = $1 \
         AND m.message_id = $2 AND g.family_id = $3 AND g.version = 1",
    )
    .bind(tenant.as_bytes())
    .bind(b"message".as_slice())
    .bind(family.as_bytes())
    .execute(&pool)
    .await
    .unwrap();
    private_failure(store.list_recent(&tenant, 64).await);
    assert_eq!(
        PostgresMessageOutbox::new_delete_only(database().await)
            .delete_all_by_tenant(&tenant)
            .await
            .unwrap(),
        1
    );
    grace.delete_family(&family).await.unwrap();
    pool.close().await;
}

#[tokio::test]
async fn postgres_outbox_rotating_keys_and_delete_only_capability_preserve_authority() {
    let base = database().await;
    let tenant = tenant();
    let old = PostgresMessageOutbox::new(base.clone(), keys("old", 0x61));
    let initial = message(&tenant, "old-message");
    old.record_delivered(initial.clone()).await.unwrap();
    let overlap = EncryptionKeyring::new(
        "new",
        vec![("old".into(), [0x61; 32]), ("new".into(), [0x62; 32])],
    )
    .unwrap();
    let new = PostgresMessageOutbox::new(base.clone(), overlap);
    assert_eq!(
        new.list_recent(&tenant, 64).await.unwrap(),
        vec![initial.clone()]
    );
    new.record_delivered(message(&tenant, "new-message"))
        .await
        .unwrap();
    private_failure(old.list_recent(&tenant, 64).await);
    let retired = PostgresMessageOutbox::new(base.clone(), keys("new", 0x62));
    private_failure(retired.list_recent(&tenant, 64).await);
    let wrong = PostgresMessageOutbox::new(base.clone(), keys("old", 0x63));
    private_failure(wrong.list_recent(&tenant, 64).await);
    let delete_only = PostgresMessageOutbox::new_delete_only(base);
    private_failure(delete_only.list_recent(&tenant, 0).await);
    private_failure(delete_only.list_recent("missing", 64).await);
    private_failure(delete_only.record_delivered(initial).await);
    assert_eq!(
        delete_only
            .delete_by_recipients(&tenant, &["person@example.test".into()])
            .await
            .unwrap(),
        2
    );
    assert_eq!(new.list_recent(&tenant, 64).await.unwrap(), vec![]);
    assert_eq!(delete_only.delete_all_by_tenant(&tenant).await.unwrap(), 0);
}

#[tokio::test]
async fn postgres_outbox_separate_pools_preserve_nul_fields_and_exact_order() {
    let first = PostgresMessageOutbox::new(database().await, keys("outbox-key", 0x61));
    let second = PostgresMessageOutbox::new(
        PostgresStore::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap(), 2)
            .await
            .unwrap(),
        keys("outbox-key", 0x61),
    );
    let tenant = format!("{}\0tail", tenant());
    let mut values = Vec::new();
    for (id, created_at) in [
        ("z\0id", i64::MIN),
        ("a\0id", i64::MAX),
        ("b\0id", i64::MAX),
    ] {
        let mut entry = message(&tenant, id);
        entry.kind.push('\0');
        entry.recipient.push('\0');
        entry.body.push('\0');
        entry.created_at = created_at;
        entry.ttl = i64::MAX;
        first.record_delivered(entry.clone()).await.unwrap();
        values.push(entry);
    }
    values.reverse();
    assert_eq!(
        second.list_recent(&tenant, usize::MAX).await.unwrap(),
        values
    );
    assert_eq!(second.list_recent(&tenant, 1).await.unwrap(), values[..1]);
    assert!(!second.record_delivered(values[0].clone()).await.unwrap());
    assert_eq!(
        second
            .delete_by_recipients(&tenant, &[values[0].recipient.clone()])
            .await
            .unwrap(),
        3
    );
    assert_eq!(first.list_recent(&tenant, 64).await.unwrap(), vec![]);
}
