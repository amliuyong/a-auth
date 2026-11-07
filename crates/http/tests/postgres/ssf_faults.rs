use super::{
    ssf_contracts::{event, isolated_database, stream},
    tenant,
};
use agent_auth_http::{
    adapters::{
        mounted_crypto::EncryptionKeyring,
        postgres::{PostgresSsfStore, PostgresStore},
    },
    ports::StoreError,
    ssf::*,
};
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::Barrier;

fn keys(kid: &str, value: u8) -> EncryptionKeyring {
    EncryptionKeyring::new(kid, vec![(kid.into(), [value; 32])]).unwrap()
}

async fn cleanup(admin: sqlx::PgPool, name: &str) {
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Envelope {
    kid: String,
    key_nonce: Vec<u8>,
    encrypted_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    context: Vec<u8>,
}

async fn envelope(pool: &sqlx::PgPool, tenant: &str, event: &str) -> Envelope {
    let row = sqlx::query(
        "SELECT *, stream_revision::TEXT AS revision_text \
        FROM a_auth.ssf_deliveries WHERE tenant = $1 AND event_id = $2",
    )
    .bind(tenant.as_bytes())
    .bind(event.as_bytes())
    .fetch_one(pool)
    .await
    .unwrap();
    let text = |column: &str| String::from_utf8(row.get::<Vec<u8>, _>(column)).unwrap();
    let lease: Option<Vec<u8>> = row.get("lease_id");
    let lease = lease.map(|bytes| String::from_utf8(bytes).unwrap());
    let revision: u64 = row.get::<String, _>("revision_text").parse().unwrap();
    let status: SsfDeliveryStatus =
        serde_json::from_value(serde_json::Value::String(row.get("status"))).unwrap();
    Envelope {
        kid: row.get("kid"),
        key_nonce: row.get("key_nonce"),
        encrypted_key: row.get("encrypted_key"),
        nonce: row.get("nonce"),
        ciphertext: row.get("ciphertext"),
        context: serde_json::to_vec(&(
            "ssf-delivery",
            text("tenant"),
            text("stream_id"),
            revision,
            text("event_id"),
            row.get::<i64, _>("created_at"),
            row.get::<i64, _>("next_attempt_at"),
            row.get::<i64, _>("expires_at"),
            status,
            lease,
            row.get::<Option<i64>, _>("lease_expires_at"),
        ))
        .unwrap(),
    }
}

fn aad(envelope: &Envelope, purpose: &[u8]) -> Vec<u8> {
    let mut result = b"a-auth-envelope-v1".to_vec();
    for part in [envelope.kid.as_bytes(), &envelope.context, purpose] {
        result.extend_from_slice(&(part.len() as u64).to_be_bytes());
        result.extend_from_slice(part);
    }
    result
}

fn data_key(envelope: &Envelope) -> zeroize::Zeroizing<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    zeroize::Zeroizing::new(
        Aes256Gcm::new_from_slice(&[0x67; 32])
            .unwrap()
            .decrypt(
                Nonce::from_slice(&envelope.key_nonce),
                Payload {
                    msg: &envelope.encrypted_key,
                    aad: &aad(envelope, b"data-key"),
                },
            )
            .unwrap(),
    )
}

fn plaintext(envelope: &Envelope) -> zeroize::Zeroizing<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    zeroize::Zeroizing::new(
        Aes256Gcm::new_from_slice(&data_key(envelope))
            .unwrap()
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad(envelope, b"payload"),
                },
            )
            .unwrap(),
    )
}

fn authenticated(envelope: &Envelope, text: &[u8]) -> Envelope {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    let mut changed = envelope.clone();
    changed.nonce = rand::random::<[u8; 12]>().to_vec();
    changed.ciphertext = Aes256Gcm::new_from_slice(&data_key(envelope))
        .unwrap()
        .encrypt(
            Nonce::from_slice(&changed.nonce),
            Payload {
                msg: text,
                aad: &aad(envelope, b"payload"),
            },
        )
        .unwrap();
    changed
}

async fn replace(pool: &sqlx::PgPool, tenant: &str, event: &str, value: &Envelope) {
    sqlx::query(
        "UPDATE a_auth.ssf_deliveries SET kid=$3, key_nonce=$4, encrypted_key=$5, \
        nonce=$6, ciphertext=$7 WHERE tenant=$1 AND event_id=$2",
    )
    .bind(tenant.as_bytes())
    .bind(event.as_bytes())
    .bind(&value.kid)
    .bind(&value.key_nonce)
    .bind(&value.encrypted_key)
    .bind(&value.nonce)
    .bind(&value.ciphertext)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_ssf_encrypted_complete_authority_rejects_corruption_without_overwrite() {
    let (base, pool, admin, name, _) = isolated_database().await;
    let store = PostgresSsfStore::new(base, keys("ssf-key", 0x67));
    let tenant = tenant();
    let event = event(&tenant, "private-event");
    store
        .create_stream(stream(&tenant, "stream"))
        .await
        .unwrap();
    store
        .enqueue_event(&event, "https://issuer.example.test", 100)
        .await
        .unwrap();
    let lease = store.acquire_due(101, 30, 1).await.unwrap().pop().unwrap();
    let signed = SignedSet {
        compact_jws: "fixture-header.private-signed-set-sentinel.fixture-signature".into(),
        jti: "jti".into(),
        kid: "signer-kid".into(),
    };
    store
        .persist_signed_set(&lease, &signed, 102, 102)
        .await
        .unwrap();
    store
        .finish_attempt(&lease, SsfAttemptResult::Accepted, 103)
        .await
        .unwrap();
    let original = envelope(&pool, &tenant, "private-event").await;
    for secret in ["private-signed-set-sentinel", "canonical-user"] {
        assert!(!original
            .ciphertext
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes()));
    }
    let value: serde_json::Value = serde_json::from_slice(&plaintext(&original)).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 27);
    assert_eq!(value["compact_set"], signed.compact_jws);
    assert_eq!(value["lease_id"], serde_json::Value::Null);
    assert_eq!(
        value["attempt_history"][0]["error_class"],
        serde_json::Value::Null
    );
    let mut corruptions = Vec::new();
    for column in ["kid", "key_nonce", "encrypted_key", "nonce", "ciphertext"] {
        let mut bad = original.clone();
        match column {
            "kid" => bad.kid = "unknown-key".into(),
            "key_nonce" => bad.key_nonce[0] ^= 1,
            "encrypted_key" => bad.encrypted_key[0] ^= 1,
            "nonce" => bad.nonce[0] ^= 1,
            "ciphertext" => bad.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        corruptions.push(bad);
    }
    for field in value.as_object().unwrap().keys() {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        corruptions.push(authenticated(&original, &serde_json::to_vec(&bad).unwrap()));
    }
    for field in value["attempt_history"][0].as_object().unwrap().keys() {
        let mut bad = value.clone();
        bad["attempt_history"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        corruptions.push(authenticated(&original, &serde_json::to_vec(&bad).unwrap()));
    }
    for (field, replacement) in [
        ("tenant_id", serde_json::json!("foreign")),
        ("stream_id", serde_json::json!("foreign-stream")),
        ("stream_revision", serde_json::json!(2)),
        ("event_id", serde_json::json!("different-event")),
        ("created_at", serde_json::json!(999)),
        ("next_attempt_at", serde_json::json!(999)),
        ("expires_at", serde_json::json!(999)),
        ("status", serde_json::json!("pending")),
        ("lease_id", serde_json::json!("foreign-lease")),
        ("lease_expires_at", serde_json::json!(999)),
        ("unknown", serde_json::json!("private-signed-set-sentinel")),
        ("attempts", serde_json::json!(2)),
        ("cycle_attempts", serde_json::json!(2)),
        ("attempt_history", serde_json::json!([])),
        ("compact_set", serde_json::Value::Null),
        ("jti", serde_json::Value::Null),
        ("signing_kid", serde_json::Value::Null),
        ("issued_at", serde_json::Value::Null),
        ("endpoint", serde_json::json!("http://127.0.0.1")),
    ] {
        let mut bad = value.clone();
        bad[field] = replacement;
        corruptions.push(authenticated(&original, &serde_json::to_vec(&bad).unwrap()));
    }
    let text = serde_json::to_string(&value).unwrap();
    let duplicate = text.replacen(
        "\"event_id\":\"private-event\"",
        "\"event_id\":\"private-event\",\"event_id\":\"private-event\"",
        1,
    );
    for text in [
        b"{}".as_slice(),
        b"not JSON".as_slice(),
        duplicate.as_bytes(),
    ] {
        corruptions.push(authenticated(&original, text));
    }
    for bad in corruptions {
        replace(&pool, &tenant, "private-event", &bad).await;
        for outcome in [
            store
                .get_delivery(&tenant, "stream", 1, "private-event")
                .await
                .map(|_| ()),
            store
                .list_deliveries(&tenant, "stream", 100, None)
                .await
                .map(|_| ()),
            store
                .enqueue_event(&event, "https://issuer.example.test", 104)
                .await
                .map(|_| ()),
            store
                .redrive_delivery(&tenant, "stream", 1, "private-event", 104)
                .await
                .map(|_| ()),
        ] {
            assert!(
                matches!(&outcome, Err(StoreError::Permanent(_))),
                "{outcome:?}"
            );
            assert!(!format!("{outcome:?}").contains("private-signed-set-sentinel"));
        }
        assert_eq!(envelope(&pool, &tenant, "private-event").await, bad);
    }
    replace(&pool, &tenant, "private-event", &original).await;
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    let mut wrong_purpose = original.clone();
    wrong_purpose.context = b"other-authority-purpose".to_vec();
    wrong_purpose.key_nonce = rand::random::<[u8; 12]>().to_vec();
    wrong_purpose.nonce = rand::random::<[u8; 12]>().to_vec();
    wrong_purpose.encrypted_key = Aes256Gcm::new_from_slice(&[0x67; 32])
        .unwrap()
        .encrypt(
            Nonce::from_slice(&wrong_purpose.key_nonce),
            Payload {
                msg: &data_key(&original),
                aad: &aad(&wrong_purpose, b"data-key"),
            },
        )
        .unwrap();
    wrong_purpose.ciphertext = Aes256Gcm::new_from_slice(&data_key(&original))
        .unwrap()
        .encrypt(
            Nonce::from_slice(&wrong_purpose.nonce),
            Payload {
                msg: &plaintext(&original),
                aad: &aad(&wrong_purpose, b"payload"),
            },
        )
        .unwrap();
    wrong_purpose.context = original.context.clone();
    replace(&pool, &tenant, "private-event", &wrong_purpose).await;
    assert!(store
        .get_delivery(&tenant, "stream", 1, "private-event")
        .await
        .is_err());
    replace(&pool, &tenant, "private-event", &original).await;
    sqlx::query("UPDATE a_auth.ssf_deliveries SET next_attempt_at=999 WHERE tenant=$1")
        .bind(tenant.as_bytes())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store
        .get_delivery(&tenant, "stream", 1, "private-event")
        .await
        .is_err());
    cleanup(admin, &name).await;
}

#[tokio::test]
async fn postgres_ssf_skip_locked_claims_another_delivery_and_fences_stream_changes() {
    let (base, pool, admin, name, url) = isolated_database().await;
    let first = PostgresSsfStore::new(base, keys("ssf-key", 0x67));
    let second = PostgresSsfStore::new(
        PostgresStore::connect(&url, 8).await.unwrap(),
        keys("ssf-key", 0x67),
    );
    let tenant = tenant();
    first
        .create_stream(stream(&tenant, "stream"))
        .await
        .unwrap();
    for id in ["a-event", "b-event"] {
        first
            .enqueue_verification(
                &tenant,
                "stream",
                1,
                id,
                "https://issuer.example.test",
                None,
                100,
            )
            .await
            .unwrap();
    }
    let mut held = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT event_id FROM a_auth.ssf_deliveries \
        WHERE tenant=$1 AND event_id=$2 FOR UPDATE",
    )
    .bind(tenant.as_bytes())
    .bind(b"a-event".as_slice())
    .fetch_one(&mut *held)
    .await
    .unwrap();
    let lease = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        second.acquire_due(101, 10, 1),
    )
    .await
    .expect("SKIP LOCKED must claim the other due delivery")
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(lease.delivery.event_id, "b-event");
    held.commit().await.unwrap();
    let first_lease = first.acquire_due(101, 10, 1).await.unwrap().pop().unwrap();
    assert_eq!(first_lease.delivery.event_id, "a-event");
    assert_eq!(second.revoke_all_by_tenant(&tenant, 102).await.unwrap(), 3);
    assert!(!first
        .persist_signed_set(
            &first_lease,
            &SignedSet {
                compact_jws: "stale-set".into(),
                jti: "stale".into(),
                kid: "stale".into(),
            },
            103,
            103
        )
        .await
        .unwrap());
    assert!(first
        .finish_attempt(&lease, SsfAttemptResult::Accepted, 103)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        first
            .get_delivery(&tenant, "stream", 1, "a-event")
            .await
            .unwrap()
            .unwrap()
            .status,
        SsfDeliveryStatus::Suppressed
    );
    assert!(first.acquire_due(112, 10, 100).await.unwrap().is_empty());
    cleanup(admin, &name).await;
}

#[tokio::test]
async fn postgres_ssf_stream_complete_authority_and_atomic_revocation_fail_closed() {
    let (base, pool, admin, name, _) = isolated_database().await;
    let store = PostgresSsfStore::new(base, keys("ssf-key", 0x67));
    let tenant = tenant();
    let initial = stream(&tenant, "a-stream");
    store.create_stream(initial.clone()).await.unwrap();
    let original = serde_json::to_value(&initial).unwrap();
    let mut corruptions = vec![];
    for field in original.as_object().unwrap().keys() {
        let mut bad = original.clone();
        bad.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for (field, replacement) in [
        ("tenant_id", serde_json::json!("foreign")),
        ("stream_id", serde_json::json!("foreign-stream")),
        ("revision", serde_json::json!(2)),
        ("status", serde_json::json!("revoked")),
        ("unknown", serde_json::json!("private-stream-sentinel")),
        ("endpoint", serde_json::json!("http://127.0.0.1")),
        ("delivered_events", serde_json::json!([])),
        ("requested_events", serde_json::json!(["unsupported-event"])),
    ] {
        let mut bad = original.clone();
        bad[field] = replacement;
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    corruptions.push(serde_json::to_string(&original).unwrap().replacen(
        "\"revision\":1",
        "\"revision\":1,\"revision\":1",
        1,
    ));
    for text in corruptions {
        sqlx::query("UPDATE a_auth.ssf_streams SET record=$2 WHERE tenant=$1")
            .bind(tenant.as_bytes())
            .bind(&text)
            .execute(&pool)
            .await
            .unwrap();
        for outcome in [
            store.get_stream(&tenant, "a-stream").await.map(|_| ()),
            store.list_streams(&tenant).await.map(|_| ()),
            store
                .mutate_stream(&tenant, "a-stream", 1, SsfStreamMutation::Pause, 101)
                .await
                .map(|_| ()),
            store.revoke_all_by_tenant(&tenant, 101).await.map(|_| ()),
        ] {
            assert!(
                matches!(&outcome, Err(StoreError::Permanent(_))),
                "{outcome:?}"
            );
        }
        let retained: String =
            sqlx::query_scalar("SELECT record FROM a_auth.ssf_streams WHERE tenant=$1")
                .bind(tenant.as_bytes())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(retained, text);
    }
    sqlx::query("UPDATE a_auth.ssf_streams SET record=$2 WHERE tenant=$1")
        .bind(tenant.as_bytes())
        .bind(serde_json::to_string(&initial).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let mut exhausted = stream(&tenant, "z-stream");
    exhausted.revision = u64::MAX;
    store.create_stream(exhausted.clone()).await.unwrap();
    assert!(store.revoke_all_by_tenant(&tenant, 102).await.is_err());
    assert_eq!(
        store.list_streams(&tenant).await.unwrap(),
        vec![initial.clone(), exhausted]
    );
    assert!(store
        .mutate_stream(&tenant, "z-stream", u64::MAX, SsfStreamMutation::Pause, 102)
        .await
        .is_err());
    sqlx::query("DELETE FROM a_auth.ssf_streams WHERE tenant=$1 AND stream_id=$2")
        .bind(tenant.as_bytes())
        .bind(b"z-stream".as_slice())
        .execute(&pool)
        .await
        .unwrap();
    store
        .enqueue_event(
            &event(&tenant, "rollback-event"),
            "https://issuer.example.test",
            100,
        )
        .await
        .unwrap();
    let before = store
        .get_delivery(&tenant, "a-stream", 1, "rollback-event")
        .await
        .unwrap()
        .unwrap();
    let before_envelope = envelope(&pool, &tenant, "rollback-event").await;
    sqlx::query(
        "ALTER TABLE a_auth.ssf_deliveries ADD CONSTRAINT injected_suppression_failure \
        CHECK (status <> 'suppressed') NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(store.revoke_all_by_tenant(&tenant, 103).await.is_err());
    assert_eq!(
        store.get_stream(&tenant, "a-stream").await.unwrap(),
        Some(initial)
    );
    assert_eq!(
        store
            .get_delivery(&tenant, "a-stream", 1, "rollback-event")
            .await
            .unwrap(),
        Some(before)
    );
    assert_eq!(
        envelope(&pool, &tenant, "rollback-event").await,
        before_envelope
    );
    cleanup(admin, &name).await;
}

#[tokio::test]
async fn postgres_ssf_independent_pools_claim_sign_finish_and_redrive_once() {
    let (base, pool, admin, name, url) = isolated_database().await;
    let second = PostgresStore::connect(&url, 8).await.unwrap();
    let first = PostgresSsfStore::new(base, keys("ssf-key", 0x67));
    let second = PostgresSsfStore::new(second, keys("ssf-key", 0x67));
    let tenant = tenant();
    first
        .create_stream(stream(&tenant, "stream"))
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for id in 0..16 {
        let store = if id % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let tenant = tenant.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .enqueue_verification(
                    &tenant,
                    "stream",
                    1,
                    &format!("event-{id}"),
                    "https://issuer.example.test",
                    Some("private-verification-state"),
                    100,
                )
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        assert!(task.await.unwrap().enqueued().is_some());
    }
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for id in 0..16 {
        let store = if id % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.acquire_due(101, 10, 1).await.unwrap()
        }));
    }
    let mut leases = vec![];
    for task in tasks {
        leases.extend(task.await.unwrap());
    }
    assert_eq!(leases.len(), 16);
    let events: std::collections::BTreeSet<_> = leases
        .iter()
        .map(|lease| &lease.delivery.event_id)
        .collect();
    assert_eq!(events.len(), 16);
    let lease = leases.pop().unwrap();
    let signed = SignedSet {
        compact_jws: "header.signed-private-set.signature".into(),
        jti: "once-jti".into(),
        kid: "key-v1".into(),
    };
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for id in 0..16 {
        let store = if id % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let (barrier, lease, signed) = (barrier.clone(), lease.clone(), signed.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .persist_signed_set(&lease, &signed, 102, 102)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for id in 0..16 {
        let store = if id % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let (barrier, lease) = (barrier.clone(), lease.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .finish_attempt(
                    &lease,
                    SsfAttemptResult::Terminal {
                        status_code: 410,
                        error_class: "terminal".into(),
                    },
                    103,
                )
                .await
                .unwrap()
        }));
    }
    let mut receipts = vec![];
    for task in tasks {
        receipts.extend(task.await.unwrap());
    }
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].attempt_history.len(), 1);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = vec![];
    for id in 0..16 {
        let store = if id % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let (barrier, tenant, event_id) = (
            barrier.clone(),
            tenant.clone(),
            lease.delivery.event_id.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .redrive_delivery(&tenant, "stream", 1, &event_id, 104)
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), SsfRedriveOutcome::Redriven(_)) {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    let retained = second
        .get_delivery(&tenant, "stream", 1, &lease.delivery.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.compact_set, Some(signed.compact_jws));
    assert_eq!(
        (
            retained.attempts,
            retained.cycle_attempts,
            retained.redrive_count
        ),
        (1, 0, 1)
    );
    assert!(!first
        .persist_signed_set(
            &lease,
            &SignedSet {
                compact_jws: "old-owner".into(),
                jti: "old".into(),
                kid: "old".into()
            },
            104,
            104
        )
        .await
        .unwrap());
    assert!(first
        .finish_attempt(&lease, SsfAttemptResult::Accepted, 104)
        .await
        .unwrap()
        .is_none());
    let replacements = first.acquire_due(111, 10, 100).await.unwrap();
    assert!(replacements.len() >= 15);
    let expired_owner = &leases[0];
    assert!(replacements
        .iter()
        .any(|replacement| replacement.delivery.event_id == expired_owner.delivery.event_id));
    assert!(!second
        .persist_signed_set(
            expired_owner,
            &SignedSet {
                compact_jws: "header.stale-owner.signature".into(),
                jti: "stale".into(),
                kid: "stale".into(),
            },
            112,
            112
        )
        .await
        .unwrap());
    assert!(second
        .finish_attempt(expired_owner, SsfAttemptResult::Accepted, 112)
        .await
        .unwrap()
        .is_none());
    let persisted = envelope(&pool, &tenant, &lease.delivery.event_id).await;
    assert!(!persisted
        .ciphertext
        .windows("private-verification-state".len())
        .any(|value| value == b"private-verification-state"));
    cleanup(admin, &name).await;
}

#[tokio::test]
async fn postgres_ssf_key_overlap_retirement_and_atomic_queue_failures() {
    let (base, pool, admin, name, _) = isolated_database().await;
    let old = PostgresSsfStore::new(base.clone(), keys("old-key", 0x67));
    let overlap = PostgresSsfStore::new(
        base.clone(),
        EncryptionKeyring::new(
            "new-key",
            vec![
                ("old-key".into(), [0x67; 32]),
                ("new-key".into(), [0x68; 32]),
            ],
        )
        .unwrap(),
    );
    let retired = PostgresSsfStore::new(base.clone(), keys("new-key", 0x68));
    let wrong = PostgresSsfStore::new(base, keys("old-key", 0x69));
    let tenant = tenant();
    old.create_stream(stream(&tenant, "stream")).await.unwrap();
    old.enqueue_event(&event(&tenant, "event"), "https://issuer.example.test", 100)
        .await
        .unwrap();
    assert!(wrong
        .get_delivery(&tenant, "stream", 1, "event")
        .await
        .is_err());
    assert!(retired.acquire_due(101, 10, 1).await.is_err());
    let original = envelope(&pool, &tenant, "event").await;
    sqlx::query(
        "ALTER TABLE a_auth.ssf_deliveries ADD CONSTRAINT injected_lease_failure \
        CHECK (lease_id IS NULL) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(overlap.acquire_due(101, 10, 1).await.is_err());
    assert_eq!(envelope(&pool, &tenant, "event").await, original);
    sqlx::query("ALTER TABLE a_auth.ssf_deliveries DROP CONSTRAINT injected_lease_failure")
        .execute(&pool)
        .await
        .unwrap();
    let lease = overlap
        .acquire_due(101, 10, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(envelope(&pool, &tenant, "event").await.kid, "new-key");
    assert_eq!(
        retired
            .get_delivery(&tenant, "stream", 1, "event")
            .await
            .unwrap(),
        Some(lease.delivery.clone())
    );
    retired
        .persist_signed_set(
            &lease,
            &SignedSet {
                compact_jws: "header.payload.signature".into(),
                jti: "jti".into(),
                kid: "signing-key".into(),
            },
            101,
            101,
        )
        .await
        .unwrap();
    let claimed = envelope(&pool, &tenant, "event").await;
    sqlx::query(
        "ALTER TABLE a_auth.ssf_deliveries ADD CONSTRAINT injected_receipt_failure \
        CHECK (status <> 'delivered') NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(retired
        .finish_attempt(&lease, SsfAttemptResult::Accepted, 102)
        .await
        .is_err());
    assert_eq!(envelope(&pool, &tenant, "event").await, claimed);
    sqlx::query("ALTER TABLE a_auth.ssf_deliveries DROP CONSTRAINT injected_receipt_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        retired
            .finish_attempt(&lease, SsfAttemptResult::Accepted, 102)
            .await
            .unwrap()
            .unwrap()
            .attempts,
        1
    );
    sqlx::query(
        "ALTER TABLE a_auth.ssf_deliveries ADD CONSTRAINT injected_insert_failure \
        CHECK (event_id <> '\\x6e65772d6576656e74'::BYTEA) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(overlap
        .enqueue_verification(
            &tenant,
            "stream",
            1,
            "new-event",
            "https://issuer.example.test",
            None,
            103
        )
        .await
        .is_err());
    assert_eq!(
        overlap
            .get_delivery(&tenant, "stream", 1, "new-event")
            .await
            .unwrap(),
        None
    );
    let fresh = format!("{tenant}-fresh");
    sqlx::query(
        "ALTER TABLE a_auth.ssf_streams ADD CONSTRAINT injected_stream_failure \
        CHECK (stream_id <> '\\x6661696c65642d73747265616d'::BYTEA) NOT VALID",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(overlap
        .create_stream(stream(&fresh, "failed-stream"))
        .await
        .is_err());
    assert_eq!(
        overlap.get_stream(&fresh, "failed-stream").await.unwrap(),
        None
    );
    let directories: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM a_auth.user_directories WHERE tenant=$1")
            .bind(fresh.as_bytes())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        directories, 0,
        "failed stream admission must roll back its initial directory"
    );
    cleanup(admin, &name).await;
}
