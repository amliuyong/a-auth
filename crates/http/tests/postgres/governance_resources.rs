use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::{
        file_secrets::FileSecretResolver,
        mounted_crypto::EncryptionKeyring,
        postgres::{PostgresSsfStore, PostgresUsersStore, UserAuthorityKey},
    },
    governance::resource_fingerprint,
    governance_resources::{
        GovernanceResourceBackend, GovernanceRetentionRequest, GovernanceRetentionTarget,
        PostgresGovernanceResourceBackend, PostgresGovernanceResourceConfig, SecretDeletionStatus,
    },
    ports::UsersStore,
};
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

#[tokio::test]
async fn postgres_resource_backend_observes_live_authority_and_operator_owned_mounts() {
    let (database, pool, admin, name, url) = isolated_database().await;
    let second = agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
        .await
        .unwrap();
    let root = std::env::temp_dir().join(format!(
        "a-auth-governance-resources-{:032x}",
        rand::random::<u128>()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let secret = root.join("client-secret");
    std::fs::write(&secret, "local-operator-secret-only").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let files = FileSecretResolver::new(
        &root,
        [
            ("operator:client".into(), "client-secret".into()),
            ("operator:retention".into(), "retention".into()),
        ],
    )
    .unwrap();
    let backend = PostgresGovernanceResourceBackend::new(
        database.clone(),
        PostgresSsfStore::new(
            database.clone(),
            EncryptionKeyring::new("test", vec![("test".into(), [0x71; 32])]).unwrap(),
        ),
        files,
        PostgresGovernanceResourceConfig {
            region: "local".into(),
            tenant_id: "default".into(),
            storage_tenant: "".into(),
            retention_reference: "operator:retention".into(),
            operator_secret_references: BTreeSet::from(["operator:client".into()]),
        },
    )
    .unwrap();
    let now = agent_auth_http::current_unix_secs();
    let request = GovernanceRetentionRequest {
        target: GovernanceRetentionTarget::Tenant {
            tenant_id: "default".into(),
            job_id: "local-job-only".into(),
        },
        storage_tenant: "".into(),
        configured_regions: vec!["local".into()],
        primary_erasure_at: now - 1,
        retention_anchor_at: now - 1,
        verified_at: now,
    };
    let absent = backend
        .verify_replicas(request.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(absent["local"]
        .live_counts
        .values()
        .all(|count| *count == 0));
    assert_eq!(absent["local"].verification_state, "provider_strong_read");
    PostgresUsersStore::new(second, UserAuthorityKey::new([0x57; 32]).unwrap())
        .create_or_get_by_email("", "live@example.test", "live-user", now)
        .await
        .unwrap();
    let live = backend
        .verify_replicas(request.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(live["local"].live_counts.values().any(|count| *count > 0));
    let retention = backend
        .verify_retention(request.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(!retention.complete);
    assert_eq!(
        retention.retention_resources["operator_backups"].state,
        "not_observed"
    );
    assert!(retention
        .retention_resources
        .keys()
        .all(|key| !key.contains("aws") && !key.contains("s3") && !key.contains("dynamodb")));
    let fingerprint = resource_fingerprint("operator:client");
    assert_eq!(
        backend
            .inspect_secret_deletion("operator:client", &fingerprint)
            .await
            .unwrap(),
        SecretDeletionStatus::Present
    );
    assert!(backend
        .schedule_secret_deletion("operator:client", &fingerprint, now)
        .await
        .is_err());
    assert!(secret.exists());
    std::fs::remove_file(&secret).unwrap();
    assert_eq!(
        backend
            .inspect_secret_deletion("operator:client", &fingerprint)
            .await
            .unwrap(),
        SecretDeletionStatus::Absent
    );
    assert!(backend
        .inspect_secret_deletion(
            "operator:unknown",
            &resource_fingerprint("operator:unknown")
        )
        .await
        .is_err());
    assert!(backend
        .inspect_secret_deletion("operator:client", "wrong-fingerprint")
        .await
        .is_err());
    let mut wrong_region = request.clone();
    wrong_region.configured_regions.push("remote".into());
    assert!(backend.verify_replicas(wrong_region).await.is_err());
    let mut wrong_tenant = request;
    wrong_tenant.storage_tenant = "foreign".into();
    assert!(backend.verify_retention(wrong_tenant).await.is_err());
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

struct ResourceFixture {
    backend: PostgresGovernanceResourceBackend,
    stores: [agent_auth_http::adapters::postgres::PostgresStore; 2],
    ssf: PostgresSsfStore,
    root: std::path::PathBuf,
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    name: String,
    request: GovernanceRetentionRequest,
}

impl ResourceFixture {
    async fn new() -> Self {
        let (store, pool, admin, name, url) = isolated_database().await;
        let second = agent_auth_http::adapters::postgres::PostgresStore::connect(&url, 8)
            .await
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "a-auth-governance-resources-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let files =
            FileSecretResolver::new(&root, [("operator:retention".into(), "retention".into())])
                .unwrap();
        let ssf = PostgresSsfStore::new(
            store.clone(),
            EncryptionKeyring::new("test", vec![("test".into(), [0x71; 32])]).unwrap(),
        );
        let backend = PostgresGovernanceResourceBackend::new(
            store.clone(),
            ssf.clone(),
            files,
            PostgresGovernanceResourceConfig {
                region: "local".into(),
                tenant_id: "default".into(),
                storage_tenant: "".into(),
                retention_reference: "operator:retention".into(),
                operator_secret_references: BTreeSet::new(),
            },
        )
        .unwrap();
        let now = agent_auth_http::current_unix_secs();
        let anchor = now - 400 * 86_400 - 10;
        let request = GovernanceRetentionRequest {
            target: GovernanceRetentionTarget::Tenant {
                tenant_id: "default".into(),
                job_id: "local-retention-job".into(),
            },
            storage_tenant: "".into(),
            configured_regions: vec!["local".into()],
            primary_erasure_at: anchor,
            retention_anchor_at: anchor,
            verified_at: now,
        };
        Self {
            backend,
            stores: [store, second],
            ssf,
            root,
            pool,
            admin,
            name,
            request,
        }
    }

    fn receipt(&self, validity: i64) -> serde_json::Value {
        let now = agent_auth_http::current_unix_secs();
        serde_json::json!({"schema_version":1,"receipts":[{
            "request_sha256":self.backend.retention_request_digest(&self.request).unwrap(),
            "observed_at":now,"valid_until":now+validity,
            "resources":{
                "operator_backups":{"absent":true,"manifest_sha256":"a".repeat(64)},
                "operator_logs":{"absent":true,"manifest_sha256":"b".repeat(64)}
            }
        }]})
    }

    fn publish(&self, value: &serde_json::Value) {
        let next = self.root.join("retention-next");
        std::fs::write(&next, serde_json::to_vec(value).unwrap()).unwrap();
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(next, self.root.join("retention")).unwrap();
    }

    async fn passed(self) {
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .unwrap();
        std::fs::remove_dir_all(self.root).unwrap();
    }
}

#[tokio::test]
async fn postgres_retention_requires_physical_removal_and_bound_operator_evidence() {
    use agent_auth_http::{
        adapters::postgres::PostgresSecurityEventFallback,
        security_event::{SecurityEventFallback, SecurityEventIngress, SecurityEventStore},
        ssf::SsfStore,
    };
    let fixture = ResourceFixture::new().await;
    fixture.publish(&fixture.receipt(300));
    assert!(
        fixture
            .backend
            .verify_retention(fixture.request.clone())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    let event = super::ssf_contracts::event("default", "retained-event");
    fixture.stores[1].put(&event).await.unwrap();
    PostgresSecurityEventFallback::new(fixture.stores[1].clone())
        .enqueue(&SecurityEventIngress::new(event.clone()))
        .await
        .unwrap();
    fixture
        .ssf
        .create_stream(super::ssf_contracts::stream("default", "retained-stream"))
        .await
        .unwrap();
    fixture
        .ssf
        .enqueue_event(&event, "https://issuer.example.test", 100)
        .await
        .unwrap();
    fixture
        .ssf
        .revoke_all_by_tenant("default", 101)
        .await
        .unwrap();
    let retained = fixture
        .backend
        .verify_retention(fixture.request.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(!retained.complete);
    for resource in [
        "postgres_security_event_hot",
        "postgres_security_event_fallback",
        "postgres_ssf_deliveries",
    ] {
        assert_eq!(
            retained.retention_resources[resource].state,
            "provider_observed_retained"
        );
    }
    assert_eq!(
        retained.retention_resources["operator_backups"].evidence_basis,
        "trusted_operator_attestation"
    );
    assert_eq!(
        retained.retention_resources["operator_logs"].state,
        "operator_attested_absent"
    );
    // Test-owned physical removals establish the observation boundary; these
    // are not a production purge worker or external backup/log inspection.
    sqlx::query("DELETE FROM a_auth.security_event_fallback")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM a_auth.security_event_fallback_identity")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM a_auth.security_events")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM a_auth.ssf_deliveries")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(
        fixture
            .backend
            .verify_retention(fixture.request.clone())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    assert!(
        fixture
            .ssf
            .get_stream("default", "retained-stream")
            .await
            .unwrap()
            .is_some(),
        "permanent revocation control survives"
    );
    let mut foreign = fixture.request.clone();
    foreign.target = GovernanceRetentionTarget::Tenant {
        tenant_id: "default".into(),
        job_id: "other-job".into(),
    };
    assert!(
        !fixture
            .backend
            .verify_retention(foreign)
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    let mut stale = fixture.receipt(1);
    stale["receipts"][0]["observed_at"] =
        serde_json::json!(agent_auth_http::current_unix_secs() - 2);
    stale["receipts"][0]["valid_until"] =
        serde_json::json!(agent_auth_http::current_unix_secs() - 1);
    fixture.publish(&stale);
    assert!(
        !fixture
            .backend
            .verify_retention(fixture.request.clone())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    let mut invalid = fixture.receipt(300);
    invalid["receipts"][0]
        .as_object_mut()
        .unwrap()
        .remove("observed_at");
    fixture.publish(&invalid);
    assert!(fixture
        .backend
        .verify_retention(fixture.request.clone())
        .await
        .is_err());
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_retention_rechecks_attestation_expiry_after_actual_directory_lock_wait() {
    let fixture = ResourceFixture::new().await;
    let receipt = fixture.receipt(2);
    let deadline = receipt["receipts"][0]["valid_until"].as_i64().unwrap();
    fixture.publish(&receipt);
    sqlx::query("INSERT INTO a_auth.user_directories (tenant) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(b"default".as_slice())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT tenant FROM a_auth.user_directories WHERE tenant=$1 FOR UPDATE")
        .bind(b"default".as_slice())
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let backend = fixture.backend.clone();
    let request = fixture.request.clone();
    let waiting = tokio::spawn(async move { backend.verify_retention(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%a_auth.user_directories%' AND pid<>pg_backend_pid())")
                .fetch_one(&fixture.pool).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("verification must reach the actual directory lock");
    while agent_auth_http::current_unix_secs() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    blocker.rollback().await.unwrap();
    assert!(!waiting.await.unwrap().unwrap().unwrap().complete);
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_retention_fences_mount_publication_during_actual_database_lock_wait() {
    let fixture = ResourceFixture::new().await;
    fixture.publish(&fixture.receipt(300));
    sqlx::query("INSERT INTO a_auth.user_directories (tenant) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(b"default".as_slice())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT tenant FROM a_auth.user_directories WHERE tenant=$1 FOR UPDATE")
        .bind(b"default".as_slice())
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let backend = fixture.backend.clone();
    let request = fixture.request.clone();
    let waiting = tokio::spawn(async move { backend.verify_retention(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%a_auth.user_directories%' AND pid<>pg_backend_pid())")
                .fetch_one(&fixture.pool).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("verification must reach the actual directory lock");
    let mut retained = fixture.receipt(300);
    retained["receipts"][0]["resources"]["operator_backups"]["absent"] = serde_json::json!(false);
    fixture.publish(&retained);
    blocker.rollback().await.unwrap();
    assert!(matches!(
        waiting.await.unwrap(),
        Err(agent_auth_http::ports::StoreError::Transient(_))
    ));
    assert!(
        !fixture
            .backend
            .verify_retention(fixture.request.clone())
            .await
            .unwrap()
            .unwrap()
            .complete
    );
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_retention_rejects_rebound_physical_records_and_duplicate_receipt_authority() {
    use agent_auth_http::security_event::SecurityEventStore;
    let fixture = ResourceFixture::new().await;
    fixture.publish(&fixture.receipt(300));
    let event = super::ssf_contracts::event("default", "event-physical-binding");
    fixture.stores[1].put(&event).await.unwrap();
    sqlx::query("UPDATE a_auth.security_events SET tenant='foreign' WHERE event_id=$1")
        .bind(&event.event_id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(fixture
        .backend
        .verify_retention(fixture.request.clone())
        .await
        .is_err());
    sqlx::query("DELETE FROM a_auth.security_events")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let text = serde_json::to_string(&fixture.receipt(300)).unwrap().replace(
        "\"operator_backups\":",
        &format!("\"operator_backups\":{{\"absent\":true,\"manifest_sha256\":\"{}\"}},\"operator_backups\":", "c".repeat(64)),
    );
    std::fs::write(fixture.root.join("retention"), text).unwrap();
    assert!(fixture
        .backend
        .verify_retention(fixture.request.clone())
        .await
        .is_err());
    fixture.publish(&fixture.receipt(300));
    let mut future = fixture.request.clone();
    let now = agent_auth_http::current_unix_secs();
    future.primary_erasure_at = now - 1;
    future.retention_anchor_at = now - 1;
    future.verified_at = now + 500 * 86_400;
    let mut statement = fixture.receipt(300);
    statement["receipts"][0]["request_sha256"] =
        serde_json::json!(fixture.backend.retention_request_digest(&future).unwrap());
    fixture.publish(&statement);
    assert!(
        !fixture
            .backend
            .verify_retention(future)
            .await
            .unwrap()
            .unwrap()
            .complete,
        "caller-supplied future time cannot elapse a real retention window"
    );
    fixture.passed().await;
}

#[tokio::test]
async fn postgres_governance_worker_rejects_foreign_resource_database() {
    use agent_auth_http::{
        governance::GovernanceJobState, governance_resources::GovernanceResourceBackendImpl,
        governance_worker::advance_user_erasure_once,
    };
    let foreign = ResourceFixture::new().await;
    let (database, pool, admin, name, _) = isolated_database().await;
    let mut state = super::governance_contracts::user_data_state(database);
    state.governance_resources = std::sync::Arc::new(GovernanceResourceBackendImpl::Postgres(
        foreign.backend.clone(),
    ));
    let now = agent_auth_http::current_unix_secs();
    state
        .users
        .create_or_get_by_email("", "erased@example.test", "erased-user", now)
        .await
        .unwrap();
    let job_id = super::governance_contracts::start_user_erasure(&state, "erased-user").await;
    for step in 1..=5 {
        let job = advance_user_erasure_once(&state, "default", &job_id, now + step)
            .await
            .unwrap();
        if step == 5 {
            assert_eq!(
                job.state,
                GovernanceJobState::Retryable,
                "a task cannot admit replica absence from another PostgreSQL database"
            );
            assert_eq!(
                job.error_class.as_deref(),
                Some("provider_replica_verification_failed")
            );
        }
    }
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
    foreign.passed().await;
}
