use super::{
    database,
    governance_contracts::{evidence, job},
    tenant,
};
use agent_auth_http::{
    adapters::postgres::{
        PostgresGovernanceStore, PostgresStore, PostgresUsersStore, UserAuthorityKey,
    },
    governance::*,
    ports::{GovernanceStore, StoreError, UsersStore},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Barrier;

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn payload(pool: &sqlx::PgPool, tenant: &str) -> String {
    sqlx::query_scalar("SELECT record FROM a_auth.governance_authority WHERE tenant = $1")
        .bind(tenant.as_bytes())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn replace(pool: &sqlx::PgPool, tenant: &str, payload: &str) {
    sqlx::query("UPDATE a_auth.governance_authority SET record = $2 WHERE tenant = $1")
        .bind(tenant.as_bytes())
        .bind(payload)
        .execute(pool)
        .await
        .unwrap();
}

async fn begin(store: &PostgresGovernanceStore, tenant: &str) -> GovernanceJobRecord {
    store
        .put_policy(GovernancePolicyRecord::default_for(tenant), 0)
        .await
        .unwrap();
    match store
        .start_or_resume_job(
            job(tenant, "erase", GovernanceJobKind::UserErasure),
            1,
            false,
        )
        .await
        .unwrap()
    {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected fixture admission: {other:?}"),
    }
}

fn completed(mut job: GovernanceJobRecord) -> GovernanceJobRecord {
    job.state = GovernanceJobState::Completed;
    job.phase = GovernanceJobPhase::Complete;
    job.updated_at = 150;
    job.primary_erasure_at = Some(149);
    job.retention_until = Some(150);
    job.evidence_revision = 1;
    job.target_id = None;
    job
}

#[tokio::test]
async fn postgres_governance_rejects_truncated_rebound_and_inconsistent_snapshots() {
    let store = PostgresGovernanceStore::new(database().await);
    let pool = pool().await;
    let tenant = tenant();
    let original = begin(&store, &tenant).await;
    store
        .claim_job_lease(&tenant, "erase", 1, "private-lease-sentinel", 100, 200)
        .await
        .unwrap();
    store
        .acquire_tenant_mutation_permit(
            TenantMutationPermit {
                tenant_id: tenant.clone(),
                permit_id: "writer".into(),
                deadline: 200,
            },
            100,
        )
        .await
        .unwrap();
    let proof = evidence(&completed(original));
    store.put_evidence(proof).await.unwrap();
    let baseline = payload(&pool, &tenant).await;
    let value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec![
        "{}".into(),
        "private-authority-sentinel".into(),
        format!(
            "{{\"generation\":{},{}",
            value["generation"],
            &baseline[1..]
        ),
        baseline.replacen(
            "\"job_id\":\"erase\"",
            "\"job_id\":\"erase\",\"job_id\":\"erase\"",
            1,
        ),
    ];
    // Real stored authorities must retain every field, including nullable
    // public DTO fields that serde ordinarily fills with defaults.
    for field in value.as_object().unwrap().keys() {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for (section, array) in [
        ("policy", false),
        ("gate", false),
        ("jobs", true),
        ("leases", true),
        ("permits", true),
    ] {
        let record = if array {
            &value[section][0]
        } else {
            &value[section]
        };
        for field in record.as_object().unwrap().keys() {
            let mut bad = value.clone();
            let object = if array {
                &mut bad[section][0]
            } else {
                &mut bad[section]
            };
            object.as_object_mut().unwrap().remove(field);
            corruptions.push(serde_json::to_string(&bad).unwrap());
        }
    }
    for path in [
        vec!["evidence", "payload_sha256"],
        vec!["evidence", "payload", "retained_counts"],
        vec!["evidence", "payload", "external_actions", "outcome"],
    ] {
        let mut bad = value.clone();
        match path.len() {
            2 => {
                bad["evidence"][0].as_object_mut().unwrap().remove(path[1]);
            }
            3 => {
                bad["evidence"][0]["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove(path[2]);
            }
            _ => {
                bad["evidence"][0]["payload"]["external_actions"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("outcome");
            }
        }
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for (field, replacement) in [
        ("tenant", serde_json::json!("foreign-tenant")),
        ("generation", serde_json::json!(u64::MAX)),
        ("unknown", serde_json::json!("private-authority-sentinel")),
    ] {
        let mut bad = value.clone();
        bad[field] = replacement;
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for bad in [
        {
            let mut v = value.clone();
            v["gate"]["active_permits"] = serde_json::json!(0);
            v
        },
        {
            let mut v = value.clone();
            v["gate"]["frozen"] = serde_json::json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["jobs"][0]["tenant_id"] = serde_json::json!("foreign");
            v
        },
        {
            let mut v = value.clone();
            v["leases"][0]["job_id"] = serde_json::json!("missing");
            v
        },
        {
            let mut v = value.clone();
            v["jobs"]
                .as_array_mut()
                .unwrap()
                .push(value["jobs"][0].clone());
            v
        },
        {
            let mut v = value.clone();
            v["evidence"][0]["payload"]["generated_at"] = serde_json::json!(1);
            v
        },
    ] {
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for bad in corruptions {
        replace(&pool, &tenant, &bad).await;
        let attempts = [
            store.get_policy(&tenant).await.map(|_| ()),
            store.list_jobs(&tenant).await.map(|_| ()),
            store
                .acquire_tenant_mutation_permit(
                    TenantMutationPermit {
                        tenant_id: tenant.clone(),
                        permit_id: "must-not-write".into(),
                        deadline: 300,
                    },
                    101,
                )
                .await
                .map(|_| ()),
        ];
        for attempt in attempts {
            assert!(
                matches!(&attempt, Err(StoreError::Permanent(_))),
                "{attempt:?}"
            );
            assert!(!format!("{attempt:?}").contains("private-"));
        }
        assert_eq!(
            payload(&pool, &tenant).await,
            bad,
            "corruption cannot be overwritten"
        );
    }
    replace(&pool, &tenant, &baseline).await;
    assert!(store.get_policy(&tenant).await.unwrap().is_some());
    pool.close().await;
}

#[tokio::test]
async fn postgres_governance_errors_preserve_permit_aggregates_and_generation() {
    let store = PostgresGovernanceStore::new(database().await);
    let pool = pool().await;
    let tenant = tenant();
    let permit = TenantMutationPermit {
        tenant_id: tenant.clone(),
        permit_id: "writer".into(),
        deadline: 200,
    };
    store
        .acquire_tenant_mutation_permit(permit.clone(), 100)
        .await
        .unwrap();
    let baseline = payload(&pool, &tenant).await;
    let mut value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    value["gate"]["revision"] = serde_json::json!(u64::MAX);
    let exhausted = serde_json::to_string(&value).unwrap();
    replace(&pool, &tenant, &exhausted).await;
    let other = TenantMutationPermit {
        permit_id: "second".into(),
        ..permit.clone()
    };
    assert!(matches!(
        store
            .acquire_tenant_mutation_permit(other.clone(), 101)
            .await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(payload(&pool, &tenant).await, exhausted);
    assert!(matches!(
        store
            .release_tenant_mutation_permit(permit.clone(), 101)
            .await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(payload(&pool, &tenant).await, exhausted);
    assert!(matches!(
        store
            .acquire_tenant_mutation_permit(
                TenantMutationPermit {
                    deadline: 300,
                    ..other
                },
                200
            )
            .await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(
        payload(&pool, &tenant).await,
        exhausted,
        "expired permit pruning must also roll back"
    );
    value["gate"]["revision"] = serde_json::json!(1);
    value["generation"] = serde_json::json!(u64::MAX);
    let exhausted = serde_json::to_string(&value).unwrap();
    sqlx::query("UPDATE a_auth.governance_authority SET generation = $2::TEXT::NUMERIC, record = $3 WHERE tenant = $1")
        .bind(tenant.as_bytes()).bind(u64::MAX.to_string()).bind(&exhausted).execute(&pool).await.unwrap();
    assert!(matches!(
        store.renew_tenant_mutation_permit(&permit, 101, 300).await,
        Err(StoreError::Permanent(_))
    ));
    assert_eq!(payload(&pool, &tenant).await, exhausted);
    pool.close().await;
}

#[tokio::test]
async fn postgres_governance_atomic_completion_and_new_directory_roll_back_on_sql_failure() {
    let store = PostgresGovernanceStore::new(database().await);
    let pool = pool().await;
    let tenant = tenant();
    let finished = completed(begin(&store, &tenant).await);
    let baseline = payload(&pool, &tenant).await;
    let fresh = super::tenant();
    let trigger = format!("contract_governance_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
         $fixture$ BEGIN IF NEW.tenant IN (convert_to('{tenant}', 'UTF8'), convert_to('{fresh}', 'UTF8')) THEN \
         RAISE EXCEPTION 'private-governance-sentinel' USING ERRCODE = '23514'; \
         END IF; RETURN NEW; END $fixture$"
    )).execute(&pool).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE ON a_auth.governance_authority \
        FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let completion = store
        .complete_job_with_evidence(finished.clone(), evidence(&finished), 1, 1)
        .await;
    let admission = store
        .put_policy(GovernancePolicyRecord::default_for(&fresh), 0)
        .await;
    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON a_auth.governance_authority"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(&completion, Err(StoreError::Permanent(_))));
    assert!(matches!(&admission, Err(StoreError::Permanent(_))));
    assert!(!format!("{completion:?} {admission:?}").contains("private-governance-sentinel"));
    assert_eq!(payload(&pool, &tenant).await, baseline);
    assert_eq!(store.latest_evidence(&tenant, "erase").await.unwrap(), None);
    let directory: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM a_auth.user_directories WHERE tenant = $1)",
    )
    .bind(fresh.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!directory);
    assert!(matches!(
        store
            .complete_job_with_evidence(finished.clone(), evidence(&finished), 1, 1)
            .await
            .unwrap(),
        GovernanceJobUpdateOutcome::Stored(_)
    ));
    assert!(store
        .latest_evidence(&tenant, "erase")
        .await
        .unwrap()
        .is_some());
    pool.close().await;
}

#[tokio::test]
async fn postgres_governance_separate_pools_coordinate_once_and_preserve_full_domains() {
    let first = PostgresGovernanceStore::new(database().await);
    let second = PostgresGovernanceStore::new(database().await);
    let tenant = format!("{}\0tenant", tenant());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for actor in 0..16 {
        let store = if actor % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let (tenant, barrier) = (tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .put_policy(GovernancePolicyRecord::default_for(&tenant), 0)
                .await
                .unwrap()
        }));
    }
    let mut stored = 0;
    for task in tasks {
        stored += usize::from(matches!(
            task.await.unwrap(),
            GovernancePolicyPutOutcome::Stored(_)
        ));
    }
    assert_eq!(stored, 1);
    let mut original = job(&tenant, "job\0identifier", GovernanceJobKind::UserErasure);
    original.target_epoch = u64::MAX;
    original.created_at = i64::MIN;
    original.updated_at = i64::MIN;
    first.start_or_resume_job(original, 1, false).await.unwrap();
    let lease = match second
        .claim_job_lease(
            &tenant,
            "job\0identifier",
            1,
            "digest\0token",
            i64::MIN,
            i64::MAX,
        )
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Acquired(value) => value,
        other => panic!("unexpected extreme lease: {other:?}"),
    };
    let suppression = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user\0class".into(),
        digest: "digest\0key".into(),
        target_epoch: u64::MAX,
        key_version: u32::MAX,
        normalization_version: u32::MAX,
        created_at: i64::MAX,
    };
    assert!(first
        .put_suppression(
            suppression.clone(),
            lease.destructive_fence(Some(u64::MAX)),
            i64::MIN
        )
        .await
        .unwrap());
    assert_eq!(
        second
            .latest_suppression_epoch(&tenant, &suppression.target_class, &suppression.digest)
            .await
            .unwrap(),
        Some(u64::MAX)
    );
    assert!(second
        .is_suppressed(&tenant, &suppression.target_class, &suppression.digest)
        .await
        .unwrap());
}

#[tokio::test]
async fn postgres_governance_suppression_corruption_fails_closed_without_replacement() {
    let store = PostgresGovernanceStore::new(database().await);
    let pool = pool().await;
    let tenant = tenant();
    begin(&store, &tenant).await;
    let lease = match store
        .claim_job_lease(&tenant, "erase", 1, "writer", 100, 200)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Acquired(value) => value,
        other => panic!("unexpected lease: {other:?}"),
    };
    let record = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user".into(),
        key_version: 1,
        normalization_version: 1,
        digest: "suppression-digest".into(),
        target_epoch: 7,
        created_at: 101,
    };
    store
        .put_suppression(record.clone(), lease.destructive_fence(Some(7)), 101)
        .await
        .unwrap();
    let baseline = serde_json::to_string(&record).unwrap();
    let value: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    let mut corruptions = vec![
        "{}".into(),
        "private-suppression-sentinel".into(),
        baseline.replacen(
            "\"target_epoch\":7",
            "\"target_epoch\":7,\"target_epoch\":7",
            1,
        ),
    ];
    for field in value.as_object().unwrap().keys() {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for (field, replacement) in [
        ("tenant_id", serde_json::json!("foreign")),
        ("target_class", serde_json::json!("tenant")),
        ("digest", serde_json::json!("rebound")),
        ("target_epoch", serde_json::json!(8)),
        ("unknown", serde_json::json!("private-suppression-sentinel")),
    ] {
        let mut bad = value.clone();
        bad[field] = replacement;
        corruptions.push(serde_json::to_string(&bad).unwrap());
    }
    for bad in corruptions {
        sqlx::query("UPDATE a_auth.governance_suppressions SET record = $2 WHERE tenant = $1")
            .bind(tenant.as_bytes())
            .bind(&bad)
            .execute(&pool)
            .await
            .unwrap();
        let attempts = [
            store
                .is_suppressed(&tenant, "user", &record.digest)
                .await
                .map(|_| ()),
            store
                .latest_suppression_epoch(&tenant, "user", &record.digest)
                .await
                .map(|_| ()),
            store
                .put_suppression(record.clone(), lease.destructive_fence(Some(7)), 102)
                .await
                .map(|_| ()),
        ];
        for attempt in attempts {
            assert!(
                matches!(&attempt, Err(StoreError::Permanent(_))),
                "{attempt:?}"
            );
            assert!(!format!("{attempt:?}").contains("private-"));
        }
        let retained: String = sqlx::query_scalar(
            "SELECT record FROM a_auth.governance_suppressions WHERE tenant = $1",
        )
        .bind(tenant.as_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(retained, bad);
    }
    sqlx::query("UPDATE a_auth.governance_suppressions SET record = $2 WHERE tenant = $1")
        .bind(tenant.as_bytes())
        .bind(baseline)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store
        .is_suppressed(&tenant, "user", &record.digest)
        .await
        .unwrap());
    pool.close().await;
}

#[tokio::test]
async fn postgres_governance_suppression_blocks_identity_admission_until_commit() {
    let base = database().await;
    let store = PostgresGovernanceStore::new(base.clone());
    let pool = pool().await;
    let tenant = tenant();
    begin(&store, &tenant).await;
    let lease = match store
        .claim_job_lease(&tenant, "erase", 1, "writer", 100, 200)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Acquired(value) => value,
        other => panic!("unexpected lease: {other:?}"),
    };
    let record = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user".into(),
        key_version: 1,
        normalization_version: 1,
        digest: suppression_digest(&[0x57; 32], &tenant, "user", "canonical_id", 1, "user-1"),
        target_epoch: 7,
        created_at: 101,
    };
    let lock = i64::from(rand::random::<u32>() & 0x7fff_ffff);
    let mut fixture = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(142, $1::INT)")
        .bind(lock as i32)
        .execute(&mut *fixture)
        .await
        .unwrap();
    let trigger = format!("contract_suppression_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE FUNCTION a_auth.{trigger}() RETURNS trigger LANGUAGE plpgsql AS \
        $fixture$ BEGIN IF NEW.tenant = convert_to('{tenant}', 'UTF8') THEN \
        PERFORM pg_advisory_xact_lock(142, {lock}); END IF; RETURN NEW; END $fixture$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON a_auth.governance_suppressions \
        FOR EACH ROW EXECUTE FUNCTION a_auth.{trigger}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let (writing_store, writing_record) = (store.clone(), record.clone());
    let writing = tokio::spawn(async move {
        writing_store
            .put_suppression(writing_record, lease.destructive_fence(Some(7)), 101)
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let authority_waiting = loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype = 'advisory' \
            AND classid = 142::OID AND objid::BIGINT = $1 AND NOT granted)",
        )
        .bind(lock)
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting || tokio::time::Instant::now() >= deadline {
            break waiting;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let application = format!("suppression_admission_{:032x}", rand::random::<u128>());
    let mut writer_url =
        url::Url::parse(&std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap()).unwrap();
    writer_url
        .query_pairs_mut()
        .append_pair("application_name", &application);
    let users = PostgresUsersStore::new(
        PostgresStore::connect(writer_url.as_str(), 1)
            .await
            .unwrap(),
        UserAuthorityKey::new([0x57; 32]).unwrap(),
    );
    let admitting_tenant = tenant.clone();
    let admission = tokio::spawn(async move {
        users
            .create_or_get_by_email(&admitting_tenant, "person@example.test", "user-1", 102)
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let admission_waiting = loop {
        if admission.is_finished() {
            break false;
        }
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE \
            application_name = $1 AND wait_event_type = 'Lock')",
        )
        .bind(&application)
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting || tokio::time::Instant::now() >= deadline {
            break waiting;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    sqlx::query("SELECT pg_advisory_unlock(142, $1::INT)")
        .bind(lock as i32)
        .execute(&mut *fixture)
        .await
        .unwrap();
    let written = writing.await.unwrap();
    let admitted = admission.await.unwrap();
    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON a_auth.governance_suppressions"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION a_auth.{trigger}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        authority_waiting,
        "observe the actual suppression transaction pause"
    );
    assert!(
        admission_waiting,
        "identity admission must wait for suppression to commit"
    );
    assert!(written.unwrap());
    assert!(matches!(admitted, Err(StoreError::Permanent(_))));
    let users = PostgresUsersStore::new(base, UserAuthorityKey::new([0x57; 32]).unwrap());
    assert_eq!(users.get_by_id(&tenant, "user-1").await.unwrap(), None);
    assert!(store
        .is_suppressed(&tenant, "user", &record.digest)
        .await
        .unwrap());
    drop(fixture);
    pool.close().await;
}
