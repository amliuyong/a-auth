use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    adapters::{file_secrets::FileSecretResolver, postgres::PostgresStore},
    admin_credentials::{
        AdminCredentialError, AdminCredentialOwner, AdminCredentialRecord, AdminCredentialResolver,
        AdminCredentialRotation, AdminCredentialSet,
    },
};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Barrier;

const REF: &str = "operator:administrator-registry";
const PLATFORM: &str = "local-platform-credential-only";
const TENANT: &str = "local-tenant-credential-only";
const SCIM: &str = "local-scim-credential-only";
const NEXT: &str = "local-platform-next-credential-only";

struct Fixture {
    root: PathBuf,
    files: FileSecretResolver,
    stores: [PostgresStore; 2],
    pool: sqlx::PgPool,
    admin: sqlx::PgPool,
    database: String,
    at: i64,
}

impl Fixture {
    async fn new() -> Self {
        let (first, pool, admin, database, url) = isolated_database().await;
        let second = PostgresStore::connect(&url, 8).await.unwrap();
        let root = std::env::temp_dir().join(format!(
            "a-auth-mounted-admin-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let files = FileSecretResolver::new(
            &root,
            [(REF.to_owned(), "administrator-registry".to_owned())],
        )
        .unwrap();
        Self {
            root,
            files,
            stores: [first, second],
            pool,
            admin,
            database,
            at: agent_auth_http::current_unix_secs(),
        }
    }

    fn resolver(&self, index: usize) -> AdminCredentialResolver {
        AdminCredentialResolver::mounted(
            self.stores[index].clone(),
            self.files.clone(),
            "auth.example.test".into(),
            REF.into(),
            Duration::ZERO,
        )
        .unwrap()
    }

    fn sets(&self) -> Vec<AdminCredentialSet> {
        [
            (AdminCredentialOwner::platform(), "platform", PLATFORM),
            (AdminCredentialOwner::tenant("default"), "tenant", TENANT),
            (AdminCredentialOwner::scim_tenant("default"), "scim", SCIM),
        ]
        .into_iter()
        .map(|(owner, id, secret)| {
            AdminCredentialSet::single(
                owner,
                AdminCredentialRecord::explicit(
                    id,
                    secret,
                    self.at - 20,
                    self.at - 20,
                    self.at + 86_400,
                ),
            )
        })
        .collect()
    }

    fn write(&self, sets: &[AdminCredentialSet]) {
        let file = self.root.join("administrator-registry");
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "version_created_at": self.at,
                "sets": sets
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    async fn passed(self) {
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
            .execute(&self.admin)
            .await
            .unwrap();
        std::fs::remove_dir_all(self.root).unwrap();
    }
}

#[tokio::test]
async fn mounted_admin_two_pool_admission_and_cold_restart_reject_durable_revision_rollback() {
    let fixture = Fixture::new().await;
    let original = fixture.sets();
    fixture.write(&original);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let resolver = fixture.resolver(index % 2);
        let at = fixture.at;
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            assert!(resolver
                .verify(&AdminCredentialOwner::platform(), PLATFORM, at)
                .await
                .unwrap()
                .is_some());
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut rotated = original.clone();
    rotated[0] = AdminCredentialSet::rotating(
        AdminCredentialOwner::platform(),
        2,
        original[0].current.clone(),
        AdminCredentialRecord::explicit(
            "platform-next",
            NEXT,
            fixture.at,
            fixture.at + 1,
            fixture.at + 90_000,
        ),
        AdminCredentialRotation {
            overlap_starts_at: fixture.at + 1,
            cutover_at: fixture.at + 60,
            retire_current_at: fixture.at + 120,
        },
    );
    fixture.write(&rotated);
    assert!(fixture
        .resolver(1)
        .verify(&AdminCredentialOwner::platform(), NEXT, fixture.at + 2)
        .await
        .unwrap()
        .is_some());
    let record: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    for secret in [PLATFORM, TENANT, SCIM, NEXT] {
        assert!(
            !record.contains(secret),
            "checkpoint cannot contain credential plaintext"
        );
    }
    assert!(fixture
        .resolver(0)
        .verify(
            &AdminCredentialOwner::platform(),
            PLATFORM,
            fixture.at + 121,
        )
        .await
        .unwrap()
        .is_none());
    let mut resurrected = original.clone();
    resurrected[0].revision = 3;
    fixture.write(&resurrected);
    assert!(matches!(
        fixture
            .resolver(1)
            .verify(
                &AdminCredentialOwner::platform(),
                PLATFORM,
                fixture.at + 121,
            )
            .await,
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    fixture.write(&original);
    assert!(matches!(
        fixture
            .resolver(0)
            .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at + 3)
            .await,
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    fixture.passed().await;
}

#[tokio::test]
async fn mounted_admin_invalid_owner_duplicate_secret_and_lifetime_never_replace_checkpoint() {
    let fixture = Fixture::new().await;
    let original = fixture.sets();
    fixture.write(&original);
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::tenant("default"), TENANT, fixture.at)
        .await
        .unwrap()
        .is_some());
    let before: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    for kind in 0..3 {
        let mut damaged = original.clone();
        match kind {
            0 => damaged[1].owner = AdminCredentialOwner::tenant("foreign"),
            1 => damaged[1].current.secret = PLATFORM.to_owned(),
            _ => damaged[1].current.expires_at = Some(fixture.at - 30),
        }
        fixture.write(&damaged);
        assert!(matches!(
            fixture
                .resolver(1)
                .verify(&AdminCredentialOwner::tenant("default"), TENANT, fixture.at)
                .await,
            Err(AdminCredentialError::InvalidConfiguration)
        ));
        let after: String =
            sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(after, before);
    }
    fixture.write(&original);
    assert!(fixture
        .resolver(0)
        .verify(
            &AdminCredentialOwner::scim_tenant("default"),
            SCIM,
            fixture.at
        )
        .await
        .unwrap()
        .is_some());
    assert!(fixture
        .resolver(1)
        .verify(&AdminCredentialOwner::platform(), SCIM, fixture.at)
        .await
        .unwrap()
        .is_none());
    fixture.passed().await;
}

#[tokio::test]
async fn mounted_admin_rechecks_credential_expiry_after_an_observed_checkpoint_lock_wait() {
    let fixture = Fixture::new().await;
    let mut expiring = fixture.sets();
    let deadline = fixture.at + 2;
    for set in &mut expiring {
        set.current.expires_at = Some(deadline);
    }
    fixture.write(&expiring);
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
        .await
        .unwrap()
        .is_some());
    let before: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT record FROM a_auth.mounted_admin_checkpoints FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let resolver = fixture.resolver(1);
    let at = fixture.at;
    let task = tokio::spawn(async move {
        resolver
            .verify(&AdminCredentialOwner::platform(), PLATFORM, at)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event_type='Lock' \
                 AND query LIKE '%a_auth.mounted_admin_checkpoints%' \
                 AND pid<>pg_backend_pid())",
            )
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("verification must reach the actual checkpoint row lock");
    while agent_auth_http::current_unix_secs() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    blocker.rollback().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    let after: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(after, before);
    fixture.passed().await;
}

#[tokio::test]
async fn mounted_admin_missing_retirement_fields_and_actual_update_failure_preserve_authority() {
    let fixture = Fixture::new().await;
    let original = fixture.sets();
    fixture.write(&original);
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
        .await
        .unwrap()
        .is_some());
    let before: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let mut damaged: serde_json::Value = serde_json::from_str(&before).unwrap();
    damaged["sets"][0]
        .as_object_mut()
        .unwrap()
        .remove("retire_current_at");
    let damaged = damaged.to_string();
    sqlx::query("UPDATE a_auth.mounted_admin_checkpoints SET record=$1")
        .bind(&damaged)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .resolver(1)
            .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
            .await,
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    let after: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(after, damaged);
    sqlx::query("UPDATE a_auth.mounted_admin_checkpoints SET record=$1")
        .bind(&before)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION a_auth.contract_mounted_admission_fault() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
         RAISE EXCEPTION 'contract-only' USING ERRCODE='23514'; END $$",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER contract_mounted_admission_fault BEFORE UPDATE \
         ON a_auth.mounted_admin_checkpoints FOR EACH ROW \
         EXECUTE FUNCTION a_auth.contract_mounted_admission_fault()",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    let mut newer = original.clone();
    newer[0].revision = 2;
    fixture.write(&newer);
    assert!(matches!(
        fixture
            .resolver(1)
            .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
            .await,
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    let after: String = sqlx::query_scalar("SELECT record FROM a_auth.mounted_admin_checkpoints")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(after, before);
    sqlx::query(
        "DROP TRIGGER contract_mounted_admission_fault ON a_auth.mounted_admin_checkpoints",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
        .await
        .unwrap()
        .is_some());
    fixture.passed().await;
}

#[tokio::test]
async fn mounted_admin_disallows_a_plaintext_cache_that_can_outlive_projected_retirement() {
    let fixture = Fixture::new().await;
    assert!(matches!(
        AdminCredentialResolver::mounted(
            fixture.stores[0].clone(),
            fixture.files.clone(),
            "auth.example.test".into(),
            REF.into(),
            Duration::from_secs(1),
        ),
        Err(AdminCredentialError::InvalidConfiguration)
    ));
    fixture.passed().await;
}

#[tokio::test]
async fn mounted_admin_rejects_a_file_snapshot_retired_during_checkpoint_lock_wait() {
    let fixture = Fixture::new().await;
    let original = fixture.sets();
    fixture.write(&original);
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::platform(), PLATFORM, fixture.at)
        .await
        .unwrap()
        .is_some());
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT record FROM a_auth.mounted_admin_checkpoints FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let resolver = fixture.resolver(1);
    let at = fixture.at;
    let task = tokio::spawn(async move {
        resolver
            .verify(&AdminCredentialOwner::platform(), PLATFORM, at)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event_type='Lock' \
                 AND query LIKE '%a_auth.mounted_admin_checkpoints%' \
                 AND pid<>pg_backend_pid())",
            )
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("old file snapshot must reach the actual checkpoint row wait");
    let mut retired = original.clone();
    retired[0] = AdminCredentialSet::single(
        AdminCredentialOwner::platform(),
        AdminCredentialRecord::explicit(
            "platform-next",
            NEXT,
            fixture.at,
            fixture.at,
            fixture.at + 90_000,
        ),
    );
    retired[0].revision = 2;
    retired[0]
        .retired
        .push(agent_auth_http::admin_credentials::AdminRetiredCredential {
            credential_id: original[0].current.credential_id.clone(),
            secret_sha256: agent_auth_http::admin_credentials::secret_sha256(PLATFORM),
            retired_at: fixture.at,
        });
    fixture.write(&retired);
    blocker.rollback().await.unwrap();
    assert!(
        matches!(
            task.await.unwrap(),
            Ok(None) | Err(AdminCredentialError::InvalidConfiguration)
        ),
        "a verifier cannot authenticate the file snapshot retired while it waited"
    );
    assert!(fixture
        .resolver(0)
        .verify(&AdminCredentialOwner::platform(), NEXT, fixture.at)
        .await
        .unwrap()
        .is_some());
    fixture.passed().await;
}
