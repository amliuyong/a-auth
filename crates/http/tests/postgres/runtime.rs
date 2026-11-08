use super::ssf_contracts::isolated_database;
use agent_auth_http::{
    admin_credentials::{AdminCredentialOwner, AdminCredentialRecord, AdminCredentialSet},
    ports::{ClientRecord, ClientStore, MessageOutbox, Notifier, UsersStore},
    postgres_runtime::PostgresRuntime,
    state::{ClientStoreImpl, CodeStoreImpl, UsersStoreImpl},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    admin: sqlx::PgPool,
    database: String,
}

impl Fixture {
    async fn new() -> Self {
        let (_store, _pool, admin, database, url) = isolated_database().await;
        let root = std::env::temp_dir().join(format!(
            "a-auth-production-runtime-{:032x}",
            rand::random::<u128>()
        ));
        for directory in ["", "crypto", "signing", "administrators", "external"] {
            let path = root.join(directory);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        fn write(path: PathBuf, bytes: impl AsRef<[u8]>) {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        write(root.join("crypto/database"), url);
        write(root.join("crypto/server-key"), STANDARD.encode([0x61; 32]));
        write(
            root.join("crypto/governance-key"),
            STANDARD.encode([0x57; 32]),
        );
        for (index, purpose) in ["grace", "ciba", "outbox", "ssf"].into_iter().enumerate() {
            write(
                root.join(format!("crypto/{purpose}")),
                serde_json::to_vec(&serde_json::json!({
                    "active_kid":"fixture",
                    "keys":[{"kid":"fixture","key_base64":STANDARD.encode([0x71+index as u8;32])}]
                }))
                .unwrap(),
            );
        }
        let ec = SigningKey::from_bytes(&[37; 32].into()).unwrap();
        let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        write(
            root.join("signing/ec.private.pem"),
            ec.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        );
        write(
            root.join("signing/ec.public.pem"),
            ec.verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        );
        write(
            root.join("signing/rsa.private.pem"),
            rsa.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        );
        write(
            root.join("signing/rsa.public.pem"),
            rsa::RsaPublicKey::from(&rsa)
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        );
        write(
            root.join("signing/keys.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema":1,"generation":1,
                "es256_key":"ec.private.pem","rs256_key":"rsa.private.pem",
                "ec_public_keys":["ec.public.pem"],"rsa_public_keys":["rsa.public.pem"]
            }))
            .unwrap(),
        );
        let now = agent_auth_http::current_unix_secs();
        let sets = [
            (
                AdminCredentialOwner::platform(),
                "platform",
                "local-platform-runtime-credential-only",
            ),
            (
                AdminCredentialOwner::tenant("default"),
                "tenant",
                "local-tenant-runtime-credential-only",
            ),
            (
                AdminCredentialOwner::scim_tenant("default"),
                "scim",
                "local-scim-runtime-credential-only",
            ),
        ]
        .into_iter()
        .map(|(owner, id, value)| {
            AdminCredentialSet::single(
                owner,
                AdminCredentialRecord::explicit(id, value, now - 20, now - 20, now + 3600),
            )
        })
        .collect::<Vec<_>>();
        write(
            root.join("administrators/bundle"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"version_created_at":now,"sets":sets
            }))
            .unwrap(),
        );
        let config = root.join("runtime.json");
        write(config.clone(), serde_json::to_vec(&serde_json::json!({
            "schema_version":1,
            "host":"auth.example.test","namespace":"local-runtime-only",
            "web_base_url":"https://auth.example.test",
            "deployment_commit":"e".repeat(40),"logical_region":"local","jurisdiction":"LOCAL",
            "max_connections":8,
            "database":{"root":root.join("crypto"),"key":"database"},
            "secrets":{
                "root":root.join("crypto"),"server_key":"server-key","governance_key":"governance-key",
                "grace":"grace","ciba":"ciba","outbox":"outbox","ssf":"ssf"
            },
            "signing":{"root":root.join("signing"),"manifest":"keys.json"},
            "administrators":{"root":root.join("administrators"),"key":"bundle"},
            "external_secrets":{"root":root.join("external"),"bindings":{},"retention_key":"retention"},
            "smtp":{
                "host":"smtp.example.test","port":465,"tls":"implicit","from":"auth@example.test",
                "root_ca_key":null,"username_key":null,"password_key":null
            },
            "phase":"P3","subject_type":"public","dcr_mode":"initial_access_token",
            "capabilities":{
                "federation":true,"passkey":true,"ciba_ping_push":true,"byod":true,
                "mtls_svid":false,"ema":false,"authz":false,"cimd":false
            },
            "redirect_hosts":[],"cimd_domains":[],"ema_policies":[],
            "invitation_ttl_secs":86400,"grace_window_secs":5,"password_workers":2
        })).unwrap());
        Self {
            root,
            config,
            admin,
            database,
        }
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
async fn production_runtime_constructs_durable_authority_and_restarts_without_development_credentials(
) {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let fixture = Fixture::new().await;
    let first = PostgresRuntime::load(&fixture.config).await.unwrap();
    let second = PostgresRuntime::load(&fixture.config).await.unwrap();
    assert!(matches!(
        first.state.clients.as_ref(),
        ClientStoreImpl::Postgres(_)
    ));
    assert!(matches!(
        first.state.codes.as_ref(),
        CodeStoreImpl::Postgres(_)
    ));
    assert!(matches!(
        first.state.users.as_ref(),
        UsersStoreImpl::Postgres(_)
    ));
    assert!(!first.state.allow_login_placeholder);
    assert!(!first.state.tenant_partitioning);
    assert!(first.state.sts_caller.is_none() && first.state.payments.is_none());
    assert!(first.state.federation_enabled && first.state.passkey_enabled);
    assert!(first.state.ciba_ping_push_enabled && first.state.byod_enabled);
    first
        .state
        .clients
        .put(
            "",
            ClientRecord {
                client_id: "durable-runtime-client".into(),
                token_endpoint_auth_method: "none".into(),
                redirect_uris: vec!["https://client.example.test/callback".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(second
        .state
        .clients
        .get("", "durable-runtime-client")
        .await
        .unwrap()
        .is_some());
    // Admission, durable SMTP acceptance and the management observation must
    // use the same configured encryption purpose across independent processes.
    first
        .state
        .notifier
        .send_magic_link(
            "",
            "runtime-mail@example.test",
            "https://auth.example.test/link",
        )
        .await
        .unwrap();
    let agent_auth_http::state::NotifierImpl::Postgres(notifier) = first.state.notifier.as_ref()
    else {
        panic!("production notifier must be durable");
    };
    let lease = notifier
        .claim(agent_auth_http::current_unix_secs(), 60, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let permit = notifier
        .prepare_send(&lease, agent_auth_http::current_unix_secs())
        .await
        .unwrap()
        .unwrap();
    // This contract records an adapter receipt; it does not claim a real
    // SMTP submission. Native SMTP acceptance is qualified separately.
    assert!(notifier.record_acceptance(&permit).await.unwrap());
    assert_eq!(
        second
            .state
            .messages
            .list_recent("", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let (router, _) = agent_auth_http::build_router(second.state.clone());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/branding")
                .header("host", "auth.example.test")
                .header("authorization", "Bearer dev-admin-token-not-for-prod")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/branding")
                .header("host", "auth.example.test")
                .header(
                    "authorization",
                    "Bearer local-platform-runtime-credential-only",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut mutated = first.state.clone();
    mutated.form = agent_auth_discovery::Form::Saas {
        zone: "example.test".into(),
        control_host: "control.example.test".into(),
    };
    let response = agent_auth_http::build_router(mutated)
        .0
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("host", "auth.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    fixture.passed().await;
}

#[tokio::test]
async fn production_runtime_rejects_missing_or_rebound_migration_authority_without_repairing_it() {
    let fixture = Fixture::new().await;
    let uri = std::fs::read_to_string(fixture.root.join("crypto/database")).unwrap();
    let pool = sqlx::PgPool::connect(uri.trim()).await.unwrap();
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=41")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=decode('00','hex') WHERE version=41")
        .execute(&pool)
        .await
        .unwrap();
    assert!(PostgresRuntime::load(&fixture.config).await.is_err());
    let unchanged: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=41")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unchanged, vec![0]);
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=41")
        .bind(checksum)
        .execute(&pool)
        .await
        .unwrap();
    assert!(PostgresRuntime::load(&fixture.config).await.is_ok());
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=41")
        .execute(&pool)
        .await
        .unwrap();
    assert!(PostgresRuntime::load(&fixture.config).await.is_err());
    let missing: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version=41")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(missing, 0);
    pool.close().await;
    fixture.passed().await;
}

#[tokio::test]
async fn production_runtime_rejects_changed_authority_keys_and_authentication_bypass_configuration()
{
    let fixture = Fixture::new().await;
    let runtime = PostgresRuntime::load(&fixture.config).await.unwrap();
    runtime
        .state
        .users
        .create_or_get_by_email(
            "",
            "runtime@example.test",
            "runtime-user",
            agent_auth_http::current_unix_secs(),
        )
        .await
        .unwrap();
    std::fs::write(
        fixture.root.join("crypto/governance-key"),
        STANDARD.encode([0x58; 32]),
    )
    .unwrap();
    assert!(PostgresRuntime::load(&fixture.config).await.is_err());
    std::fs::write(
        fixture.root.join("crypto/governance-key"),
        STANDARD.encode([0x57; 32]),
    )
    .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.config).unwrap()).unwrap();
    value["allow_login_placeholder"] = serde_json::json!(true);
    std::fs::write(&fixture.config, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(PostgresRuntime::load(&fixture.config).await.is_err());
    assert!(runtime
        .state
        .users
        .get_by_id("", "runtime-user")
        .await
        .unwrap()
        .is_some());
    fixture.passed().await;
}
