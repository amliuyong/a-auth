use super::production_runtime_contracts::Fixture;
use agent_auth_http::{
    postgres_runtime::PostgresRuntime,
    production_server::{production_routers, ProductionHealth},
    RouteScope,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn request(router: &axum::Router, path: &str, credential: Option<&str>) -> StatusCode {
    let mut request = Request::builder()
        .uri(path)
        .header("host", "auth.example.test");
    if let Some(value) = credential {
        request = request.header("authorization", format!("Bearer {value}"));
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn production_planes_keep_management_private_and_preserve_its_authentication() {
    let fixture = Fixture::new().await;
    let runtime = PostgresRuntime::load_for_scope(&fixture.config, RouteScope::NonToken)
        .await
        .unwrap();
    let health = ProductionHealth::new();
    health.mark_ready();
    let (public, management, probes) =
        production_routers(runtime.state, RouteScope::NonToken, health).unwrap();
    assert_eq!(
        request(&public, "/.well-known/openid-configuration", None).await,
        StatusCode::OK
    );
    for path in [
        "/admin/branding",
        "/admin/messages",
        "/scim/v2/Users",
        "/%61dmin/branding",
        "/admin%2Fbranding",
        "//admin/branding",
    ] {
        assert_eq!(
            request(
                &public,
                path,
                Some("local-platform-runtime-credential-only")
            )
            .await,
            StatusCode::NOT_FOUND,
            "{path} must not expose management on the public listener"
        );
    }
    assert_eq!(
        request(&management, "/admin/branding", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &management,
            "/admin/branding",
            Some("dev-admin-token-not-for-prod")
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &management,
            "/admin/branding",
            Some("local-platform-runtime-credential-only")
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        request(&management, "/.well-known/openid-configuration", None).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&probes, "/health/ready", None).await,
        StatusCode::OK
    );
    fixture.passed().await;
}

#[tokio::test]
async fn production_readiness_and_shutdown_gate_protocol_admission_without_killing_liveness() {
    let fixture = Fixture::new().await;
    let runtime = PostgresRuntime::load_for_scope(&fixture.config, RouteScope::NonToken)
        .await
        .unwrap();
    let health = ProductionHealth::new();
    let (public, management, probes) =
        production_routers(runtime.state, RouteScope::NonToken, health.clone()).unwrap();
    assert_eq!(request(&probes, "/health/live", None).await, StatusCode::OK);
    assert_eq!(
        request(&probes, "/health/ready", None).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&public, "/.well-known/openid-configuration", None).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    health.mark_ready();
    assert_eq!(
        request(&public, "/.well-known/openid-configuration", None).await,
        StatusCode::OK
    );
    health.begin_shutdown();
    assert_eq!(request(&probes, "/health/live", None).await, StatusCode::OK);
    assert_eq!(
        request(&probes, "/health/ready", None).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&public, "/.well-known/openid-configuration", None).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(
            &management,
            "/admin/branding",
            Some("local-platform-runtime-credential-only")
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    health.mark_ready();
    assert_eq!(
        request(&probes, "/health/ready", None).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.passed().await;
}

#[tokio::test]
async fn production_non_token_runtime_does_not_read_grace_decryption_keys_and_full_scope_is_rejected(
) {
    let fixture = Fixture::new().await;
    std::fs::rename(
        fixture.root.join("crypto/grace"),
        fixture.root.join("crypto/grace-retained"),
    )
    .unwrap();
    assert!(
        PostgresRuntime::load_for_scope(&fixture.config, RouteScope::NonToken)
            .await
            .is_ok()
    );
    assert!(
        PostgresRuntime::load_for_scope(&fixture.config, RouteScope::Token)
            .await
            .is_err()
    );
    assert!(
        PostgresRuntime::load_for_scope(&fixture.config, RouteScope::Full)
            .await
            .is_err()
    );
    fixture.passed().await;
}

#[tokio::test]
async fn production_tcp_process_rechecks_database_readiness_and_drains_an_accepted_request_on_sigterm(
) {
    use std::{
        os::unix::fs::OpenOptionsExt,
        process::{Child, Command, Stdio},
        time::Duration,
    };
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    fn port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    async fn status(client: &reqwest::Client, url: &str, wanted: StatusCode) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if client
                .get(url)
                .send()
                .await
                .is_ok_and(|response| response.status() == wanted)
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "native listener did not reach the required state"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let fixture = Fixture::new().await;
    let (public_port, management_port, probe_port) = (port(), port(), port());
    assert!(
        public_port != management_port
            && public_port != probe_port
            && management_port != probe_port
    );
    let log_path = fixture.root.join("process.log");
    let output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&log_path)
        .unwrap();
    let application = format!("native_server_{:032x}", rand::random::<u128>());
    let mut uri =
        url::Url::parse(&std::fs::read_to_string(fixture.root.join("crypto/database")).unwrap())
            .unwrap();
    let pool = sqlx::PgPool::connect(uri.as_str()).await.unwrap();
    uri.query_pairs_mut()
        .append_pair("application_name", &application);
    std::fs::write(fixture.root.join("crypto/database"), uri.as_str()).unwrap();
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_agent-auth-postgres"))
            .args(["serve-web", fixture.config.to_str().unwrap()])
            .env("A_AUTH_BIND", format!("127.0.0.1:{public_port}"))
            .env(
                "A_AUTH_MANAGEMENT_BIND",
                format!("127.0.0.1:{management_port}"),
            )
            .env("A_AUTH_PROBE_BIND", format!("127.0.0.1:{probe_port}"))
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()
        .unwrap();
    let ready = format!("http://127.0.0.1:{probe_port}/health/ready");
    let live = format!("http://127.0.0.1:{probe_port}/health/live");
    let discovery = format!("http://127.0.0.1:{public_port}/.well-known/openid-configuration");
    status(&client, &ready, StatusCode::OK).await;
    assert_eq!(
        client
            .get(format!("http://127.0.0.1:{public_port}/admin/branding"))
            .header("host", "auth.example.test")
            .bearer_auth("local-platform-runtime-credential-only")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(format!("http://127.0.0.1:{management_port}/admin/branding"))
            .header("host", "auth.example.test")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE public._sqlx_migrations SET success=false WHERE version=41")
        .execute(&pool)
        .await
        .unwrap();
    status(&client, &ready, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        client
            .get(&discovery)
            .header("host", "auth.example.test")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    status(&client, &live, StatusCode::OK).await;
    sqlx::query("UPDATE public._sqlx_migrations SET success=true WHERE version=41")
        .execute(&pool)
        .await
        .unwrap();
    status(&client, &ready, StatusCode::OK).await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT namespace FROM a_auth.mounted_admin_checkpoints WHERE namespace=$1 FOR UPDATE",
    )
    .bind(b"local-runtime-only".as_slice())
    .fetch_one(&mut *holder)
    .await
    .unwrap();
    let sending = client.clone();
    let inflight = tokio::spawn(async move {
        sending
            .get(format!("http://127.0.0.1:{management_port}/admin/branding"))
            .header("host", "auth.example.test")
            .bearer_auth("local-platform-runtime-credential-only")
            .send()
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')")
            .bind(&application).fetch_one(&pool).await.unwrap();
        if waiting {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "owned process never entered the database lock wait"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!inflight.is_finished());
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    holder.commit().await.unwrap();
    assert_eq!(inflight.await.unwrap().unwrap().status(), StatusCode::OK);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(exit) = child.0.try_wait().unwrap() {
            assert!(exit.success(), "owned process failed instead of draining");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "owned process did not exit after SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(std::fs::read_to_string(log_path)
        .unwrap()
        .contains("\"event\":\"http_stopped\""));
    pool.close().await;
    fixture.passed().await;
}

#[tokio::test]
async fn migration_grants_runtime_dml_without_ddl_or_migration_writes_and_rejects_privileged_roles()
{
    use agent_auth_http::adapters::postgres::PostgresStore;
    let fixture = Fixture::new().await;
    let role = format!("contract_runtime_{:032x}", rand::random::<u128>());
    sqlx::query(&format!(
        "CREATE ROLE \"{role}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"
    ))
    .execute(&fixture.admin)
    .await
    .unwrap();
    let uri = std::fs::read_to_string(fixture.root.join("crypto/database")).unwrap();
    let store = PostgresStore::connect(uri.trim(), 2).await.unwrap();
    store.grant_runtime_role(&role).await.unwrap();
    let permissions: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_database_privilege($1,current_database(),'CREATE'), \
         has_schema_privilege($1,'a_auth','CREATE'), \
         has_table_privilege($1,'a_auth.clients','SELECT'), \
         has_table_privilege($1,'a_auth.clients','INSERT'), \
         has_table_privilege($1,'a_auth.clients','UPDATE'), \
         has_table_privilege($1,'a_auth.clients','DELETE'), \
         has_table_privilege($1,'public._sqlx_migrations','SELECT'), \
         has_table_privilege($1,'public._sqlx_migrations','UPDATE')",
    )
    .bind(&role)
    .fetch_one(&sqlx::PgPool::connect(uri.trim()).await.unwrap())
    .await
    .unwrap();
    assert_eq!(
        permissions,
        (false, false, true, true, true, true, true, false)
    );
    assert!(store
        .grant_runtime_role("invalid\"; DROP SCHEMA a_auth CASCADE")
        .await
        .is_err());
    sqlx::query(&format!("ALTER ROLE \"{role}\" CREATEDB"))
        .execute(&fixture.admin)
        .await
        .unwrap();
    assert!(store.grant_runtime_role(&role).await.is_err());
    sqlx::query(&format!("ALTER ROLE \"{role}\" NOCREATEDB"))
        .execute(&fixture.admin)
        .await
        .unwrap();
    store.grant_runtime_role(&role).await.unwrap();
    let admin = fixture.admin.clone();
    store.close().await;
    fixture.passed().await;
    sqlx::query(&format!("DROP ROLE \"{role}\""))
        .execute(&admin)
        .await
        .unwrap();
}
