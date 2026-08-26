//! Deployment-time credential migration Lambda.
//!
//! `admin` mode wraps legacy admin bearers before the serving Lambda update.
//! `client` mode runs from the dedicated post-deploy stack and converts historical
//! client secrets and registration-token hashes into versioned verifier sets.

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    match std::env::var("CREDENTIAL_MIGRATION_MODE").as_deref() {
        Ok("admin") => run_admin_migration(config).await,
        Ok("client") => run_client_migration(config).await,
        Ok("authority_refs") => run_authority_reference_migration(config).await,
        _ => Err(lambda_runtime::Error::from(
            "CREDENTIAL_MIGRATION_MODE must be admin, client, or authority_refs",
        )),
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn run_admin_migration(config: aws_config::SdkConfig) -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{service_fn, LambdaEvent};

    let secrets = aws_sdk_secretsmanager::Client::new(&config);
    let func = service_fn(move |event: LambdaEvent<serde_json::Value>| {
        let secrets = secrets.clone();
        async move {
            let request_type = event
                .payload
                .get("RequestType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Create");
            if request_type == "Delete" {
                return Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
                    "PhysicalResourceId": "agent-auth-admin-credential-set-v2-copy"
                }));
            }

            let entries = serde_json::from_value::<
                Vec<agent_auth_http::admin_credentials::AdminCredentialMigrationEntry>,
            >(
                event
                    .payload
                    .pointer("/ResourceProperties/Credentials")
                    .cloned()
                    .ok_or_else(|| {
                        lambda_runtime::Error::from("ResourceProperties.Credentials is required")
                    })?,
            )
            .map_err(|error| {
                lambda_runtime::Error::from(format!(
                    "invalid admin credential migration entries: {error}"
                ))
            })?;
            let migrated = agent_auth_http::admin_credentials::migrate_legacy_admin_credentials(
                &secrets,
                &entries,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .map_err(|error| {
                lambda_runtime::Error::from(format!("admin credential migration failed: {error:?}"))
            })?;
            println!("ADMIN_CREDENTIAL_MIGRATION migrated_secrets={migrated}");
            Ok(serde_json::json!({
                "PhysicalResourceId": "agent-auth-admin-credential-set-v2-copy",
                "Data": { "MigratedSecrets": migrated }
            }))
        }
    });
    lambda_runtime::run(func).await
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn run_client_migration(config: aws_config::SdkConfig) -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{service_fn, LambdaEvent};

    let db = aws_sdk_dynamodb::Client::new(&config);
    let table = std::env::var("CLIENTS_TABLE")
        .map_err(|_| lambda_runtime::Error::from("CLIENTS_TABLE is required"))?;
    let server_secret = std::env::var("SERVER_SECRET")
        .map_err(|_| lambda_runtime::Error::from("SERVER_SECRET is required"))?
        .into_bytes();
    let store = agent_auth_http::adapters::aws::DynamoClientStore::new(db, table);

    let func = service_fn(move |event: LambdaEvent<serde_json::Value>| {
        let store = store.clone();
        let server_secret = server_secret.clone();
        async move {
            let request_type = event
                .payload
                .get("RequestType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Create");
            if request_type == "Delete" {
                return Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
                    "PhysicalResourceId": "agent-auth-credential-migration-v1"
                }));
            }

            let now = agent_auth_http::current_unix_secs();
            let migrated = store
                .migrate_legacy_credentials(&server_secret, now)
                .await
                .map_err(|error| {
                    lambda_runtime::Error::from(format!("credential migration failed: {error:?}"))
                })?;
            println!("CREDENTIAL_MIGRATION migrated_records={migrated}");
            Ok(serde_json::json!({
                "PhysicalResourceId": "agent-auth-credential-migration-v1",
                "Data": { "MigratedRecords": migrated }
            }))
        }
    });
    lambda_runtime::run(func).await
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn run_authority_reference_migration(
    config: aws_config::SdkConfig,
) -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{service_fn, LambdaEvent};

    let db = aws_sdk_dynamodb::Client::new(&config);
    let lambda = aws_sdk_lambda::Client::new(&config);
    let codes_table = std::env::var("CODES_TABLE")
        .map_err(|_| lambda_runtime::Error::from("CODES_TABLE is required"))?;
    let refresh_table = std::env::var("REFRESH_TABLE")
        .map_err(|_| lambda_runtime::Error::from("REFRESH_TABLE is required"))?;
    let refs_table = std::env::var("AUTH_REFS_TABLE")
        .map_err(|_| lambda_runtime::Error::from("AUTH_REFS_TABLE is required"))?;
    let deployment_commit = std::env::var("AGENT_AUTH_DEPLOYMENT_COMMIT")
        .map_err(|_| lambda_runtime::Error::from("AGENT_AUTH_DEPLOYMENT_COMMIT is required"))?;
    validate_deployment_commit(&deployment_commit)?;
    let function_name = std::env::var("AWS_LAMBDA_FUNCTION_NAME")
        .map_err(|_| lambda_runtime::Error::from("AWS_LAMBDA_FUNCTION_NAME is required"))?;
    let expected_migration_version =
        agent_auth_http::adapters::aws::authority_reference_migration_version(&deployment_commit);
    let migrator = agent_auth_http::adapters::aws::DynamoAuthorityReferenceMigrator::new(
        db,
        codes_table,
        refresh_table,
        refs_table.clone(),
    );

    let func = service_fn(move |event: LambdaEvent<serde_json::Value>| {
        let migrator = migrator.clone();
        let lambda = lambda.clone();
        let expected_migration_version = expected_migration_version.clone();
        let deployment_commit = deployment_commit.clone();
        let function_name = function_name.clone();
        let refs_table = refs_table.clone();
        async move {
            const PHYSICAL_ID: &str = "agent-auth-client-authority-refs-v1";
            const LEGACY_MUTATOR_DRAIN_SECS: i64 = 315;
            let invocation_started_at_ms = current_unix_millis()?;
            verify_current_authority_reference_migration_deployment(
                &lambda,
                &function_name,
                &deployment_commit,
                &refs_table,
            )
            .await?;
            let request_type = event
                .payload
                .get("RequestType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Create");
            if event
                .payload
                .get("MigrationDelete")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                return Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
                    "IsComplete": true,
                    "PhysicalResourceId": PHYSICAL_ID
                }));
            }
            if request_type == "Delete" {
                return Ok::<serde_json::Value, lambda_runtime::Error>(serde_json::json!({
                    "PhysicalResourceId": PHYSICAL_ID,
                    "MigrationDelete": true
                }));
            }
            if let Some(migration_id) = event
                .payload
                .get("MigrationId")
                .and_then(serde_json::Value::as_str)
            {
                if migration_id != expected_migration_version {
                    return Err(lambda_runtime::Error::from(
                        "authority reference migration id does not match the deployed writer",
                    ));
                }
                let now = agent_auth_http::current_unix_secs();
                return match migrator.step(migration_id, now).await.map_err(|error| {
                    lambda_runtime::Error::from(format!(
                        "authority reference migration step failed: {error:?}"
                    ))
                })? {
                    agent_auth_http::adapters::aws::AuthorityReferenceMigrationProgress::Pending => {
                        Ok(serde_json::json!({ "IsComplete": false }))
                    }
                    agent_auth_http::adapters::aws::AuthorityReferenceMigrationProgress::Complete(
                        stats,
                    ) => {
                        println!(
                            "AUTHORITY_REFERENCE_MIGRATION code_references={} refresh_references={}",
                            stats.code_references, stats.refresh_references
                        );
                        Ok(serde_json::json!({
                            "IsComplete": true,
                            "PhysicalResourceId": PHYSICAL_ID,
                            "Data": {
                                "CodeReferences": stats.code_references,
                                "RefreshReferences": stats.refresh_references,
                                "SchemaVersion": agent_auth_http::adapters::aws::AUTHORITY_REFERENCE_SCHEMA_VERSION
                            }
                        }))
                    }
                };
            }

            let migration_id = event
                .payload
                .pointer("/ResourceProperties/MigrationVersion")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    lambda_runtime::Error::from("ResourceProperties.MigrationVersion is required")
                })?;
            if migration_id != expected_migration_version {
                return Err(lambda_runtime::Error::from(
                    "authority reference migration version does not match the deployed writer",
                ));
            }
            let request_id = event
                .payload
                .get("RequestId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    lambda_runtime::Error::from(
                        "authority reference migration RequestId is required",
                    )
                })?;
            let drain_until = agent_auth_http::current_unix_secs()
                .checked_add(LEGACY_MUTATOR_DRAIN_SECS)
                .ok_or_else(|| lambda_runtime::Error::from("migration drain deadline overflow"))?;
            let previous_migration_id = match request_type {
                "Create" => None,
                "Update" => Some(
                    event
                        .payload
                        .pointer("/OldResourceProperties/MigrationVersion")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            lambda_runtime::Error::from(
                                "OldResourceProperties.MigrationVersion is required for update",
                            )
                        })?,
                ),
                other => {
                    return Err(lambda_runtime::Error::from(format!(
                        "unsupported authority reference migration request type: {other}"
                    )));
                }
            };
            migrator
                .begin(
                    migration_id,
                    previous_migration_id,
                    request_id,
                    invocation_started_at_ms,
                    drain_until,
                )
                .await
                .map_err(|error| {
                    lambda_runtime::Error::from(format!(
                        "authority reference migration initialization failed: {error:?}"
                    ))
                })?;
            Ok(serde_json::json!({
                "PhysicalResourceId": PHYSICAL_ID,
                "MigrationId": migration_id
            }))
        }
    });
    lambda_runtime::run(func).await
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn validate_deployment_commit(value: &str) -> Result<(), lambda_runtime::Error> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(lambda_runtime::Error::from(
            "AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn current_unix_millis() -> Result<u64, lambda_runtime::Error> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| lambda_runtime::Error::from("system clock is before the Unix epoch"))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| lambda_runtime::Error::from("current Unix milliseconds overflow u64"))
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn verify_current_authority_reference_migration_deployment(
    lambda: &aws_sdk_lambda::Client,
    function_name: &str,
    expected_commit: &str,
    expected_refs_table: &str,
) -> Result<(), lambda_runtime::Error> {
    let current = lambda
        .get_function_configuration()
        .function_name(function_name)
        .send()
        .await
        .map_err(|error| {
            lambda_runtime::Error::from(format!(
                "read current authority-reference migration deployment: {error}"
            ))
        })?;
    if current.state().map(|state| state.as_str()) != Some("Active")
        || current.last_update_status().map(|status| status.as_str()) != Some("Successful")
    {
        return Err(lambda_runtime::Error::from(
            "authority-reference migration deployment is not stable",
        ));
    }
    let variables = current
        .environment()
        .and_then(|environment| environment.variables())
        .ok_or_else(|| {
            lambda_runtime::Error::from(
                "authority-reference migration deployment environment is missing",
            )
        })?;
    if variables
        .get("AGENT_AUTH_DEPLOYMENT_COMMIT")
        .map(String::as_str)
        != Some(expected_commit)
        || variables
            .get("CREDENTIAL_MIGRATION_MODE")
            .map(String::as_str)
            != Some("authority_refs")
        || variables.get("AUTH_REFS_TABLE").map(String::as_str) != Some(expected_refs_table)
    {
        return Err(lambda_runtime::Error::from(
            "authority-reference migration invocation was superseded by another deployment",
        ));
    }
    Ok(())
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-migrate-credentials requires --features lambda,aws");
    std::process::exit(1);
}

#[cfg(all(test, feature = "lambda", feature = "aws"))]
mod tests {
    use super::validate_deployment_commit;

    #[test]
    fn authority_reference_migration_requires_a_full_lowercase_git_sha() {
        assert!(validate_deployment_commit("0123456789abcdef0123456789abcdef01234567").is_ok());
        for invalid in [
            "unversioned",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "g123456789abcdef0123456789abcdef01234567",
        ] {
            assert!(
                validate_deployment_commit(invalid).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }
}
