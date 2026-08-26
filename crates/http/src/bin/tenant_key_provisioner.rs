//! SQS commands and scheduled reconciliation for SaaS tenant signing keys.

#[cfg(all(feature = "lambda", feature = "aws"))]
fn configured_tenants() -> Result<std::collections::HashSet<String>, lambda_runtime::Error> {
    let encoded = std::env::var("SAAS_TENANTS").map_err(|_| "SAAS_TENANTS is required")?;
    let tenants: Vec<String> = serde_json::from_str(&encoded)
        .map_err(|error| format!("SAAS_TENANTS is invalid: {error}"))?;
    if tenants.is_empty() || tenants.iter().any(|tenant| tenant.is_empty()) {
        return Err("SAAS_TENANTS must contain at least one tenant".into());
    }
    let unique: std::collections::HashSet<String> = tenants.into_iter().collect();
    Ok(unique)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn configured_replica_regions(primary_region: &str) -> Result<Vec<String>, lambda_runtime::Error> {
    let encoded = std::env::var("TENANT_KEY_REPLICA_REGIONS")
        .map_err(|_| "TENANT_KEY_REPLICA_REGIONS is required")?;
    let regions: Vec<String> = serde_json::from_str(&encoded)
        .map_err(|error| format!("TENANT_KEY_REPLICA_REGIONS is invalid: {error}"))?;
    let mut unique = std::collections::HashSet::new();
    for region in &regions {
        if region == primary_region
            || region.len() > 32
            || region.is_empty()
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !unique.insert(region.clone())
        {
            return Err(
                "TENANT_KEY_REPLICA_REGIONS must contain unique non-primary AWS regions".into(),
            );
        }
    }
    Ok(regions)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn process_command(
    registry: &agent_auth_http::tenant_keys::TenantKeyRegistryImpl,
    backend: &agent_auth_http::adapters::aws::AwsTenantKeyProvisioningBackend,
    governance: &agent_auth_http::adapters::aws::DynamoGovernanceStore,
    tenants: &std::collections::HashSet<String>,
    command: &agent_auth_http::tenant_keys::TenantKeyCommand,
) -> Result<(), String> {
    let now = agent_auth_http::current_unix_secs();
    if !tenants.contains(&command.tenant_id) {
        return Err(format!(
            "tenant {} is not in SAAS_TENANTS",
            command.tenant_id
        ));
    }
    if command.action == agent_auth_http::tenant_keys::TenantKeyCommandAction::Offboard {
        let permit = command
            .governance_dispatch
            .as_ref()
            .ok_or_else(|| "tenant key offboarding command has no governance permit".to_string())?;
        if !governance
            .authorize_tenant_key_dispatch(&command.tenant_id, permit, now)
            .await
            .map_err(|error| format!("{error:?}"))?
        {
            println!(
                "TENANT_KEY_OPERATION_SKIPPED tenant={} action=offboard operation={} reason=stale_governance_permit",
                command.tenant_id, command.operation_id
            );
            return Ok(());
        }
    } else if command.governance_dispatch.is_some() {
        return Err("non-offboarding tenant key command carries a governance permit".into());
    }
    let execution =
        agent_auth_http::tenant_key_provisioner::execute_command(registry, backend, command, now);
    let record = if let Some(permit) = command.governance_dispatch.as_ref() {
        let remaining = permit
            .claim_deadline
            .saturating_sub(agent_auth_http::current_unix_secs());
        if remaining <= 0 {
            return Ok(());
        }
        tokio::time::timeout(std::time::Duration::from_secs(remaining as u64), execution)
            .await
            .map_err(|_| "tenant key offboarding exceeded governance claim deadline".to_string())?
            .map_err(|error| format!("{error:?}"))?
    } else {
        execution.await.map_err(|error| format!("{error:?}"))?
    };
    if let Some(permit) = command.governance_dispatch.as_ref() {
        if !governance
            .commit_tenant_key_dispatch(
                &command.tenant_id,
                permit,
                agent_auth_http::current_unix_secs(),
            )
            .await
            .map_err(|error| format!("{error:?}"))?
        {
            return Err("tenant key governance outcome reconciliation failed".into());
        }
    }
    if let Some(record) = record {
        println!(
            "TENANT_KEY_OPERATION tenant={} action={:?} operation={} lifecycle={:?} revision={}",
            command.tenant_id,
            command.action,
            command.operation_id,
            record.lifecycle,
            record.revision
        );
    }
    Ok(())
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn handler(
    event: lambda_runtime::LambdaEvent<serde_json::Value>,
    registry: agent_auth_http::tenant_keys::TenantKeyRegistryImpl,
    backend: agent_auth_http::adapters::aws::AwsTenantKeyProvisioningBackend,
    governance: agent_auth_http::adapters::aws::DynamoGovernanceStore,
    region: agent_auth_http::region::RegionRuntime,
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
    tenants: std::collections::HashSet<String>,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    use agent_auth_http::tenant_keys::{TenantKeyCommand, TenantKeyCommandAction};
    use aws_sdk_sqs::types::SendMessageBatchRequestEntry;

    let now = agent_auth_http::current_unix_secs();
    let is_queue_invocation = event.payload.get("Records").is_some();
    match region.admit(now).await {
        Ok(agent_auth_http::region::RegionAdmission::Active) => {}
        Ok(agent_auth_http::region::RegionAdmission::Inactive { .. }) => {
            if is_queue_invocation {
                return Err("tenant key writer Region is inactive".into());
            }
            return Ok(serde_json::json!({ "skipped": "region_inactive" }));
        }
        Err(error) => {
            return Err(format!("Region admission unavailable: {error:?}").into());
        }
    }
    if let Some(records) = event
        .payload
        .get("Records")
        .and_then(|value| value.as_array())
    {
        let mut failures = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let message_id = record
                .get("messageId")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("missing-message-id-{index}"));
            let result = match record.get("body").and_then(|value| value.as_str()) {
                Some(body) => serde_json::from_str::<TenantKeyCommand>(body)
                    .map_err(|error| format!("invalid command: {error}")),
                None => Err("SQS record has no body".to_string()),
            };
            let result = match result {
                Ok(command) => {
                    process_command(&registry, &backend, &governance, &tenants, &command).await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                eprintln!(
                    "TENANT_KEY_OPERATION_FAILURE message_id={} error={}",
                    message_id, error
                );
                failures.push(serde_json::json!({ "itemIdentifier": message_id }));
            }
        }
        return Ok(serde_json::json!({ "batchItemFailures": failures }));
    }

    let mut commands = Vec::with_capacity(tenants.len());
    for (index, tenant_id) in tenants.iter().enumerate() {
        let command = TenantKeyCommand {
            tenant_id: tenant_id.clone(),
            action: TenantKeyCommandAction::Reconcile,
            operation_id: format!("onboard-{tenant_id}-v1"),
            requested_at: now,
            governance_dispatch: None,
        };
        commands.push(
            SendMessageBatchRequestEntry::builder()
                .id(format!("tenant-{index}"))
                .message_body(serde_json::to_string(&command)?)
                .build()?,
        );
    }
    let mut queued = 0usize;
    for batch in commands.chunks(10) {
        let output = sqs
            .send_message_batch()
            .queue_url(&queue_url)
            .set_entries(Some(batch.to_vec()))
            .send()
            .await?;
        if !output.failed().is_empty() {
            return Err(format!(
                "tenant key reconciliation fan-out failed for {} messages",
                output.failed().len()
            )
            .into());
        }
        queued += output.successful().len();
    }
    Ok(serde_json::json!({
        "queued": queued,
        "failed": 0,
    }))
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::service_fn;

    let table = std::env::var("TENANT_KEYS_TABLE").map_err(|_| "TENANT_KEYS_TABLE is required")?;
    let governance_table =
        std::env::var("GOVERNANCE_TABLE").map_err(|_| "GOVERNANCE_TABLE is required")?;
    let suppression_table = std::env::var("GOVERNANCE_SUPPRESSION_TABLE")
        .map_err(|_| "GOVERNANCE_SUPPRESSION_TABLE is required")?;
    let queue_url = std::env::var("TENANT_KEY_OPERATIONS_QUEUE_URL")
        .map_err(|_| "TENANT_KEY_OPERATIONS_QUEUE_URL is required")?;
    let tenants = configured_tenants()?;
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_timeout = aws_config::timeout::TimeoutConfig::builder()
        .operation_timeout(std::time::Duration::from_secs(5))
        .build();
    let primary_region = config
        .region()
        .ok_or("AWS region is required for tenant key provisioning")?
        .as_ref();
    let replica_regions = configured_replica_regions(primary_region)?;
    let replica_kms = replica_regions
        .into_iter()
        .map(|region| {
            let regional_config = aws_sdk_kms::config::Builder::from(&config)
                .region(aws_sdk_kms::config::Region::new(region.clone()))
                .timeout_config(kms_timeout.clone())
                .build();
            (region, aws_sdk_kms::Client::from_conf(regional_config))
        })
        .collect();
    let deployment_id = table.clone();
    let db = aws_sdk_dynamodb::Client::new(&config);
    let registry = agent_auth_http::tenant_keys::TenantKeyRegistryImpl::Dynamo(
        agent_auth_http::adapters::aws::DynamoTenantKeyRegistry::new(db.clone(), table),
    );
    let governance = agent_auth_http::adapters::aws::DynamoGovernanceStore::new(
        db.clone(),
        governance_table,
        suppression_table,
    );
    let region = match agent_auth_http::region::resolve_control_region(
        std::env::var("AGENT_AUTH_REGION_ID")
            .ok()
            .filter(|value| !value.is_empty()),
        std::env::var("AWS_REGION")
            .ok()
            .filter(|value| !value.is_empty()),
        std::env::var("REGION_CONTROL_TABLE")
            .ok()
            .filter(|value| !value.is_empty()),
    )
    .map_err(lambda_runtime::Error::from)?
    {
        None => agent_auth_http::region::RegionRuntime::single_region(),
        Some((region_id, table)) => agent_auth_http::region::RegionRuntime::controlled(
            region_id,
            agent_auth_http::region::RegionControlStoreImpl::Dynamo(
                agent_auth_http::adapters::aws::DynamoRegionControlStore::new(db, table),
            ),
        )
        .map_err(lambda_runtime::Error::from)?,
    };
    let primary_kms_config = aws_sdk_kms::config::Builder::from(&config)
        .timeout_config(kms_timeout)
        .build();
    let backend = agent_auth_http::adapters::aws::AwsTenantKeyProvisioningBackend::new(
        aws_sdk_kms::Client::from_conf(primary_kms_config),
        aws_sdk_resourcegroupstagging::Client::new(&config),
        deployment_id,
        replica_kms,
    );
    let sqs = aws_sdk_sqs::Client::new(&config);
    lambda_runtime::run(service_fn(move |event| {
        handler(
            event,
            registry.clone(),
            backend.clone(),
            governance.clone(),
            region.clone(),
            sqs.clone(),
            queue_url.clone(),
            tenants.clone(),
        )
    }))
    .await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-tenant-key-provisioner requires --features lambda,aws");
    std::process::exit(1);
}
