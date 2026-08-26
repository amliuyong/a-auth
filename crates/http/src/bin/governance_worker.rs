//! Durable SQS worker for destructive data-governance checkpoints.

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn handler(
    event: lambda_runtime::LambdaEvent<serde_json::Value>,
    state: agent_auth_http::AppState,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    use agent_auth_http::governance::GovernanceJobCommand;

    if event
        .payload
        .get("source")
        .and_then(serde_json::Value::as_str)
        == Some("aws.events")
    {
        return match state
            .region
            .admit(agent_auth_http::current_unix_secs())
            .await
        {
            Ok(agent_auth_http::region::RegionAdmission::Active) => {
                let completed = agent_auth_http::governance_worker::run_retention_pass(
                    &state,
                    agent_auth_http::current_unix_secs(),
                )
                .await
                .map_err(|error| format!("retention verification failed: {error:?}"))?;
                println!("GOVERNANCE_RETENTION_PASS completed={completed}");
                Ok(serde_json::json!({ "completed": completed }))
            }
            Ok(agent_auth_http::region::RegionAdmission::Inactive { .. }) => {
                Err("governance retention writer Region is inactive".into())
            }
            Err(error) => Err(format!("Region admission unavailable: {error:?}").into()),
        };
    }

    let records = event
        .payload
        .get("Records")
        .and_then(serde_json::Value::as_array)
        .ok_or("governance worker requires SQS Records")?;
    let mut failures = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let message_id = record
            .get("messageId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("missing-message-id-{index}"));
        let command = record
            .get("body")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "SQS record has no body".to_string())
            .and_then(|body| {
                serde_json::from_str::<GovernanceJobCommand>(body)
                    .map_err(|error| format!("invalid governance command: {error}"))
            });
        let result = match command {
            Ok(command) => {
                let local_region = state.region.local_region();
                if !state
                    .governance_config
                    .admits_destructive_governance(&command.tenant_id, local_region)
                {
                    Err(format!(
                        "tenant {} is not admitted for destructive governance in {}",
                        command.tenant_id, local_region
                    ))
                } else {
                    match state.region.admit(agent_auth_http::current_unix_secs()).await {
                        Ok(agent_auth_http::region::RegionAdmission::Active) => {
                            agent_auth_http::governance_worker::process_command_once(
                                &state,
                                command,
                                agent_auth_http::current_unix_secs(),
                            )
                            .await
                            .map(|outcome| {
                                let (delivery, job) = match &outcome {
                                    agent_auth_http::governance_worker::GovernanceCommandOutcome::Requeued(job) => {
                                        ("requeued", job)
                                    }
                                    agent_auth_http::governance_worker::GovernanceCommandOutcome::Terminal(job) => {
                                        ("terminal", job)
                                    }
                                };
                                println!(
                                    "GOVERNANCE_CHECKPOINT delivery={} tenant={} job={} state={:?} phase={:?} revision={}",
                                    delivery,
                                    job.tenant_id,
                                    job.job_id,
                                    job.state,
                                    job.phase,
                                    job.revision
                                );
                            })
                            .map_err(|error| format!("{error:?}"))
                        }
                        Ok(agent_auth_http::region::RegionAdmission::Inactive { .. }) => {
                            Err("governance writer Region is inactive".to_string())
                        }
                        Err(error) => {
                            Err(format!("Region admission unavailable: {error:?}"))
                        }
                    }
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!(
                "GOVERNANCE_CHECKPOINT_FAILURE message_id={} error={}",
                message_id, error
            );
            failures.push(serde_json::json!({ "itemIdentifier": message_id }));
        }
    }
    Ok(serde_json::json!({ "batchItemFailures": failures }))
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::service_fn;

    let state = agent_auth_http::AppState::from_env_aws()
        .await
        .map_err(lambda_runtime::Error::from)?;
    lambda_runtime::run(service_fn(move |event| handler(event, state.clone()))).await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-governance-worker requires --features lambda,aws");
    std::process::exit(1);
}
