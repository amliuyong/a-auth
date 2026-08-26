//! SecurityEvents DynamoDB Stream -> SSF outbox projection and scheduled push worker.
//!
//! Build:
//! `cargo lambda build --release --arm64 --features lambda,aws --bin agent-auth-ssf-delivery`.

#[cfg(all(feature = "lambda", feature = "aws"))]
const MAX_FAILURE_OBJECT_BYTES: usize = 1024 * 1024;

#[cfg(all(feature = "lambda", feature = "aws"))]
fn canonical_security_events(
    payload: &serde_json::Value,
) -> Result<Vec<agent_auth_http::security_event::SecurityEvent>, lambda_runtime::Error> {
    use agent_auth_http::security_event::{SecurityEvent, SECURITY_EVENT_SCHEMA_VERSION};

    let Some(records) = payload.get("Records").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let source = record
            .get("eventSource")
            .or_else(|| record.get("EventSource"))
            .and_then(serde_json::Value::as_str);
        if source != Some("aws:dynamodb") {
            return Err("SSF worker received a non-DynamoDB record".into());
        }
        if record
            .get("eventName")
            .or_else(|| record.get("EventName"))
            .and_then(serde_json::Value::as_str)
            != Some("INSERT")
        {
            continue;
        }
        let envelope = record
            .pointer("/dynamodb/NewImage/envelope/S")
            .and_then(serde_json::Value::as_str)
            .ok_or("security event stream record is missing NewImage.envelope.S")?;
        let event: SecurityEvent = serde_json::from_str(envelope)
            .map_err(|error| format!("invalid security event envelope JSON: {error}"))?;
        if event.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported security event schema version {}",
                event.schema_version
            )
            .into());
        }
        let validated = SecurityEvent::new_at(
            event.event_id.clone(),
            event.occurred_at,
            event.tenant_id.clone(),
            event.actor.clone(),
            Some(event.subject.clone()),
            event.category,
            event.action.clone(),
            event.outcome,
            event.correlation.clone(),
        )
        .map_err(|error| format!("invalid security event envelope: {error}"))?;
        if validated != event {
            return Err("security event envelope canonicalization mismatch".into());
        }
        events.push(validated);
    }
    Ok(events)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn source_name(record: &serde_json::Value) -> Option<&str> {
    record
        .get("eventSource")
        .or_else(|| record.get("EventSource"))
        .and_then(serde_json::Value::as_str)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn failure_object_locations(
    payload: &serde_json::Value,
    expected_bucket: &str,
) -> Result<Vec<(String, String, Option<String>)>, lambda_runtime::Error> {
    let records = payload
        .get("Records")
        .and_then(serde_json::Value::as_array)
        .ok_or("SSF source replay is missing SQS Records")?;
    let mut locations = Vec::new();
    let mut saw_notification = false;
    for record in records {
        if source_name(record) != Some("aws:sqs") {
            return Err("SSF source replay received a non-SQS record".into());
        }
        let body = record
            .get("body")
            .and_then(serde_json::Value::as_str)
            .ok_or("SSF source replay SQS record is missing body")?;
        let notification: serde_json::Value = serde_json::from_str(body)
            .map_err(|error| format!("invalid SSF source replay notification: {error}"))?;
        if notification
            .get("Service")
            .and_then(serde_json::Value::as_str)
            == Some("Amazon S3")
            && notification
                .get("Event")
                .and_then(serde_json::Value::as_str)
                == Some("s3:TestEvent")
        {
            continue;
        }
        saw_notification = true;
        let notifications = notification
            .get("Records")
            .and_then(serde_json::Value::as_array)
            .ok_or("SSF source replay body is missing S3 Records")?;
        for notification in notifications {
            if source_name(notification) != Some("aws:s3") {
                return Err("SSF source replay received a non-S3 notification".into());
            }
            let bucket = notification
                .pointer("/s3/bucket/name")
                .and_then(serde_json::Value::as_str)
                .ok_or("SSF source replay notification is missing bucket")?;
            if bucket != expected_bucket {
                return Err("SSF source replay notification names an unexpected bucket".into());
            }
            let encoded_key = notification
                .pointer("/s3/object/key")
                .and_then(serde_json::Value::as_str)
                .ok_or("SSF source replay notification is missing object key")?;
            let key_with_spaces = encoded_key.replace('+', " ");
            let key = percent_encoding::percent_decode_str(&key_with_spaces)
                .decode_utf8()
                .map_err(|_| "SSF source replay object key is not UTF-8")?
                .into_owned();
            let version_id = notification
                .pointer("/s3/object/versionId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            locations.push((bucket.to_string(), key, version_id));
        }
    }
    if locations.is_empty() && saw_notification {
        return Err("SSF source replay notification contained no objects".into());
    }
    Ok(locations)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn failed_invocation_payload(object: &[u8]) -> Result<serde_json::Value, lambda_runtime::Error> {
    if object.len() > MAX_FAILURE_OBJECT_BYTES {
        return Err("SSF source failure object exceeds 1 MiB".into());
    }
    let invocation: serde_json::Value = serde_json::from_slice(object)
        .map_err(|error| format!("invalid SSF source failure object JSON: {error}"))?;
    let payload = invocation
        .get("payload")
        .or_else(|| invocation.get("requestPayload"))
        .ok_or("SSF source failure object is missing payload")?;
    let payload: serde_json::Value = match payload {
        serde_json::Value::String(encoded) => serde_json::from_str(encoded)
            .map_err(|error| format!("invalid SSF source failure payload JSON: {error}"))?,
        serde_json::Value::Object(_) => payload.clone(),
        _ => return Err("SSF source failure payload must be an object or JSON string".into()),
    };
    if !payload
        .get("Records")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err("SSF source failure payload is missing Records".into());
    }
    Ok(payload)
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn load_source_events(
    payload: &serde_json::Value,
    s3: &aws_sdk_s3::Client,
    failure_bucket: &str,
) -> Result<(Vec<agent_auth_http::security_event::SecurityEvent>, usize), lambda_runtime::Error> {
    let Some(records) = payload.get("Records").and_then(serde_json::Value::as_array) else {
        return Ok((Vec::new(), 0));
    };
    if records
        .iter()
        .all(|record| source_name(record) == Some("aws:dynamodb"))
    {
        return canonical_security_events(payload).map(|events| (events, 0));
    }
    if !records
        .iter()
        .all(|record| source_name(record) == Some("aws:sqs"))
    {
        return Err("SSF worker received mixed or unsupported source records".into());
    }

    let locations = failure_object_locations(payload, failure_bucket)?;
    let replayed = locations.len();
    let mut events = Vec::new();
    for (bucket, key, version_id) in locations {
        let object = s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .set_version_id(version_id)
            .send()
            .await
            .map_err(|error| format!("cannot read SSF source failure object: {error}"))?;
        if object
            .content_length()
            .is_some_and(|length| length < 0 || length as usize > MAX_FAILURE_OBJECT_BYTES)
        {
            return Err("SSF source failure object exceeds 1 MiB".into());
        }
        let bytes = object
            .body
            .collect()
            .await
            .map_err(|error| format!("cannot collect SSF source failure object: {error}"))?
            .into_bytes();
        let request_payload = failed_invocation_payload(&bytes)?;
        events.extend(canonical_security_events(&request_payload)?);
    }
    Ok((events, replayed))
}

#[cfg(all(feature = "lambda", feature = "aws"))]
async fn handler(
    event: lambda_runtime::LambdaEvent<serde_json::Value>,
    form: agent_auth_discovery::Form,
    store: agent_auth_http::adapters::aws::DynamoSsfStore,
    signer: agent_auth_http::tenant_keys::TenantKeyService,
    push_client: agent_auth_http::adapters::aws::HttpSsfPushClient,
    s3: aws_sdk_s3::Client,
    failure_bucket: String,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    use agent_auth_http::ssf::SsfStore;

    let (events, replayed_failures) =
        load_source_events(&event.payload, &s3, &failure_bucket).await?;
    let now = agent_auth_http::current_unix_secs();
    let mut enqueued = 0usize;
    for event in &events {
        let issuer =
            agent_auth_discovery::issuer_for_tenant(&form, &event.tenant_id).map_err(|error| {
                lambda_runtime::Error::from(format!(
                    "cannot reconstruct SSF issuer for tenant {}: {error:?}",
                    event.tenant_id
                ))
            })?;
        enqueued += store
            .enqueue_event(event, issuer.as_str(), now)
            .await
            .map_err(|error| {
                lambda_runtime::Error::from(format!(
                    "SSF projection failed for event {}: {error:?}",
                    event.event_id
                ))
            })?
            .len();
    }

    // DynamoDB stream invocations only project immutable source events into the
    // outbox. Scheduled invocations exclusively own leases and outbound pushes,
    // leaving a deterministic revocation window between enqueue and delivery.
    let stats = if event.payload.get("Records").is_some() {
        agent_auth_http::ssf_worker::SsfWorkerStats::default()
    } else {
        agent_auth_http::ssf_worker::process_due_deliveries(&store, &signer, &push_client, now)
            .await
            .map_err(|error| {
                lambda_runtime::Error::from(format!("SSF delivery pass failed: {error:?}"))
            })?
    };
    println!(
        "SSF_DELIVERY_PASS source_events={} replayed_failures={} enqueued={} acquired={} \
         delivered={} retrying={} terminal={} dead_lettered={} lost_leases={}",
        events.len(),
        replayed_failures,
        enqueued,
        stats.acquired,
        stats.delivered,
        stats.retrying,
        stats.terminal,
        stats.dead_lettered,
        stats.lost_leases,
    );
    if stats.dead_lettered > 0 {
        eprintln!(
            "SSF_DELIVERY_FAILURE result=dead_lettered count={}",
            stats.dead_lettered
        );
    }
    if stats.terminal > 0 {
        eprintln!(
            "SSF_DELIVERY_FAILURE result=terminal count={}",
            stats.terminal
        );
    }
    if stats.lost_leases > 0 {
        eprintln!(
            "SSF_DELIVERY_FAILURE result=lost_lease count={}",
            stats.lost_leases
        );
    }
    Ok(serde_json::json!({
        "source_events": events.len(),
        "replayed_failures": replayed_failures,
        "enqueued": enqueued,
        "acquired": stats.acquired,
        "delivered": stats.delivered,
        "retrying": stats.retrying,
        "terminal": stats.terminal,
        "dead_lettered": stats.dead_lettered,
        "lost_leases": stats.lost_leases,
    }))
}

#[cfg(all(feature = "lambda", feature = "aws"))]
fn deployment_form() -> Result<agent_auth_discovery::Form, lambda_runtime::Error> {
    let host = std::env::var("AGENT_AUTH_HOST").map_err(|_| "AGENT_AUTH_HOST is required")?;
    if std::env::var("AGENT_AUTH_FORM")
        .unwrap_or_default()
        .eq_ignore_ascii_case("saas")
    {
        let zone =
            std::env::var("AGENT_AUTH_ZONE").map_err(|_| "AGENT_AUTH_ZONE is required for SaaS")?;
        let control_host = std::env::var("AGENT_AUTH_CONTROL_HOST")
            .map_err(|_| "AGENT_AUTH_CONTROL_HOST is required for SaaS")?;
        Ok(agent_auth_discovery::Form::Saas { zone, control_host })
    } else {
        Ok(agent_auth_discovery::Form::SelfHosted {
            configured_host: host,
        })
    }
}

#[cfg(all(feature = "lambda", feature = "aws"))]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::service_fn;

    let table =
        std::env::var("SSF_DELIVERIES_TABLE").map_err(|_| "SSF_DELIVERIES_TABLE is required")?;
    let failure_bucket = std::env::var("SSF_STREAM_FAILURE_BUCKET")
        .map_err(|_| "SSF_STREAM_FAILURE_BUCKET is required")?;
    let form = deployment_form()?;
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let store = agent_auth_http::adapters::aws::DynamoSsfStore::new(
        aws_sdk_dynamodb::Client::new(&config),
        table,
    );
    let s3 = aws_sdk_s3::Client::new(&config);
    let kms = aws_sdk_kms::Client::new(&config);
    let signer = if matches!(form, agent_auth_discovery::Form::Saas { .. }) {
        let registry_table =
            std::env::var("TENANT_KEYS_TABLE").map_err(|_| "TENANT_KEYS_TABLE is required")?;
        let service = agent_auth_http::tenant_keys::TenantKeyService::dynamo_readonly(
            agent_auth_http::adapters::aws::DynamoTenantKeyRegistry::new(
                aws_sdk_dynamodb::Client::new(&config),
                registry_table,
            ),
            kms,
        );
        match std::env::var("AGENT_AUTH_REGION_ID")
            .ok()
            .filter(|value| !value.is_empty())
        {
            Some(region_id) => service.with_region(
                agent_auth_http::region::RegionRuntime::artifact_owner(region_id)
                    .map_err(lambda_runtime::Error::from)?,
            ),
            None => service,
        }
    } else {
        let key_id = std::env::var("SIGNING_KEY_ID").map_err(|_| "SIGNING_KEY_ID is required")?;
        let published_ec_csv = std::env::var("SIGNING_KEY_IDS_PUBLISHED")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let fixed = agent_auth_http::adapters::aws::KmsSigner::new(
            kms,
            key_id,
            None,
            published_ec_csv,
            None,
        )
        .await
        .map_err(|error| {
            lambda_runtime::Error::from(format!("SSF KMS signer init failed: {error:?}"))
        })?;
        agent_auth_http::tenant_keys::TenantKeyService::shared(std::sync::Arc::new(
            agent_auth_http::state::SignerImpl::Kms(fixed),
        ))
    };
    let push_client = agent_auth_http::adapters::aws::HttpSsfPushClient::new();
    lambda_runtime::run(service_fn(move |event| {
        handler(
            event,
            form.clone(),
            store.clone(),
            signer.clone(),
            push_client.clone(),
            s3.clone(),
            failure_bucket.clone(),
        )
    }))
    .await
}

#[cfg(not(all(feature = "lambda", feature = "aws")))]
fn main() {
    eprintln!("agent-auth-ssf-delivery requires --features lambda,aws");
    std::process::exit(1);
}

#[cfg(all(test, feature = "lambda", feature = "aws"))]
mod tests {
    use super::{canonical_security_events, failed_invocation_payload, failure_object_locations};

    fn stream_payload(envelope: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "Records": [{
                "eventSource": "aws:dynamodb",
                "eventName": "INSERT",
                "dynamodb": {
                    "NewImage": {
                        "envelope": { "S": envelope.to_string() }
                    }
                }
            }]
        })
    }

    #[test]
    fn parses_and_validates_canonical_stream_envelope() {
        let payload = stream_payload(serde_json::json!({
            "schema_version": "1.0",
            "event_id": "evt-ssf-worker",
            "occurred_at": 1_785_500_000,
            "tenant_id": "t1",
            "actor": {"kind": "admin", "id": "admin:operator"},
            "subject": {"kind": "user", "id": "user:alice@example.com"},
            "category": "user_lifecycle",
            "action": "user.disable",
            "outcome": "success",
            "correlation": {}
        }));
        let events = canonical_security_events(&payload).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-ssf-worker");
    }

    #[test]
    fn rejects_noncanonical_or_unsupported_envelopes() {
        let payload = stream_payload(serde_json::json!({
            "schema_version": "2.0",
            "event_id": "evt-ssf-worker",
            "occurred_at": 1_785_500_000,
            "tenant_id": "t1",
            "actor": {"kind": "admin", "id": "admin:operator"},
            "subject": {"kind": "user", "id": "user:alice@example.com"},
            "category": "user_lifecycle",
            "action": "user.disable",
            "outcome": "success",
            "correlation": {}
        }));
        assert!(canonical_security_events(&payload).is_err());
    }

    #[test]
    fn parses_only_the_configured_failure_bucket_notification() {
        let payload = serde_json::json!({
            "Records": [{
                "eventSource": "aws:sqs",
                "body": serde_json::json!({
                    "Records": [{
                        "eventSource": "aws:s3",
                        "s3": {
                            "bucket": {"name": "expected-failure-bucket"},
                            "object": {
                                "key": "aws%2Flambda%2Ffailure+record.json",
                                "versionId": "failure-version"
                            }
                        }
                    }]
                }).to_string()
            }]
        });
        assert_eq!(
            failure_object_locations(&payload, "expected-failure-bucket").unwrap(),
            vec![(
                "expected-failure-bucket".to_string(),
                "aws/lambda/failure record.json".to_string(),
                Some("failure-version".to_string())
            )]
        );
        assert!(failure_object_locations(&payload, "other-bucket").is_err());
    }

    #[test]
    fn ignores_s3_notification_configuration_test_events() {
        let payload = serde_json::json!({
            "Records": [{
                "eventSource": "aws:sqs",
                "body": serde_json::json!({
                    "Service": "Amazon S3",
                    "Event": "s3:TestEvent"
                }).to_string()
            }]
        });
        assert_eq!(
            failure_object_locations(&payload, "expected-failure-bucket").unwrap(),
            Vec::<(String, String, Option<String>)>::new()
        );
    }

    #[test]
    fn extracts_live_and_legacy_stream_failure_payloads_with_a_size_bound() {
        let request_payload = stream_payload(serde_json::json!({
            "schema_version": "1.0",
            "event_id": "evt-ssf-replay",
            "occurred_at": 1_785_500_000,
            "tenant_id": "t1",
            "actor": {"kind": "admin", "id": "admin:operator"},
            "subject": {"kind": "user", "id": "user:alice@example.com"},
            "category": "user_lifecycle",
            "action": "user.disable",
            "outcome": "success",
            "correlation": {}
        }));
        let object = serde_json::to_vec(&serde_json::json!({
            "version": "1.0",
            "payload": request_payload.to_string()
        }))
        .unwrap();
        let replay = failed_invocation_payload(&object).unwrap();
        assert_eq!(
            canonical_security_events(&replay).unwrap()[0].event_id,
            "evt-ssf-replay"
        );
        for request_payload in [request_payload.clone(), request_payload.to_string().into()] {
            let object = serde_json::to_vec(&serde_json::json!({
                "version": "1.0",
                "requestPayload": request_payload
            }))
            .unwrap();
            let replay = failed_invocation_payload(&object).unwrap();
            assert_eq!(
                canonical_security_events(&replay).unwrap()[0].event_id,
                "evt-ssf-replay"
            );
        }
        assert!(failed_invocation_payload(&vec![b'x'; 1024 * 1024 + 1]).is_err());
    }
}
