use std::collections::HashMap;

use agent_auth_infra_core::TenantKeyRecord;
use aws_sdk_dynamodb::{error::ProvideErrorMetadata, types::AttributeValue};

use crate::{
    ports::StoreError,
    tenant_keys::{TenantKeyCommand, TenantKeyCommandSink, TenantKeyRegistry},
};

fn ddb_error<E, R>(error: aws_sdk_dynamodb::error::SdkError<E, R>) -> StoreError
where
    aws_sdk_dynamodb::error::SdkError<E, R>: ProvideErrorMetadata,
{
    if matches!(
        &error,
        aws_sdk_dynamodb::error::SdkError::TimeoutError(_)
            | aws_sdk_dynamodb::error::SdkError::DispatchFailure(_)
            | aws_sdk_dynamodb::error::SdkError::ResponseError(_)
    ) {
        return StoreError::Transient("tenant key registry transport failure".to_string());
    }
    let code = error.code().unwrap_or("");
    if code.contains("Throttling")
        || code.contains("ProvisionedThroughputExceeded")
        || code.contains("RequestLimitExceeded")
        || code.contains("InternalServerError")
        || code.contains("TransactionConflict")
    {
        StoreError::Transient(code.to_string())
    } else {
        StoreError::Permanent(format!("{code}: {}", error.message().unwrap_or("")))
    }
}

#[derive(Clone)]
pub struct DynamoTenantKeyRegistry {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

impl DynamoTenantKeyRegistry {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn item(record: &TenantKeyRecord) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let record_json = serde_json::to_string(record)
            .map_err(|error| StoreError::Permanent(format!("tenant key record encode: {error}")))?;
        Ok(HashMap::from([
            (
                "tenant_id".to_string(),
                AttributeValue::S(record.tenant_id.clone()),
            ),
            (
                "revision".to_string(),
                AttributeValue::N(record.revision.to_string()),
            ),
            (
                "lifecycle".to_string(),
                AttributeValue::S(
                    serde_json::to_value(&record.lifecycle)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_string))
                        .ok_or_else(|| {
                            StoreError::Permanent(
                                "tenant key lifecycle serialization failed".to_string(),
                            )
                        })?,
                ),
            ),
            ("record_json".to_string(), AttributeValue::S(record_json)),
            (
                "updated_at".to_string(),
                AttributeValue::N(record.updated_at.to_string()),
            ),
        ]))
    }

    fn decode(item: &HashMap<String, AttributeValue>) -> Result<TenantKeyRecord, StoreError> {
        let encoded = item
            .get("record_json")
            .and_then(|value| value.as_s().ok())
            .ok_or_else(|| StoreError::Permanent("tenant key record_json missing".to_string()))?;
        let record: TenantKeyRecord = serde_json::from_str(encoded)
            .map_err(|error| StoreError::Permanent(format!("tenant key record decode: {error}")))?;
        if let Some(snapshot) = &record.served_snapshot {
            snapshot.validate().map_err(|error| {
                StoreError::Permanent(format!("invalid tenant key snapshot: {error:?}"))
            })?;
        }
        Ok(record)
    }
}

impl TenantKeyRegistry for DynamoTenantKeyRegistry {
    async fn get(&self, tenant_id: &str) -> Result<Option<TenantKeyRecord>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_error)?;
        output.item().map(Self::decode).transpose()
    }

    async fn create(&self, record: TenantKeyRecord) -> Result<bool, StoreError> {
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::item(&record)?))
            .condition_expression("attribute_not_exists(tenant_id)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if error.code() == Some("ConditionalCheckFailedException") => Ok(false),
            Err(error) => Err(ddb_error(error)),
        }
    }

    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        record: TenantKeyRecord,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::item(&record)?))
            .condition_expression("revision = :expected_revision")
            .expression_attribute_values(
                ":expected_revision",
                AttributeValue::N(expected_revision.to_string()),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if error.code() == Some("ConditionalCheckFailedException") => Ok(false),
            Err(error) => Err(ddb_error(error)),
        }
    }
}

#[derive(Clone)]
pub struct SqsTenantKeyCommandSink {
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
}

impl SqsTenantKeyCommandSink {
    pub fn new(sqs: aws_sdk_sqs::Client, queue_url: impl Into<String>) -> Self {
        Self {
            sqs,
            queue_url: queue_url.into(),
        }
    }
}

impl TenantKeyCommandSink for SqsTenantKeyCommandSink {
    async fn send(&self, command: TenantKeyCommand) -> Result<(), StoreError> {
        let body = serde_json::to_string(&command).map_err(|error| {
            StoreError::Permanent(format!("tenant key command encode: {error}"))
        })?;
        self.sqs
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .send()
            .await
            .map_err(|error| {
                if error
                    .as_service_error()
                    .and_then(|service| service.code())
                    .is_some_and(|code| {
                        code.contains("Throttling") || code.contains("InternalError")
                    })
                {
                    StoreError::Transient("tenant key command queue unavailable".to_string())
                } else {
                    StoreError::Permanent("tenant key command rejected".to_string())
                }
            })?;
        Ok(())
    }
}
