//! Durable deployment presentation, separate from tenant identity configuration.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::ports::StoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredBranding {
    pub version: u32,
    pub revision: u64,
    pub settings: Value,
}

#[derive(Clone)]
pub struct BrandingStore {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Memory(Arc<RwLock<HashMap<String, StoredBranding>>>),
    #[cfg(feature = "aws")]
    Dynamo {
        db: aws_sdk_dynamodb::Client,
        table: String,
    },
}

impl BrandingStore {
    pub fn memory() -> Self {
        Self {
            backend: Backend::Memory(Arc::default()),
        }
    }

    #[cfg(feature = "aws")]
    pub fn dynamo(db: aws_sdk_dynamodb::Client, table: String) -> Self {
        Self {
            backend: Backend::Dynamo { db, table },
        }
    }

    // The handler supplies only Form::SelfHosted.configured_host. A request
    // cannot select another deployment, tenant, row, or table.
    fn key(deployment_host: &str) -> String {
        format!("branding#deployment#{deployment_host}")
    }

    pub(crate) async fn get(
        &self,
        deployment_host: &str,
    ) -> Result<Option<StoredBranding>, StoreError> {
        let key = Self::key(deployment_host);
        match &self.backend {
            Backend::Memory(rows) => Ok(rows.read().await.get(&key).cloned()),
            #[cfg(feature = "aws")]
            Backend::Dynamo { db, table } => {
                use aws_sdk_dynamodb::types::AttributeValue;
                let response = db
                    .get_item()
                    .table_name(table)
                    .key("key", AttributeValue::S(key))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(|_| StoreError::Transient("branding read unavailable".into()))?;
                let Some(item) = response.item else {
                    return Ok(None);
                };
                let invalid = || StoreError::Permanent("invalid branding record".into());
                if item
                    .get("record_type")
                    .and_then(|v| v.as_s().ok())
                    .map(String::as_str)
                    != Some("branding")
                {
                    return Err(invalid());
                }
                let json = item
                    .get("record_json")
                    .and_then(|v| v.as_s().ok())
                    .ok_or_else(invalid)?;
                let record: StoredBranding = serde_json::from_str(json).map_err(|_| invalid())?;
                if item.get("revision").and_then(|v| v.as_n().ok())
                    != Some(&record.revision.to_string())
                    || item.get("schema_version").and_then(|v| v.as_n().ok())
                        != Some(&record.version.to_string())
                {
                    return Err(invalid());
                }
                Ok(Some(record))
            }
        }
    }

    pub(crate) async fn put(
        &self,
        deployment_host: &str,
        record: StoredBranding,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        if record.version != 1 || expected_revision.checked_add(1) != Some(record.revision) {
            return Ok(false);
        }
        let key = Self::key(deployment_host);
        match &self.backend {
            Backend::Memory(rows) => {
                let mut rows = rows.write().await;
                let matches = match rows.get(&key) {
                    None => expected_revision == 0,
                    Some(current) => current.version == 1 && current.revision == expected_revision,
                };
                if matches {
                    rows.insert(key, record);
                }
                Ok(matches)
            }
            #[cfg(feature = "aws")]
            Backend::Dynamo { db, table } => {
                use aws_sdk_dynamodb::types::AttributeValue;
                let json = serde_json::to_string(&record)
                    .map_err(|_| StoreError::Permanent("branding serialization failed".into()))?;
                let request = db
                    .put_item()
                    .table_name(table)
                    .item("key", AttributeValue::S(key))
                    .item("record_type", AttributeValue::S("branding".into()))
                    .item(
                        "schema_version",
                        AttributeValue::N(record.version.to_string()),
                    )
                    .item("revision", AttributeValue::N(record.revision.to_string()))
                    .item("record_json", AttributeValue::S(json));
                let request = if expected_revision == 0 {
                    request
                        .condition_expression("attribute_not_exists(#key)")
                        .expression_attribute_names("#key", "key")
                } else {
                    request
                        .condition_expression(
                            "#revision = :revision AND #version = :version AND #type = :type",
                        )
                        .expression_attribute_names("#revision", "revision")
                        .expression_attribute_names("#version", "schema_version")
                        .expression_attribute_names("#type", "record_type")
                        .expression_attribute_values(
                            ":revision",
                            AttributeValue::N(expected_revision.to_string()),
                        )
                        .expression_attribute_values(":version", AttributeValue::N("1".into()))
                        .expression_attribute_values(":type", AttributeValue::S("branding".into()))
                };
                match request.send().await {
                    Ok(_) => Ok(true),
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
                    {
                        Ok(false)
                    }
                    Err(_) => Err(StoreError::Transient("branding write unavailable".into())),
                }
            }
        }
    }
}

#[cfg(all(test, feature = "aws"))]
mod tests {
    use super::{BrandingStore, StoredBranding};
    use aws_smithy_http_client::test_util::capture_request;
    use aws_smithy_types::body::SdkBody;
    use serde_json::{json, Value};

    #[tokio::test]
    async fn a_durable_update_fences_revision_schema_and_record_kind() {
        let response = axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/x-amz-json-1.0")
            .body(SdkBody::from(
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                    "message": "another writer changed the record"
                })
                .to_string(),
            ))
            .unwrap();
        let (http, captured) = capture_request(Some(response));
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        let stored = BrandingStore::dynamo(db, "DurableAdminTable".into())
            .put(
                "configured.example",
                StoredBranding {
                    version: 1,
                    revision: 2,
                    settings: json!({"name": null, "logo": "none", "primary": "blue"}),
                },
                1,
            )
            .await
            .unwrap();
        assert!(!stored, "a conditional write rejection is a conflict");
        let captured = captured.expect_request();
        let body: Value = serde_json::from_slice(captured.body().bytes().unwrap()).unwrap();
        assert_eq!(body["TableName"], "DurableAdminTable");
        assert_eq!(
            body["Item"]["key"]["S"],
            "branding#deployment#configured.example"
        );
        assert_eq!(body["Item"]["record_type"]["S"], "branding");
        assert_eq!(body["Item"]["revision"]["N"], "2");
        assert_eq!(body["Item"]["schema_version"]["N"], "1");
        assert_eq!(
            body["ConditionExpression"],
            "#revision = :revision AND #version = :version AND #type = :type"
        );
        assert_eq!(
            body["ExpressionAttributeNames"],
            json!({
                "#revision": "revision", "#version": "schema_version", "#type": "record_type"
            })
        );
        assert_eq!(
            body["ExpressionAttributeValues"],
            json!({
                ":revision": {"N": "1"}, ":version": {"N": "1"}, ":type": {"S": "branding"}
            })
        );
    }
}
