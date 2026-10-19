//! DynamoDB payment intent store (issue #77).
//!
//! One table keyed by `pk` holds two record types:
//!
//! - `intent#<id>`: the JSON intent plus the condition attributes `revision`,
//!   `status`, `execute_before`, `accepted` and, while an attempt is not
//!   channel-final, `unsettled`.
//! - `order#<len(payee)>:<payee>#<order>`: the intent bound to that order.
//!
//! Creation writes both records in one transaction with `attribute_not_exists`.
//! Every later write is a `PutItem` conditional on the expected revision and
//! status, plus `execute_before > :now` for acceptance. No deployment stack
//! provisions this table in this delivery.

use std::collections::HashMap;

use agent_auth_payment::{PaymentIntent, PaymentStatus};
use aws_sdk_dynamodb::{
    error::ProvideErrorMetadata,
    types::{AttributeValue, ConditionCheck, Put, TransactWriteItem},
};

use super::{ddb_err, s, send_idempotent_transaction};
use crate::payment::store::{order_key, CasGuard, CreateOutcome, PaymentStore};
use crate::ports::StoreError;
use crate::tenant::tpk;

#[derive(Clone)]
pub struct DynamoPaymentStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

fn intent_pk(tenant: &str, intent_id: &str) -> String {
    tpk(tenant, &format!("intent#{intent_id}"))
}

fn order_pk(tenant: &str, payee_id: &str, order_id: &str) -> String {
    tpk(
        tenant,
        &format!("order#{}:{payee_id}#{order_id}", payee_id.len()),
    )
}

impl DynamoPaymentStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }

    fn intent_item(
        tenant: &str,
        intent: &PaymentIntent,
    ) -> Result<HashMap<String, AttributeValue>, StoreError> {
        let json = serde_json::to_string(intent)
            .map_err(|error| StoreError::Permanent(format!("payment intent encode: {error}")))?;
        let mut item = HashMap::from([
            (
                "pk".to_string(),
                AttributeValue::S(intent_pk(tenant, &intent.intent_id)),
            ),
            (
                "record_type".to_string(),
                AttributeValue::S("intent".into()),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(tenant.to_string()),
            ),
            (
                "revision".to_string(),
                AttributeValue::N(intent.revision.to_string()),
            ),
            (
                "status".to_string(),
                AttributeValue::S(intent.status.as_str().to_string()),
            ),
            (
                "execute_before".to_string(),
                AttributeValue::N(intent.terms.execute_before.to_string()),
            ),
            (
                "accepted".to_string(),
                AttributeValue::N(u8::from(intent.attempt.is_some()).to_string()),
            ),
            (
                "updated_at".to_string(),
                AttributeValue::N(intent.updated_at.to_string()),
            ),
            ("intent_json".to_string(), AttributeValue::S(json)),
        ]);
        if intent.status.is_unsettled() {
            item.insert("unsettled".to_string(), AttributeValue::N("1".into()));
        }
        Ok(item)
    }

    fn decode(item: &HashMap<String, AttributeValue>) -> Result<PaymentIntent, StoreError> {
        let json = s(item.get("intent_json"))
            .ok_or_else(|| StoreError::Permanent("payment intent item without JSON".into()))?;
        serde_json::from_str(&json)
            .map_err(|error| StoreError::Permanent(format!("payment intent decode: {error}")))
    }

    async fn order_intent(&self, pk: &str) -> Result<Option<String>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(pk.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(output.item().and_then(|item| s(item.get("intent_id"))))
    }
}

impl PaymentStore for DynamoPaymentStore {
    async fn create(
        &self,
        tenant: &str,
        intent: &PaymentIntent,
        replaces: Option<&str>,
    ) -> Result<CreateOutcome, StoreError> {
        let (payee, order) = order_key(intent);
        let order_pk = order_pk(tenant, &payee, &order);
        let intent_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::intent_item(tenant, intent)?))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|error| StoreError::Permanent(format!("build intent put: {error}")))?;
        let order_item = HashMap::from([
            ("pk".to_string(), AttributeValue::S(order_pk.clone())),
            ("record_type".to_string(), AttributeValue::S("order".into())),
            (
                "tenant_id".to_string(),
                AttributeValue::S(tenant.to_string()),
            ),
            (
                "intent_id".to_string(),
                AttributeValue::S(intent.intent_id.clone()),
            ),
        ]);
        let mut order_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(order_item));
        let mut request = self
            .db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(intent_put).build());
        match replaces {
            None => {
                order_put = order_put.condition_expression("attribute_not_exists(pk)");
            }
            Some(old) => {
                order_put = order_put
                    .condition_expression("intent_id = :old")
                    .expression_attribute_values(":old", AttributeValue::S(old.to_string()));
                let closed = ConditionCheck::builder()
                    .table_name(&self.table)
                    .key("pk", AttributeValue::S(intent_pk(tenant, old)))
                    .condition_expression(
                        "accepted = :zero AND (#status = :expired OR #status = :cancelled)",
                    )
                    .expression_attribute_names("#status", "status")
                    .expression_attribute_values(":zero", AttributeValue::N("0".into()))
                    .expression_attribute_values(
                        ":expired",
                        AttributeValue::S(PaymentStatus::Expired.as_str().into()),
                    )
                    .expression_attribute_values(
                        ":cancelled",
                        AttributeValue::S(PaymentStatus::Cancelled.as_str().into()),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!("build closed intent check: {error}"))
                    })?;
                request = request
                    .transact_items(TransactWriteItem::builder().condition_check(closed).build());
            }
        }
        let order_put = order_put
            .build()
            .map_err(|error| StoreError::Permanent(format!("build order put: {error}")))?;
        request = request.transact_items(TransactWriteItem::builder().put(order_put).build());
        if send_idempotent_transaction(request).await? {
            return Ok(CreateOutcome::Created);
        }
        match self.order_intent(&order_pk).await? {
            Some(existing) => Ok(CreateOutcome::OrderTaken(existing)),
            None => Err(StoreError::Transient(
                "payment order binding changed during creation".into(),
            )),
        }
    }

    async fn get(
        &self,
        tenant: &str,
        intent_id: &str,
    ) -> Result<Option<PaymentIntent>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(intent_pk(tenant, intent_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        output.item().map(Self::decode).transpose()
    }

    async fn compare_and_set(
        &self,
        tenant: &str,
        guard: CasGuard,
        next: &PaymentIntent,
    ) -> Result<bool, StoreError> {
        let mut condition = "revision = :revision AND #status = :status".to_string();
        let mut request = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(Self::intent_item(tenant, next)?))
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(
                ":revision",
                AttributeValue::N(guard.expected_revision.to_string()),
            )
            .expression_attribute_values(
                ":status",
                AttributeValue::S(guard.expected_status.as_str().to_string()),
            );
        if let Some(now) = guard.accept_at {
            condition.push_str(" AND execute_before > :now");
            request =
                request.expression_attribute_values(":now", AttributeValue::N(now.to_string()));
        }
        match request.condition_expression(condition).send().await {
            Ok(_) => Ok(true),
            Err(error) if error.code() == Some("ConditionalCheckFailedException") => Ok(false),
            Err(error) => Err(ddb_err(error)),
        }
    }

    async fn list_unsettled(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<PaymentIntent>, StoreError> {
        let mut intents = Vec::new();
        let mut start: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let output = self
                .db
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .filter_expression(
                    "record_type = :intent AND tenant_id = :tenant AND unsettled = :one",
                )
                .expression_attribute_values(":intent", AttributeValue::S("intent".into()))
                .expression_attribute_values(":tenant", AttributeValue::S(tenant.to_string()))
                .expression_attribute_values(":one", AttributeValue::N("1".into()))
                .set_exclusive_start_key(start.clone())
                .send()
                .await
                .map_err(ddb_err)?;
            for item in output.items() {
                intents.push(Self::decode(item)?);
            }
            match output.last_evaluated_key() {
                Some(key) if !key.is_empty() && intents.len() < limit => start = Some(key.clone()),
                _ => break,
            }
        }
        intents.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
        intents.truncate(limit);
        Ok(intents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    fn client(events: Vec<ReplayEvent>) -> (aws_sdk_dynamodb::Client, StaticReplayClient) {
        let http = StaticReplayClient::new(events);
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-east-1.amazonaws.com")
                .http_client(http.clone())
                .build(),
        );
        (db, http)
    }

    fn response(status: u16, body: &str) -> axum::http::Response<SdkBody> {
        let mut builder = axum::http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.0");
        if status == 400 {
            builder = builder.header("x-amzn-errortype", "ConditionalCheckFailedException");
        }
        builder
            .body(SdkBody::from(body.to_string()))
            .expect("response")
    }

    fn request() -> axum::http::Request<SdkBody> {
        axum::http::Request::builder()
            .uri("https://dynamodb.us-east-1.amazonaws.com/")
            .body(SdkBody::empty())
            .expect("placeholder request")
    }

    fn intent() -> PaymentIntent {
        PaymentIntent::prepared(
            "pi_1".into(),
            crate::payment::store::tests::terms("o-1", 2_000_000_000),
            1,
        )
    }

    #[tokio::test]
    async fn dynamo_payment_cas_maps_condition_failure_to_false_and_sends_the_deadline() {
        let condition_failed = response(
            400,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed"}"#,
        );
        let (db, http) = client(vec![ReplayEvent::new(request(), condition_failed)]);
        let store = DynamoPaymentStore::new(db, "payments");
        let prepared = intent();
        let accepted = prepared
            .accept(
                agent_auth_payment::derive_attempt_keys(b"s", "default", "pi_1"),
                crate::payment::store::tests::evidence(),
                60,
                10,
            )
            .unwrap();
        assert_eq!(
            store
                .compare_and_set("acme", CasGuard::accepting(&prepared, 10), &accepted)
                .await,
            Ok(false)
        );
        let sent = http.actual_requests().next().expect("one request");
        let body: serde_json::Value =
            serde_json::from_slice(sent.body().bytes().expect("buffered body")).unwrap();
        assert_eq!(
            body["ConditionExpression"],
            "revision = :revision AND #status = :status AND execute_before > :now"
        );
        assert_eq!(body["ExpressionAttributeValues"][":now"]["N"], "10");
        assert_eq!(
            body["ExpressionAttributeValues"][":status"]["S"],
            "PREPARED"
        );
        assert_eq!(body["Item"]["status"]["S"], "ACCEPTED");
        assert_eq!(body["Item"]["unsettled"]["N"], "1");
        assert_eq!(body["Item"]["accepted"]["N"], "1");
        assert_eq!(body["Item"]["pk"]["S"], "acme\u{1f}intent#pi_1");
        assert!(
            !body.to_string().contains("eyJ"),
            "no token material is persisted"
        );
    }

    #[tokio::test]
    async fn dynamo_payment_create_binds_the_order_key_in_the_same_transaction() {
        let (db, http) = client(vec![ReplayEvent::new(request(), response(200, "{}"))]);
        let store = DynamoPaymentStore::new(db, "payments");
        assert_eq!(
            store.create("", &intent(), None).await,
            Ok(CreateOutcome::Created)
        );
        let sent = http.actual_requests().next().expect("one request");
        let body: serde_json::Value =
            serde_json::from_slice(sent.body().bytes().expect("buffered body")).unwrap();
        let items = body["TransactItems"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0]["Put"]["ConditionExpression"],
            "attribute_not_exists(pk)"
        );
        assert_eq!(items[0]["Put"]["Item"]["pk"]["S"], "intent#pi_1");
        assert_eq!(
            items[1]["Put"]["Item"]["pk"]["S"],
            "order#14:merchant_books#o-1"
        );
        assert_eq!(
            items[1]["Put"]["ConditionExpression"],
            "attribute_not_exists(pk)"
        );
    }
}
