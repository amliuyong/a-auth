use std::collections::HashMap;

use aws_sdk_dynamodb::types::{AttributeValue, Get, TransactGetItem};

use crate::{
    ports::StoreError,
    region::{RegionControlRecord, RegionControlStore},
};

#[derive(Clone)]
pub struct DynamoRegionControlStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
}

impl DynamoRegionControlStore {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }
}

impl RegionControlStore for DynamoRegionControlStore {
    async fn get(&self, region_id: &str) -> Result<Option<RegionControlRecord>, StoreError> {
        let get = |key: &str| {
            TransactGetItem::builder()
                .get(
                    Get::builder()
                        .table_name(&self.table)
                        .key("region_id", AttributeValue::S(key.to_string()))
                        .build()
                        .expect("region control Get has its required fields"),
                )
                .build()
        };
        let output = self
            .db
            .transact_get_items()
            .transact_items(get("control"))
            .transact_items(get(region_id))
            .transact_items(get(&format!("fence#{region_id}")))
            .send()
            .await
            .map_err(super::ddb_err)?;
        let responses = output.responses();
        if responses.len() != 3 {
            return Err(StoreError::Permanent(
                "region control transaction returned an incomplete snapshot".to_string(),
            ));
        }
        let Some(coordinator) = responses[0].item.as_ref() else {
            return Ok(None);
        };
        let Some(region) = responses[1].item.as_ref() else {
            return Ok(None);
        };
        let Some(fence) = responses[2].item.as_ref() else {
            return Ok(None);
        };
        parse_coordinated_snapshot(region_id, coordinator, region, fence).map(Some)
    }
}

fn required_string<'a>(
    item: &'a HashMap<String, AttributeValue>,
    name: &str,
) -> Result<&'a str, StoreError> {
    item.get(name)
        .and_then(|value| value.as_s().ok())
        .map(String::as_str)
        .ok_or_else(|| StoreError::Permanent(format!("region control {name} missing or invalid")))
}

fn required_i64(item: &HashMap<String, AttributeValue>, name: &str) -> Result<i64, StoreError> {
    item.get(name)
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| StoreError::Permanent(format!("region control {name} missing or invalid")))
}

fn required_revision(
    item: &HashMap<String, AttributeValue>,
    name: &str,
) -> Result<u64, StoreError> {
    u64::try_from(required_i64(item, name)?)
        .map_err(|_| StoreError::Permanent(format!("region control {name} invalid")))
}

fn parse_coordinated_snapshot(
    region_id: &str,
    coordinator: &HashMap<String, AttributeValue>,
    region: &HashMap<String, AttributeValue>,
    fence: &HashMap<String, AttributeValue>,
) -> Result<RegionControlRecord, StoreError> {
    let parse_region = |item: &HashMap<String, AttributeValue>| {
        Ok(RegionControlRecord {
            active: item
                .get("active")
                .and_then(|value| value.as_bool().ok())
                .copied()
                .ok_or_else(|| {
                    StoreError::Permanent("region control active missing".to_string())
                })?,
            activation_not_before: required_i64(item, "activation_not_before")?,
            revision: required_revision(item, "revision")?,
        })
    };
    let record = parse_region(region)?;
    let persisted_fence = parse_region(fence)?;
    if record != persisted_fence {
        return Err(StoreError::Permanent(
            "Region row does not match its persistent revision fence".to_string(),
        ));
    }
    let coordinator_revision = required_revision(coordinator, "revision")?;
    let coordinator_state = required_string(coordinator, "state")?;
    let active_region = required_string(coordinator, "active_region")?;

    let coordinated = record.active
        && coordinator_state == "active"
        && active_region == region_id
        && coordinator_revision == record.revision;
    if record.active && !coordinated {
        return Err(StoreError::Permanent(
            "active Region row does not match the single-writer coordinator".to_string(),
        ));
    }
    Ok(RegionControlRecord {
        active: coordinated,
        activation_not_before: record.activation_not_before,
        revision: record.revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http_client::test_util::{capture_request, CaptureRequestHandler};
    use aws_smithy_types::body::SdkBody;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn dynamo_response(body: serde_json::Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .body(SdkBody::from(body.to_string()))
            .expect("Dynamo response")
    }

    fn dynamo_client(http: CaptureRequestHandler) -> aws_sdk_dynamodb::Client {
        aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .endpoint_url("https://dynamodb.us-west-2.amazonaws.com")
                .http_client(http)
                .build(),
        )
    }

    async fn regional_discovery(db: aws_sdk_dynamodb::Client) -> axum::response::Response {
        let mut state = crate::state::AppState::dev("localhost");
        state.region = crate::region::RegionRuntime::controlled(
            "us-west-2",
            crate::region::RegionControlStoreImpl::Dynamo(DynamoRegionControlStore::new(
                db,
                "region-control",
            )),
        )
        .expect("valid controlled Region");
        let (router, _) = crate::build_router(state);
        router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .header("host", "localhost")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response")
    }

    fn item(values: &[(&str, AttributeValue)]) -> HashMap<String, AttributeValue> {
        values
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect()
    }

    fn coordinator(
        active_region: &str,
        state: &str,
        revision: i64,
    ) -> HashMap<String, AttributeValue> {
        item(&[
            (
                "active_region",
                AttributeValue::S(active_region.to_string()),
            ),
            ("state", AttributeValue::S(state.to_string())),
            ("revision", AttributeValue::N(revision.to_string())),
        ])
    }

    fn region(active: bool, not_before: i64, revision: i64) -> HashMap<String, AttributeValue> {
        item(&[
            ("active", AttributeValue::Bool(active)),
            (
                "activation_not_before",
                AttributeValue::N(not_before.to_string()),
            ),
            ("revision", AttributeValue::N(revision.to_string())),
        ])
    }

    #[test]
    fn admits_only_the_coordinated_active_region_and_revision() {
        assert_eq!(
            parse_coordinated_snapshot(
                "us-west-2",
                &coordinator("us-west-2", "active", 2),
                &region(true, 1_330, 2),
                &region(true, 1_330, 2),
            )
            .unwrap(),
            RegionControlRecord {
                active: true,
                activation_not_before: 1_330,
                revision: 2,
            }
        );
    }

    #[test]
    fn rejects_split_brain_and_revision_skew() {
        for coordinator in [
            coordinator("us-east-1", "active", 2),
            coordinator("us-west-2", "quiescing", 2),
            coordinator("us-west-2", "active", 3),
        ] {
            assert!(parse_coordinated_snapshot(
                "us-west-2",
                &coordinator,
                &region(true, 1_330, 2),
                &region(true, 1_330, 2),
            )
            .is_err());
        }
    }

    #[test]
    fn inactive_region_remains_inactive_during_quiescence() {
        assert_eq!(
            parse_coordinated_snapshot(
                "us-east-1",
                &coordinator("us-west-2", "quiescing", 2),
                &region(false, 0, 2),
                &region(false, 0, 2),
            )
            .unwrap(),
            RegionControlRecord {
                active: false,
                activation_not_before: 0,
                revision: 2,
            }
        );
    }

    #[test]
    fn persistent_fence_rejects_cold_start_rollback_and_same_revision_mutation() {
        let coordinator = coordinator("us-west-2", "active", 3);
        let fence = region(true, 1_330, 3);
        for mutated in [
            region(false, 1_330, 3),
            region(true, 1_331, 3),
            region(true, 1_330, 2),
        ] {
            assert!(
                parse_coordinated_snapshot("us-west-2", &coordinator, &mutated, &fence).is_err()
            );
        }
    }

    #[tokio::test]
    async fn dynamo_region_admission_reads_coordinator_region_and_fence_and_fails_closed() {
        let mismatched_snapshot = serde_json::json!({
            "Responses": [
                {"Item": {
                    "active_region": {"S": "us-east-1"},
                    "state": {"S": "active"},
                    "revision": {"N": "7"}
                }},
                {"Item": {
                    "active": {"BOOL": true},
                    "activation_not_before": {"N": "0"},
                    "revision": {"N": "7"}
                }},
                {"Item": {
                    "active": {"BOOL": true},
                    "activation_not_before": {"N": "0"},
                    "revision": {"N": "7"}
                }}
            ]
        });
        let (http, captured) = capture_request(Some(dynamo_response(mismatched_snapshot)));
        let response = regional_discovery(dynamo_client(http)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("30")
        );
        assert!(
            response.headers().get("x-agent-auth-region").is_none(),
            "an ambiguous control snapshot must not advertise an active Region"
        );
        let response_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("response body"),
        )
        .expect("JSON response");
        assert_eq!(response_body["error"], "temporarily_unavailable");

        let request = captured.expect_request();
        let body: serde_json::Value = serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured Dynamo request body is in memory"),
        )
        .expect("captured Dynamo request is JSON");
        let items = body["TransactItems"]
            .as_array()
            .expect("TransactGetItems request");
        assert_eq!(items.len(), 3);
        let keys: Vec<&str> = items
            .iter()
            .map(|item| {
                assert_eq!(item["Get"]["TableName"], "region-control");
                item["Get"]["Key"]["region_id"]["S"]
                    .as_str()
                    .expect("string Region control key")
            })
            .collect();
        assert_eq!(keys, ["control", "us-west-2", "fence#us-west-2"]);

        let (http, _) = capture_request(Some(dynamo_response(serde_json::json!({
            "Responses": [{}, {}, {}]
        }))));
        let response = regional_discovery(dynamo_client(http)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("response body"),
        )
        .expect("JSON response");
        assert_eq!(response_body["error"], "region_inactive");
    }
}
