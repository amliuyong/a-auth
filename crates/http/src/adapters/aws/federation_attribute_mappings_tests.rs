use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::{json, Value};

use super::{DynamoFederationAttributeMappingsStore, DynamoFederationConfigStore};
use crate::federation_attributes::{
    FederationAttributeMappingsStore, MappingChange, MappingChangeOutcome, MappingMode,
    MappingRegistry, MappingSpec,
};

#[derive(Clone, Default)]
struct FakeDynamo {
    items: Arc<Mutex<FakeItems>>,
    transactions: Arc<Mutex<Vec<Value>>>,
    fail_transactions_after_apply: Arc<AtomicBool>,
    corrupt_marker_after_apply: Arc<AtomicBool>,
}

type FakeItems = BTreeMap<(String, String, String), Value>;

fn item_key(table: &str, item: &Value) -> (String, String, String) {
    (
        table.to_string(),
        item["tenant_id"]["S"].as_str().unwrap().to_string(),
        item.get("lookup_key")
            .or_else(|| item.get("upstream_idp_id"))
            .and_then(|value| value["S"].as_str())
            .unwrap()
            .to_string(),
    )
}

async fn dynamo(
    State(fake): State<FakeDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let request: Value = serde_json::from_slice(&body).unwrap();
    if target.ends_with(".GetItem") {
        let key = item_key(request["TableName"].as_str().unwrap(), &request["Key"]);
        let response = fake
            .items
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .map(|item| json!({"Item": item}))
            .unwrap_or_else(|| json!({}));
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            response.to_string(),
        );
    }
    if target.ends_with(".Query") {
        let table = request["TableName"].as_str().unwrap();
        let tenant = request["ExpressionAttributeValues"][":tenant"]["S"]
            .as_str()
            .unwrap();
        let items = fake
            .items
            .lock()
            .unwrap()
            .iter()
            .filter(|((item_table, item_tenant, _), _)| {
                item_table == table && item_tenant == tenant
            })
            .map(|(_, item)| item.clone())
            .collect::<Vec<_>>();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({
                "Items": items,
                "Count": items.len(),
                "ScannedCount": items.len()
            })
            .to_string(),
        );
    }
    if target.ends_with(".DeleteItem") {
        let key = item_key(request["TableName"].as_str().unwrap(), &request["Key"]);
        fake.items.lock().unwrap().remove(&key);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}".to_string(),
        );
    }
    if target.ends_with(".TransactWriteItems") {
        fake.transactions.lock().unwrap().push(request.clone());
        let mut items = fake.items.lock().unwrap();
        for transaction in request["TransactItems"].as_array().unwrap() {
            if let Some(put) = transaction.get("Put") {
                let table = put["TableName"].as_str().unwrap();
                let item = put["Item"].clone();
                items.insert(item_key(table, &item), item);
            }
            if let Some(delete) = transaction.get("Delete") {
                let table = delete["TableName"].as_str().unwrap();
                items.remove(&item_key(table, &delete["Key"]));
            }
        }
        if fake.corrupt_marker_after_apply.load(Ordering::Relaxed) {
            for item in items.values_mut() {
                if item["row_type"]["S"].as_str() == Some("marker") {
                    item["upstream_idp_id"] = json!({"S": "other-idp"});
                }
            }
        }
        drop(items);
        if fake.fail_transactions_after_apply.load(Ordering::Relaxed) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
                json!({
                    "__type": "InternalServerError",
                    "message": "response lost after commit"
                })
                .to_string(),
            );
        }
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            "{}".to_string(),
        );
    }
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        json!({"message": format!("unexpected target {target}")}).to_string(),
    )
}

fn test_client(address: std::net::SocketAddr) -> aws_sdk_dynamodb::Client {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .endpoint_url(format!("http://{address}"))
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1))
        .build();
    aws_sdk_dynamodb::Client::from_conf(config)
}

async fn serve(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, server)
}

fn copy_spec(target_key: &str) -> MappingSpec {
    MappingSpec {
        source_claim: "department".to_string(),
        target_namespace: "https://resources.example.com/finance".to_string(),
        target_key: target_key.to_string(),
        mode: MappingMode::CopyString,
    }
}

fn federation_config() -> agent_auth_authn::federation::FederationConfig {
    agent_auth_authn::federation::FederationConfig {
        tenant_id: "tenant-a".to_string(),
        upstream_idp_id: "okta".to_string(),
        protocol: agent_auth_authn::federation::UpstreamProtocol::Saml,
        upstream_issuer: "https://okta.example.com".to_string(),
        strong_acr_values: vec![],
        oidc: None,
    }
}

#[tokio::test]
async fn dynamo_mapping_store_preserves_registry_target_and_permanent_marker_invariants() {
    let fake = FakeDynamo::default();
    let (address, server) = serve(
        Router::new()
            .route("/", post(dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let store = DynamoFederationAttributeMappingsStore::new(test_client(address), "mappings-table");

    let created = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Create {
                mapping_id: "fm_dynamo".to_string(),
                expected_registry_revision: 0,
                spec: copy_spec("department"),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        created,
        MappingChangeOutcome::Applied(ref registry) if registry.revision == 1
    ));
    assert_eq!(
        store
            .get_registry("tenant-a", "okta")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );

    let updated = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Update {
                mapping_id: "fm_dynamo".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: true,
                spec: copy_spec("cost_center"),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        updated,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 2
                && registry.mappings[0].revision == 2
                && registry.mappings[0].target_key == "cost_center"
    ));

    let deleted = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Delete {
                mapping_id: "fm_dynamo".to_string(),
                expected_registry_revision: 2,
                expected_mapping_revision: 2,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        deleted,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 3 && registry.mappings.is_empty()
    ));

    let (registry_rows, marker_rows, target_rows) = {
        let items = fake.items.lock().unwrap();
        let count = |row_type: &str| {
            items
                .values()
                .filter(|item| item["row_type"]["S"].as_str() == Some(row_type))
                .count()
        };
        (count("registry"), count("marker"), count("target"))
    };
    assert_eq!(registry_rows, 1);
    assert_eq!(marker_rows, 1);
    assert_eq!(target_rows, 0);

    let registry = store
        .get_registry("tenant-a", "okta")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(registry.revision, 3);
    assert!(registry.mappings.is_empty());
    assert_eq!(fake.transactions.lock().unwrap().len(), 3);
    server.abort();
}

#[tokio::test]
async fn dynamo_mapping_crud_recovers_ambiguous_commits_from_exact_authority_state() {
    let fake = FakeDynamo::default();
    fake.fail_transactions_after_apply
        .store(true, Ordering::Relaxed);
    let (address, server) = serve(
        Router::new()
            .route("/", post(dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let store = DynamoFederationAttributeMappingsStore::new(test_client(address), "mappings-table");

    let created = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Create {
                mapping_id: "fm_ambiguous".to_string(),
                expected_registry_revision: 0,
                spec: copy_spec("department"),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        created,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 1 && registry.mappings[0].revision == 1
    ));

    let updated = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Update {
                mapping_id: "fm_ambiguous".to_string(),
                expected_registry_revision: 1,
                expected_mapping_revision: 1,
                enabled: true,
                spec: copy_spec("cost_center"),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        updated,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 2
                && registry.mappings[0].revision == 2
                && registry.mappings[0].target_key == "cost_center"
    ));

    let deleted = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Delete {
                mapping_id: "fm_ambiguous".to_string(),
                expected_registry_revision: 2,
                expected_mapping_revision: 2,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        deleted,
        MappingChangeOutcome::Applied(ref registry)
            if registry.revision == 3 && registry.mappings.is_empty()
    ));
    assert_eq!(
        fake.transactions.lock().unwrap().len(),
        6,
        "each ambiguous transaction is replayed once with the same SDK token"
    );
    server.abort();
}

#[tokio::test]
async fn dynamo_mapping_create_never_recovers_from_a_mismatched_permanent_marker() {
    let fake = FakeDynamo::default();
    fake.fail_transactions_after_apply
        .store(true, Ordering::Relaxed);
    fake.corrupt_marker_after_apply
        .store(true, Ordering::Relaxed);
    let (address, server) = serve(
        Router::new()
            .route("/", post(dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let store = DynamoFederationAttributeMappingsStore::new(test_client(address), "mappings-table");

    let error = store
        .change(
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Create {
                mapping_id: "fm_corrupt_marker".to_string(),
                expected_registry_revision: 0,
                spec: copy_spec("department"),
            },
        )
        .await
        .expect_err("a mismatched permanent marker cannot prove an ambiguous commit");
    assert!(matches!(error, crate::ports::StoreError::Transient(_)));
    server.abort();
}

#[tokio::test]
async fn mapping_and_idp_mutations_fence_each_other_in_single_transactions() {
    let fake = FakeDynamo::default();
    let (address, server) = serve(
        Router::new()
            .route("/", post(dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let client = test_client(address);
    let mappings = DynamoFederationAttributeMappingsStore::new(client.clone(), "mappings-table");
    let configs = DynamoFederationConfigStore::new(client, "configs-table");
    let config = federation_config();

    let config_condition = configs.snapshot_condition(&config).unwrap();
    let created = mappings
        .change_authorized(
            config_condition,
            "tenant-a",
            "okta",
            "https://okta.example.com",
            MappingChange::Create {
                mapping_id: "fm_atomic".to_string(),
                expected_registry_revision: 0,
                spec: copy_spec("department"),
            },
        )
        .await
        .unwrap();
    assert!(matches!(created, MappingChangeOutcome::Applied(_)));
    let mapping_transaction = fake.transactions.lock().unwrap()[0].clone();
    assert_eq!(
        mapping_transaction["TransactItems"][0]["ConditionCheck"]["TableName"],
        "configs-table"
    );

    let empty_registry = MappingRegistry {
        tenant_id: "tenant-a".to_string(),
        upstream_idp_id: "okta".to_string(),
        upstream_issuer: "https://okta.example.com".to_string(),
        revision: 2,
        mappings: vec![],
    };
    let mapping_condition = mappings
        .reconciliation_authority_condition("tenant-a", "okta", Some(&empty_registry))
        .unwrap();
    assert!(configs
        .put_authorized(mapping_condition, None, config.clone())
        .await
        .unwrap());
    let config_transaction = fake.transactions.lock().unwrap()[1].clone();
    assert_eq!(
        config_transaction["TransactItems"][0]["ConditionCheck"]["TableName"],
        "mappings-table"
    );
    assert_eq!(
        config_transaction["TransactItems"][1]["Put"]["TableName"],
        "configs-table"
    );

    let mapping_condition = mappings
        .reconciliation_authority_condition("tenant-a", "okta", Some(&empty_registry))
        .unwrap();
    assert!(configs
        .delete_authorized(mapping_condition, &config)
        .await
        .unwrap());
    let delete_transaction = fake.transactions.lock().unwrap()[2].clone();
    assert_eq!(
        delete_transaction["TransactItems"][0]["ConditionCheck"]["TableName"],
        "mappings-table"
    );
    assert_eq!(
        delete_transaction["TransactItems"][1]["Delete"]["TableName"],
        "configs-table"
    );
    server.abort();
}

#[tokio::test]
async fn dynamo_mapping_governance_lists_counts_and_deletes_every_tenant_row() {
    let fake = FakeDynamo::default();
    let (address, server) = serve(
        Router::new()
            .route("/", post(dynamo))
            .with_state(fake.clone()),
    )
    .await;
    let store = DynamoFederationAttributeMappingsStore::new(test_client(address), "mappings-table");
    assert!(matches!(
        store
            .change(
                "tenant-a",
                "okta",
                "https://okta.example.com",
                MappingChange::Create {
                    mapping_id: "fm_governance".to_string(),
                    expected_registry_revision: 0,
                    spec: copy_spec("department"),
                },
            )
            .await
            .unwrap(),
        MappingChangeOutcome::Applied(_)
    ));
    assert_eq!(
        store
            .governance_count_all_by_tenant("tenant-a")
            .await
            .unwrap(),
        3
    );
    let registries = store.list_by_tenant("tenant-a").await.unwrap();
    assert_eq!(registries.len(), 1);
    assert_eq!(registries[0].upstream_idp_id, "okta");
    assert_eq!(store.delete_all_by_tenant("tenant-a").await.unwrap(), 3);
    assert_eq!(
        store
            .governance_count_all_by_tenant("tenant-a")
            .await
            .unwrap(),
        0
    );
    server.abort();
}

#[test]
fn reconciliation_registry_condition_fences_the_exact_mapping_snapshot() {
    let store = DynamoFederationAttributeMappingsStore::new(
        aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
                .build(),
        ),
        "mappings-table",
    );
    let registry = MappingRegistry {
        tenant_id: "tenant-a".to_string(),
        upstream_idp_id: "okta".to_string(),
        upstream_issuer: "https://okta.example.com".to_string(),
        revision: 4,
        mappings: vec![],
    };
    let item = store
        .reconciliation_authority_condition("tenant-a", "okta", Some(&registry))
        .unwrap();
    let condition = item.condition_check().unwrap();
    assert_eq!(condition.table_name(), "mappings-table");
    let expression = condition.condition_expression();
    assert!(expression.contains("upstream_idp_id = :idp"));
    assert!(expression.contains("upstream_issuer = :issuer"));
    assert!(expression.contains("revision = :revision"));
    assert!(expression.contains("payload = :payload"));
    let values = condition.expression_attribute_values().unwrap();
    assert_eq!(
        values.get(":revision"),
        Some(&aws_sdk_dynamodb::types::AttributeValue::N("4".into()))
    );
    assert_eq!(
        values.get(":payload"),
        Some(&aws_sdk_dynamodb::types::AttributeValue::S(
            serde_json::to_string(&registry).unwrap()
        ))
    );
}
