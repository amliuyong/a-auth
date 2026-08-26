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

use super::{
    AuthorizedFederatedReconciliation, DynamoAttributeNamespaceStore,
    DynamoFederationAttributeMappingsStore, DynamoUsersStore,
};
use crate::{
    attribute_namespace::AttributeWriteAuthority,
    federation_attributes::{
        plan_federated_attribute_owner_purge, DesiredFederatedAttribute,
        DesiredFederatedAttributes, FederationAttributeOwnerPurgeOutcome,
        FederationAttributeReconciliationOutcome, MappingRegistry,
    },
    ports::{FederatedAttributeOwner, NamespaceAttrs, UserRecord, UserStatus},
};

#[derive(Clone)]
struct FakeDynamo {
    user: Arc<Mutex<Value>>,
    transactions: Arc<Mutex<Vec<Value>>>,
    fail_transactions_after_apply: bool,
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
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
            json!({"Item": fake.user.lock().unwrap().clone()}).to_string(),
        );
    }
    if target.ends_with(".TransactWriteItems") {
        fake.transactions.lock().unwrap().push(request.clone());
        if fake.fail_transactions_after_apply {
            let update = request["TransactItems"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .get("Update")
                .unwrap();
            let values = &update["ExpressionAttributeValues"];
            let mut user = fake.user.lock().unwrap();
            user["attributes"] = values[":next_attributes"].clone();
            user["attributes_generation"] = values[":next_generation"].clone();
            user["federation_reconciliation_id"] = values[":reconciliation_id"].clone();
            user["federation_reconciliation_fingerprint"] =
                values[":reconciliation_fingerprint"].clone();
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

#[tokio::test]
async fn reconciliation_sends_mapping_namespace_and_user_fences_in_one_transaction() {
    let fake = FakeDynamo {
        user: Arc::new(Mutex::new(json!({
            "user_id": {"S": "tenant-a\u{001f}user-1"},
            "created_at": {"N": "1"},
            "attributes_generation": {"N": "0"}
        }))),
        transactions: Arc::new(Mutex::new(vec![])),
        fail_transactions_after_apply: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn({
        let fake = fake.clone();
        async move {
            axum::serve(
                listener,
                Router::new().route("/", post(dynamo)).with_state(fake),
            )
            .await
            .unwrap();
        }
    });
    let client = test_client(address);
    let users = DynamoUsersStore::new(client.clone(), "users-table");
    let mappings = DynamoFederationAttributeMappingsStore::new(client.clone(), "mappings-table");
    let namespaces = DynamoAttributeNamespaceStore::new(client, "namespaces-table");
    let registry = MappingRegistry {
        tenant_id: "tenant-a".into(),
        upstream_idp_id: "okta".into(),
        upstream_issuer: "https://idp.example.com".into(),
        revision: 3,
        mappings: vec![],
    };
    let conditions = vec![
        mappings
            .reconciliation_authority_condition("tenant-a", "okta", Some(&registry))
            .unwrap(),
        namespaces
            .write_authority_condition(
                "tenant-a",
                &AttributeWriteAuthority::ActiveCanonical {
                    canonical_namespace: "https://resource.example.com".into(),
                    registration_revision: 7,
                },
            )
            .unwrap(),
    ];
    let desired = DesiredFederatedAttributes::from([(
        (
            "https://resource.example.com".to_string(),
            "role".to_string(),
        ),
        DesiredFederatedAttribute {
            namespace: "https://resource.example.com".into(),
            key: "role".into(),
            value: "admin".into(),
            owner: FederatedAttributeOwner {
                upstream_idp_id: "okta".into(),
                upstream_issuer: "https://idp.example.com".into(),
                mapping_id: "fm_role".into(),
                mapping_revision: 2,
            },
        },
    )]);

    let outcome = users
        .reconcile_federated_attributes_authorized(AuthorizedFederatedReconciliation {
            tenant: "tenant-a",
            user_id: "user-1",
            upstream_idp_id: "okta",
            desired: &desired,
            registry_revision: registry.revision,
            operation_id: "flow-1",
            fingerprint: "fingerprint-1",
            authority_conditions: conditions,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        outcome,
        FederationAttributeReconciliationOutcome::Applied { changed: true, .. }
    ));

    let transactions = fake.transactions.lock().unwrap();
    assert_eq!(transactions.len(), 1);
    let items = transactions[0]["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(
        items[0]["ConditionCheck"]["TableName"],
        Value::String("mappings-table".into())
    );
    assert_eq!(
        items[1]["ConditionCheck"]["TableName"],
        Value::String("namespaces-table".into())
    );
    assert_eq!(
        items[2]["Update"]["TableName"],
        Value::String("users-table".into())
    );
    server.abort();
}

#[tokio::test]
async fn stale_purge_sends_mapping_and_user_fences_in_one_transaction() {
    let fake = FakeDynamo {
        user: Arc::new(Mutex::new(json!({
            "user_id": {"S": "tenant-a\u{001f}user-1"},
            "created_at": {"N": "1"},
            "attributes_generation": {"N": "3"}
        }))),
        transactions: Arc::new(Mutex::new(vec![])),
        fail_transactions_after_apply: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn({
        let fake = fake.clone();
        async move {
            axum::serve(
                listener,
                Router::new().route("/", post(dynamo)).with_state(fake),
            )
            .await
            .unwrap();
        }
    });
    let client = test_client(address);
    let users = DynamoUsersStore::new(client.clone(), "users-table");
    let mappings = DynamoFederationAttributeMappingsStore::new(client, "mappings-table");
    let registry = MappingRegistry {
        tenant_id: "tenant-a".into(),
        upstream_idp_id: "okta".into(),
        upstream_issuer: "https://idp.example.com".into(),
        revision: 4,
        mappings: vec![],
    };
    let owner = FederatedAttributeOwner {
        upstream_idp_id: "okta".into(),
        upstream_issuer: "https://idp.example.com".into(),
        mapping_id: "fm_role".into(),
        mapping_revision: 2,
    };
    let current = UserRecord {
        user_id: "user-1".into(),
        email: "user@example.com".into(),
        created_at: 1,
        updated_at: 1,
        last_login_at: None,
        status: UserStatus::Active,
        credential_epoch: 0,
        revocation_pending: false,
        scim_external_id: None,
        scim_user_name: None,
        scim_display_name: None,
        attributes_generation: 3,
        attributes: std::collections::BTreeMap::from([(
            "https://resource.example.com".into(),
            NamespaceAttrs {
                revision: 4,
                kv: std::collections::BTreeMap::from([("role".into(), "admin".into())]),
                federation_owners: std::collections::BTreeMap::from([(
                    "role".into(),
                    owner.clone(),
                )]),
            },
        )]),
    };
    let FederationAttributeOwnerPurgeOutcome::Purged { user: next, .. } =
        plan_federated_attribute_owner_purge(
            &current,
            "https://resource.example.com",
            "role",
            4,
            &owner,
        )
        .unwrap()
    else {
        panic!("stale owner must produce a purge plan");
    };
    let authority_condition = mappings
        .reconciliation_authority_condition("tenant-a", "okta", Some(&registry))
        .unwrap();

    assert!(users
        .purge_federated_attribute_owner_authorized(
            "tenant-a",
            &current,
            &next,
            authority_condition,
        )
        .await
        .unwrap());

    let transactions = fake.transactions.lock().unwrap();
    assert_eq!(transactions.len(), 1);
    let items = transactions[0]["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]["ConditionCheck"]["TableName"],
        Value::String("mappings-table".into())
    );
    assert_eq!(
        items[1]["Update"]["TableName"],
        Value::String("users-table".into())
    );
    assert!(items[0]["ConditionCheck"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("payload = :payload"));
    let user_condition = items[1]["Update"]["ConditionExpression"].as_str().unwrap();
    assert!(user_condition.contains("#generation = :expected_generation"));
    assert!(user_condition.contains("#attrs = :expected_attributes"));
    server.abort();
}

#[tokio::test]
async fn reconciliation_recovers_an_ambiguous_commit_from_the_user_marker() {
    let fake = FakeDynamo {
        user: Arc::new(Mutex::new(json!({
            "user_id": {"S": "tenant-a\u{001f}user-1"},
            "created_at": {"N": "1"},
            "attributes_generation": {"N": "0"}
        }))),
        transactions: Arc::new(Mutex::new(vec![])),
        fail_transactions_after_apply: true,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn({
        let fake = fake.clone();
        async move {
            axum::serve(
                listener,
                Router::new().route("/", post(dynamo)).with_state(fake),
            )
            .await
            .unwrap();
        }
    });
    let users = DynamoUsersStore::new(test_client(address), "users-table");
    let desired = DesiredFederatedAttributes::from([(
        (
            "https://resource.example.com".to_string(),
            "role".to_string(),
        ),
        DesiredFederatedAttribute {
            namespace: "https://resource.example.com".into(),
            key: "role".into(),
            value: "admin".into(),
            owner: FederatedAttributeOwner {
                upstream_idp_id: "okta".into(),
                upstream_issuer: "https://idp.example.com".into(),
                mapping_id: "fm_role".into(),
                mapping_revision: 2,
            },
        },
    )]);

    let outcome = users
        .reconcile_federated_attributes_authorized(AuthorizedFederatedReconciliation {
            tenant: "tenant-a",
            user_id: "user-1",
            upstream_idp_id: "okta",
            desired: &desired,
            registry_revision: 3,
            operation_id: "flow-ambiguous",
            fingerprint: "fingerprint-ambiguous",
            authority_conditions: vec![],
        })
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        outcome,
        FederationAttributeReconciliationOutcome::Applied { changed: true, .. }
    ));
    assert_eq!(
        fake.transactions.lock().unwrap().len(),
        2,
        "the SDK replay uses the same transaction before marker recovery"
    );
    server.abort();
}
