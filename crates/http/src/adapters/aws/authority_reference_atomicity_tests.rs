use super::{DynamoClientStore, DynamoCodeStore, DynamoGrantStore, DynamoRefreshStore};
use crate::ports::{
    ClientStore, CodeRecord, CodeStore, GrantStore, RefreshFamilyRecord, RefreshStore,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct FakeDynamo {
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    scan_items: Arc<Vec<Value>>,
    get_item: Arc<Option<Value>>,
}

async fn dynamo(
    State(fake): State<FakeDynamo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
    fake.requests
        .lock()
        .expect("request lock")
        .push((target, request));
    let target = fake
        .requests
        .lock()
        .expect("request lock")
        .last()
        .map(|(target, _)| target.clone())
        .unwrap_or_default();
    let response = if target.ends_with(".Scan") {
        serde_json::json!({
            "Items": fake.scan_items.as_ref(),
            "Count": fake.scan_items.len(),
            "ScannedCount": fake.scan_items.len()
        })
        .to_string()
    } else if target.ends_with(".GetItem") {
        fake.get_item
            .as_ref()
            .as_ref()
            .map(|item| serde_json::json!({"Item": item}).to_string())
            .unwrap_or_else(|| "{}".to_string())
    } else {
        "{}".to_string()
    };
    (
        StatusCode::OK,
        [("content-type", "application/x-amz-json-1.0")],
        response,
    )
        .into_response()
}

async fn fake_client() -> (
    aws_sdk_dynamodb::Client,
    FakeDynamo,
    tokio::task::JoinHandle<()>,
) {
    fake_client_with_responses(Vec::new(), None).await
}

async fn fake_client_with_scan(
    scan_items: Vec<Value>,
) -> (
    aws_sdk_dynamodb::Client,
    FakeDynamo,
    tokio::task::JoinHandle<()>,
) {
    fake_client_with_responses(scan_items, None).await
}

async fn fake_client_with_responses(
    scan_items: Vec<Value>,
    get_item: Option<Value>,
) -> (
    aws_sdk_dynamodb::Client,
    FakeDynamo,
    tokio::task::JoinHandle<()>,
) {
    let fake = FakeDynamo {
        requests: Arc::new(Mutex::new(Vec::new())),
        scan_items: Arc::new(scan_items),
        get_item: Arc::new(get_item),
    };
    let app = Router::new()
        .route("/", post(dynamo))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .endpoint_url(format!("http://{address}"))
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1))
        .build();
    (aws_sdk_dynamodb::Client::from_conf(config), fake, server)
}

fn code_record() -> CodeRecord {
    CodeRecord {
        code: "code-1".to_string(),
        client_id: "client-1".to_string(),
        cimd_snapshot: None,
        redirect_uri: "https://client.example/callback".to_string(),
        code_challenge: "challenge".to_string(),
        resources: vec!["https://api.example".to_string()],
        user_id: "user-1".to_string(),
        scope: vec!["openid".to_string()],
        expires_at: 1_700_000_100,
        authz_session_id: None,
        nonce: None,
        auth_time: 1_700_000_000,
        authorization_details: Vec::new(),
        acr: None,
        amr: Vec::new(),
        credential_epoch: Some(1),
        password_credential_version: None,
    }
}

fn refresh_record() -> RefreshFamilyRecord {
    RefreshFamilyRecord {
        family_id: "family-1".to_string(),
        current_version: 0,
        revoked: false,
        client_id: "client-1".to_string(),
        cimd_snapshot: None,
        user_id: "user-1".to_string(),
        credential_epoch: 1,
        resources: vec!["https://api.example".to_string()],
        scope: vec!["openid".to_string()],
        actor_allowlist: Vec::new(),
        max_act_chain: 1,
        dpop_jkt: None,
        pkce_code_challenge: None,
        auth_time: Some(1_700_000_000),
        acr: None,
        password_credential_version: None,
    }
}

fn grant_record() -> agent_auth_grant::Grant {
    agent_auth_grant::Grant {
        grant_id: "grant-1".to_string(),
        user_id: "user-1".to_string(),
        client_id: "client-1".to_string(),
        per_resource: Vec::new(),
        effective_per_resource: Vec::new(),
        effective_pv: 0,
        allowed_ip_cidrs: Vec::new(),
        allowed_vpce: Vec::new(),
        credential_epoch: 1,
        revision: 0,
        constraints: agent_auth_grant::GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: Vec::new(),
            expires_at: 1_700_000_100,
        },
        status: agent_auth_grant::GrantStatus::Active,
    }
}

#[tokio::test]
async fn code_creation_writes_source_and_reference_in_one_transaction() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoCodeStore::new(
        db,
        "codes-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    store.put("t1", code_record()).await.unwrap();
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(".TransactWriteItems"));
    let items = requests[0].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["Put"]["TableName"], "codes-table");
    assert_eq!(
        items[0]["Put"]["ConditionExpression"],
        "attribute_not_exists(code)"
    );
    assert_eq!(items[0]["Put"]["Item"]["code"]["S"], "t1\u{1f}code-1");
    assert_eq!(items[1]["Put"]["TableName"], "refs-table");
    assert_eq!(
        items[1]["Put"]["Item"]["client_key"]["S"],
        "client#00000002t100000008client-1"
    );
    assert!(items[1]["Put"]["Item"]["reference_key"]["S"]
        .as_str()
        .unwrap()
        .starts_with("c#00000000001700000100#"));
    assert_eq!(items[2]["Update"]["TableName"], "clients-table");
    assert_eq!(
        items[2]["Update"]["Key"]["client_id"]["S"],
        "t1\u{1f}client-1"
    );
    assert!(items[2]["Update"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("attribute_not_exists(tombstoned_at)"));
    assert!(items[2]["Update"]["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("ADD authority_revision :one"));
}

#[tokio::test]
async fn refresh_creation_writes_source_and_reference_in_one_transaction() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoRefreshStore::new(
        db,
        "refresh-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    store.create("t2", refresh_record()).await.unwrap();
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(".TransactWriteItems"));
    let items = requests[0].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["Put"]["TableName"], "refresh-table");
    assert_eq!(
        items[0]["Put"]["ConditionExpression"],
        "attribute_not_exists(family_id)"
    );
    assert_eq!(
        items[0]["Put"]["Item"]["family_id"]["S"],
        "t2\u{1f}family-1"
    );
    assert_eq!(items[1]["Put"]["TableName"], "refs-table");
    assert_eq!(
        items[1]["Put"]["Item"]["client_key"]["S"],
        "client#00000002t200000008client-1"
    );
    assert!(items[1]["Put"]["Item"]["reference_key"]["S"]
        .as_str()
        .unwrap()
        .starts_with("r#"));
    assert_eq!(items[2]["Update"]["TableName"], "clients-table");
    assert_eq!(
        items[2]["Update"]["Key"]["client_id"]["S"],
        "t2\u{1f}client-1"
    );
    assert!(items[2]["Update"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("attribute_not_exists(tombstoned_at)"));
    assert!(items[2]["Update"]["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("ADD authority_revision :one"));
}

#[tokio::test]
async fn grant_creation_is_fenced_by_the_active_client_in_one_transaction() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoGrantStore::new(db, "grants-table", "clients-table");
    assert!(store
        .put_for_active_client("t1", grant_record())
        .await
        .unwrap());
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(".TransactWriteItems"));
    let items = requests[0].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["Update"]["TableName"], "clients-table");
    assert_eq!(
        items[0]["Update"]["Key"]["client_id"]["S"],
        "t1\u{1f}client-1"
    );
    assert!(items[0]["Update"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("attribute_not_exists(tombstoned_at)"));
    assert!(items[0]["Update"]["UpdateExpression"]
        .as_str()
        .unwrap()
        .contains("ADD authority_revision :one"));
    assert_eq!(items[1]["Put"]["TableName"], "grants-table");
    assert_eq!(items[1]["Put"]["Item"]["grant_id"]["S"], "t1\u{1f}grant-1");
}

#[tokio::test]
async fn grant_client_cascade_binds_tenant_client_and_observed_blob() {
    let grant = grant_record();
    let grant_json = serde_json::to_string(&grant).unwrap();
    let (db, fake, server) = fake_client_with_scan(vec![
        serde_json::json!({
            "grant_id": {"S": "t1\u{1f}grant-1"},
            "user_id": {"S": "t1\u{1f}user-1"},
            "grant_json": {"S": grant_json},
            "gv_tenant": {"S": "t1\u{1f}gv"},
            "effective_pv": {"N": "0"},
            "revision": {"N": "0"},
            "credential_epoch": {"N": "1"}
        }),
        serde_json::json!({
            "grant_id": {"S": "t2\u{1f}grant-1"},
            "user_id": {"S": "t2\u{1f}user-1"},
            "grant_json": {"S": serde_json::to_string(&grant).unwrap()},
            "gv_tenant": {"S": "t2\u{1f}gv"},
            "effective_pv": {"N": "0"},
            "revision": {"N": "0"},
            "credential_epoch": {"N": "1"}
        }),
    ])
    .await;
    let store = DynamoGrantStore::new(db, "grants-table", "clients-table");
    assert_eq!(store.delete_by_client("t1", "client-1").await.unwrap(), 1);
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].0.ends_with(".Scan"));
    assert_eq!(requests[0].1["ConsistentRead"], true);
    assert!(requests[1].0.ends_with(".DeleteItem"));
    assert_eq!(requests[1].1["Key"]["grant_id"]["S"], "t1\u{1f}grant-1");
    assert_eq!(
        requests[1].1["ConditionExpression"],
        "attribute_exists(grant_id) AND grant_json = :grant_json AND user_id = :user_id"
    );
}

#[tokio::test]
async fn client_metadata_writes_cannot_replace_a_tombstone() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoClientStore::new(db, "clients-table");
    assert!(store
        .put_if_credential_versions(
            "t1",
            crate::ports::ClientRecord {
                client_id: "client-1".to_string(),
                ..Default::default()
            },
            0,
            0,
        )
        .await
        .unwrap());
    assert!(store
        .replace_credential_set(
            "t1",
            "client-1",
            crate::credential::CredentialKind::ClientSecret,
            0,
            crate::credential::CredentialSet {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap());
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for (_, request) in requests.iter() {
        assert!(request["ConditionExpression"]
            .as_str()
            .unwrap()
            .contains("attribute_not_exists(tombstoned_at)"));
    }
    let metadata_condition = requests[0].1["ConditionExpression"].as_str().unwrap();
    assert!(metadata_condition.contains("authority_revision"));
    assert_eq!(
        requests[0].1["ExpressionAttributeValues"][":authority_revision"]["N"],
        "0"
    );
}

#[tokio::test]
async fn tombstone_cas_binds_the_authority_revision_snapshot() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoClientStore::new(db, "clients-table");
    assert!(store
        .convert_to_tombstone("t1", "client-1", 1_700_000_100, Some(19_675), 7)
        .await
        .unwrap());
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(".UpdateItem"));
    assert!(requests[0].1["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("authority_revision = :authority_revision"));
    assert_eq!(
        requests[0].1["ExpressionAttributeValues"][":authority_revision"]["N"],
        "7"
    );
}

#[tokio::test]
async fn pre_revoked_refresh_does_not_create_an_active_reference() {
    let (db, fake, server) = fake_client().await;
    let store = DynamoRefreshStore::new(
        db,
        "refresh-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    let mut record = refresh_record();
    record.revoked = true;
    store.create("t2", record).await.unwrap();
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let items = requests[0].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["Put"]["TableName"], "refresh-table");
    assert_eq!(items[0]["Put"]["Item"]["revoked"]["BOOL"], true);
}

#[tokio::test]
async fn client_refresh_cascade_is_strong_and_returns_already_revoked_families() {
    let (db, fake, server) = fake_client_with_scan(vec![serde_json::json!({
        "family_id": {"S": "t1\u{1f}family-1"},
        "client_id": {"S": "t1\u{1f}client-1"},
        "revoked": {"BOOL": true}
    })])
    .await;
    let store = DynamoRefreshStore::new(
        db,
        "refresh-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    assert_eq!(
        store.revoke_by_client("t1", "client-1").await.unwrap(),
        vec!["family-1".to_string()]
    );
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(".Scan"));
    assert_eq!(requests[0].1["ConsistentRead"], true);
    assert_eq!(requests[0].1["FilterExpression"], "client_id = :c");
}

#[tokio::test]
async fn code_governance_delete_binds_the_scanned_source_and_reference() {
    let (db, fake, server) = fake_client_with_scan(vec![serde_json::json!({
        "code": {"S": "t1\u{1f}code-1"},
        "client_id": {"S": "t1\u{1f}client-1"},
        "expires_at": {"N": "1700000100"},
        "user_id": {"S": "user-1"}
    })])
    .await;
    let store = DynamoCodeStore::new(
        db,
        "codes-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    assert_eq!(store.delete_all_by_tenant("t1").await.unwrap(), 1);
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let items = requests[1].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["Delete"]["TableName"], "codes-table");
    assert_eq!(
        items[0]["Delete"]["ConditionExpression"],
        "attribute_exists(code) AND client_id = :client_id AND expires_at = :expires_at"
    );
    assert_eq!(
        items[0]["Delete"]["ExpressionAttributeValues"][":client_id"]["S"],
        "t1\u{1f}client-1"
    );
    assert_eq!(
        items[0]["Delete"]["ExpressionAttributeValues"][":expires_at"]["N"],
        "1700000100"
    );
    assert_eq!(items[1]["Delete"]["TableName"], "refs-table");
}

#[tokio::test]
async fn refresh_governance_delete_binds_the_scanned_source_and_reference() {
    let (db, fake, server) = fake_client_with_scan(vec![serde_json::json!({
        "family_id": {"S": "t2\u{1f}family-1"},
        "client_id": {"S": "t2\u{1f}client-1"},
        "user_id": {"S": "t2\u{1f}user-1"}
    })])
    .await;
    let store = DynamoRefreshStore::new(
        db,
        "refresh-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    assert_eq!(
        store.delete_all_by_tenant("t2").await.unwrap(),
        vec!["family-1"]
    );
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let items = requests[1].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["Delete"]["TableName"], "refresh-table");
    assert_eq!(
        items[0]["Delete"]["ConditionExpression"],
        "attribute_exists(family_id) AND client_id = :client_id"
    );
    assert_eq!(
        items[0]["Delete"]["ExpressionAttributeValues"][":client_id"]["S"],
        "t2\u{1f}client-1"
    );
    assert_eq!(items[1]["Delete"]["TableName"], "refs-table");
}

#[tokio::test]
async fn refresh_revoke_binds_the_strongly_read_client_and_reference() {
    let (db, fake, server) = fake_client_with_responses(
        Vec::new(),
        Some(serde_json::json!({
            "family_id": {"S": "t3\u{1f}family-1"},
            "client_id": {"S": "t3\u{1f}client-1"},
            "current_version": {"N": "0"},
            "revoked": {"BOOL": false}
        })),
    )
    .await;
    let store = DynamoRefreshStore::new(
        db,
        "refresh-table",
        "clients-table",
        "refs-table",
        "client-authority-refs-v1:test",
    );
    store.revoke("t3", "family-1").await.unwrap();
    server.abort();

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].0.ends_with(".GetItem"));
    assert_eq!(requests[0].1["ConsistentRead"], true);
    let items = requests[1].1["TransactItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["Update"]["TableName"], "refresh-table");
    assert!(items[0]["Update"]["ConditionExpression"]
        .as_str()
        .unwrap()
        .contains("client_id = :client_id"));
    assert_eq!(
        items[0]["Update"]["ExpressionAttributeValues"][":client_id"]["S"],
        "t3\u{1f}client-1"
    );
    assert_eq!(items[1]["Delete"]["TableName"], "refs-table");
}
