use super::{DynamoUsersStore, SCIM_ALIAS_EXTERNAL, SCIM_ALIAS_USERNAME};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap},
    routing::post,
    Router,
};
use serde_json::{json, Value};

#[derive(Clone)]
struct AliasSnapshots {
    external_key: String,
    username_key: String,
    external: Value,
    username: Value,
}

async fn dynamo(
    State(snapshots): State<AliasSnapshots>,
    headers: HeaderMap,
    body: Bytes,
) -> ([(header::HeaderName, &'static str); 1], String) {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let target = headers.get("x-amz-target").unwrap().to_str().unwrap();
    let response = if target.ends_with(".TransactGetItems") {
        json!({"Responses": [{"Item": snapshots.external}, {"Item": snapshots.username}]})
    } else {
        assert!(target.ends_with(".GetItem"));
        let key = request["Key"]["user_id"]["S"].as_str().unwrap();
        // The atomic create commits between the two independent strong reads.
        // Each individual response is valid, but they are different snapshots.
        if key == snapshots.external_key {
            json!({})
        } else {
            assert_eq!(key, snapshots.username_key);
            json!({"Item": snapshots.username})
        }
    };
    (
        [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
        response.to_string(),
    )
}

#[tokio::test]
async fn scim_alias_classification_cannot_mix_pre_and_post_commit_snapshots() {
    fn alias(kind: &str, value: &str) -> Value {
        json!({
            "user_id": {"S": DynamoUsersStore::scim_alias_key("tenant", kind, value)},
            "record_type": {"S": "scim_alias"},
            "alias_kind": {"S": kind},
            "alias_value": {"S": value},
            "canonical_user_id": {"S": "tenant\u{1f}canonical"}
        })
    }
    let snapshots = AliasSnapshots {
        external_key: DynamoUsersStore::scim_alias_key("tenant", SCIM_ALIAS_EXTERNAL, "external"),
        username_key: DynamoUsersStore::scim_alias_key(
            "tenant",
            SCIM_ALIAS_USERNAME,
            "person@example.test",
        ),
        external: alias(SCIM_ALIAS_EXTERNAL, "external"),
        username: alias(SCIM_ALIAS_USERNAME, "person@example.test"),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(dynamo)).with_state(snapshots),
        )
        .await
        .unwrap();
    });
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .endpoint_url(format!("http://{address}"))
        .build();
    let store = DynamoUsersStore::new(aws_sdk_dynamodb::Client::from_conf(config), "users-fixture");
    let result = store
        .classify_scim_aliases("tenant", "external", "person@example.test")
        .await;
    server.abort();
    assert_eq!(
        result.unwrap(),
        (Some("canonical".into()), Some("canonical".into()))
    );
}
