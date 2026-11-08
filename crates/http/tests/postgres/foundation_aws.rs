//! Run the foundation contracts through the actual DynamoDB adapters.

use super::aws_contract_database::{table, table_with_range};
use agent_auth_http::adapters::aws::{
    DynamoClientStore, DynamoCodeStore, DynamoInitialAccessTokenStore, DynamoParStore,
    DynamoRefreshStore, DynamoReplayStore,
};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, GlobalSecondaryIndex, KeySchemaElement, KeyType,
    Projection, ProjectionType, ScalarAttributeType,
};

#[tokio::test]
async fn aws_par_contract() {
    let (db, name) = table("request_uri", vec![], vec![]).await;
    super::par_contract(DynamoParStore::new(db.clone(), &name)).await;
    db.delete_table().table_name(name).send().await.unwrap();
}

#[tokio::test]
async fn aws_replay_contract() {
    let (db, name) = table("pk", vec![], vec![]).await;
    super::replay_contract(DynamoReplayStore::new(db.clone(), &name)).await;
    db.delete_table().table_name(name).send().await.unwrap();
}

#[tokio::test]
async fn aws_initial_access_token_contract() {
    let (db, name) = table("token_id", vec![], vec![]).await;
    super::initial_access_token_contract(DynamoInitialAccessTokenStore::new(db.clone(), &name))
        .await;
    db.delete_table().table_name(name).send().await.unwrap();
}

#[tokio::test]
async fn aws_client_contract() {
    let attributes = vec![AttributeDefinition::builder()
        .attribute_name("last_used_day")
        .attribute_type(ScalarAttributeType::N)
        .build()
        .unwrap()];
    let index = GlobalSecondaryIndex::builder()
        .index_name("last_used_day-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("last_used_day")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::KeysOnly)
                .build(),
        )
        .build()
        .unwrap();
    let (db, name) = table("client_id", attributes, vec![index]).await;
    super::client_contract(DynamoClientStore::new(db.clone(), &name)).await;
    db.delete_table().table_name(name).send().await.unwrap();
}

async fn references() -> (aws_sdk_dynamodb::Client, String) {
    let (db, name) = table_with_range("client_key", Some("reference_key"), vec![], vec![]).await;
    // New empty databases have complete code/family reference coverage.
    for kind in ["code", "refresh"] {
        db.put_item()
            .table_name(&name)
            .item("client_key", AttributeValue::S("meta\u{1f}coverage".into()))
            .item(
                "reference_key",
                AttributeValue::S(format!("{kind}\u{1f}client-authority-refs-v1")),
            )
            .item(
                "schema_version",
                AttributeValue::S("client-authority-refs-v1".into()),
            )
            .item(
                "migration_version",
                AttributeValue::S("contract-complete-v1".into()),
            )
            .send()
            .await
            .unwrap();
    }
    (db, name)
}

async fn refresh_table() -> (aws_sdk_dynamodb::Client, String) {
    let attributes = vec![AttributeDefinition::builder()
        .attribute_name("user_id")
        .attribute_type(ScalarAttributeType::S)
        .build()
        .unwrap()];
    let index = GlobalSecondaryIndex::builder()
        .index_name("user_id-index")
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("user_id")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
        .unwrap();
    table("family_id", attributes, vec![index]).await
}

#[tokio::test]
async fn aws_code_contract() {
    let (_, refs) = references().await;
    let (_, clients) = table("client_id", vec![], vec![]).await;
    let (db, codes) = table("code", vec![], vec![]).await;
    super::code_contract(
        DynamoCodeStore::new(db.clone(), &codes, &clients, &refs, "contract-complete-v1"),
        DynamoClientStore::new(db.clone(), &clients),
    )
    .await;
    for name in [codes, clients, refs] {
        db.delete_table().table_name(name).send().await.unwrap();
    }
}

#[tokio::test]
async fn aws_refresh_contract() {
    let (_, refs) = references().await;
    let (_, clients) = table("client_id", vec![], vec![]).await;
    let (db, families) = refresh_table().await;
    super::refresh_contract(
        DynamoRefreshStore::new(
            db.clone(),
            &families,
            &clients,
            &refs,
            "contract-complete-v1",
        ),
        DynamoClientStore::new(db.clone(), &clients),
    )
    .await;
    for name in [families, clients, refs] {
        db.delete_table().table_name(name).send().await.unwrap();
    }
}
