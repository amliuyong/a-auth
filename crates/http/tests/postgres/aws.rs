//! Exercise the actual AWS adapters against a loopback-only DynamoDB emulator.
//! This is adapter contract evidence, not live AWS deployment acceptance.

use aws_sdk_dynamodb::{
    types::{
        AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
        Projection, ProjectionType, ScalarAttributeType,
    },
    Client,
};

pub async fn table(
    primary_key: &str,
    attributes: Vec<AttributeDefinition>,
    indexes: Vec<GlobalSecondaryIndex>,
) -> (Client, String) {
    table_with_range(primary_key, None, attributes, indexes).await
}

pub async fn table_with_string_index(
    primary_key: &str,
    index_name: &str,
    index_attribute: &str,
) -> (Client, String) {
    let attribute = AttributeDefinition::builder()
        .attribute_name(index_attribute)
        .attribute_type(ScalarAttributeType::S)
        .build()
        .unwrap();
    let index = GlobalSecondaryIndex::builder()
        .index_name(index_name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(index_attribute)
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
    table(primary_key, vec![attribute], vec![index]).await
}

pub async fn table_with_range(
    primary_key: &str,
    range_key: Option<&str>,
    attributes: Vec<AttributeDefinition>,
    indexes: Vec<GlobalSecondaryIndex>,
) -> (Client, String) {
    table_with_typed_range(
        primary_key,
        range_key.map(|key| (key, ScalarAttributeType::S)),
        attributes,
        indexes,
    )
    .await
}

pub async fn table_with_typed_range(
    primary_key: &str,
    range_key: Option<(&str, ScalarAttributeType)>,
    attributes: Vec<AttributeDefinition>,
    indexes: Vec<GlobalSecondaryIndex>,
) -> (Client, String) {
    let endpoint = std::env::var("A_AUTH_TEST_DYNAMODB_ENDPOINT")
        .expect("AWS adapter contracts require A_AUTH_TEST_DYNAMODB_ENDPOINT");
    let parsed = url::Url::parse(&endpoint).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(
        parsed.host_str(),
        Some("127.0.0.1"),
        "contract writes must stay on loopback"
    );
    let database = Client::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
            .endpoint_url(endpoint)
            .build(),
    );
    let name = format!("a-auth-142-contract-{:032x}", rand::random::<u128>());
    let mut all_attributes = vec![AttributeDefinition::builder()
        .attribute_name(primary_key)
        .attribute_type(ScalarAttributeType::S)
        .build()
        .unwrap()];
    all_attributes.extend(attributes);
    let mut keys = vec![KeySchemaElement::builder()
        .attribute_name(primary_key)
        .key_type(KeyType::Hash)
        .build()
        .unwrap()];
    if let Some((range, kind)) = range_key {
        all_attributes.push(
            AttributeDefinition::builder()
                .attribute_name(range)
                .attribute_type(kind)
                .build()
                .unwrap(),
        );
        keys.push(
            KeySchemaElement::builder()
                .attribute_name(range)
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        );
    }
    database
        .create_table()
        .table_name(&name)
        .billing_mode(BillingMode::PayPerRequest)
        .set_attribute_definitions(Some(all_attributes))
        .set_key_schema(Some(keys))
        .set_global_secondary_indexes((!indexes.is_empty()).then_some(indexes))
        .send()
        .await
        .unwrap();
    (database, name)
}
