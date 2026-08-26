use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(crate) const GRANT_SUMMARY_TYPE: &str = "agent_auth_grant_summary_v1";

const SUMMARY_KEYS: &[&str] = &[
    "authorization_details_count",
    "authorization_details_sha256",
    "introspection_required",
    "locations",
    "type",
];
const DIGEST_DOMAIN: &[u8] = b"agent-auth:grant-backed-rar:v1\0";

#[derive(Debug)]
pub(crate) struct GrantRarSummary<'a> {
    pub resource: &'a str,
    pub count: usize,
    pub digest: &'a str,
}

pub(crate) fn summary(resource: &str, details: &[Value]) -> Value {
    serde_json::json!({
        "type": GRANT_SUMMARY_TYPE,
        "locations": [resource],
        "authorization_details_count": details.len(),
        "authorization_details_sha256": digest(resource, details),
        "introspection_required": true,
    })
}

pub(crate) fn parse_summary(value: &Value) -> Result<Option<GrantRarSummary<'_>>, ()> {
    let Some(details) = value.as_array() else {
        return Err(());
    };
    let contains_summary = details
        .iter()
        .any(|detail| detail.get("type").and_then(Value::as_str) == Some(GRANT_SUMMARY_TYPE));
    if !contains_summary {
        return Ok(None);
    }
    if details.len() != 1 {
        return Err(());
    }
    let object = details[0].as_object().ok_or(())?;
    if object.len() != SUMMARY_KEYS.len()
        || object
            .keys()
            .any(|key| !SUMMARY_KEYS.contains(&key.as_str()))
    {
        return Err(());
    }
    if object.get("type").and_then(Value::as_str) != Some(GRANT_SUMMARY_TYPE)
        || object
            .get("introspection_required")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(());
    }
    let locations = object
        .get("locations")
        .and_then(Value::as_array)
        .ok_or(())?;
    if locations.len() != 1 {
        return Err(());
    }
    let resource = locations[0].as_str().ok_or(())?;
    let count_u64 = object
        .get("authorization_details_count")
        .and_then(Value::as_u64)
        .ok_or(())?;
    let count = usize::try_from(count_u64).map_err(|_| ())?;
    let digest = object
        .get("authorization_details_sha256")
        .and_then(Value::as_str)
        .filter(|digest| digest.len() == 43)
        .ok_or(())?;
    Ok(Some(GrantRarSummary {
        resource,
        count,
        digest,
    }))
}

pub(crate) fn matches(summary: &GrantRarSummary<'_>, resource: &str, details: &[Value]) -> bool {
    summary.resource == resource
        && summary.count == details.len()
        && summary.digest == digest(resource, details)
}

fn digest(resource: &str, details: &[Value]) -> String {
    let canonical = canonicalize(&Value::Array(details.to_vec()));
    let encoded = serde_json::to_vec(&canonical).expect("canonical JSON serialization");
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((resource.len() as u64).to_be_bytes());
    hasher.update(resource.as_bytes());
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize(&object[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_parser_rejects_mixed_and_malformed_shapes() {
        let resource = "https://rs.example";
        let details = vec![
            serde_json::json!({
                "type": "agent_auth_rar_v1",
                "locations": [resource],
                "identifier": "policy-1",
                "max_records": 5
            }),
            serde_json::json!({
                "type": "agent_auth_rar_v1",
                "locations": [resource],
                "identifier": "policy-2",
                "max_records": 7
            }),
        ];
        let valid = serde_json::Value::Array(vec![summary(resource, &details)]);
        let parsed = parse_summary(&valid)
            .expect("the canonical summary shape must parse")
            .expect("the canonical summary must be detected");
        assert!(matches(&parsed, resource, &details));
        assert!(!matches(&parsed, "https://other.example", &details));
        let mut changed_details = details.clone();
        changed_details[0]["identifier"] = serde_json::json!("changed-policy");
        assert!(!matches(&parsed, resource, &changed_details));
        let mut reversed_details = details.clone();
        reversed_details.reverse();
        assert!(!matches(&parsed, resource, &reversed_details));

        let reordered_details = vec![
            serde_json::from_str(
                r#"{"max_records":5,"identifier":"policy-1","locations":["https://rs.example"],"type":"agent_auth_rar_v1"}"#,
            )
            .unwrap(),
            serde_json::from_str(
                r#"{"identifier":"policy-2","type":"agent_auth_rar_v1","max_records":7,"locations":["https://rs.example"]}"#,
            )
            .unwrap(),
        ];
        assert!(
            matches(&parsed, resource, &reordered_details),
            "object key ordering must not change the canonical digest"
        );

        let mut wrong_count = valid[0].clone();
        wrong_count["authorization_details_count"] = serde_json::json!(details.len() + 1);
        let wrong_count_value = serde_json::Value::Array(vec![wrong_count]);
        let wrong_count_summary = parse_summary(&wrong_count_value)
            .expect("a well-shaped summary with a different count still parses")
            .expect("summary detected");
        assert!(!matches(&wrong_count_summary, resource, &details));

        let mut wrong_digest = valid[0].clone();
        wrong_digest["authorization_details_sha256"] = serde_json::json!("x".repeat(43));
        let wrong_digest_value = serde_json::Value::Array(vec![wrong_digest]);
        let wrong_digest_summary = parse_summary(&wrong_digest_value)
            .expect("a fixed-width but different digest still parses")
            .expect("summary detected");
        assert!(!matches(&wrong_digest_summary, resource, &details));

        let mut short_digest = valid[0].clone();
        short_digest["authorization_details_sha256"] = serde_json::json!("short");
        assert!(parse_summary(&serde_json::Value::Array(vec![short_digest])).is_err());

        let mut mixed = valid.as_array().unwrap().clone();
        mixed.push(details[0].clone());
        assert!(parse_summary(&serde_json::Value::Array(mixed)).is_err());

        let mut extra_field = valid[0].clone();
        extra_field["unexpected"] = serde_json::json!(true);
        assert!(parse_summary(&serde_json::Value::Array(vec![extra_field])).is_err());

        let mut not_required = valid[0].clone();
        not_required["introspection_required"] = serde_json::json!(false);
        assert!(parse_summary(&serde_json::Value::Array(vec![not_required])).is_err());

        let mut multiple_locations = valid[0].clone();
        multiple_locations["locations"] = serde_json::json!([resource, "https://other.example"]);
        assert!(parse_summary(&serde_json::Value::Array(vec![multiple_locations])).is_err());
        assert!(parse_summary(&serde_json::json!({"type": GRANT_SUMMARY_TYPE})).is_err());
    }
}
