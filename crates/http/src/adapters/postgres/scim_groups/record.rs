use crate::ports::ScimGroupRecord;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    group_id: String,
    external_id: String,
    display_name: String,
    members: Vec<String>,
    version: u64,
    created_at: i64,
    updated_at: i64,
}

pub(super) fn serialize<S>(record: &ScimGroupRecord, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    StoredRecord {
        group_id: record.group_id.clone(),
        external_id: record.external_id.clone(),
        display_name: record.display_name.clone(),
        members: record.members.clone(),
        version: record.version,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
    .serialize(serializer)
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<ScimGroupRecord, D::Error>
where
    D: Deserializer<'de>,
{
    let stored = StoredRecord::deserialize(deserializer)?;
    Ok(ScimGroupRecord {
        group_id: stored.group_id,
        external_id: stored.external_id,
        display_name: stored.display_name,
        members: stored.members,
        version: stored.version,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    })
}
