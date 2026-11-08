use super::super::serialization::required_option;
use crate::ports::SessionRecord;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    session_id: String,
    user_id: String,
    credential_epoch: u64,
    auth_time: i64,
    created_at: i64,
    last_used_at: i64,
    device: String,
    expires_at: i64,
    #[serde(deserialize_with = "required_option")]
    acr: Option<String>,
    amr: Vec<String>,
}

pub(super) fn serialize<S>(record: &SessionRecord, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    StoredRecord {
        session_id: record.session_id.clone(),
        user_id: record.user_id.clone(),
        credential_epoch: record.credential_epoch,
        auth_time: record.auth_time,
        created_at: record.created_at,
        last_used_at: record.last_used_at,
        device: record.device.clone(),
        expires_at: record.expires_at,
        acr: record.acr.clone(),
        amr: record.amr.clone(),
    }
    .serialize(serializer)
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<SessionRecord, D::Error>
where
    D: Deserializer<'de>,
{
    let stored = StoredRecord::deserialize(deserializer)?;
    Ok(SessionRecord {
        session_id: stored.session_id,
        user_id: stored.user_id,
        credential_epoch: stored.credential_epoch,
        auth_time: stored.auth_time,
        created_at: stored.created_at,
        last_used_at: stored.last_used_at,
        device: stored.device,
        expires_at: stored.expires_at,
        acr: stored.acr,
        amr: stored.amr,
    })
}
