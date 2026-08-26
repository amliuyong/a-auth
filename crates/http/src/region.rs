//! Regional ownership and the operator-controlled active/passive runtime fence.
//!
//! Multi-Region mode deliberately keeps replay-sensitive stores Region-local.
//! A request is admitted only when the strongly consistent local control row is
//! active, and newly issued opaque identifiers carry their Region owner.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::RETRY_AFTER, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::sync::{Mutex, RwLock};

use crate::{ports::StoreError, state::AppState};

const REGIONAL_ID_VERSION: &str = "r1";
const REGIONAL_ID_SEPARATOR: char = '_';
const KMS_MRK_PREFIX: &str = "mrk-";
pub const REPLAY_QUIESCENCE_SECS: i64 = 330;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionControlRecord {
    pub active: bool,
    pub activation_not_before: i64,
    pub revision: u64,
}

pub trait RegionControlStore: Send + Sync {
    fn get(
        &self,
        region_id: &str,
    ) -> impl Future<Output = Result<Option<RegionControlRecord>, StoreError>> + Send;
}

#[derive(Clone, Default)]
pub struct MemoryRegionControlStore {
    record: Arc<RwLock<Option<RegionControlRecord>>>,
}

impl MemoryRegionControlStore {
    pub fn with_record(record: RegionControlRecord) -> Self {
        Self {
            record: Arc::new(RwLock::new(Some(record))),
        }
    }

    pub async fn set(&self, record: Option<RegionControlRecord>) {
        *self.record.write().await = record;
    }
}

impl RegionControlStore for MemoryRegionControlStore {
    async fn get(&self, _region_id: &str) -> Result<Option<RegionControlRecord>, StoreError> {
        Ok(self.record.read().await.clone())
    }
}

#[derive(Clone)]
pub enum RegionControlStoreImpl {
    Memory(MemoryRegionControlStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoRegionControlStore),
}

impl RegionControlStore for RegionControlStoreImpl {
    async fn get(&self, region_id: &str) -> Result<Option<RegionControlRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get(region_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get(region_id).await,
        }
    }
}

#[derive(Clone)]
pub struct RegionRuntime {
    local_region: Arc<str>,
    region_id: Option<Arc<str>>,
    control: Option<Arc<RegionControlStoreImpl>>,
    observed_control: Arc<Mutex<Option<RegionControlRecord>>>,
    active_revision: Arc<AtomicU64>,
    activation_not_before: Arc<AtomicI64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionAdmission {
    Active,
    Inactive { retry_after_secs: u64 },
}

impl RegionRuntime {
    pub fn single_region() -> Self {
        Self {
            local_region: Arc::from("local"),
            region_id: None,
            control: None,
            observed_control: Arc::new(Mutex::new(None)),
            active_revision: Arc::new(AtomicU64::new(0)),
            activation_not_before: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn single_region_in(local_region: impl Into<String>) -> Result<Self, String> {
        let local_region = local_region.into();
        validate_region_id(&local_region)?;
        Ok(Self {
            local_region: Arc::from(local_region),
            region_id: None,
            control: None,
            observed_control: Arc::new(Mutex::new(None)),
            active_revision: Arc::new(AtomicU64::new(0)),
            activation_not_before: Arc::new(AtomicI64::new(0)),
        })
    }

    pub fn controlled(
        region_id: impl Into<String>,
        control: RegionControlStoreImpl,
    ) -> Result<Self, String> {
        let region_id = region_id.into();
        validate_region_id(&region_id)?;
        Ok(Self {
            local_region: Arc::from(region_id.clone()),
            region_id: Some(Arc::from(region_id)),
            control: Some(Arc::new(control)),
            observed_control: Arc::new(Mutex::new(None)),
            active_revision: Arc::new(AtomicU64::new(0)),
            activation_not_before: Arc::new(AtomicI64::new(0)),
        })
    }

    pub fn artifact_owner(region_id: impl Into<String>) -> Result<Self, String> {
        let region_id = region_id.into();
        validate_region_id(&region_id)?;
        Ok(Self {
            local_region: Arc::from(region_id.clone()),
            region_id: Some(Arc::from(region_id)),
            control: None,
            observed_control: Arc::new(Mutex::new(None)),
            active_revision: Arc::new(AtomicU64::new(0)),
            activation_not_before: Arc::new(AtomicI64::new(0)),
        })
    }

    pub fn is_multi_region(&self) -> bool {
        self.region_id.is_some()
    }

    pub fn region_id(&self) -> Option<&str> {
        self.region_id.as_deref()
    }

    pub fn local_region(&self) -> &str {
        &self.local_region
    }

    /// Revision admitted by the most recent active-writer control read.
    /// Single-Region mode has the stable revision zero.
    pub fn active_revision(&self) -> u64 {
        self.active_revision.load(Ordering::Acquire)
    }

    pub fn issue_id(&self, random: impl AsRef<str>) -> String {
        match self.region_id() {
            Some(region_id) => format!(
                "{REGIONAL_ID_VERSION}{REGIONAL_ID_SEPARATOR}{region_id}{REGIONAL_ID_SEPARATOR}{}{REGIONAL_ID_SEPARATOR}{}",
                self.active_revision.load(Ordering::Acquire),
                random.as_ref()
            ),
            None => random.as_ref().to_string(),
        }
    }

    pub fn issue_base64_id(&self, random_b64url: impl AsRef<str>) -> String {
        match self.region_id() {
            Some(_) => URL_SAFE_NO_PAD.encode(self.issue_id(random_b64url).as_bytes()),
            None => random_b64url.as_ref().to_string(),
        }
    }

    pub fn owns_id(&self, value: &str) -> bool {
        let Some(expected_region) = self.region_id() else {
            return true;
        };
        let expected_revision = self.active_revision.load(Ordering::Acquire);
        if expected_revision == 0 {
            return false;
        }
        matches!(
            parse_regional_id(value),
            Some((region, revision, opaque))
                if region == expected_region
                    && revision == expected_revision
                    && !opaque.is_empty()
        )
    }

    pub fn owns_base64_id(&self, value: &str) -> bool {
        if self.region_id().is_none() {
            return true;
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(value) else {
            return false;
        };
        let Ok(framed) = std::str::from_utf8(&decoded) else {
            return false;
        };
        self.owns_id(framed)
    }

    /// External proofs use client-chosen identifiers, so failover ownership
    /// is enforced by rejecting proofs minted before this activation.
    pub fn accepts_external_issued_at(&self, issued_at: i64) -> bool {
        if self.region_id().is_none() {
            return true;
        }
        self.active_revision.load(Ordering::Acquire) != 0
            && issued_at >= self.activation_not_before.load(Ordering::Acquire)
    }

    pub fn local_kms_key_arn(&self, key_arn: &str) -> Result<String, String> {
        let Some(expected_region) = self.region_id() else {
            return Ok(key_arn.to_string());
        };
        let mut parts: Vec<&str> = key_arn.splitn(6, ':').collect();
        if parts.len() != 6
            || parts[0] != "arn"
            || parts[2] != "kms"
            || !parts[5].starts_with("key/")
        {
            return Err("tenant signing key is not a KMS key ARN".to_string());
        }
        let key_id = &parts[5]["key/".len()..];
        if parts[3] != expected_region && !key_id.starts_with(KMS_MRK_PREFIX) {
            return Err(
                "tenant signing key is single-Region and unavailable in this Region".to_string(),
            );
        }
        parts[3] = expected_region;
        Ok(parts.join(":"))
    }

    pub async fn admit(&self, now: i64) -> Result<RegionAdmission, StoreError> {
        let (region_id, control) = match (self.region_id(), self.control.as_ref()) {
            (None, None) => return Ok(RegionAdmission::Active),
            (Some(region_id), Some(control)) => (region_id, control),
            _ => {
                return Err(StoreError::Permanent(
                    "regional runtime has no admission control store".to_string(),
                ))
            }
        };
        let Some(record) = control.get(region_id).await? else {
            return Ok(RegionAdmission::Inactive {
                retry_after_secs: 30,
            });
        };
        if record.revision == 0 {
            return Err(StoreError::Permanent(
                "region control revision must be non-zero".to_string(),
            ));
        }
        {
            let mut observed = self.observed_control.lock().await;
            if let Some(previous) = observed.as_ref() {
                if record.revision < previous.revision {
                    return Err(StoreError::Permanent(format!(
                        "region control revision rolled back from {} to {}",
                        previous.revision, record.revision
                    )));
                }
                if record.revision == previous.revision && record != *previous {
                    return Err(StoreError::Permanent(
                        "region control record changed without a new revision".to_string(),
                    ));
                }
            }
            if observed
                .as_ref()
                .is_none_or(|previous| record.revision > previous.revision)
            {
                *observed = Some(record.clone());
            }
        }
        if record.active && now >= record.activation_not_before {
            self.activation_not_before
                .store(record.activation_not_before, Ordering::Release);
            self.active_revision
                .store(record.revision, Ordering::Release);
            return Ok(RegionAdmission::Active);
        }
        let retry_after_secs = record
            .activation_not_before
            .saturating_sub(now)
            .clamp(1, 300) as u64;
        Ok(RegionAdmission::Inactive { retry_after_secs })
    }
}

pub fn resolve_control_region(
    explicit_region: Option<String>,
    aws_region: Option<String>,
    control_table: Option<String>,
) -> Result<Option<(String, String)>, String> {
    let explicit_region = explicit_region.filter(|value| !value.is_empty());
    let aws_region = aws_region.filter(|value| !value.is_empty());
    let control_table = control_table.filter(|value| !value.is_empty());
    match (explicit_region, control_table) {
        (None, None) => Ok(None),
        (Some(_), None) => Err("AGENT_AUTH_REGION_ID requires REGION_CONTROL_TABLE".to_string()),
        (explicit_region, Some(table)) => {
            let region = explicit_region
                .or(aws_region)
                .ok_or("REGION_CONTROL_TABLE requires AGENT_AUTH_REGION_ID or AWS_REGION")?;
            validate_region_id(&region)?;
            Ok(Some((region, table)))
        }
    }
}

fn validate_region_id(region_id: &str) -> Result<(), String> {
    if region_id.is_empty()
        || region_id.len() > 32
        || !region_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(
            "AGENT_AUTH_REGION_ID must be 1..=32 lowercase ASCII letters, digits, or hyphens"
                .to_string(),
        );
    }
    Ok(())
}

fn parse_regional_id(value: &str) -> Option<(&str, u64, &str)> {
    let mut parts = value.splitn(4, REGIONAL_ID_SEPARATOR);
    if parts.next()? != REGIONAL_ID_VERSION {
        return None;
    }
    let region = parts.next()?;
    let revision = parts.next()?.parse().ok()?;
    Some((region, revision, parts.next()?))
}

pub async fn region_admission_layer(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let now = crate::token::current_unix_secs_pub();
    let region = state.region.region_id().map(str::to_string);
    match state.region.admit(now).await {
        Ok(RegionAdmission::Active) => {
            let mut response = next.run(request).await;
            if let Some(region) = region {
                if let Ok(value) = HeaderValue::from_str(&region) {
                    response.headers_mut().insert("x-agent-auth-region", value);
                }
            }
            response
        }
        Ok(RegionAdmission::Inactive { retry_after_secs }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, retry_after_secs.to_string())],
            Json(serde_json::json!({
                "error": "region_inactive",
                "error_description": "This Region is not active for Agent Auth traffic"
            })),
        )
            .into_response(),
        Err(error) => {
            eprintln!("REGION_ADMISSION_FAILURE region={region:?} error={error:?}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(RETRY_AFTER, "30")],
                Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "Regional activation state is unavailable"
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_record(not_before: i64) -> RegionControlRecord {
        RegionControlRecord {
            active: true,
            activation_not_before: not_before,
            revision: 1,
        }
    }

    #[test]
    fn single_region_keeps_legacy_identifier_shape() {
        let runtime = RegionRuntime::single_region();
        assert_eq!(runtime.issue_id("opaque"), "opaque");
        assert_eq!(runtime.issue_base64_id("AQIDBA"), "AQIDBA");
        assert!(runtime.owns_id("legacy-without-region"));
        assert!(runtime.owns_base64_id("legacy-without-region"));
    }

    #[test]
    fn control_table_uses_lambda_region_without_changing_single_region_mode() {
        assert_eq!(
            resolve_control_region(None, Some("us-east-1".to_string()), None).unwrap(),
            None
        );
        assert_eq!(
            resolve_control_region(
                None,
                Some("us-east-1".to_string()),
                Some("region-control".to_string()),
            )
            .unwrap(),
            Some(("us-east-1".to_string(), "region-control".to_string()))
        );
        assert_eq!(
            resolve_control_region(
                Some("us-west-2".to_string()),
                Some("us-east-1".to_string()),
                Some("region-control".to_string()),
            )
            .unwrap(),
            Some(("us-west-2".to_string(), "region-control".to_string()))
        );
        assert!(resolve_control_region(None, None, Some("region-control".to_string())).is_err());
        assert!(resolve_control_region(Some("us-east-1".to_string()), None, None).is_err());
    }

    #[tokio::test]
    async fn single_region_in_tracks_the_deployed_region_without_enabling_failover() {
        let runtime = RegionRuntime::single_region_in("us-east-1").unwrap();
        assert_eq!(runtime.local_region(), "us-east-1");
        assert_eq!(runtime.region_id(), None);
        assert!(!runtime.is_multi_region());
        assert_eq!(runtime.active_revision(), 0);
        assert_eq!(runtime.admit(0).await.unwrap(), RegionAdmission::Active);
        assert_eq!(runtime.issue_id("opaque"), "opaque");

        assert!(RegionRuntime::single_region_in("US-EAST-1").is_err());
        assert!(RegionRuntime::single_region_in("").is_err());
    }

    #[tokio::test]
    async fn regional_identifiers_are_owned_by_exact_activation() {
        let store = MemoryRegionControlStore::with_record(active_record(100));
        let runtime =
            RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(store)).unwrap();
        assert_eq!(runtime.admit(100).await.unwrap(), RegionAdmission::Active);
        let id = runtime.issue_id("opaque");
        assert_eq!(id, "r1_us-east-1_1_opaque");
        assert!(id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        assert!(runtime.owns_id(&id));
        assert!(!runtime.owns_id("r1_us-west-2_1_opaque"));
        assert!(!runtime.owns_id("r1_us-east-1_2_opaque"));
        assert!(!runtime.owns_id("opaque"));
        assert!(!runtime.owns_id("r1_us-east-1_1_"));
    }

    #[tokio::test]
    async fn regional_base64_identifiers_remain_decodable_at_all_revision_widths() {
        let store = MemoryRegionControlStore::default();
        let runtime =
            RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(store.clone()))
                .unwrap();
        let mut previous: Option<String> = None;
        for revision in [1, 10, 100, 1_000] {
            store
                .set(Some(RegionControlRecord {
                    active: true,
                    activation_not_before: 0,
                    revision,
                }))
                .await;
            assert_eq!(runtime.admit(1).await.unwrap(), RegionAdmission::Active);
            let id = runtime.issue_base64_id("AQIDBA");
            assert!(URL_SAFE_NO_PAD.decode(&id).is_ok());
            assert!(runtime.owns_base64_id(&id));
            if let Some(previous) = previous {
                assert!(!runtime.owns_base64_id(&previous));
            }
            previous = Some(id);
        }
        assert!(!runtime.owns_base64_id("not=base64url"));
    }

    #[test]
    fn multi_region_kms_arn_rebinds_only_related_mrk_keys() {
        let runtime = RegionRuntime::controlled(
            "us-west-2",
            RegionControlStoreImpl::Memory(MemoryRegionControlStore::default()),
        )
        .unwrap();
        assert_eq!(
            runtime
                .local_kms_key_arn("arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef")
                .unwrap(),
            "arn:aws:kms:us-west-2:123456789012:key/mrk-0123456789abcdef"
        );
        assert!(runtime
            .local_kms_key_arn(
                "arn:aws:kms:us-east-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
            )
            .is_err());
        assert!(runtime.local_kms_key_arn("not-an-arn").is_err());
    }

    #[tokio::test]
    async fn activation_time_is_a_runtime_enforced_quiescence_fence() {
        let store = MemoryRegionControlStore::with_record(active_record(1_330));
        let runtime =
            RegionRuntime::controlled("us-west-2", RegionControlStoreImpl::Memory(store)).unwrap();
        assert_eq!(
            runtime.admit(1_000).await.unwrap(),
            RegionAdmission::Inactive {
                retry_after_secs: 300
            }
        );
        assert_eq!(
            runtime.admit(1_329).await.unwrap(),
            RegionAdmission::Inactive {
                retry_after_secs: 1
            }
        );
        assert_eq!(runtime.admit(1_330).await.unwrap(), RegionAdmission::Active);
    }

    #[tokio::test]
    async fn missing_or_explicitly_inactive_control_row_fails_closed() {
        let store = MemoryRegionControlStore::default();
        let runtime =
            RegionRuntime::controlled("us-west-2", RegionControlStoreImpl::Memory(store.clone()))
                .unwrap();
        assert!(matches!(
            runtime.admit(1_000).await.unwrap(),
            RegionAdmission::Inactive { .. }
        ));
        store
            .set(Some(RegionControlRecord {
                active: false,
                activation_not_before: 0,
                revision: 2,
            }))
            .await;
        assert!(matches!(
            runtime.admit(1_000).await.unwrap(),
            RegionAdmission::Inactive { .. }
        ));
    }

    #[tokio::test]
    async fn failback_never_reactivates_artifacts_from_an_older_activation() {
        let east_store = MemoryRegionControlStore::with_record(RegionControlRecord {
            active: true,
            activation_not_before: 100,
            revision: 1,
        });
        let west_store = MemoryRegionControlStore::with_record(RegionControlRecord {
            active: false,
            activation_not_before: 0,
            revision: 0,
        });
        let east = RegionRuntime::controlled(
            "us-east-1",
            RegionControlStoreImpl::Memory(east_store.clone()),
        )
        .unwrap();
        let west = RegionRuntime::controlled(
            "us-west-2",
            RegionControlStoreImpl::Memory(west_store.clone()),
        )
        .unwrap();

        assert_eq!(east.admit(100).await.unwrap(), RegionAdmission::Active);
        let first_east_id = east.issue_id("code-a");

        east_store
            .set(Some(RegionControlRecord {
                active: false,
                activation_not_before: 0,
                revision: 2,
            }))
            .await;
        assert!(matches!(
            east.admit(101).await.unwrap(),
            RegionAdmission::Inactive { .. }
        ));
        west_store
            .set(Some(RegionControlRecord {
                active: true,
                activation_not_before: 431,
                revision: 3,
            }))
            .await;
        assert_eq!(west.admit(431).await.unwrap(), RegionAdmission::Active);
        let west_id = west.issue_id("code-b");

        west_store
            .set(Some(RegionControlRecord {
                active: false,
                activation_not_before: 0,
                revision: 4,
            }))
            .await;
        east_store
            .set(Some(RegionControlRecord {
                active: true,
                activation_not_before: 762,
                revision: 5,
            }))
            .await;
        assert_eq!(east.admit(762).await.unwrap(), RegionAdmission::Active);
        let second_east_id = east.issue_id("code-c");

        assert!(!east.owns_id(&first_east_id));
        assert!(!east.owns_id(&west_id));
        assert!(east.owns_id(&second_east_id));
        assert_eq!(second_east_id, "r1_us-east-1_5_code-c");
    }

    #[tokio::test]
    async fn zero_rollback_and_same_revision_mutation_fail_closed() {
        let store = MemoryRegionControlStore::with_record(active_record(100));
        let runtime =
            RegionRuntime::controlled("us-east-1", RegionControlStoreImpl::Memory(store.clone()))
                .unwrap();
        assert_eq!(runtime.admit(100).await.unwrap(), RegionAdmission::Active);

        store
            .set(Some(RegionControlRecord {
                active: false,
                activation_not_before: 0,
                revision: 1,
            }))
            .await;
        assert!(runtime.admit(101).await.is_err());

        store
            .set(Some(RegionControlRecord {
                active: true,
                activation_not_before: 100,
                revision: 0,
            }))
            .await;
        assert!(runtime.admit(101).await.is_err());
    }

    #[tokio::test]
    async fn external_proofs_must_be_minted_in_the_current_activation() {
        let store = MemoryRegionControlStore::with_record(RegionControlRecord {
            active: true,
            activation_not_before: 1_330,
            revision: 7,
        });
        let runtime =
            RegionRuntime::controlled("us-west-2", RegionControlStoreImpl::Memory(store)).unwrap();
        assert_eq!(runtime.admit(1_330).await.unwrap(), RegionAdmission::Active);
        assert!(!runtime.accepts_external_issued_at(1_329));
        assert!(runtime.accepts_external_issued_at(1_330));
        assert!(runtime.accepts_external_issued_at(1_331));
    }
}
