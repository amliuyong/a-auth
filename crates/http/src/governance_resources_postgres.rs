//! PostgreSQL observations and explicitly operator-owned external resources.
//! Mounted attestations are identified as operator statements, never provider
//! reads. Missing statements leave retention incomplete.

use super::*;
use crate::{
    adapters::{
        file_secrets::FileSecretResolver,
        postgres::{PostgresGovernanceStore, PostgresSsfStore, PostgresStore},
    },
    ports::SecretResolver,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const PORTABLE_RETENTION_SECS: i64 = 400 * 86_400;
const RECEIPT_VALIDITY_SECS: i64 = 300;

#[derive(Clone)]
pub struct PostgresGovernanceResourceConfig {
    pub region: String,
    pub tenant_id: String,
    pub storage_tenant: String,
    pub retention_reference: String,
    pub operator_secret_references: BTreeSet<String>,
}

#[derive(Clone)]
pub struct PostgresGovernanceResourceBackend {
    governance: PostgresGovernanceStore,
    ssf: PostgresSsfStore,
    files: FileSecretResolver,
    config: PostgresGovernanceResourceConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBundle {
    schema_version: u32,
    receipts: Vec<Receipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    request_sha256: String,
    observed_at: i64,
    valid_until: i64,
    resources: ExternalResources,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalResources {
    operator_backups: ExternalObservation,
    operator_logs: ExternalObservation,
}

impl ExternalResources {
    fn iter(&self) -> [(&'static str, &ExternalObservation); 2] {
        [
            ("operator_backups", &self.operator_backups),
            ("operator_logs", &self.operator_logs),
        ]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalObservation {
    absent: bool,
    manifest_sha256: String,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid portable governance resource authority".into())
}

fn reference_valid(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 1024
        && !reference
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

fn digest_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn resource(
    state: &str,
    basis: &str,
    source: &str,
    deadline: Option<i64>,
) -> GovernanceRetentionEvidence {
    GovernanceRetentionEvidence {
        state: state.into(),
        evidence_basis: basis.into(),
        lifecycle_source: source.into(),
        retention_until: deadline,
    }
}

pub(crate) fn portable_retention_evidence(
    anchor: i64,
) -> BTreeMap<String, GovernanceRetentionEvidence> {
    BTreeMap::from([
        (
            "postgres_security_event_hot".into(),
            resource(
                "not_observed",
                "missing_database_observation",
                "PostgreSQL immutable security ledger",
                Some(anchor.saturating_add(PORTABLE_RETENTION_SECS)),
            ),
        ),
        (
            "postgres_security_event_fallback".into(),
            resource(
                "not_observed",
                "missing_database_observation",
                "PostgreSQL ingress snapshots and dead letters",
                Some(anchor.saturating_add(PORTABLE_RETENTION_SECS)),
            ),
        ),
        (
            "postgres_ssf_deliveries".into(),
            resource(
                "not_observed",
                "missing_database_observation",
                "PostgreSQL encrypted SSF delivery audit",
                Some(anchor.saturating_add(PORTABLE_RETENTION_SECS)),
            ),
        ),
        (
            "operator_backups".into(),
            resource(
                "not_observed",
                "missing_operator_attestation",
                "Operator-managed PostgreSQL recovery copies",
                None,
            ),
        ),
        (
            "operator_logs".into(),
            resource(
                "not_observed",
                "missing_operator_attestation",
                "Operator-managed runtime logs",
                None,
            ),
        ),
        (
            "security_event_archive".into(),
            resource(
                "disabled",
                "deployment_profile",
                "Portable profile disables external event archives",
                None,
            ),
        ),
        (
            "ssf_revoke_tombstones".into(),
            resource(
                "permanent_control_record",
                "durable_control_record",
                "SSF receiver revocation policy",
                None,
            ),
        ),
        (
            "mounted_operator_resources".into(),
            resource(
                "operator_owned_retained",
                "deployment_profile",
                "Operator-mounted signing and external client keys",
                None,
            ),
        ),
    ])
}

impl PostgresGovernanceResourceBackend {
    pub(crate) fn belongs_to(&self, governance: &PostgresGovernanceStore) -> bool {
        self.governance.shares_pool_with(governance)
    }

    pub fn new(
        database: PostgresStore,
        ssf: PostgresSsfStore,
        files: FileSecretResolver,
        config: PostgresGovernanceResourceConfig,
    ) -> Result<Self, StoreError> {
        // This implementation is deliberately single-tenant and single-region.
        if !ssf.belongs_to(&database)
            || config.tenant_id != "default"
            || !config.storage_tenant.is_empty()
            || config.region.is_empty()
            || config.region.len() > 32
            || !config
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !reference_valid(&config.retention_reference)
            || !files.has_reference(&config.retention_reference)
            || config.operator_secret_references.len() > 256
            || config.operator_secret_references.iter().any(|r| {
                !reference_valid(r) || r == &config.retention_reference || !files.has_reference(r)
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            governance: PostgresGovernanceStore::new(database),
            ssf,
            files,
            config,
        })
    }

    fn validate(&self, request: &GovernanceRetentionRequest) -> Result<(), StoreError> {
        let user_valid = match &request.target {
            GovernanceRetentionTarget::User {
                user_id, aliases, ..
            } => {
                !user_id.is_empty()
                    && user_id.len() <= 256
                    && aliases.len() <= 64
                    && aliases.iter().all(|a| !a.is_empty() && a.len() <= 1024)
            }
            GovernanceRetentionTarget::Tenant { .. } => true,
        };
        if !user_valid
            || request.target.tenant_id() != self.config.tenant_id
            || request.target.job_id().is_empty()
            || request.target.job_id().len() > 256
            || request.storage_tenant != self.config.storage_tenant
            || request.configured_regions != [self.config.region.clone()]
            || request.primary_erasure_at <= 0
            || request.retention_anchor_at < request.primary_erasure_at
            || request.verified_at < request.retention_anchor_at
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Bind an operator statement to this exact target, deployment and anchor.
    /// The digest conveys no proof that an external resource was inspected.
    pub fn retention_request_digest(
        &self,
        request: &GovernanceRetentionRequest,
    ) -> Result<String, StoreError> {
        self.validate(request)?;
        #[derive(Serialize)]
        struct Binding<'a> {
            tenant: &'a str,
            storage_tenant: &'a str,
            region: &'a str,
            job_id: &'a str,
            user_id: Option<&'a str>,
            aliases: &'a [String],
            primary_erasure_at: i64,
            retention_anchor_at: i64,
        }
        let (user_id, aliases) = match &request.target {
            GovernanceRetentionTarget::User {
                user_id, aliases, ..
            } => (Some(user_id.as_str()), aliases.as_slice()),
            GovernanceRetentionTarget::Tenant { .. } => (None, [].as_slice()),
        };
        let binding = Binding {
            tenant: &self.config.tenant_id,
            storage_tenant: &self.config.storage_tenant,
            region: &self.config.region,
            job_id: request.target.job_id(),
            user_id,
            aliases,
            primary_erasure_at: request.primary_erasure_at,
            retention_anchor_at: request.retention_anchor_at,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&binding).map_err(|_| invalid())?)
        ))
    }

    async fn replicas(
        &self,
        request: &GovernanceRetentionRequest,
    ) -> Result<BTreeMap<String, GovernanceReplicaEvidence>, StoreError> {
        self.validate(request)?;
        let inventory = self
            .governance
            .resource_inventory(&self.ssf, request)
            .await?;
        Ok(BTreeMap::from([(
            self.config.region.clone(),
            GovernanceReplicaEvidence {
                verification_state: "provider_strong_read".into(),
                verified_at: Some(crate::current_unix_secs()),
                live_counts: inventory.live_counts,
                retained_counts: inventory.retained_counts,
            },
        )]))
    }
}

impl GovernanceResourceBackend for PostgresGovernanceResourceBackend {
    async fn schedule_secret_deletion(
        &self,
        _: &str,
        _: &str,
        _: i64,
    ) -> Result<SecretDeletionStatus, StoreError> {
        Err(StoreError::Permanent(
            "Mounted resources require operator lifecycle management".into(),
        ))
    }

    async fn inspect_secret_deletion(
        &self,
        reference: &str,
        fingerprint: &str,
    ) -> Result<SecretDeletionStatus, StoreError> {
        if !self.config.operator_secret_references.contains(reference)
            || resource_fingerprint(reference) != fingerprint
        {
            return Err(invalid());
        }
        Ok(if self.files.resolve(reference).await?.is_some() {
            SecretDeletionStatus::Present
        } else {
            SecretDeletionStatus::Absent
        })
    }

    async fn verify_replicas(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<BTreeMap<String, GovernanceReplicaEvidence>>, StoreError> {
        self.replicas(&request).await.map(Some)
    }

    async fn verify_retention(
        &self,
        request: GovernanceRetentionRequest,
    ) -> Result<Option<GovernanceRetentionObservation>, StoreError> {
        self.validate(&request)?;
        let document = self.files.resolve(&self.config.retention_reference).await?;
        let mut resources = portable_retention_evidence(request.retention_anchor_at);
        let counts = self
            .governance
            .resource_retained_counts(&self.ssf, &request)
            .await?;
        let deadline = request
            .retention_anchor_at
            .checked_add(PORTABLE_RETENTION_SECS)
            .ok_or_else(invalid)?;
        for (name, count) in &counts {
            resources.insert(
                name.clone(),
                resource(
                    if *count == 0 {
                        "provider_verified_absent"
                    } else {
                        "provider_observed_retained"
                    },
                    "postgresql_repeatable_read",
                    "PostgreSQL physical retained records",
                    Some(deadline),
                ),
            );
        }
        let mut external_absent = false;
        let mut receipt_deadline = None;
        if let Some(document) = document.as_deref() {
            let bundle: ReceiptBundle = serde_json::from_str(document).map_err(|_| invalid())?;
            if bundle.schema_version != 1 || bundle.receipts.len() > 128 {
                return Err(invalid());
            }
            let digest = self.retention_request_digest(&request)?;
            let mut seen = BTreeSet::new();
            for receipt in &bundle.receipts {
                if !digest_valid(&receipt.request_sha256)
                    || !seen.insert(&receipt.request_sha256)
                    || receipt.observed_at <= 0
                    || receipt.valid_until <= receipt.observed_at
                    || receipt.valid_until - receipt.observed_at > RECEIPT_VALIDITY_SECS
                    || receipt
                        .resources
                        .iter()
                        .iter()
                        .any(|(_, r)| !digest_valid(&r.manifest_sha256))
                {
                    return Err(invalid());
                }
                if receipt.request_sha256 != digest {
                    continue;
                }
                let now = crate::current_unix_secs();
                if receipt.observed_at > now
                    || receipt.observed_at < request.retention_anchor_at
                    || now >= receipt.valid_until
                {
                    continue;
                }
                external_absent = receipt.resources.iter().iter().all(|(_, r)| r.absent);
                receipt_deadline = Some(receipt.valid_until);
                for (name, observation) in receipt.resources.iter() {
                    resources.insert(
                        name.into(),
                        resource(
                            if observation.absent {
                                "operator_attested_absent"
                            } else {
                                "operator_attested_retained"
                            },
                            "trusted_operator_attestation",
                            &format!("Operator manifest sha256:{}", observation.manifest_sha256),
                            None,
                        ),
                    );
                }
            }
        }
        let replicas = self.replicas(&request).await?;
        // Fence publication and expiry after every database lock wait.
        if self.files.resolve(&self.config.retention_reference).await? != document {
            return Err(StoreError::Transient(
                "Portable governance receipt changed".into(),
            ));
        }
        let now = crate::current_unix_secs();
        external_absent &= receipt_deadline.is_some_and(|deadline| now < deadline);
        if receipt_deadline.is_some_and(|deadline| now >= deadline) {
            for name in ["operator_backups", "operator_logs"] {
                if let Some(resource) = resources.get_mut(name) {
                    resource.state = "operator_attestation_expired".into();
                }
            }
        }
        let live_absent = replicas
            .values()
            .all(|r| r.live_counts.values().all(|c| *c == 0));
        Ok(Some(GovernanceRetentionObservation {
            complete: now >= deadline
                && external_absent
                && live_absent
                && counts.values().all(|c| *c == 0),
            replica_live_counts: replicas,
            retention_resources: resources,
        }))
    }
}
