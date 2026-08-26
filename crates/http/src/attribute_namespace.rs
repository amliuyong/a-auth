//! Exact audience aliases for canonical RS user-attribute namespaces.
//!
//! This module owns the pure registration and migration rules. HTTP handlers and
//! storage adapters call this interface instead of reimplementing matching or
//! merge behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::ports::{NamespaceAttrs, StoreError};

pub const MAX_EXACT_AUDIENCES: usize = 32;
pub const MAX_NAMESPACE_URI_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudienceState {
    Active,
    Blocked,
    Retired,
    CanonicalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudienceBinding {
    pub audience: String,
    pub canonical_namespace: String,
    pub registration_revision: u64,
    pub state: AudienceState,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceResolution {
    Active { canonical_namespace: String },
    Blocked,
    Unbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeWriteAuthority {
    Unbound {
        namespace: String,
    },
    ActiveCanonical {
        canonical_namespace: String,
        registration_revision: u64,
    },
    ActiveAudience {
        audience: String,
        canonical_namespace: String,
        registration_revision: u64,
    },
}

impl AttributeWriteAuthority {
    pub fn canonical_namespace(&self) -> &str {
        match self {
            Self::Unbound { namespace } => namespace,
            Self::ActiveCanonical {
                canonical_namespace,
                ..
            }
            | Self::ActiveAudience {
                canonical_namespace,
                ..
            } => canonical_namespace,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeWriteResolution {
    Authorized(AttributeWriteAuthority),
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Pending,
    Active,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceChangeKind {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMigrationPhase {
    Validating,
    Migrating,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationSnapshot {
    pub revision: u64,
    pub exact_audiences: BTreeSet<String>,
    pub state: RegistrationState,
    pub last_operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceMigrationOperation {
    pub operation_id: String,
    pub expected_registration_revision: u64,
    pub revision: u64,
    pub kind: NamespaceChangeKind,
    pub desired_exact_audiences: BTreeSet<String>,
    pub source_namespaces: BTreeSet<String>,
    pub previous_registration: Option<RegistrationSnapshot>,
    pub previous_bindings: BTreeMap<String, Option<AudienceBinding>>,
    pub phase: NamespaceMigrationPhase,
    pub cursor: Option<String>,
    pub scan_complete: bool,
    pub started_mutation: bool,
    #[serde(default)]
    pub inflight_user_id: Option<String>,
    pub users_scanned: u64,
    pub users_completed: u64,
    pub conflict_count: u64,
    pub conflict_user_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceRegistration {
    pub canonical_namespace: String,
    pub revision: u64,
    pub exact_audiences: BTreeSet<String>,
    pub state: RegistrationState,
    pub last_operation_id: Option<String>,
    pub operation: Option<NamespaceMigrationOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelledNamespaceOperation {
    pub canonical_namespace: String,
    pub operation_id: String,
    pub operation_revision: u64,
    pub restored_registration: Option<NamespaceRegistration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginNamespaceChange {
    pub canonical_namespace: String,
    pub exact_audiences: BTreeSet<String>,
    pub expected_revision: u64,
    pub operation_id: String,
    pub kind: NamespaceChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginNamespaceChangeOutcome {
    Started(Box<NamespaceRegistration>),
    RevisionConflict {
        current: u64,
    },
    Busy {
        operation_id: String,
    },
    AudienceConflict {
        audience: String,
        canonical_namespace: String,
    },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceOperationCheckpoint {
    pub expected_revision: u64,
    pub phase: NamespaceMigrationPhase,
    pub cursor: Option<String>,
    pub scan_complete: bool,
    pub started_mutation: bool,
    pub inflight_user_id: Option<String>,
    pub users_scanned: u64,
    pub users_completed: u64,
    pub conflict_count: u64,
    pub conflict_user_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceChangeOutcome {
    Updated(NamespaceRegistration),
    Cancelled(Option<NamespaceRegistration>),
    OperationConflict { operation_id: String, revision: u64 },
    InvalidState,
    CannotCancel,
    NotFound,
}

pub fn invalid_inflight_checkpoint(
    operation: &NamespaceMigrationOperation,
    checkpoint: &NamespaceOperationCheckpoint,
) -> bool {
    if checkpoint.inflight_user_id.is_some()
        && (checkpoint.phase != NamespaceMigrationPhase::Migrating
            || !checkpoint.started_mutation
            || checkpoint.scan_complete)
    {
        return true;
    }
    let same_page = checkpoint.phase == operation.phase
        && checkpoint.cursor == operation.cursor
        && checkpoint.scan_complete == operation.scan_complete
        && checkpoint.users_scanned == operation.users_scanned;
    match (
        operation.inflight_user_id.as_deref(),
        checkpoint.inflight_user_id.as_deref(),
    ) {
        (None, None) => false,
        (None, Some(_)) => {
            !operation.started_mutation
                || !same_page
                || checkpoint.users_completed != operation.users_completed
                || checkpoint.conflict_count != operation.conflict_count
        }
        (Some(current), Some(next)) => {
            current != next
                || !same_page
                || checkpoint.users_completed != operation.users_completed
                || checkpoint.conflict_count != operation.conflict_count
        }
        (Some(_), None) => {
            !same_page
                || checkpoint.users_completed > operation.users_completed.saturating_add(1)
                || checkpoint.conflict_count > operation.conflict_count.saturating_add(1)
        }
    }
}

pub trait AttributeNamespaceStore: Send + Sync {
    fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> impl Future<Output = Result<AudienceResolution, StoreError>> + Send;

    fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> impl Future<Output = Result<AttributeWriteResolution, StoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> impl Future<Output = Result<Option<NamespaceRegistration>, StoreError>> + Send;

    fn list(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Vec<NamespaceRegistration>, StoreError>> + Send;

    fn begin_change(
        &self,
        tenant: &str,
        request: BeginNamespaceChange,
    ) -> impl Future<Output = Result<BeginNamespaceChangeOutcome, StoreError>> + Send;

    fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: NamespaceOperationCheckpoint,
    ) -> impl Future<Output = Result<NamespaceChangeOutcome, StoreError>> + Send;

    fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> impl Future<Output = Result<NamespaceChangeOutcome, StoreError>> + Send;

    fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> impl Future<Output = Result<NamespaceChangeOutcome, StoreError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationDecision {
    Noop,
    Replace {
        attributes: BTreeMap<String, NamespaceAttrs>,
    },
    Conflict {
        namespaces: Vec<String>,
    },
    RevisionExhausted,
}

pub fn validate_namespace_uri(value: &str) -> bool {
    if value.len() > MAX_NAMESPACE_URI_BYTES || value.contains(['*', '{', '}']) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    parsed.fragment().is_none()
}

pub fn validate_exact_audiences(
    canonical_namespace: &str,
    exact_audiences: &[String],
) -> Result<BTreeSet<String>, &'static str> {
    if !validate_namespace_uri(canonical_namespace) {
        return Err("canonical_namespace must be an absolute resource URI");
    }
    if exact_audiences.is_empty() || exact_audiences.len() > MAX_EXACT_AUDIENCES {
        return Err("exact_audiences must contain 1..=32 values");
    }
    let mut exact = BTreeSet::new();
    for audience in exact_audiences {
        if !validate_namespace_uri(audience) {
            return Err("exact audience must be an absolute resource URI");
        }
        if !exact.insert(audience.clone()) {
            return Err("duplicate exact audience");
        }
    }
    Ok(exact)
}

pub fn resolve_exact(binding: Option<&AudienceBinding>, verified_aud: &str) -> AudienceResolution {
    let Some(binding) = binding else {
        return AudienceResolution::Unbound;
    };
    if binding.audience != verified_aud {
        return AudienceResolution::Blocked;
    }
    match binding.state {
        AudienceState::Active => AudienceResolution::Active {
            canonical_namespace: binding.canonical_namespace.clone(),
        },
        AudienceState::Blocked | AudienceState::Retired | AudienceState::CanonicalOnly => {
            AudienceResolution::Blocked
        }
    }
}

pub fn plan_attribute_migration(
    attributes: &BTreeMap<String, NamespaceAttrs>,
    canonical_namespace: &str,
    source_namespaces: &BTreeSet<String>,
) -> MigrationDecision {
    let mut ordered_namespaces = Vec::with_capacity(source_namespaces.len() + 1);
    ordered_namespaces.push(canonical_namespace.to_string());
    ordered_namespaces.extend(
        source_namespaces
            .iter()
            .filter(|namespace| namespace.as_str() != canonical_namespace)
            .cloned(),
    );

    let present: Vec<(&String, &NamespaceAttrs)> = ordered_namespaces
        .iter()
        .filter_map(|namespace| attributes.get_key_value(namespace))
        .collect();
    if present.is_empty() {
        return MigrationDecision::Noop;
    }
    let valued: Vec<(&String, &NamespaceAttrs)> = present
        .iter()
        .copied()
        .filter(|(_, value)| !value.kv.is_empty())
        .collect();
    let (migrated_values, migrated_owners) = if let Some((_, first)) = valued.first().copied() {
        if valued.iter().any(|(_, value)| {
            value.kv != first.kv || value.federation_owners != first.federation_owners
        }) {
            return MigrationDecision::Conflict {
                namespaces: valued
                    .iter()
                    .map(|(namespace, _)| (*namespace).clone())
                    .collect(),
            };
        }
        (first.kv.clone(), first.federation_owners.clone())
    } else {
        (BTreeMap::new(), BTreeMap::new())
    };

    let aliases_present = present
        .iter()
        .any(|(namespace, _)| namespace.as_str() != canonical_namespace);
    if !aliases_present && attributes.contains_key(canonical_namespace) {
        return MigrationDecision::Noop;
    }
    let Some(next_revision) = present
        .iter()
        .map(|(_, value)| value.revision)
        .max()
        .and_then(|revision| revision.checked_add(1))
    else {
        return MigrationDecision::RevisionExhausted;
    };

    let mut migrated = attributes.clone();
    for namespace in source_namespaces {
        if namespace != canonical_namespace {
            migrated.remove(namespace);
        }
    }
    migrated.insert(
        canonical_namespace.to_string(),
        NamespaceAttrs {
            revision: next_revision,
            kv: migrated_values,
            federation_owners: migrated_owners,
        },
    );
    MigrationDecision::Replace {
        attributes: migrated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(revision: u64, values: &[(&str, &str)]) -> NamespaceAttrs {
        NamespaceAttrs {
            revision,
            kv: values
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            federation_owners: BTreeMap::new(),
        }
    }

    #[test]
    fn namespace_uris_are_exact_absolute_resources_without_patterns() {
        assert!(validate_namespace_uri("https://finance.example.com"));
        assert!(validate_namespace_uri("urn:example:finance"));
        assert!(validate_namespace_uri(
            "https://finance.example.com/Region/One"
        ));
        assert!(!validate_namespace_uri("finance"));
        assert!(!validate_namespace_uri("https://finance.example.com/#frag"));
        assert!(!validate_namespace_uri("https://*.example.com"));
        assert!(!validate_namespace_uri(
            "https://finance.example.com/{tenant}"
        ));
        assert!(validate_namespace_uri(&format!(
            "https://example.com/{}",
            "a".repeat(MAX_NAMESPACE_URI_BYTES - "https://example.com/".len())
        )));
        assert!(!validate_namespace_uri(&format!(
            "https://example.com/{}",
            "a".repeat(MAX_NAMESPACE_URI_BYTES + 1 - "https://example.com/".len())
        )));

        let exact = validate_exact_audiences(
            "https://resources.example.com/finance",
            &[
                "https://finance.example.com".into(),
                "https://finance.example.com/".into(),
                "https://FINANCE.example.com".into(),
                "https://finance.example.com:443".into(),
                "https://finance.example.com/Region/One".into(),
                "https://finance.example.com/region/one".into(),
            ],
        )
        .unwrap();
        assert_eq!(exact.len(), 6, "no URI normalization is permitted");

        let maximum = (0..MAX_EXACT_AUDIENCES)
            .map(|index| format!("https://finance.example.com/{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_exact_audiences("https://resources.example.com/finance", &maximum)
                .unwrap()
                .len(),
            MAX_EXACT_AUDIENCES
        );
        let mut over_limit = maximum;
        over_limit.push("https://finance.example.com/overflow".into());
        assert_eq!(
            validate_exact_audiences("https://resources.example.com/finance", &over_limit),
            Err("exact_audiences must contain 1..=32 values")
        );
    }

    #[test]
    fn runtime_resolution_is_exact_and_fail_closed_for_managed_states() {
        let active = AudienceBinding {
            audience: "https://finance.example.com".into(),
            canonical_namespace: "https://resources.example.com/finance".into(),
            registration_revision: 3,
            state: AudienceState::Active,
            operation_id: None,
        };
        assert_eq!(
            resolve_exact(Some(&active), "https://finance.example.com"),
            AudienceResolution::Active {
                canonical_namespace: "https://resources.example.com/finance".into()
            }
        );
        assert_eq!(
            resolve_exact(Some(&active), "https://finance.example.com/"),
            AudienceResolution::Blocked,
            "a hash/key collision or mismatched stored URI must fail closed"
        );

        for state in [
            AudienceState::Blocked,
            AudienceState::Retired,
            AudienceState::CanonicalOnly,
        ] {
            let binding = AudienceBinding {
                state,
                ..active.clone()
            };
            assert_eq!(
                resolve_exact(Some(&binding), "https://finance.example.com"),
                AudienceResolution::Blocked
            );
        }
        assert_eq!(
            resolve_exact(None, "https://unmanaged.example.com"),
            AudienceResolution::Unbound
        );
    }

    #[test]
    fn migration_moves_one_unique_value_and_removes_alias_keys() {
        let canonical = "https://resources.example.com/finance";
        let alias = "https://finance.example.com";
        let mut current = BTreeMap::new();
        current.insert(alias.into(), attrs(4, &[("role", "admin")]));
        let sources = BTreeSet::from([alias.to_string()]);

        let MigrationDecision::Replace { attributes } =
            plan_attribute_migration(&current, canonical, &sources)
        else {
            panic!("expected a safe migration");
        };
        assert!(!attributes.contains_key(alias));
        let migrated = attributes.get(canonical).unwrap();
        assert_eq!(migrated.kv.get("role").map(String::as_str), Some("admin"));
        assert_eq!(migrated.revision, 5);
    }

    #[test]
    fn migration_deduplicates_identical_values_but_never_merges_different_values() {
        let canonical = "https://resources.example.com/finance";
        let a = "https://finance.example.com";
        let b = "https://finance-dr.example.com";
        let sources = BTreeSet::from([a.to_string(), b.to_string()]);

        let mut identical = BTreeMap::new();
        identical.insert(canonical.into(), attrs(2, &[("role", "admin")]));
        identical.insert(a.into(), attrs(7, &[("role", "admin")]));
        identical.insert(b.into(), attrs(3, &[("role", "admin")]));
        let MigrationDecision::Replace { attributes } =
            plan_attribute_migration(&identical, canonical, &sources)
        else {
            panic!("identical values may be deduplicated");
        };
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[canonical].revision, 8);

        let mut conflicting = identical;
        conflicting.insert(b.into(), attrs(3, &[("role", "viewer")]));
        assert_eq!(
            plan_attribute_migration(&conflicting, canonical, &sources),
            MigrationDecision::Conflict {
                namespaces: vec![canonical.into(), b.into(), a.into()]
            }
        );
    }

    #[test]
    fn migration_moves_empty_revision_tombstones_to_the_canonical_namespace() {
        let canonical = "https://resources.example.com/finance";
        let alias = "https://finance.example.com";
        let sources = BTreeSet::from([alias.to_string()]);
        let current = BTreeMap::from([(alias.to_string(), attrs(4, &[]))]);

        let MigrationDecision::Replace { attributes } =
            plan_attribute_migration(&current, canonical, &sources)
        else {
            panic!("an empty revision tombstone still requires structural migration");
        };
        assert!(!attributes.contains_key(alias));
        assert_eq!(attributes[canonical], attrs(5, &[]));
    }

    #[tokio::test]
    async fn beginning_change_blocks_exact_keys_and_enforces_tenant_uniqueness() {
        use crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore;

        let store = MemoryAttributeNamespaceStore::default();
        let alias = "https://finance.example.com";
        let first = store
            .begin_change(
                "tenant-a",
                BeginNamespaceChange {
                    canonical_namespace: "https://resources.example.com/finance".into(),
                    exact_audiences: BTreeSet::from([alias.to_string()]),
                    expected_revision: 0,
                    operation_id: "operation-a".into(),
                    kind: NamespaceChangeKind::Upsert,
                },
            )
            .await
            .unwrap();
        assert!(matches!(first, BeginNamespaceChangeOutcome::Started(_)));
        assert_eq!(
            store.resolve("tenant-a", alias).await.unwrap(),
            AudienceResolution::Blocked
        );
        assert_eq!(
            store
                .resolve("tenant-a", "https://resources.example.com/finance")
                .await
                .unwrap(),
            AudienceResolution::Blocked
        );

        let collision = store
            .begin_change(
                "tenant-a",
                BeginNamespaceChange {
                    canonical_namespace: "https://resources.example.com/other".into(),
                    exact_audiences: BTreeSet::from([alias.to_string()]),
                    expected_revision: 0,
                    operation_id: "operation-b".into(),
                    kind: NamespaceChangeKind::Upsert,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            collision,
            BeginNamespaceChangeOutcome::AudienceConflict {
                audience: alias.into(),
                canonical_namespace: "https://resources.example.com/finance".into(),
            }
        );

        assert!(matches!(
            store
                .begin_change(
                    "tenant-b",
                    BeginNamespaceChange {
                        canonical_namespace: "https://resources.example.com/other".into(),
                        exact_audiences: BTreeSet::from([alias.to_string()]),
                        expected_revision: 0,
                        operation_id: "operation-c".into(),
                        kind: NamespaceChangeKind::Upsert,
                    },
                )
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Started(_)
        ));
    }

    #[tokio::test]
    async fn activation_cancel_and_removal_preserve_fail_closed_lifecycle() {
        use crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore;

        let store = MemoryAttributeNamespaceStore::default();
        let canonical = "https://resources.example.com/finance";
        let primary = "https://finance.example.com";
        let replacement = "https://finance-dr.example.com";
        let begin = |operation_id: &str, audience: &str, expected_revision| BeginNamespaceChange {
            canonical_namespace: canonical.into(),
            exact_audiences: BTreeSet::from([audience.to_string()]),
            expected_revision,
            operation_id: operation_id.into(),
            kind: NamespaceChangeKind::Upsert,
        };

        store
            .begin_change("tenant-a", begin("operation-a", primary, 0))
            .await
            .unwrap();
        let ready = store
            .checkpoint(
                "tenant-a",
                canonical,
                "operation-a",
                NamespaceOperationCheckpoint {
                    expected_revision: 1,
                    phase: NamespaceMigrationPhase::Migrating,
                    cursor: None,
                    scan_complete: true,
                    started_mutation: false,
                    inflight_user_id: None,
                    users_scanned: 0,
                    users_completed: 0,
                    conflict_count: 0,
                    conflict_user_ids: vec![],
                },
            )
            .await
            .unwrap();
        assert!(matches!(ready, NamespaceChangeOutcome::Updated(_)));
        let active = store
            .activate("tenant-a", canonical, "operation-a", 2)
            .await
            .unwrap();
        assert!(matches!(active, NamespaceChangeOutcome::Updated(_)));
        assert_eq!(
            store.resolve("tenant-a", primary).await.unwrap(),
            AudienceResolution::Active {
                canonical_namespace: canonical.into()
            }
        );
        assert_eq!(
            store.resolve("tenant-a", canonical).await.unwrap(),
            AudienceResolution::Blocked,
            "canonical is not an audience unless explicitly registered"
        );
        assert_eq!(
            store
                .resolve_write_authority("tenant-a", canonical)
                .await
                .unwrap(),
            AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveCanonical {
                canonical_namespace: canonical.into(),
                registration_revision: 1,
            })
        );
        assert_eq!(
            store
                .resolve_write_authority("tenant-a", primary)
                .await
                .unwrap(),
            AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveAudience {
                audience: primary.into(),
                canonical_namespace: canonical.into(),
                registration_revision: 1,
            })
        );
        assert_eq!(
            store
                .resolve_write_authority("tenant-a", "https://unbound.example.com")
                .await
                .unwrap(),
            AttributeWriteResolution::Authorized(AttributeWriteAuthority::Unbound {
                namespace: "https://unbound.example.com".into(),
            })
        );

        store
            .begin_change("tenant-a", begin("operation-b", replacement, 1))
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve_write_authority("tenant-a", primary)
                .await
                .unwrap(),
            AttributeWriteResolution::Blocked
        );
        assert_eq!(
            store
                .resolve_write_authority("tenant-a", replacement)
                .await
                .unwrap(),
            AttributeWriteResolution::Blocked
        );
        assert!(matches!(
            store
                .cancel("tenant-a", canonical, "operation-b", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(Some(_))
        ));
        assert!(matches!(
            store
                .cancel("tenant-a", canonical, "operation-b", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(Some(_))
        ));
        assert!(matches!(
            store.resolve("tenant-a", primary).await.unwrap(),
            AudienceResolution::Active { .. }
        ));
        assert_eq!(
            store.resolve("tenant-a", replacement).await.unwrap(),
            AudienceResolution::Unbound
        );

        store
            .begin_change("tenant-a", begin("operation-c", replacement, 1))
            .await
            .unwrap();
        store
            .checkpoint(
                "tenant-a",
                canonical,
                "operation-c",
                NamespaceOperationCheckpoint {
                    expected_revision: 1,
                    phase: NamespaceMigrationPhase::Migrating,
                    cursor: None,
                    scan_complete: true,
                    started_mutation: true,
                    inflight_user_id: None,
                    users_scanned: 1,
                    users_completed: 1,
                    conflict_count: 0,
                    conflict_user_ids: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .cancel("tenant-a", canonical, "operation-c", 2)
                .await
                .unwrap(),
            NamespaceChangeOutcome::CannotCancel
        );
        store
            .activate("tenant-a", canonical, "operation-c", 2)
            .await
            .unwrap();
        assert_eq!(
            store.resolve("tenant-a", primary).await.unwrap(),
            AudienceResolution::Blocked,
            "removed active audience must remain retired, never unbound"
        );
        assert!(matches!(
            store.resolve("tenant-a", replacement).await.unwrap(),
            AudienceResolution::Active { .. }
        ));
    }

    #[tokio::test]
    async fn cancelled_new_registration_replays_the_terminal_result() {
        use crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore;

        let store = MemoryAttributeNamespaceStore::default();
        let canonical = "https://resources.example.com/new";
        store
            .begin_change(
                "tenant-a",
                BeginNamespaceChange {
                    canonical_namespace: canonical.into(),
                    exact_audiences: BTreeSet::from(["https://new.example.com".into()]),
                    expected_revision: 0,
                    operation_id: "operation-new".into(),
                    kind: NamespaceChangeKind::Upsert,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .cancel("tenant-a", canonical, "operation-new", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(None)
        );
        assert_eq!(
            store
                .cancel("tenant-a", canonical, "operation-new", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(None)
        );
    }

    #[tokio::test]
    async fn operation_ids_are_bound_to_one_complete_immutable_request() {
        use crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore;

        let store = MemoryAttributeNamespaceStore::default();
        let canonical = "urn:example:finance";
        let request = |operation_id: &str, expected_revision| BeginNamespaceChange {
            canonical_namespace: canonical.into(),
            exact_audiences: BTreeSet::from(["urn:example:finance:primary".into()]),
            expected_revision,
            operation_id: operation_id.into(),
            kind: NamespaceChangeKind::Upsert,
        };

        assert!(matches!(
            store
                .begin_change("tenant-a", request("operation-reused", 0))
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Started(_)
        ));
        assert!(matches!(
            store
                .begin_change("tenant-a", request("operation-reused", 1))
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Busy { .. }
        ));
        assert_eq!(
            store
                .cancel("tenant-a", canonical, "operation-reused", 1)
                .await
                .unwrap(),
            NamespaceChangeOutcome::Cancelled(None)
        );
        assert!(matches!(
            store
                .begin_change("tenant-a", request("operation-reused", 0))
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Busy { .. }
        ));

        store
            .begin_change("tenant-a", request("operation-completed", 0))
            .await
            .unwrap();
        store
            .checkpoint(
                "tenant-a",
                canonical,
                "operation-completed",
                NamespaceOperationCheckpoint {
                    expected_revision: 1,
                    phase: NamespaceMigrationPhase::Migrating,
                    cursor: None,
                    scan_complete: true,
                    started_mutation: false,
                    inflight_user_id: None,
                    users_scanned: 0,
                    users_completed: 0,
                    conflict_count: 0,
                    conflict_user_ids: vec![],
                },
            )
            .await
            .unwrap();
        store
            .activate("tenant-a", canonical, "operation-completed", 2)
            .await
            .unwrap();
        assert!(matches!(
            store
                .begin_change("tenant-a", request("operation-completed", 1))
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Busy { .. }
        ));
        assert!(matches!(
            store
                .begin_change("tenant-a", request("operation-reused", 1))
                .await
                .unwrap(),
            BeginNamespaceChangeOutcome::Busy { .. }
        ));
    }
}
