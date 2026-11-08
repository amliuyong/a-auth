//! Operator-mounted single-tenant registry. Durable checkpoints carry hashes
//! and lifecycle metadata, never the file's credential values.

use super::*;
use crate::{
    adapters::{file_secrets::FileSecretResolver, postgres::PostgresStore},
    ports::{SecretResolver, StoreError},
};
use serde::Deserializer;

#[derive(Clone)]
pub(super) struct MountedAdminCredentialBackend {
    store: PostgresStore,
    files: FileSecretResolver,
    namespace: String,
    reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u8,
    version_created_at: i64,
    sets: Vec<AdminCredentialSet>,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecordMetadata {
    credential_id: String,
    secret_sha256: String,
    created_at: i64,
    not_before: i64,
    expires_at: i64,
}

impl RecordMetadata {
    fn from_record(record: &NormalizedRecord) -> Self {
        Self {
            credential_id: record.credential_id.clone(),
            secret_sha256: record.secret_sha256.clone(),
            created_at: record.created_at,
            not_before: record.not_before,
            expires_at: record.expires_at,
        }
    }

    fn normalized(&self) -> Result<NormalizedRecord, AdminCredentialError> {
        if !valid_credential_id(&self.credential_id)
            || self.secret_sha256.len() != 64
            || !self
                .secret_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.created_at <= 0
            || self.created_at > self.not_before
            || self.not_before >= self.expires_at
            || self
                .expires_at
                .checked_sub(self.created_at)
                .is_none_or(|lifetime| lifetime > MAX_ADMIN_CREDENTIAL_LIFETIME_SECS)
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        Ok(NormalizedRecord {
            credential_id: self.credential_id.clone(),
            secret: String::new(),
            secret_sha256: self.secret_sha256.clone(),
            created_at: self.created_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SetMetadata {
    owner: AdminCredentialOwner,
    revision: u64,
    current: RecordMetadata,
    #[serde(deserialize_with = "required_option")]
    next: Option<RecordMetadata>,
    #[serde(deserialize_with = "required_option")]
    retire_current_at: Option<i64>,
    retired: Vec<AdminRetiredCredential>,
}

impl SetMetadata {
    fn from_set(set: &NormalizedSet) -> Self {
        Self {
            owner: set.owner.clone(),
            revision: set.revision,
            current: RecordMetadata::from_record(&set.current),
            next: set.next.as_ref().map(RecordMetadata::from_record),
            retire_current_at: set.retire_current_at,
            retired: set.retired.clone(),
        }
    }

    fn normalized(&self, version_created_at: i64) -> Result<NormalizedSet, AdminCredentialError> {
        validate_owner(&self.owner)?;
        if self.revision == 0 || !allowed_owner(&self.owner) {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        let current = self.current.normalized()?;
        let next = self
            .next
            .as_ref()
            .map(RecordMetadata::normalized)
            .transpose()?;
        let retired = normalize_retired(self.retired.clone())?;
        if retired
            .iter()
            .any(|entry| entry.retired_at > version_created_at)
            || current.created_at > version_created_at
            || next
                .as_ref()
                .is_some_and(|entry| entry.created_at > version_created_at)
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        match (&next, self.retire_current_at) {
            (None, None) => {}
            (Some(next), Some(retire_at))
                if next.not_before >= current.not_before
                    && next.not_before < retire_at
                    && retire_at <= current.expires_at
                    && retire_at < next.expires_at
                    && retire_at - next.not_before <= MAX_ADMIN_ROTATION_OVERLAP_SECS
                    && next.credential_id != current.credential_id
                    && next.secret_sha256 != current.secret_sha256 => {}
            _ => return Err(AdminCredentialError::InvalidConfiguration),
        }
        for record in std::iter::once(&current).chain(next.iter()) {
            if retired.iter().any(|retired| {
                retired.credential_id == record.credential_id
                    || retired.secret_sha256 == record.secret_sha256
            }) {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
        Ok(NormalizedSet {
            owner: self.owner.clone(),
            revision: self.revision,
            current,
            next,
            retire_current_at: self.retire_current_at,
            retired,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u8,
    namespace: String,
    document_digest: Vec<u8>,
    version_created_at: i64,
    sets: Vec<SetMetadata>,
}

fn allowed_owner(owner: &AdminCredentialOwner) -> bool {
    matches!(owner, AdminCredentialOwner::Platform)
        || owner == &AdminCredentialOwner::tenant("default")
        || owner == &AdminCredentialOwner::scim_tenant("default")
}

fn owner_rank(owner: &AdminCredentialOwner) -> u8 {
    match owner {
        AdminCredentialOwner::Platform => 0,
        AdminCredentialOwner::Tenant { .. } => 1,
        AdminCredentialOwner::ScimTenant { .. } => 2,
    }
}

fn invalid_store() -> StoreError {
    StoreError::Permanent("Invalid mounted administrator checkpoint".into())
}

fn store_error(error: StoreError) -> AdminCredentialError {
    match error {
        StoreError::Transient(_) => AdminCredentialError::Unavailable,
        StoreError::Permanent(_) => AdminCredentialError::InvalidConfiguration,
    }
}

impl MountedAdminCredentialBackend {
    pub(super) async fn load(
        &self,
        offboarded: &HashSet<String>,
        now: i64,
    ) -> Result<CredentialRegistry, AdminCredentialError> {
        let document = self
            .files
            .resolve(&self.reference)
            .await
            .map_err(store_error)?
            .ok_or(AdminCredentialError::InvalidConfiguration)?;
        let bundle: Bundle = serde_json::from_str(&document)
            .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
        if bundle.schema_version != 1
            || bundle.version_created_at <= 0
            || bundle.version_created_at > now.max(crate::current_unix_secs())
            || bundle.sets.len() != 3
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        let mut all_sets = HashMap::new();
        for wire in bundle.sets {
            if !allowed_owner(&wire.owner) {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
            let owner = wire.owner.clone();
            let set = normalize_set(wire, bundle.version_created_at, &owner)?;
            if all_sets.insert(owner, set).is_some() {
                return Err(AdminCredentialError::InvalidConfiguration);
            }
        }
        validate_registry_uniqueness(all_sets.values())?;
        let mut metadata: Vec<_> = all_sets.values().map(SetMetadata::from_set).collect();
        metadata.sort_by_key(|set| owner_rank(&set.owner));
        let checkpoint = Checkpoint {
            schema_version: 1,
            namespace: self.namespace.clone(),
            document_digest: Sha256::digest(document.as_bytes()).to_vec(),
            version_created_at: bundle.version_created_at,
            sets: metadata,
        };
        // Validate every metadata field before initial durable admission too.
        for set in &checkpoint.sets {
            set.normalized(checkpoint.version_created_at)?;
        }
        let record = serde_json::to_string(&checkpoint)
            .map_err(|_| AdminCredentialError::InvalidConfiguration)?;
        self.store
            .admit_mounted_admin_checkpoint(
                &self.namespace,
                &checkpoint.document_digest,
                checkpoint.version_created_at,
                &record,
                |digest, created, record| {
                    if record.len() > 65_536 {
                        return Err(invalid_store());
                    }
                    let prior: Checkpoint =
                        serde_json::from_str(record).map_err(|_| invalid_store())?;
                    if prior.schema_version != 1
                        || prior.namespace != self.namespace
                        || prior.document_digest != digest
                        || digest.len() != 32
                        || prior.version_created_at != created
                        || created <= 0
                        || created > checkpoint.version_created_at
                        || prior.sets.len() != 3
                        || serde_json::to_string(&prior).map_err(|_| invalid_store())? != record
                    {
                        return Err(invalid_store());
                    }
                    let mut owners = HashSet::new();
                    let mut ids = HashSet::new();
                    let mut hashes = HashSet::new();
                    let observed = now.max(crate::current_unix_secs());
                    for old in &prior.sets {
                        if !owners.insert(old.owner.clone()) {
                            return Err(invalid_store());
                        }
                        let normalized = old.normalized(created).map_err(|_| invalid_store())?;
                        for entry in std::iter::once(&old.current).chain(old.next.iter()) {
                            if !ids.insert(entry.credential_id.clone())
                                || !hashes.insert(entry.secret_sha256.clone())
                            {
                                return Err(invalid_store());
                            }
                        }
                        let current = all_sets.get(&old.owner).ok_or_else(invalid_store)?;
                        if current.revision == old.revision {
                            if SetMetadata::from_set(current) != *old {
                                return Err(invalid_store());
                            }
                        } else {
                            validate_transition(&normalized, current, observed)
                                .map_err(|_| invalid_store())?;
                        }
                        let disabled = !matches!(old.owner, AdminCredentialOwner::Platform)
                            && offboarded.contains("default");
                        if !disabled && !current.has_active_credential(observed) {
                            return Err(invalid_store());
                        }
                    }
                    Ok(())
                },
            )
            .await
            .map_err(store_error)?;
        let observed = self
            .files
            .resolve(&self.reference)
            .await
            .map_err(store_error)?;
        if observed.as_deref() != Some(document.as_str())
            || !self
                .store
                .mounted_admin_checkpoint_matches(
                    &self.namespace,
                    &checkpoint.document_digest,
                    checkpoint.version_created_at,
                    &record,
                )
                .await
                .map_err(store_error)?
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        let sets = all_sets
            .into_iter()
            .filter(|(owner, _)| {
                matches!(owner, AdminCredentialOwner::Platform) || !offboarded.contains("default")
            })
            .collect();
        Ok(CredentialRegistry { sets })
    }
}

impl AdminCredentialResolver {
    /// Single-tenant mounted registry plus durable, secret-free revision trust.
    /// Operators rotate the complete projected bundle; AWS stage mutations are
    /// not a capability of this provider.
    pub fn mounted(
        store: PostgresStore,
        files: FileSecretResolver,
        namespace: String,
        reference: String,
        cache_ttl: Duration,
    ) -> Result<Self, AdminCredentialError> {
        if namespace.is_empty()
            || namespace.len() > 1024
            || reference.is_empty()
            || reference.len() > 1024
            || cache_ttl != Duration::ZERO
        {
            return Err(AdminCredentialError::InvalidConfiguration);
        }
        Ok(Self {
            platform_secret_ref: Some(reference.clone()),
            tenant_secret_refs: HashMap::from([("default".into(), reference.clone())]),
            scim_tenant_secret_refs: HashMap::from([("default".into(), reference.clone())]),
            offboarded_tenants: HashSet::new(),
            backend: AdminCredentialBackend::Mounted(MountedAdminCredentialBackend {
                store,
                files,
                namespace,
                reference,
            }),
            cache_ttl,
            cache: Mutex::new(CacheState::default()),
            refresh: Mutex::new(()),
        })
    }
}
