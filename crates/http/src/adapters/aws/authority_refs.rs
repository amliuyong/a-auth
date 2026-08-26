use super::*;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put};

pub const AUTHORITY_REFERENCE_SCHEMA_VERSION: &str = "client-authority-refs-v1";
const CLIENT_KEY_ATTRIBUTE: &str = "client_key";
const REFERENCE_KEY_ATTRIBUTE: &str = "reference_key";
const COVERAGE_PARTITION: &str = "meta\u{1f}coverage";
const CODE_COVERAGE_KEY: &str = "code\u{1f}client-authority-refs-v1";
const REFRESH_COVERAGE_KEY: &str = "refresh\u{1f}client-authority-refs-v1";
const MIGRATION_PARTITION: &str = "meta\u{1f}migration";
const MIGRATION_STATE_KEY: &str = "state\u{1f}client-authority-refs-v1";
const MIGRATION_REQUEST_PARTITION: &str = "meta\u{1f}migration-request";
const MIGRATION_PAGE_SIZE: i32 = 250;
const MIGRATION_CONCURRENCY: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityReferenceKind {
    Code,
    Refresh,
}

impl AuthorityReferenceKind {
    fn coverage_key(self) -> &'static str {
        match self {
            Self::Code => CODE_COVERAGE_KEY,
            Self::Refresh => REFRESH_COVERAGE_KEY,
        }
    }
}

#[derive(Clone)]
pub(crate) struct DynamoAuthorityReferenceStore {
    db: aws_sdk_dynamodb::Client,
    table: String,
    expected_coverage_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityReferenceMigrationStats {
    pub code_references: usize,
    pub refresh_references: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityReferenceMigrationProgress {
    Pending,
    Complete(AuthorityReferenceMigrationStats),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationPhase {
    Drain,
    CleanupReferences,
    BackfillCodes,
    BackfillRefreshes,
    VerifyCodes,
    VerifyRefreshes,
    PublishCoverage,
    Complete,
}

impl MigrationPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Drain => "drain",
            Self::CleanupReferences => "cleanup_references",
            Self::BackfillCodes => "backfill_codes",
            Self::BackfillRefreshes => "backfill_refreshes",
            Self::VerifyCodes => "verify_codes",
            Self::VerifyRefreshes => "verify_refreshes",
            Self::PublishCoverage => "publish_coverage",
            Self::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "drain" => Ok(Self::Drain),
            "cleanup_references" => Ok(Self::CleanupReferences),
            "backfill_codes" => Ok(Self::BackfillCodes),
            "backfill_refreshes" => Ok(Self::BackfillRefreshes),
            "verify_codes" => Ok(Self::VerifyCodes),
            "verify_refreshes" => Ok(Self::VerifyRefreshes),
            "publish_coverage" => Ok(Self::PublishCoverage),
            "complete" => Ok(Self::Complete),
            _ => Err(StoreError::Permanent(format!(
                "unknown authority reference migration phase: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationState {
    migration_id: String,
    phase: MigrationPhase,
    checkpoint_version: u64,
    invocation_started_at_ms: u64,
    drain_until: i64,
    cursor_partition: Option<String>,
    cursor_sort: Option<String>,
    code_references: usize,
    refresh_references: usize,
}

#[derive(Clone)]
pub struct DynamoAuthorityReferenceMigrator {
    db: aws_sdk_dynamodb::Client,
    codes_table: String,
    refresh_table: String,
    refs: DynamoAuthorityReferenceStore,
}

impl DynamoAuthorityReferenceStore {
    pub(crate) fn new(
        db: aws_sdk_dynamodb::Client,
        table: impl Into<String>,
        expected_coverage_version: impl Into<String>,
    ) -> Self {
        Self {
            db,
            table: table.into(),
            expected_coverage_version: expected_coverage_version.into(),
        }
    }

    pub(crate) fn table(&self) -> &str {
        &self.table
    }

    pub(crate) fn client_key(tenant: &str, client_id: &str) -> String {
        format!(
            "client#{tenant_len:08x}{tenant}{client_len:08x}{client_id}",
            tenant_len = tenant.len(),
            client_len = client_id.len(),
        )
    }

    fn source_digest(source_id: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(source_id.as_bytes()))
    }

    pub(crate) fn code_reference_key(expires_at: i64, code: &str) -> Result<String, StoreError> {
        if expires_at < 0 {
            return Err(StoreError::Permanent(
                "authorization code expiry cannot be negative".to_string(),
            ));
        }
        Ok(format!("c#{expires_at:020}#{}", Self::source_digest(code)))
    }

    pub(crate) fn refresh_reference_key(family_id: &str) -> String {
        format!("r#{}", Self::source_digest(family_id))
    }

    fn reference_item(
        tenant: &str,
        client_id: &str,
        reference_key: String,
        source_id: &str,
        kind: AuthorityReferenceKind,
        expires_at: Option<i64>,
    ) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::from([
            (
                CLIENT_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(Self::client_key(tenant, client_id)),
            ),
            (
                REFERENCE_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(reference_key),
            ),
            (
                "source_id".to_string(),
                AttributeValue::S(tpk(tenant, source_id)),
            ),
            (
                "kind".to_string(),
                AttributeValue::S(
                    match kind {
                        AuthorityReferenceKind::Code => "code",
                        AuthorityReferenceKind::Refresh => "refresh",
                    }
                    .to_string(),
                ),
            ),
            (
                "tenant_id".to_string(),
                AttributeValue::S(tenant.to_string()),
            ),
            (
                "client_id".to_string(),
                AttributeValue::S(client_id.to_string()),
            ),
        ]);
        if let Some(expires_at) = expires_at {
            item.insert(
                "expires_at".to_string(),
                AttributeValue::N(expires_at.to_string()),
            );
        }
        item
    }

    pub(crate) fn code_put(&self, tenant: &str, record: &CodeRecord) -> Result<Put, StoreError> {
        let reference_key = Self::code_reference_key(record.expires_at, &record.code)?;
        Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::reference_item(
                tenant,
                &record.client_id,
                reference_key,
                &record.code,
                AuthorityReferenceKind::Code,
                Some(record.expires_at),
            )))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build authorization code reference put: {error}"))
            })
    }

    pub(crate) fn code_delete(
        &self,
        tenant: &str,
        client_id: &str,
        expires_at: i64,
        code: &str,
    ) -> Result<Delete, StoreError> {
        let reference_key = Self::code_reference_key(expires_at, code)?;
        Delete::builder()
            .table_name(&self.table)
            .key(
                CLIENT_KEY_ATTRIBUTE,
                AttributeValue::S(Self::client_key(tenant, client_id)),
            )
            .key(REFERENCE_KEY_ATTRIBUTE, AttributeValue::S(reference_key))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!(
                    "build authorization code reference delete: {error}"
                ))
            })
    }

    pub(crate) fn refresh_put(
        &self,
        tenant: &str,
        record: &RefreshFamilyRecord,
    ) -> Result<Put, StoreError> {
        Put::builder()
            .table_name(&self.table)
            .set_item(Some(Self::reference_item(
                tenant,
                &record.client_id,
                Self::refresh_reference_key(&record.family_id),
                &record.family_id,
                AuthorityReferenceKind::Refresh,
                None,
            )))
            .build()
            .map_err(|error| StoreError::Permanent(format!("build refresh reference put: {error}")))
    }

    pub(crate) fn refresh_delete(
        &self,
        tenant: &str,
        client_id: &str,
        family_id: &str,
    ) -> Result<Delete, StoreError> {
        Delete::builder()
            .table_name(&self.table)
            .key(
                CLIENT_KEY_ATTRIBUTE,
                AttributeValue::S(Self::client_key(tenant, client_id)),
            )
            .key(
                REFERENCE_KEY_ATTRIBUTE,
                AttributeValue::S(Self::refresh_reference_key(family_id)),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build refresh reference delete: {error}"))
            })
    }

    async fn require_coverage(&self, kind: AuthorityReferenceKind) -> Result<(), StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(&self.table)
            .key(
                CLIENT_KEY_ATTRIBUTE,
                AttributeValue::S(COVERAGE_PARTITION.to_string()),
            )
            .key(
                REFERENCE_KEY_ATTRIBUTE,
                AttributeValue::S(kind.coverage_key().to_string()),
            )
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let covered = output.item().is_some_and(|item| {
            s(item.get("schema_version")).as_deref() == Some(AUTHORITY_REFERENCE_SCHEMA_VERSION)
                && s(item.get("migration_version")).as_deref()
                    == Some(self.expected_coverage_version.as_str())
        });
        if !covered {
            return Err(StoreError::Transient(format!(
                "{} coverage is incomplete",
                match kind {
                    AuthorityReferenceKind::Code => "authorization code reference",
                    AuthorityReferenceKind::Refresh => "refresh reference",
                }
            )));
        }
        Ok(())
    }

    pub(crate) async fn has_unexpired_code(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.require_coverage(AuthorityReferenceKind::Code).await?;
        if now < 0 {
            return Err(StoreError::Permanent(
                "authorization code reference query time cannot be negative".to_string(),
            ));
        }
        let lower_bound = format!("c#{now:020}$");
        let upper_bound = "c#~".to_string();
        let output = self
            .db
            .query()
            .table_name(&self.table)
            .key_condition_expression("#client = :client AND #reference BETWEEN :lower AND :upper")
            .expression_attribute_names("#client", CLIENT_KEY_ATTRIBUTE)
            .expression_attribute_names("#reference", REFERENCE_KEY_ATTRIBUTE)
            .expression_attribute_values(
                ":client",
                AttributeValue::S(Self::client_key(tenant, client_id)),
            )
            .expression_attribute_values(":lower", AttributeValue::S(lower_bound))
            .expression_attribute_values(":upper", AttributeValue::S(upper_bound))
            .consistent_read(true)
            .limit(1)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(!output.items().is_empty())
    }

    pub(crate) async fn has_active_refresh(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        self.require_coverage(AuthorityReferenceKind::Refresh)
            .await?;
        let output = self
            .db
            .query()
            .table_name(&self.table)
            .key_condition_expression("#client = :client AND begins_with(#reference, :prefix)")
            .expression_attribute_names("#client", CLIENT_KEY_ATTRIBUTE)
            .expression_attribute_names("#reference", REFERENCE_KEY_ATTRIBUTE)
            .expression_attribute_values(
                ":client",
                AttributeValue::S(Self::client_key(tenant, client_id)),
            )
            .expression_attribute_values(":prefix", AttributeValue::S("r#".to_string()))
            .consistent_read(true)
            .limit(1)
            .send()
            .await
            .map_err(ddb_err)?;
        Ok(!output.items().is_empty())
    }

    pub(crate) fn coverage_item(
        kind: AuthorityReferenceKind,
        migration_version: &str,
    ) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                CLIENT_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(COVERAGE_PARTITION.to_string()),
            ),
            (
                REFERENCE_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(kind.coverage_key().to_string()),
            ),
            (
                "schema_version".to_string(),
                AttributeValue::S(AUTHORITY_REFERENCE_SCHEMA_VERSION.to_string()),
            ),
            (
                "migration_version".to_string(),
                AttributeValue::S(migration_version.to_string()),
            ),
        ])
    }
}

pub fn authority_reference_migration_version(deployment_commit: &str) -> String {
    format!("{AUTHORITY_REFERENCE_SCHEMA_VERSION}:{deployment_commit}")
}

impl DynamoAuthorityReferenceMigrator {
    pub fn new(
        db: aws_sdk_dynamodb::Client,
        codes_table: impl Into<String>,
        refresh_table: impl Into<String>,
        refs_table: impl Into<String>,
    ) -> Self {
        Self {
            refs: DynamoAuthorityReferenceStore::new(
                db.clone(),
                refs_table,
                AUTHORITY_REFERENCE_SCHEMA_VERSION,
            ),
            db,
            codes_table: codes_table.into(),
            refresh_table: refresh_table.into(),
        }
    }

    fn migration_state_item(state: &MigrationState) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::from([
            (
                CLIENT_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(MIGRATION_PARTITION.to_string()),
            ),
            (
                REFERENCE_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(MIGRATION_STATE_KEY.to_string()),
            ),
            (
                "migration_id".to_string(),
                AttributeValue::S(state.migration_id.clone()),
            ),
            (
                "phase".to_string(),
                AttributeValue::S(state.phase.as_str().to_string()),
            ),
            (
                "checkpoint_version".to_string(),
                AttributeValue::N(state.checkpoint_version.to_string()),
            ),
            (
                "invocation_started_at_ms".to_string(),
                AttributeValue::N(state.invocation_started_at_ms.to_string()),
            ),
            (
                "drain_until".to_string(),
                AttributeValue::N(state.drain_until.to_string()),
            ),
            (
                "code_references".to_string(),
                AttributeValue::N(state.code_references.to_string()),
            ),
            (
                "refresh_references".to_string(),
                AttributeValue::N(state.refresh_references.to_string()),
            ),
            (
                "schema_version".to_string(),
                AttributeValue::S(AUTHORITY_REFERENCE_SCHEMA_VERSION.to_string()),
            ),
        ]);
        if let Some(cursor) = &state.cursor_partition {
            item.insert(
                "cursor_partition".to_string(),
                AttributeValue::S(cursor.clone()),
            );
        }
        if let Some(cursor) = &state.cursor_sort {
            item.insert("cursor_sort".to_string(), AttributeValue::S(cursor.clone()));
        }
        item
    }

    fn migration_state_from_item(
        item: &HashMap<String, AttributeValue>,
    ) -> Result<MigrationState, StoreError> {
        let required_string = |name: &str| {
            s(item.get(name))
                .ok_or_else(|| StoreError::Permanent(format!("migration state is missing {name}")))
        };
        Ok(MigrationState {
            migration_id: required_string("migration_id")?,
            phase: MigrationPhase::parse(&required_string("phase")?)?,
            checkpoint_version: n_u64(item.get("checkpoint_version")).ok_or_else(|| {
                StoreError::Permanent("migration state is missing checkpoint_version".to_string())
            })?,
            invocation_started_at_ms: n_u64(item.get("invocation_started_at_ms")).ok_or_else(
                || {
                    StoreError::Permanent(
                        "migration state is missing invocation_started_at_ms".to_string(),
                    )
                },
            )?,
            drain_until: n_i64(item.get("drain_until")).ok_or_else(|| {
                StoreError::Permanent("migration state is missing drain_until".to_string())
            })?,
            cursor_partition: s(item.get("cursor_partition")),
            cursor_sort: s(item.get("cursor_sort")),
            code_references: n_u64(item.get("code_references")).unwrap_or(0) as usize,
            refresh_references: n_u64(item.get("refresh_references")).unwrap_or(0) as usize,
        })
    }

    fn state_key() -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                CLIENT_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(MIGRATION_PARTITION.to_string()),
            ),
            (
                REFERENCE_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(MIGRATION_STATE_KEY.to_string()),
            ),
        ])
    }

    fn request_key(request_id: &str) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                CLIENT_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(MIGRATION_REQUEST_PARTITION.to_string()),
            ),
            (
                REFERENCE_KEY_ATTRIBUTE.to_string(),
                AttributeValue::S(format!("request\u{1f}{request_id}")),
            ),
        ])
    }

    async fn applied_request(&self, request_id: &str) -> Result<Option<String>, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(self.refs.table())
            .set_key(Some(Self::request_key(request_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        output
            .item()
            .map(|item| {
                s(item.get("migration_id")).ok_or_else(|| {
                    StoreError::Permanent(
                        "migration request marker is missing migration_id".to_string(),
                    )
                })
            })
            .transpose()
    }

    pub async fn begin(
        &self,
        migration_id: &str,
        previous_migration_id: Option<&str>,
        request_id: &str,
        invocation_started_at_ms: u64,
        drain_until: i64,
    ) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{Delete, Put, TransactWriteItem};

        if migration_id.is_empty() || migration_id.len() > 256 {
            return Err(StoreError::Permanent(
                "authority reference migration id must be 1..=256 bytes".to_string(),
            ));
        }
        if request_id.is_empty() || request_id.len() > 256 {
            return Err(StoreError::Permanent(
                "authority reference migration request id must be 1..=256 bytes".to_string(),
            ));
        }
        if invocation_started_at_ms == 0 {
            return Err(StoreError::Permanent(
                "authority reference migration invocation start must be non-zero".to_string(),
            ));
        }
        if let Some(applied_migration_id) = self.applied_request(request_id).await? {
            return if applied_migration_id == migration_id {
                Ok(())
            } else {
                Err(StoreError::Permanent(
                    "authority reference migration request id was reused".to_string(),
                ))
            };
        }
        let existing = self
            .db
            .get_item()
            .table_name(self.refs.table())
            .set_key(Some(Self::state_key()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?
            .item
            .as_ref()
            .map(Self::migration_state_from_item)
            .transpose()?;
        if existing
            .as_ref()
            .is_some_and(|current| current.invocation_started_at_ms >= invocation_started_at_ms)
        {
            return Err(StoreError::Transient(
                "authority reference migration invocation was superseded by a newer or concurrent invocation"
                    .to_string(),
            ));
        }
        match (existing.as_ref(), previous_migration_id) {
            (None, None) => {}
            (Some(current), None) if current.migration_id == migration_id => {}
            (Some(previous), Some(expected)) if previous.migration_id == expected => {}
            (Some(_), Some(_)) => {
                return Err(StoreError::Transient(
                    "authority reference migration predecessor does not match".to_string(),
                ));
            }
            (Some(_), None) => {
                return Err(StoreError::Transient(
                    "authority reference migration predecessor is required".to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(StoreError::Transient(
                    "authority reference migration predecessor is missing".to_string(),
                ));
            }
        }

        let state = MigrationState {
            migration_id: migration_id.to_string(),
            phase: MigrationPhase::Drain,
            checkpoint_version: 0,
            invocation_started_at_ms,
            drain_until,
            cursor_partition: None,
            cursor_sort: None,
            code_references: 0,
            refresh_references: 0,
        };
        let mut request = self.db.transact_write_items();
        for kind in [
            AuthorityReferenceKind::Code,
            AuthorityReferenceKind::Refresh,
        ] {
            let delete = Delete::builder()
                .table_name(self.refs.table())
                .key(
                    CLIENT_KEY_ATTRIBUTE,
                    AttributeValue::S(COVERAGE_PARTITION.to_string()),
                )
                .key(
                    REFERENCE_KEY_ATTRIBUTE,
                    AttributeValue::S(kind.coverage_key().to_string()),
                )
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build coverage delete: {error}"))
                })?;
            request = request.transact_items(TransactWriteItem::builder().delete(delete).build());
        }
        let request_marker = Put::builder()
            .table_name(self.refs.table())
            .set_item(Some(HashMap::from([
                (
                    CLIENT_KEY_ATTRIBUTE.to_string(),
                    AttributeValue::S(MIGRATION_REQUEST_PARTITION.to_string()),
                ),
                (
                    REFERENCE_KEY_ATTRIBUTE.to_string(),
                    AttributeValue::S(format!("request\u{1f}{request_id}")),
                ),
                (
                    "migration_id".to_string(),
                    AttributeValue::S(migration_id.to_string()),
                ),
                (
                    "schema_version".to_string(),
                    AttributeValue::S(AUTHORITY_REFERENCE_SCHEMA_VERSION.to_string()),
                ),
            ])))
            .condition_expression(
                "attribute_not_exists(client_key) AND attribute_not_exists(reference_key)",
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build migration request marker: {error}"))
            })?;
        request = request.transact_items(TransactWriteItem::builder().put(request_marker).build());
        let mut state_put = Put::builder()
            .table_name(self.refs.table())
            .set_item(Some(Self::migration_state_item(&state)));
        state_put = match existing {
            Some(previous) => state_put
                .condition_expression(
                    "migration_id = :previous_id AND checkpoint_version = :previous_version \
                     AND invocation_started_at_ms = :previous_started_at",
                )
                .expression_attribute_values(
                    ":previous_id",
                    AttributeValue::S(previous.migration_id),
                )
                .expression_attribute_values(
                    ":previous_version",
                    AttributeValue::N(previous.checkpoint_version.to_string()),
                )
                .expression_attribute_values(
                    ":previous_started_at",
                    AttributeValue::N(previous.invocation_started_at_ms.to_string()),
                ),
            None => state_put.condition_expression(
                "attribute_not_exists(client_key) AND attribute_not_exists(reference_key)",
            ),
        };
        let state_put = state_put.build().map_err(|error| {
            StoreError::Permanent(format!("build migration state put: {error}"))
        })?;
        request = request.transact_items(TransactWriteItem::builder().put(state_put).build());
        match send_idempotent_transaction(request).await? {
            true => Ok(()),
            false => {
                if self.applied_request(request_id).await?.as_deref() == Some(migration_id) {
                    return Ok(());
                }
                Err(StoreError::Transient(
                    "authority reference migration initialization conflicted before the request marker was committed"
                        .to_string(),
                ))
            }
        }
    }

    async fn load_state(&self, migration_id: &str) -> Result<MigrationState, StoreError> {
        let output = self
            .db
            .get_item()
            .table_name(self.refs.table())
            .set_key(Some(Self::state_key()))
            .consistent_read(true)
            .send()
            .await
            .map_err(ddb_err)?;
        let item = output.item().ok_or_else(|| {
            StoreError::Transient("authority reference migration state is missing".to_string())
        })?;
        let state = Self::migration_state_from_item(item)?;
        if state.migration_id != migration_id {
            return Err(StoreError::Transient(
                "authority reference migration was superseded".to_string(),
            ));
        }
        Ok(state)
    }

    async fn replace_state(
        &self,
        previous: &MigrationState,
        next: &MigrationState,
    ) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::Put;

        let mut checkpoint = next.clone();
        checkpoint.checkpoint_version = previous
            .checkpoint_version
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("migration checkpoint overflow".to_string()))?;
        let put = Put::builder()
            .table_name(self.refs.table())
            .set_item(Some(Self::migration_state_item(&checkpoint)))
            .condition_expression(
                "migration_id = :migration_id AND checkpoint_version = :checkpoint_version \
                 AND invocation_started_at_ms = :invocation_started_at_ms",
            )
            .expression_attribute_values(
                ":migration_id",
                AttributeValue::S(previous.migration_id.clone()),
            )
            .expression_attribute_values(
                ":checkpoint_version",
                AttributeValue::N(previous.checkpoint_version.to_string()),
            )
            .expression_attribute_values(
                ":invocation_started_at_ms",
                AttributeValue::N(previous.invocation_started_at_ms.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build migration state update: {error}"))
            })?;
        match send_idempotent_transaction(
            self.db.transact_write_items().transact_items(
                aws_sdk_dynamodb::types::TransactWriteItem::builder()
                    .put(put)
                    .build(),
            ),
        )
        .await?
        {
            true => Ok(()),
            false => {
                let current = self.load_state(&previous.migration_id).await?;
                if current.invocation_started_at_ms == previous.invocation_started_at_ms
                    && current.checkpoint_version > previous.checkpoint_version
                {
                    Ok(())
                } else {
                    Err(StoreError::Transient(
                        "authority reference migration checkpoint changed concurrently".to_string(),
                    ))
                }
            }
        }
    }

    fn source_cursor(state: &MigrationState, key: &str) -> Option<HashMap<String, AttributeValue>> {
        state
            .cursor_partition
            .as_ref()
            .map(|cursor| HashMap::from([(key.to_string(), AttributeValue::S(cursor.clone()))]))
    }

    fn reference_cursor(
        state: &MigrationState,
    ) -> Result<Option<HashMap<String, AttributeValue>>, StoreError> {
        match (&state.cursor_partition, &state.cursor_sort) {
            (None, None) => Ok(None),
            (Some(partition), Some(sort)) => Ok(Some(HashMap::from([
                (
                    CLIENT_KEY_ATTRIBUTE.to_string(),
                    AttributeValue::S(partition.clone()),
                ),
                (
                    REFERENCE_KEY_ATTRIBUTE.to_string(),
                    AttributeValue::S(sort.clone()),
                ),
            ]))),
            _ => Err(StoreError::Permanent(
                "authority reference migration cursor is incomplete".to_string(),
            )),
        }
    }

    async fn backfill_code(
        &self,
        item: &HashMap<String, AttributeValue>,
        now: i64,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem};

        let physical_code = s(item.get("code")).ok_or_else(|| {
            StoreError::Permanent("code migration row is missing code".to_string())
        })?;
        let tenant = tenant_from_tpk(&physical_code);
        let record = DynamoCodeStore::record(item)?;
        if item
            .get("consumed")
            .and_then(|value| value.as_bool().ok())
            .copied()
            .unwrap_or(false)
            || record.expires_at <= now
        {
            return Ok(false);
        }
        let source_check = ConditionCheck::builder()
            .table_name(&self.codes_table)
            .key("code", AttributeValue::S(physical_code))
            .condition_expression(
                "attribute_exists(code) AND \
                 (attribute_not_exists(#consumed) OR #consumed = :false) \
                 AND expires_at = :expires_at AND expires_at > :now AND client_id = :client_id",
            )
            .expression_attribute_names("#consumed", "consumed")
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(
                ":expires_at",
                AttributeValue::N(record.expires_at.to_string()),
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(
                ":client_id",
                AttributeValue::S(tpk(&tenant, &record.client_id)),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build code migration condition: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .condition_check(source_check)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(self.refs.code_put(&tenant, &record)?)
                    .build(),
            );
        send_idempotent_transaction(request).await
    }

    async fn backfill_refresh(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<bool, StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, TransactWriteItem};

        let physical_family = s(item.get("family_id")).ok_or_else(|| {
            StoreError::Permanent("refresh migration row is missing family_id".to_string())
        })?;
        if item
            .get("revoked")
            .and_then(|value| value.as_bool().ok())
            .copied()
            .unwrap_or(false)
        {
            return Ok(false);
        }
        let tenant = tenant_from_tpk(&physical_family);
        let record = RefreshFamilyRecord {
            family_id: strip_tpk(&physical_family),
            current_version: n_u64(item.get("current_version")).unwrap_or(0),
            revoked: false,
            client_id: strip_tpk(&s(item.get("client_id")).ok_or_else(|| {
                StoreError::Permanent("refresh migration row is missing client_id".to_string())
            })?),
            cimd_snapshot: None,
            user_id: String::new(),
            credential_epoch: 0,
            resources: Vec::new(),
            scope: Vec::new(),
            actor_allowlist: Vec::new(),
            max_act_chain: 1,
            dpop_jkt: None,
            pkce_code_challenge: None,
            auth_time: None,
            acr: None,
            password_credential_version: None,
        };
        let source_check = ConditionCheck::builder()
            .table_name(&self.refresh_table)
            .key("family_id", AttributeValue::S(physical_family))
            .condition_expression(
                "attribute_exists(family_id) AND \
                 (attribute_not_exists(#revoked) OR #revoked = :false) AND client_id = :client_id",
            )
            .expression_attribute_names("#revoked", "revoked")
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(
                ":client_id",
                AttributeValue::S(tpk(&tenant, &record.client_id)),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build refresh migration condition: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .condition_check(source_check)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(self.refs.refresh_put(&tenant, &record)?)
                    .build(),
            );
        send_idempotent_transaction(request).await
    }

    async fn reconcile_reference(
        &self,
        item: &HashMap<String, AttributeValue>,
        now: i64,
    ) -> Result<(), StoreError> {
        use aws_sdk_dynamodb::types::{ConditionCheck, Delete, TransactWriteItem};

        let Some(kind) = s(item.get("kind")) else {
            let partition = s(item.get(CLIENT_KEY_ATTRIBUTE)).unwrap_or_default();
            if partition == COVERAGE_PARTITION
                || partition == MIGRATION_PARTITION
                || partition == MIGRATION_REQUEST_PARTITION
            {
                return Ok(());
            }
            return Err(StoreError::Permanent(
                "authority reference row is missing kind".to_string(),
            ));
        };
        let source_id = s(item.get("source_id")).ok_or_else(|| {
            StoreError::Permanent("authority reference row is missing source_id".to_string())
        })?;
        let tenant = s(item.get("tenant_id")).ok_or_else(|| {
            StoreError::Permanent("authority reference row is missing tenant_id".to_string())
        })?;
        let client_id = s(item.get("client_id")).ok_or_else(|| {
            StoreError::Permanent("authority reference row is missing client_id".to_string())
        })?;
        let (source_check, active) = match kind.as_str() {
            "code" => {
                let output = self
                    .db
                    .get_item()
                    .table_name(&self.codes_table)
                    .key("code", AttributeValue::S(source_id.clone()))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                let active = output.item().is_some_and(|source| {
                    !source
                        .get("consumed")
                        .and_then(|value| value.as_bool().ok())
                        .copied()
                        .unwrap_or(false)
                        && n_i64(source.get("expires_at")).is_some_and(|expiry| expiry > now)
                        && s(source.get("client_id")).as_deref()
                            == Some(tpk(&tenant, &client_id).as_str())
                });
                let check = ConditionCheck::builder()
                    .table_name(&self.codes_table)
                    .key("code", AttributeValue::S(source_id.clone()))
                    .condition_expression(
                        "attribute_not_exists(code) OR attribute_not_exists(expires_at) OR \
                         attribute_not_exists(client_id) OR #consumed = :true OR \
                         expires_at <= :now OR client_id <> :client_id",
                    )
                    .expression_attribute_names("#consumed", "consumed")
                    .expression_attribute_values(":true", AttributeValue::Bool(true))
                    .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                    .expression_attribute_values(
                        ":client_id",
                        AttributeValue::S(tpk(&tenant, &client_id)),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build orphan code reference condition: {error}"
                        ))
                    })?;
                (check, active)
            }
            "refresh" => {
                let output = self
                    .db
                    .get_item()
                    .table_name(&self.refresh_table)
                    .key("family_id", AttributeValue::S(source_id.clone()))
                    .consistent_read(true)
                    .send()
                    .await
                    .map_err(ddb_err)?;
                let active = output.item().is_some_and(|source| {
                    !source
                        .get("revoked")
                        .and_then(|value| value.as_bool().ok())
                        .copied()
                        .unwrap_or(false)
                        && s(source.get("client_id")).as_deref()
                            == Some(tpk(&tenant, &client_id).as_str())
                });
                let check = ConditionCheck::builder()
                    .table_name(&self.refresh_table)
                    .key("family_id", AttributeValue::S(source_id.clone()))
                    .condition_expression(
                        "attribute_not_exists(family_id) OR attribute_not_exists(client_id) OR \
                         #revoked = :true OR client_id <> :client_id",
                    )
                    .expression_attribute_names("#revoked", "revoked")
                    .expression_attribute_values(":true", AttributeValue::Bool(true))
                    .expression_attribute_values(
                        ":client_id",
                        AttributeValue::S(tpk(&tenant, &client_id)),
                    )
                    .build()
                    .map_err(|error| {
                        StoreError::Permanent(format!(
                            "build orphan refresh reference condition: {error}"
                        ))
                    })?;
                (check, active)
            }
            _ => {
                return Err(StoreError::Permanent(format!(
                    "unknown authority reference kind: {kind}"
                )))
            }
        };
        if active {
            return Ok(());
        }
        let reference_delete = Delete::builder()
            .table_name(self.refs.table())
            .key(
                CLIENT_KEY_ATTRIBUTE,
                item.get(CLIENT_KEY_ATTRIBUTE).cloned().ok_or_else(|| {
                    StoreError::Permanent(
                        "authority reference row is missing client_key".to_string(),
                    )
                })?,
            )
            .key(
                REFERENCE_KEY_ATTRIBUTE,
                item.get(REFERENCE_KEY_ATTRIBUTE).cloned().ok_or_else(|| {
                    StoreError::Permanent(
                        "authority reference row is missing reference_key".to_string(),
                    )
                })?,
            )
            .condition_expression("source_id = :source_id AND #kind = :kind")
            .expression_attribute_names("#kind", "kind")
            .expression_attribute_values(":source_id", AttributeValue::S(source_id))
            .expression_attribute_values(":kind", AttributeValue::S(kind))
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build orphan reference delete: {error}"))
            })?;
        let request = self
            .db
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .condition_check(source_check)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .delete(reference_delete)
                    .build(),
            );
        let _ = send_idempotent_transaction(request).await?;
        Ok(())
    }

    async fn cleanup_reference_page(
        &self,
        state: &MigrationState,
        now: i64,
    ) -> Result<MigrationState, StoreError> {
        let output = self
            .db
            .scan()
            .table_name(self.refs.table())
            .consistent_read(true)
            .limit(MIGRATION_PAGE_SIZE)
            .set_exclusive_start_key(Self::reference_cursor(state)?)
            .send()
            .await
            .map_err(ddb_err)?;
        for chunk in output.items().chunks(MIGRATION_CONCURRENCY) {
            let mut tasks = tokio::task::JoinSet::new();
            for item in chunk {
                let migrator = self.clone();
                let item = item.clone();
                tasks.spawn(async move { migrator.reconcile_reference(&item, now).await });
            }
            while let Some(result) = tasks.join_next().await {
                result.map_err(|error| {
                    StoreError::Transient(format!(
                        "authority reference cleanup task failed: {error}"
                    ))
                })??;
            }
        }
        let mut next = state.clone();
        match output.last_evaluated_key() {
            Some(key) if !key.is_empty() => {
                next.cursor_partition = s(key.get(CLIENT_KEY_ATTRIBUTE));
                next.cursor_sort = s(key.get(REFERENCE_KEY_ATTRIBUTE));
            }
            _ => {
                next.phase = MigrationPhase::BackfillCodes;
                next.cursor_partition = None;
                next.cursor_sort = None;
            }
        }
        Ok(next)
    }

    async fn source_page(
        &self,
        state: &MigrationState,
        now: i64,
    ) -> Result<MigrationState, StoreError> {
        let (table, key, next_phase, is_code, count_results) = match state.phase {
            MigrationPhase::BackfillCodes => (
                &self.codes_table,
                "code",
                MigrationPhase::BackfillRefreshes,
                true,
                true,
            ),
            MigrationPhase::BackfillRefreshes => (
                &self.refresh_table,
                "family_id",
                MigrationPhase::VerifyCodes,
                false,
                true,
            ),
            MigrationPhase::VerifyCodes => (
                &self.codes_table,
                "code",
                MigrationPhase::VerifyRefreshes,
                true,
                false,
            ),
            MigrationPhase::VerifyRefreshes => (
                &self.refresh_table,
                "family_id",
                MigrationPhase::PublishCoverage,
                false,
                false,
            ),
            _ => {
                return Err(StoreError::Permanent(
                    "authority reference migration source phase is invalid".to_string(),
                ))
            }
        };
        let output = self
            .db
            .scan()
            .table_name(table)
            .consistent_read(true)
            .limit(MIGRATION_PAGE_SIZE)
            .set_exclusive_start_key(Self::source_cursor(state, key))
            .send()
            .await
            .map_err(ddb_err)?;
        let mut migrated = 0usize;
        for chunk in output.items().chunks(MIGRATION_CONCURRENCY) {
            let mut tasks = tokio::task::JoinSet::new();
            for item in chunk {
                let migrator = self.clone();
                let item = item.clone();
                tasks.spawn(async move {
                    if is_code {
                        migrator.backfill_code(&item, now).await
                    } else {
                        migrator.backfill_refresh(&item).await
                    }
                });
            }
            while let Some(result) = tasks.join_next().await {
                migrated += usize::from(result.map_err(|error| {
                    StoreError::Transient(format!(
                        "authority reference backfill task failed: {error}"
                    ))
                })??);
            }
        }
        let mut next = state.clone();
        if count_results {
            if is_code {
                next.code_references = next.code_references.saturating_add(migrated);
            } else {
                next.refresh_references = next.refresh_references.saturating_add(migrated);
            }
        }
        match output.last_evaluated_key() {
            Some(last_key) if !last_key.is_empty() => {
                next.cursor_partition = s(last_key.get(key));
            }
            _ => {
                next.phase = next_phase;
                next.cursor_partition = None;
            }
        }
        Ok(next)
    }

    async fn publish_coverage(
        &self,
        state: &MigrationState,
    ) -> Result<AuthorityReferenceMigrationStats, StoreError> {
        use aws_sdk_dynamodb::types::{Put, TransactWriteItem};

        let mut request = self.db.transact_write_items();
        for kind in [
            AuthorityReferenceKind::Code,
            AuthorityReferenceKind::Refresh,
        ] {
            let put = Put::builder()
                .table_name(self.refs.table())
                .set_item(Some(DynamoAuthorityReferenceStore::coverage_item(
                    kind,
                    &state.migration_id,
                )))
                .build()
                .map_err(|error| {
                    StoreError::Permanent(format!("build coverage marker put: {error}"))
                })?;
            request = request.transact_items(TransactWriteItem::builder().put(put).build());
        }
        let mut completed = state.clone();
        completed.phase = MigrationPhase::Complete;
        completed.checkpoint_version = state
            .checkpoint_version
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("migration checkpoint overflow".to_string()))?;
        let state_put = Put::builder()
            .table_name(self.refs.table())
            .set_item(Some(Self::migration_state_item(&completed)))
            .condition_expression(
                "migration_id = :migration_id AND checkpoint_version = :checkpoint_version \
                 AND phase = :phase \
                 AND invocation_started_at_ms = :invocation_started_at_ms",
            )
            .expression_attribute_values(
                ":migration_id",
                AttributeValue::S(state.migration_id.clone()),
            )
            .expression_attribute_values(
                ":phase",
                AttributeValue::S(MigrationPhase::PublishCoverage.as_str().to_string()),
            )
            .expression_attribute_values(
                ":checkpoint_version",
                AttributeValue::N(state.checkpoint_version.to_string()),
            )
            .expression_attribute_values(
                ":invocation_started_at_ms",
                AttributeValue::N(state.invocation_started_at_ms.to_string()),
            )
            .build()
            .map_err(|error| {
                StoreError::Permanent(format!("build completed migration state: {error}"))
            })?;
        request = request.transact_items(TransactWriteItem::builder().put(state_put).build());
        match send_idempotent_transaction(request).await? {
            true => Ok(AuthorityReferenceMigrationStats {
                code_references: state.code_references,
                refresh_references: state.refresh_references,
            }),
            false => {
                let current = self.load_state(&state.migration_id).await?;
                if current.phase == MigrationPhase::Complete
                    && current.invocation_started_at_ms == state.invocation_started_at_ms
                {
                    Ok(AuthorityReferenceMigrationStats {
                        code_references: current.code_references,
                        refresh_references: current.refresh_references,
                    })
                } else {
                    Err(StoreError::Transient(
                        "authority reference coverage publish conflicted".to_string(),
                    ))
                }
            }
        }
    }

    pub async fn step(
        &self,
        migration_id: &str,
        now: i64,
    ) -> Result<AuthorityReferenceMigrationProgress, StoreError> {
        let state = self.load_state(migration_id).await?;
        if state.phase == MigrationPhase::Drain {
            if now < state.drain_until {
                return Ok(AuthorityReferenceMigrationProgress::Pending);
            }
            let mut next = state.clone();
            next.phase = MigrationPhase::CleanupReferences;
            self.replace_state(&state, &next).await?;
            return Ok(AuthorityReferenceMigrationProgress::Pending);
        }
        if state.phase == MigrationPhase::PublishCoverage {
            return self
                .publish_coverage(&state)
                .await
                .map(AuthorityReferenceMigrationProgress::Complete);
        }
        if state.phase == MigrationPhase::Complete {
            return Ok(AuthorityReferenceMigrationProgress::Complete(
                AuthorityReferenceMigrationStats {
                    code_references: state.code_references,
                    refresh_references: state.refresh_references,
                },
            ));
        }
        let next = if state.phase == MigrationPhase::CleanupReferences {
            self.cleanup_reference_page(&state, now).await?
        } else {
            self.source_page(&state, now).await?
        };
        self.replace_state(&state, &next).await?;
        Ok(AuthorityReferenceMigrationProgress::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Router,
    };
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    #[derive(Clone)]
    struct FakeDynamo {
        coverage_schema: Option<String>,
        coverage_version: Option<String>,
        requests: Arc<Mutex<Vec<(String, Value)>>>,
    }

    #[derive(Clone, Default)]
    struct MigrationFake {
        requests: Arc<Mutex<Vec<(String, Value)>>>,
        state: Arc<Mutex<Option<Value>>>,
        request_markers: Arc<Mutex<HashMap<String, Value>>>,
        reject_next_transaction: Arc<AtomicBool>,
    }

    async fn dynamo(
        State(fake): State<FakeDynamo>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let target = headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
        fake.requests
            .lock()
            .expect("request lock")
            .push((target.clone(), request));

        let response = if target.ends_with(".GetItem") && fake.coverage_schema.is_some() {
            json!({
                "Item": {
                    CLIENT_KEY_ATTRIBUTE: { "S": COVERAGE_PARTITION },
                    REFERENCE_KEY_ATTRIBUTE: { "S": CODE_COVERAGE_KEY },
                    "schema_version": { "S": fake.coverage_schema.as_deref().unwrap() },
                    "migration_version": {
                        "S": fake.coverage_version.as_deref().unwrap_or_default()
                    }
                }
            })
        } else if target.ends_with(".Query") {
            json!({
                "Items": [{
                    CLIENT_KEY_ATTRIBUTE: { "S": "client#00000002t100000008client-a" },
                    REFERENCE_KEY_ATTRIBUTE: { "S": "r#source" }
                }],
                "Count": 1,
                "ScannedCount": 1
            })
        } else {
            json!({})
        };
        (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.0")],
            response.to_string(),
        )
            .into_response()
    }

    async fn fake_client(
        coverage_schema: Option<&str>,
        coverage_version: Option<&str>,
    ) -> (
        aws_sdk_dynamodb::Client,
        Arc<Mutex<Vec<(String, Value)>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeDynamo {
            coverage_schema: coverage_schema.map(str::to_string),
            coverage_version: coverage_version.map(str::to_string),
            requests: requests.clone(),
        };
        let app = Router::new().route("/", post(dynamo)).with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = aws_sdk_dynamodb::Config::builder()
            .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
            .endpoint_url(format!("http://{address}"))
            .retry_config(
                aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1),
            )
            .build();
        (
            aws_sdk_dynamodb::Client::from_conf(config),
            requests,
            server,
        )
    }

    async fn migration_dynamo(
        State(fake): State<MigrationFake>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let target = headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let request: Value = serde_json::from_slice(&body).expect("DynamoDB request is JSON");
        fake.requests
            .lock()
            .expect("request lock")
            .push((target.clone(), request.clone()));

        if target.ends_with(".TransactWriteItems")
            && fake.reject_next_transaction.swap(false, Ordering::SeqCst)
        {
            return (
                StatusCode::BAD_REQUEST,
                [
                    ("content-type", "application/x-amz-json-1.0"),
                    ("x-amzn-errortype", "TransactionCanceledException"),
                ],
                json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#TransactionCanceledException",
                    "CancellationReasons": [
                        { "Code": "ConditionalCheckFailed", "Message": "checkpoint changed" }
                    ],
                    "message": "transaction canceled"
                })
                .to_string(),
            )
                .into_response();
        }

        if target.ends_with(".TransactWriteItems") {
            for item in request["TransactItems"].as_array().into_iter().flatten() {
                if item["Put"]["Item"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_PARTITION
                    && item["Put"]["Item"][REFERENCE_KEY_ATTRIBUTE]["S"] == MIGRATION_STATE_KEY
                {
                    *fake.state.lock().expect("state lock") = Some(item["Put"]["Item"].clone());
                }
                if item["Put"]["Item"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_REQUEST_PARTITION {
                    let key = item["Put"]["Item"][REFERENCE_KEY_ATTRIBUTE]["S"]
                        .as_str()
                        .expect("request marker key")
                        .to_string();
                    fake.request_markers
                        .lock()
                        .expect("request marker lock")
                        .insert(key, item["Put"]["Item"].clone());
                }
                if item["Delete"]["Key"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_PARTITION
                    && item["Delete"]["Key"][REFERENCE_KEY_ATTRIBUTE]["S"] == MIGRATION_STATE_KEY
                {
                    *fake.state.lock().expect("state lock") = None;
                }
            }
        }

        let response = if target.ends_with(".GetItem")
            && request["TableName"] == "refs-table"
            && request["Key"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_REQUEST_PARTITION
        {
            let key = request["Key"][REFERENCE_KEY_ATTRIBUTE]["S"]
                .as_str()
                .expect("request marker key");
            fake.request_markers
                .lock()
                .expect("request marker lock")
                .get(key)
                .cloned()
                .map(|item| json!({ "Item": item }))
                .unwrap_or_else(|| json!({}))
        } else if target.ends_with(".GetItem")
            && request["TableName"] == "refs-table"
            && request["Key"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_PARTITION
        {
            fake.state
                .lock()
                .expect("state lock")
                .clone()
                .map(|item| json!({ "Item": item }))
                .unwrap_or_else(|| json!({}))
        } else if target.ends_with(".Scan") && request["TableName"] == "codes-table" {
            json!({
                "Items": [{
                    "code": { "S": "t1\u{1f}code-1" },
                    "client_id": { "S": "t1\u{1f}client-1" },
                    "redirect_uri": { "S": "https://client.example/callback" },
                    "code_challenge": { "S": "challenge" },
                    "resources": { "L": [] },
                    "user_id": { "S": "user-1" },
                    "scope": { "L": [] },
                    "expires_at": { "N": "1700010000" },
                    "auth_time": { "N": "1699999900" },
                    "consumed": { "BOOL": false }
                }],
                "Count": 1,
                "ScannedCount": 1
            })
        } else if target.ends_with(".Scan") && request["TableName"] == "refresh-table" {
            json!({
                "Items": [{
                    "family_id": { "S": "t2\u{1f}family-1" },
                    "client_id": { "S": "t2\u{1f}client-2" },
                    "current_version": { "N": "0" },
                    "revoked": { "BOOL": false }
                }],
                "Count": 1,
                "ScannedCount": 1
            })
        } else if target.ends_with(".Scan") && request["TableName"] == "refs-table" {
            json!({
                "Items": [],
                "Count": 0,
                "ScannedCount": 0
            })
        } else {
            json!({})
        };
        (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.0")],
            response.to_string(),
        )
            .into_response()
    }

    async fn migration_client() -> (
        aws_sdk_dynamodb::Client,
        MigrationFake,
        tokio::task::JoinHandle<()>,
    ) {
        let fake = MigrationFake::default();
        let app = Router::new()
            .route("/", post(migration_dynamo))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = aws_sdk_dynamodb::Config::builder()
            .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
            .endpoint_url(format!("http://{address}"))
            .retry_config(
                aws_sdk_dynamodb::config::retry::RetryConfig::standard().with_max_attempts(1),
            )
            .build();
        (aws_sdk_dynamodb::Client::from_conf(config), fake, server)
    }

    #[test]
    fn client_keys_separate_tenants_and_reserved_metadata() {
        assert_ne!(
            DynamoAuthorityReferenceStore::client_key("t1", "shared"),
            DynamoAuthorityReferenceStore::client_key("t2", "shared")
        );
        assert_ne!(
            DynamoAuthorityReferenceStore::client_key("", "meta\u{1f}coverage"),
            COVERAGE_PARTITION
        );
        assert_ne!(
            DynamoAuthorityReferenceStore::client_key("a", "b\u{1f}c"),
            DynamoAuthorityReferenceStore::client_key("a\u{1f}b", "c")
        );
        assert_ne!(
            DynamoAuthorityReferenceStore::client_key("租户", "client"),
            DynamoAuthorityReferenceStore::client_key("租", "户client")
        );
    }

    #[test]
    fn code_reference_order_excludes_equal_expiry() {
        let same =
            DynamoAuthorityReferenceStore::code_reference_key(1_700_000_000, "code-a").unwrap();
        let later =
            DynamoAuthorityReferenceStore::code_reference_key(1_700_000_001, "code-b").unwrap();
        let lower = format!("c#{:020}$", 1_700_000_000);
        assert!(same < lower);
        assert!(later > lower);
        assert!(later.as_str() < "c#~");
    }

    #[test]
    fn multiple_sources_have_distinct_reference_keys() {
        assert_ne!(
            DynamoAuthorityReferenceStore::code_reference_key(100, "a").unwrap(),
            DynamoAuthorityReferenceStore::code_reference_key(100, "b").unwrap()
        );
        assert_ne!(
            DynamoAuthorityReferenceStore::refresh_reference_key("a"),
            DynamoAuthorityReferenceStore::refresh_reference_key("b")
        );
    }

    #[tokio::test]
    async fn missing_coverage_fails_closed_before_querying() {
        let (client, requests, server) = fake_client(None, None).await;
        let store = DynamoAuthorityReferenceStore::new(
            client,
            "refs-table",
            "client-authority-refs-v1:test",
        );
        let error = store
            .has_unexpired_code("t1", "client-a", 1_700_000_000)
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(error, StoreError::Transient(_)));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.ends_with(".GetItem"));
        assert_eq!(requests[0].1["ConsistentRead"], true);
        assert_eq!(requests[0].1["TableName"], "refs-table");
    }

    #[tokio::test]
    async fn stale_coverage_schema_fails_closed_before_querying() {
        let (client, requests, server) = fake_client(
            Some("client-authority-refs-v0"),
            Some("client-authority-refs-v1:test"),
        )
        .await;
        let store = DynamoAuthorityReferenceStore::new(
            client,
            "refs-table",
            "client-authority-refs-v1:test",
        );
        let error = store
            .has_unexpired_code("t1", "client-a", 1_700_000_000)
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(error, StoreError::Transient(_)));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.ends_with(".GetItem"));
    }

    #[tokio::test]
    async fn stale_coverage_migration_version_fails_closed_before_querying() {
        let (client, requests, server) = fake_client(
            Some(AUTHORITY_REFERENCE_SCHEMA_VERSION),
            Some("client-authority-refs-v1:old"),
        )
        .await;
        let store = DynamoAuthorityReferenceStore::new(
            client,
            "refs-table",
            "client-authority-refs-v1:current",
        );
        let error = store
            .has_unexpired_code("t1", "client-a", 1_700_000_000)
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(error, StoreError::Transient(_)));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.ends_with(".GetItem"));
    }

    #[tokio::test]
    async fn covered_code_lookup_is_bounded_and_strongly_consistent() {
        let coverage_version = "client-authority-refs-v1:test";
        let (client, requests, server) = fake_client(
            Some(AUTHORITY_REFERENCE_SCHEMA_VERSION),
            Some(coverage_version),
        )
        .await;
        let store = DynamoAuthorityReferenceStore::new(client, "refs-table", coverage_version);
        assert!(store
            .has_unexpired_code("t1", "client-a", 1_700_000_000)
            .await
            .unwrap());
        server.abort();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].0.ends_with(".Query"));
        let query = &requests[1].1;
        assert_eq!(query["ConsistentRead"], true);
        assert_eq!(query["Limit"], 1);
        assert_eq!(
            query["ExpressionAttributeValues"][":client"]["S"],
            "client#00000002t100000008client-a"
        );
        assert_eq!(
            query["ExpressionAttributeValues"][":lower"]["S"],
            "c#00000000001700000000$"
        );
        assert_eq!(query["ExpressionAttributeValues"][":upper"]["S"], "c#~");
    }

    #[tokio::test]
    async fn covered_refresh_lookup_uses_the_same_tenant_client_partition() {
        let coverage_version = "client-authority-refs-v1:test";
        let (client, requests, server) = fake_client(
            Some(AUTHORITY_REFERENCE_SCHEMA_VERSION),
            Some(coverage_version),
        )
        .await;
        let store = DynamoAuthorityReferenceStore::new(client, "refs-table", coverage_version);
        assert!(store.has_active_refresh("t2", "shared").await.unwrap());
        server.abort();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let query = &requests[1].1;
        assert_eq!(query["ConsistentRead"], true);
        assert_eq!(query["Limit"], 1);
        assert_eq!(
            query["ExpressionAttributeValues"][":client"]["S"],
            "client#00000002t200000006shared"
        );
        assert_eq!(query["ExpressionAttributeValues"][":prefix"]["S"], "r#");
    }

    #[tokio::test]
    async fn migration_checkpoints_bounded_pages_before_publishing_coverage() {
        let (client, fake, server) = migration_client().await;
        let migrator = DynamoAuthorityReferenceMigrator::new(
            client,
            "codes-table",
            "refresh-table",
            "refs-table",
        );
        let migration_id = "client-authority-refs-v1:test";
        migrator
            .begin(
                migration_id,
                None,
                "request-test",
                1_700_000_000_000,
                1_700_000_315,
            )
            .await
            .unwrap();
        // At-least-once onEvent delivery must resume without withdrawing coverage
        // or resetting the persisted checkpoint.
        migrator
            .begin(
                migration_id,
                None,
                "request-test",
                1_700_000_000_000,
                1_700_000_999,
            )
            .await
            .unwrap();
        assert_eq!(
            migrator.step(migration_id, 1_700_000_314).await.unwrap(),
            AuthorityReferenceMigrationProgress::Pending
        );
        let stats = loop {
            match migrator.step(migration_id, 1_700_000_315).await.unwrap() {
                AuthorityReferenceMigrationProgress::Pending => {}
                AuthorityReferenceMigrationProgress::Complete(stats) => break stats,
            }
        };
        server.abort();

        assert_eq!(
            stats,
            AuthorityReferenceMigrationStats {
                code_references: 1,
                refresh_references: 1,
            }
        );
        let requests = fake.requests.lock().unwrap();
        let transactions = requests
            .iter()
            .filter(|(target, _)| target.ends_with(".TransactWriteItems"))
            .collect::<Vec<_>>();
        let first = &transactions[0].1["TransactItems"];
        assert_eq!(first.as_array().unwrap().len(), 4);
        assert!(first[0]["Delete"]["Key"]["reference_key"]["S"]
            .as_str()
            .unwrap()
            .contains(AUTHORITY_REFERENCE_SCHEMA_VERSION));
        assert_eq!(
            first[3]["Put"]["Item"]["phase"]["S"],
            MigrationPhase::Drain.as_str()
        );

        let scans = requests
            .iter()
            .filter(|(target, _)| target.ends_with(".Scan"))
            .collect::<Vec<_>>();
        assert_eq!(scans.len(), 5);
        assert!(scans
            .iter()
            .all(|(_, request)| request["ConsistentRead"] == true
                && request["Limit"] == MIGRATION_PAGE_SIZE));

        let last = transactions.last().unwrap();
        let coverage = last.1["TransactItems"].as_array().unwrap();
        assert_eq!(coverage.len(), 3);
        assert!(coverage[..2].iter().all(|item| {
            item["Put"]["Item"]["schema_version"]["S"] == AUTHORITY_REFERENCE_SCHEMA_VERSION
                && item["Put"]["Item"]["migration_version"]["S"] == migration_id
        }));
        assert_eq!(
            coverage[2]["Put"]["Item"][CLIENT_KEY_ATTRIBUTE]["S"],
            MIGRATION_PARTITION
        );
        assert_eq!(
            coverage[2]["Put"]["Item"]["phase"]["S"],
            MigrationPhase::Complete.as_str()
        );
        assert_eq!(
            transactions
                .iter()
                .filter(|(_, request)| {
                    request["TransactItems"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["Put"]["Item"]["phase"]["S"] == MigrationPhase::Drain.as_str()
                        })
                    })
                })
                .count(),
            1,
            "repeated begin must not reset migration progress"
        );
    }

    #[tokio::test]
    async fn migration_generation_allows_an_active_predecessor_to_roll_back() {
        async fn finish(migrator: &DynamoAuthorityReferenceMigrator, migration_id: &str, now: i64) {
            for _ in 0..32 {
                if matches!(
                    migrator.step(migration_id, now).await.unwrap(),
                    AuthorityReferenceMigrationProgress::Complete(_)
                ) {
                    return;
                }
            }
            panic!("migration did not complete within the bounded fake pages");
        }

        let (client, fake, server) = migration_client().await;
        let migrator = DynamoAuthorityReferenceMigrator::new(
            client,
            "codes-table",
            "refresh-table",
            "refs-table",
        );
        let old = "client-authority-refs-v1:old";
        let new = "client-authority-refs-v1:new";
        migrator
            .begin(old, None, "request-old-1", 1_000, 1_700_000_000)
            .await
            .unwrap();
        finish(&migrator, old, 1_700_000_000).await;
        migrator
            .begin(new, Some(old), "request-new-1", 2_000, 1_700_000_100)
            .await
            .unwrap();
        migrator
            .begin(old, Some(new), "request-old-2", 3_000, 1_700_000_200)
            .await
            .unwrap();
        migrator
            .begin(new, Some(old), "request-new-1", 2_000, 1_700_000_250)
            .await
            .unwrap();

        let delayed_error = migrator
            .begin(new, Some(old), "request-new-delayed", 2_500, 1_700_000_275)
            .await
            .unwrap_err();
        assert!(matches!(delayed_error, StoreError::Transient(_)));

        let delayed_same_id_error = migrator
            .begin(old, Some(new), "request-old-delayed", 2_500, 1_700_000_280)
            .await
            .unwrap_err();
        assert!(matches!(delayed_same_id_error, StoreError::Transient(_)));

        let error = migrator
            .begin(
                new,
                Some("client-authority-refs-v1:before-old"),
                "request-new-2",
                4_000,
                1_700_000_300,
            )
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(error, StoreError::Transient(_)));
        let state = fake.state.lock().unwrap().clone().unwrap();
        assert_eq!(state["migration_id"]["S"], old);
        assert_eq!(state["phase"]["S"], MigrationPhase::Drain.as_str());
    }

    #[tokio::test]
    async fn migration_generation_fences_stale_steps_and_coverage_publication() {
        let (client, fake, server) = migration_client().await;
        let migrator = DynamoAuthorityReferenceMigrator::new(
            client,
            "codes-table",
            "refresh-table",
            "refs-table",
        );
        let migration_id = "client-authority-refs-v1:test";
        migrator
            .begin(migration_id, None, "request-original", 1_000, 1_700_000_000)
            .await
            .unwrap();
        let stale = migrator.load_state(migration_id).await.unwrap();

        {
            let mut state = fake.state.lock().unwrap();
            let current = state.as_mut().unwrap();
            current["invocation_started_at_ms"]["N"] = json!("2000");
            current["checkpoint_version"]["N"] = json!("1");
            current["phase"]["S"] = json!(MigrationPhase::Complete.as_str());
        }

        let mut stale_next = stale.clone();
        stale_next.phase = MigrationPhase::CleanupReferences;
        fake.reject_next_transaction.store(true, Ordering::SeqCst);
        let step_error = migrator
            .replace_state(&stale, &stale_next)
            .await
            .unwrap_err();
        assert!(matches!(step_error, StoreError::Transient(_)));

        let mut stale_publish = stale;
        stale_publish.phase = MigrationPhase::PublishCoverage;
        fake.reject_next_transaction.store(true, Ordering::SeqCst);
        let publish_error = migrator.publish_coverage(&stale_publish).await.unwrap_err();
        server.abort();

        assert!(matches!(publish_error, StoreError::Transient(_)));
        let requests = fake.requests.lock().unwrap();
        let conditional_state_writes = requests.iter().filter_map(|(target, request)| {
            if !target.ends_with(".TransactWriteItems") {
                return None;
            }
            request["TransactItems"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|item| {
                    let put = &item["Put"];
                    (put["Item"][CLIENT_KEY_ATTRIBUTE]["S"] == MIGRATION_PARTITION
                        && put["Item"][REFERENCE_KEY_ATTRIBUTE]["S"] == MIGRATION_STATE_KEY
                        && put["ConditionExpression"]
                            .as_str()
                            .is_some_and(|condition| condition.contains("checkpoint_version")))
                    .then_some(put)
                })
        });
        let conditional_state_writes = conditional_state_writes.collect::<Vec<_>>();
        assert_eq!(conditional_state_writes.len(), 2);
        assert!(conditional_state_writes
            .iter()
            .all(|put| put["ConditionExpression"]
                .as_str()
                .unwrap()
                .contains("invocation_started_at_ms = :invocation_started_at_ms")));
    }

    #[tokio::test]
    async fn migration_begin_requires_the_request_marker_after_a_condition_conflict() {
        let (client, fake, server) = migration_client().await;
        let migrator = DynamoAuthorityReferenceMigrator::new(
            client,
            "codes-table",
            "refresh-table",
            "refs-table",
        );
        let migration_id = "client-authority-refs-v1:test";
        migrator
            .begin(migration_id, None, "request-original", 1_000, 1_700_000_000)
            .await
            .unwrap();

        fake.reject_next_transaction.store(true, Ordering::SeqCst);
        let error = migrator
            .begin(
                migration_id,
                None,
                "request-not-committed",
                2_000,
                1_700_000_100,
            )
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(error, StoreError::Transient(_)));
        assert!(!fake
            .request_markers
            .lock()
            .unwrap()
            .contains_key("request\u{1f}request-not-committed"));
    }
}
