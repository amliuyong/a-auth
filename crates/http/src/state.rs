//! 应用状态:配置 + 服务端口(signer / stores)。
//!
//! 端口 trait 用 `async fn`(RPITIT),**不 dyn 兼容**;为让 AppState 单一类型、handler 不泛型、
//! 内存与 AWS 适配器**共存且运行时可选**,用**枚举分发**包装(`SignerImpl`/`CodeStoreImpl`/
//! `ClientStoreImpl`)。本地/测试选 `Memory` 变体;Lambda 真机选 `Kms`/`Dynamo` 变体(`aws` feature)。
//! OAuth/OIDC 协议决策不在此;这里只聚合配置、IO 端口及跨端口的 runtime
//! delivery 编排。

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use agent_auth_discovery::{Form, Phase, SubjectType};
use agent_auth_infra_core::EcJwk;

use crate::adapters::memory::{
    LogAuthzEventSink, LogNotifier, MemoryAuthzSessionStore, MemoryCibaStore, MemoryClientStore,
    MemoryCodeStore, MemoryDeviceStore, MemoryGraceStore, MemoryInitialAccessTokenStore,
    MemoryInvitationStore, MemoryMagicLinkStore, MemoryOutboxNotifier, MemoryRecoveryStore,
    MemoryRefreshStore, MemorySessionStore, MemorySigner, MemoryWorkloadTrustStore,
};
use crate::attribute_namespace::AttributeNamespaceStore;
use crate::federation_attributes::FederationAttributeMappingsStore;
use crate::ports::{
    AdminAuthStore, AdminOidcConfig, AdminOidcConfigDeleteOutcome, AdminOidcConfigPutOutcome,
    AdminOidcFlow, AdminSessionRecord, AuthzEventSink, AuthzSessionRecord, AuthzSessionStore,
    CibaAuthRequest, CibaStore, ClientRecord, ClientStore, CodeIssueOutcome, CodeRecord, CodeStore,
    DeviceAuthGrant, DeviceStore, GraceStore, GrantStore, InitialAccessTokenStore,
    InvitationAcceptOutcome, InvitationAcceptRequest, InvitationIssueOutcome, InvitationRecord,
    InvitationStore, LeaseAcquire, MagicLinkRecord, MagicLinkStore, MessageOutbox, Notifier,
    RecoveryAuthorityConsume, RecoveryConsume, RecoveryConsumeRequest, RecoveryRecord,
    RecoveryStore, RecoverySuccessResult, RefreshFamilyRecord, RefreshLeaseAcquire, RefreshStore,
    SentMessage, SessionRecord, SessionStore, Signer, SignerError, StoreError, WorkloadTrustStore,
};
use crate::security_event::{
    MemorySecurityEventStore, SecurityEvent, SecurityEventCursor, SecurityEventDelivery,
    SecurityEventDeliveryStatus, SecurityEventDraft, SecurityEventFallback,
    SecurityEventFallbackOutcome, SecurityEventIngress, SecurityEventPage, SecurityEventStore,
    StoredSecurityEvent,
};
use crate::ssf::{
    MemorySsfStore, SignedSet, SsfAttemptResult, SsfDelivery, SsfDeliveryCursor, SsfDeliveryLease,
    SsfDeliveryPage, SsfRedriveOutcome, SsfStore, SsfStream, SsfStreamCreateOutcome,
    SsfStreamMutation, SsfStreamMutationOutcome, SsfVerificationOutcome,
};

const SECURITY_EVENT_IO_TIMEOUT: Duration = Duration::from_millis(500);
const SECURITY_EVENT_BATCH_TIMEOUT: Duration = Duration::from_millis(3_500);
const MAX_CONCURRENT_SECURITY_EVENT_DELIVERIES: usize = 16;
const SECURITY_EVENT_FALLBACK_BATCH_SIZE: usize = 10;

async fn bounded_security_event_io<T>(
    operation: &'static str,
    timeout: Duration,
    future: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(StoreError::Transient(format!(
            "security event {operation} timed out"
        ))),
    }
}

/// DCR 准入档(DESIGN §3.2 / spec 002 C4.3)。默认随形态,由 `AGENT_AUTH_DCR_MODE` 显式配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DcrMode {
    /// 无凭证公开注册(自部署内网可信默认;SaaS 需租户显式开)。
    Open,
    /// 凭 initial access token(Bearer)注册(SaaS 默认;票据由控制面分发)。**fail-closed 缺省档**。
    #[default]
    InitialAccessToken,
    /// 凭签名 software statement 注册(RFC 7591 §3.1.1)。P0 未实现 → 显式拒(501)。
    SoftwareStatement,
}

impl DcrMode {
    /// 是否 open 档(供 CORS/文档/测试判定;只读 helper,不再有可写派生 bool)。
    pub fn is_open(self) -> bool {
        matches!(self, DcrMode::Open)
    }

    /// 从环境串解析(`open`/`initial_access_token`/`software_statement`);未知/缺失 → None(上层定缺省)。
    pub fn from_env_str(s: &str) -> Option<Self> {
        match s {
            "open" => Some(DcrMode::Open),
            "initial_access_token" => Some(DcrMode::InitialAccessToken),
            "software_statement" => Some(DcrMode::SoftwareStatement),
            _ => None,
        }
    }
}

/// 签名端口的枚举分发(内存 / KMS)。
#[derive(Clone)]
pub enum SignerImpl {
    Memory(MemorySigner),
    #[cfg(feature = "aws")]
    Kms(crate::adapters::aws::KmsSigner),
    /// SaaS has no deployment-wide signing authority. Every data-plane path
    /// must resolve a complete tenant snapshot before it can sign or publish.
    Unavailable,
}

impl Signer for SignerImpl {
    async fn sign_es256(&self, input: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self {
            SignerImpl::Memory(s) => s.sign_es256(input).await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.sign_es256(input).await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=sign_es256 class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
    async fn public_jwks(&self) -> Result<Vec<EcJwk>, SignerError> {
        match self {
            SignerImpl::Memory(s) => s.public_jwks().await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.public_jwks().await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=public_jwks class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
    async fn active_kid(&self) -> Result<String, SignerError> {
        match self {
            SignerImpl::Memory(s) => s.active_kid().await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.active_kid().await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=active_kid class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
    async fn sign_rs256(&self, input: &[u8]) -> Result<(String, Vec<u8>), SignerError> {
        match self {
            SignerImpl::Memory(s) => s.sign_rs256(input).await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.sign_rs256(input).await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=sign_rs256 class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
    async fn public_rsa_jwks(&self) -> Result<Vec<agent_auth_infra_core::RsaJwk>, SignerError> {
        match self {
            SignerImpl::Memory(s) => s.public_rsa_jwks().await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.public_rsa_jwks().await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=public_rsa_jwks class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
    async fn active_rsa_kid(&self) -> Result<String, SignerError> {
        match self {
            SignerImpl::Memory(s) => s.active_rsa_kid().await,
            #[cfg(feature = "aws")]
            SignerImpl::Kms(s) => {
                let result = s.active_rsa_kid().await;
                if let Err(error) = &result {
                    eprintln!("KMS_SIGNING_ERROR operation=active_rsa_kid class={error:?}");
                }
                result
            }
            SignerImpl::Unavailable => Err(SignerError::Permanent(
                "deployment-wide signer is unavailable".to_string(),
            )),
        }
    }
}

/// 授权码存储端口的枚举分发。
#[derive(Clone)]
pub enum CodeStoreImpl {
    Memory(MemoryCodeStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoCodeStore),
}

impl CodeStoreImpl {
    pub(crate) async fn finalize_exchange_failure(
        &self,
        authz_sessions: &AuthzSessionStoreImpl,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        authz_session_id: Option<&str>,
        last_error: String,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        match (self, authz_sessions) {
            (CodeStoreImpl::Memory(codes), AuthzSessionStoreImpl::Memory(sessions)) => {
                codes
                    .finalize_exchange_failure(
                        sessions,
                        tenant,
                        code,
                        client_id,
                        expires_at,
                        now,
                        lease_owner,
                        authz_session_id,
                        last_error,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (CodeStoreImpl::Dynamo(codes), AuthzSessionStoreImpl::Dynamo(sessions)) => {
                codes
                    .finalize_exchange_failure(
                        sessions,
                        tenant,
                        code,
                        client_id,
                        expires_at,
                        now,
                        lease_owner,
                        authz_session_id,
                        last_error,
                    )
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "code and authorization session stores use incompatible backends".to_string(),
            )),
        }
    }

    pub(crate) async fn put_authorized(
        &self,
        users: &UsersStoreImpl,
        tenant: &str,
        record: CodeRecord,
        expected_epoch: u64,
    ) -> Result<CodeIssueOutcome, StoreError> {
        match (self, users) {
            (CodeStoreImpl::Memory(codes), UsersStoreImpl::Memory(users)) => {
                codes
                    .put_authorized(users, tenant, record, expected_epoch)
                    .await
            }
            #[cfg(feature = "aws")]
            (CodeStoreImpl::Dynamo(codes), UsersStoreImpl::Dynamo(users)) => {
                codes
                    .put_authorized(users, tenant, record, expected_epoch)
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "code and user stores use incompatible backends".to_string(),
            )),
        }
    }
}

impl CodeStore for CodeStoreImpl {
    async fn put(&self, tenant: &str, r: CodeRecord) -> Result<(), StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.put(tenant, r).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.put(tenant, r).await,
        }
    }
    async fn acquire_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<LeaseAcquire, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => {
                s.acquire_lease(tenant, code, lease_owner, now, lease_expires_at)
                    .await
            }
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => {
                s.acquire_lease(tenant, code, lease_owner, now, lease_expires_at)
                    .await
            }
        }
    }
    async fn finalize(
        &self,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        issued_grant_id: Option<&str>,
    ) -> Result<(), StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => {
                s.finalize(
                    tenant,
                    code,
                    client_id,
                    expires_at,
                    now,
                    lease_owner,
                    issued_grant_id,
                )
                .await
            }
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => {
                s.finalize(
                    tenant,
                    code,
                    client_id,
                    expires_at,
                    now,
                    lease_owner,
                    issued_grant_id,
                )
                .await
            }
        }
    }
    async fn release_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.release_lease(tenant, code, lease_owner, now).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.release_lease(tenant, code, lease_owner, now).await,
        }
    }
    async fn record_replay(&self, tenant: &str, code: &str, now: i64) -> Result<bool, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.record_replay(tenant, code, now).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.record_replay(tenant, code, now).await,
        }
    }
    async fn replay_detected(&self, tenant: &str, code: &str) -> Result<bool, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.replay_detected(tenant, code).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.replay_detected(tenant, code).await,
        }
    }
    async fn has_unexpired_by_client(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.has_unexpired_by_client(tenant, client_id, now).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.has_unexpired_by_client(tenant, client_id, now).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            CodeStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            CodeStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 客户端存储端口的枚举分发。
#[derive(Clone)]
pub enum ClientStoreImpl {
    Memory(MemoryClientStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoClientStore),
}

impl ClientStore for ClientStoreImpl {
    async fn get(&self, tenant: &str, client_id: &str) -> Result<Option<ClientRecord>, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.get(tenant, client_id).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.get(tenant, client_id).await,
        }
    }
    async fn put(&self, tenant: &str, r: ClientRecord) -> Result<(), StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.put(tenant, r).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.put(tenant, r).await,
        }
    }
    async fn put_if_credential_versions(
        &self,
        tenant: &str,
        record: ClientRecord,
        expected_client_secret_version: u64,
        expected_registration_token_version: u64,
    ) -> Result<bool, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => {
                s.put_if_credential_versions(
                    tenant,
                    record,
                    expected_client_secret_version,
                    expected_registration_token_version,
                )
                .await
            }
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => {
                s.put_if_credential_versions(
                    tenant,
                    record,
                    expected_client_secret_version,
                    expected_registration_token_version,
                )
                .await
            }
        }
    }
    async fn replace_credential_set(
        &self,
        tenant: &str,
        client_id: &str,
        kind: crate::credential::CredentialKind,
        expected_version: u64,
        credentials: crate::credential::CredentialSet,
    ) -> Result<bool, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => {
                s.replace_credential_set(tenant, client_id, kind, expected_version, credentials)
                    .await
            }
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => {
                s.replace_credential_set(tenant, client_id, kind, expected_version, credentials)
                    .await
            }
        }
    }
    async fn list(&self, tenant: &str) -> Result<Vec<ClientRecord>, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.list(tenant).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.list(tenant).await,
        }
    }
    async fn delete(&self, tenant: &str, client_id: &str) -> Result<(), StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.delete(tenant, client_id).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.delete(tenant, client_id).await,
        }
    }
    async fn touch_last_used(
        &self,
        tenant: &str,
        client_id: &str,
        today: i64,
    ) -> Result<(), StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.touch_last_used(tenant, client_id, today).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.touch_last_used(tenant, client_id, today).await,
        }
    }
    async fn convert_to_tombstone(
        &self,
        tenant: &str,
        client_id: &str,
        tombstoned_at: i64,
        snapshot_day: Option<i64>,
        snapshot_authority_revision: u64,
    ) -> Result<bool, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => {
                s.convert_to_tombstone(
                    tenant,
                    client_id,
                    tombstoned_at,
                    snapshot_day,
                    snapshot_authority_revision,
                )
                .await
            }
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => {
                s.convert_to_tombstone(
                    tenant,
                    client_id,
                    tombstoned_at,
                    snapshot_day,
                    snapshot_authority_revision,
                )
                .await
            }
        }
    }
    async fn list_reclaim_candidates(
        &self,
        tenant: &str,
        older_than_day: i64,
    ) -> Result<Vec<(String, ClientRecord)>, StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => s.list_reclaim_candidates(tenant, older_than_day).await,
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => s.list_reclaim_candidates(tenant, older_than_day).await,
        }
    }
    async fn hard_delete_with_audit(
        &self,
        tenant: &str,
        record: &ClientRecord,
        hard_deleted_at: i64,
    ) -> Result<(), StoreError> {
        match self {
            ClientStoreImpl::Memory(s) => {
                s.hard_delete_with_audit(tenant, record, hard_deleted_at)
                    .await
            }
            #[cfg(feature = "aws")]
            ClientStoreImpl::Dynamo(s) => {
                s.hard_delete_with_audit(tenant, record, hard_deleted_at)
                    .await
            }
        }
    }
}

#[derive(Clone)]
pub enum InitialAccessTokenStoreImpl {
    Memory(MemoryInitialAccessTokenStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoInitialAccessTokenStore),
}

impl InitialAccessTokenStore for InitialAccessTokenStoreImpl {
    async fn get(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> Result<Option<crate::credential::InitialAccessTokenRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get(tenant, token_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get(tenant, token_id).await,
        }
    }

    async fn put_new(
        &self,
        tenant: &str,
        record: crate::credential::InitialAccessTokenRecord,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.put_new(tenant, record).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_new(tenant, record).await,
        }
    }

    async fn list(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::credential::InitialAccessTokenRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.list(tenant).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list(tenant).await,
        }
    }

    async fn revoke(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .revoke(tenant, token_id, expected_version, revoked_at)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .revoke(tenant, token_id, expected_version, revoked_at)
                    .await
            }
        }
    }

    async fn consume_once(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        used_at: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .consume_once(tenant, token_id, expected_version, used_at)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .consume_once(tenant, token_id, expected_version, used_at)
                    .await
            }
        }
    }

    async fn delete(&self, tenant: &str, token_id: &str) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.delete(tenant, token_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.delete(tenant, token_id).await,
        }
    }
}

/// refresh family 存储端口的枚举分发。
#[derive(Clone)]
pub enum RefreshStoreImpl {
    Memory(MemoryRefreshStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoRefreshStore),
}

impl RefreshStore for RefreshStoreImpl {
    async fn create(&self, tenant: &str, r: RefreshFamilyRecord) -> Result<(), StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.create(tenant, r).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.create(tenant, r).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> Result<Option<RefreshFamilyRecord>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.get(tenant, family_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.get(tenant, family_id).await,
        }
    }
    async fn acquire_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<RefreshLeaseAcquire, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => {
                s.acquire_lease(
                    tenant,
                    family_id,
                    expected_version,
                    lease_owner,
                    now,
                    lease_expires_at,
                )
                .await
            }
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => {
                s.acquire_lease(
                    tenant,
                    family_id,
                    expected_version,
                    lease_owner,
                    now,
                    lease_expires_at,
                )
                .await
            }
        }
    }
    async fn finalize_rotation(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => {
                s.finalize_rotation(tenant, family_id, expected_version, lease_owner, now)
                    .await
            }
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => {
                s.finalize_rotation(tenant, family_id, expected_version, lease_owner, now)
                    .await
            }
        }
    }
    async fn release_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
    ) -> Result<bool, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => {
                s.release_lease(tenant, family_id, expected_version, lease_owner)
                    .await
            }
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => {
                s.release_lease(tenant, family_id, expected_version, lease_owner)
                    .await
            }
        }
    }
    async fn revoke(&self, tenant: &str, family_id: &str) -> Result<(), StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.revoke(tenant, family_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.revoke(tenant, family_id).await,
        }
    }
    async fn revoke_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.revoke_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.revoke_by_user(tenant, user_id).await,
        }
    }
    async fn revoke_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<Vec<String>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => {
                s.revoke_by_user_before_epoch(tenant, user_id, epoch).await
            }
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => {
                s.revoke_by_user_before_epoch(tenant, user_id, epoch).await
            }
        }
    }
    async fn revoke_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.revoke_by_client(tenant, client_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.revoke_by_client(tenant, client_id).await,
        }
    }
    async fn has_active_family_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.has_active_family_by_client(tenant, client_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.has_active_family_by_client(tenant, client_id).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<Vec<String>, StoreError> {
        match self {
            RefreshStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            RefreshStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 宽限窗缓存存储端口的枚举分发(C3.2/C3.4/C3.5)。
#[derive(Clone)]
pub enum GraceStoreImpl {
    Memory(MemoryGraceStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoGraceStore),
}

impl RefreshStoreImpl {
    pub async fn finalize_rotation_with_grace(
        &self,
        grace: Option<&GraceStoreImpl>,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        entry: Option<crate::ports::GraceCacheEntry>,
    ) -> Result<bool, StoreError> {
        match (self, grace) {
            (RefreshStoreImpl::Memory(refresh), Some(GraceStoreImpl::Memory(grace))) => {
                refresh
                    .finalize_rotation_with_grace(
                        Some(grace),
                        tenant,
                        family_id,
                        expected_version,
                        lease_owner,
                        now,
                        entry,
                    )
                    .await
            }
            (RefreshStoreImpl::Memory(refresh), None) => {
                refresh
                    .finalize_rotation_with_grace(
                        None,
                        tenant,
                        family_id,
                        expected_version,
                        lease_owner,
                        now,
                        entry,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (RefreshStoreImpl::Dynamo(refresh), Some(GraceStoreImpl::Dynamo(grace))) => {
                refresh
                    .finalize_rotation_with_grace(
                        Some(grace),
                        tenant,
                        family_id,
                        expected_version,
                        lease_owner,
                        now,
                        entry,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (RefreshStoreImpl::Dynamo(refresh), None) => {
                refresh
                    .finalize_rotation_with_grace(
                        None,
                        tenant,
                        family_id,
                        expected_version,
                        lease_owner,
                        now,
                        entry,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            _ => Err(StoreError::Permanent(
                "refresh and grace stores use incompatible backends".into(),
            )),
        }
    }
}

impl crate::ports::GraceStore for GraceStoreImpl {
    async fn put(&self, entry: crate::ports::GraceCacheEntry) -> Result<(), StoreError> {
        match self {
            GraceStoreImpl::Memory(s) => s.put(entry).await,
            #[cfg(feature = "aws")]
            GraceStoreImpl::Dynamo(s) => s.put(entry).await,
        }
    }
    async fn get(
        &self,
        family_id: &str,
        version: u64,
    ) -> Result<Option<crate::ports::GraceCacheEntry>, StoreError> {
        match self {
            GraceStoreImpl::Memory(s) => s.get(family_id, version).await,
            #[cfg(feature = "aws")]
            GraceStoreImpl::Dynamo(s) => s.get(family_id, version).await,
        }
    }
    async fn delete_family(&self, family_id: &str) -> Result<(), StoreError> {
        match self {
            GraceStoreImpl::Memory(s) => s.delete_family(family_id).await,
            #[cfg(feature = "aws")]
            GraceStoreImpl::Dynamo(s) => s.delete_family(family_id).await,
        }
    }
}

/// 平台 JWKS 取用端口的枚举分发(spec 012 workload_oidc_jwt)。
#[derive(Clone)]
pub enum JwksFetcherImpl {
    Memory(crate::adapters::memory::MemoryJwksFetcher),
    #[cfg(feature = "aws")]
    Http(crate::adapters::aws::HttpJwksFetcher),
}

impl crate::ports::JwksFetcher for JwksFetcherImpl {
    async fn fetch(&self, jwks_uri: &str) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        match self {
            JwksFetcherImpl::Memory(s) => s.fetch(jwks_uri).await,
            #[cfg(feature = "aws")]
            JwksFetcherImpl::Http(s) => s.fetch(jwks_uri).await,
        }
    }
    async fn fetch_fresh(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        match self {
            JwksFetcherImpl::Memory(s) => s.fetch_fresh(jwks_uri).await,
            #[cfg(feature = "aws")]
            JwksFetcherImpl::Http(s) => s.fetch_fresh(jwks_uri).await,
        }
    }
}

/// STS caller 端口枚举分发(spec 012 C5.2)。dev/测试 = Memory(mock);真机 = Http(reqwest→STS)。
pub enum StsCallerImpl {
    Memory(crate::adapters::memory::MemoryStsCaller),
    #[cfg(feature = "aws")]
    Http(crate::adapters::aws::HttpStsCaller),
}

impl crate::ports::StsCaller for StsCallerImpl {
    async fn get_caller_identity(
        &self,
        assertion: &agent_auth_workload::SigV4Assertion,
    ) -> Result<Option<agent_auth_workload::StsCallerIdentity>, StoreError> {
        match self {
            StsCallerImpl::Memory(s) => s.get_caller_identity(assertion).await,
            #[cfg(feature = "aws")]
            StsCallerImpl::Http(s) => s.get_caller_identity(assertion).await,
        }
    }
}

/// 上游 token 交换器端口枚举分发(spec 003 §4)。dev/测试 = Memory(预置 code→token);真机 = Http(reqwest→上游)。
#[derive(Clone)]
pub enum UpstreamTokenExchangerImpl {
    Memory(crate::adapters::memory::MemoryUpstreamTokenExchanger),
    #[cfg(feature = "aws")]
    Http(crate::adapters::aws::HttpUpstreamTokenExchanger),
}

impl crate::ports::UpstreamTokenExchanger for UpstreamTokenExchangerImpl {
    async fn exchange_code(
        &self,
        req: &crate::ports::UpstreamTokenExchangeRequest<'_>,
    ) -> Result<Option<crate::ports::UpstreamTokenSet>, StoreError> {
        match self {
            UpstreamTokenExchangerImpl::Memory(s) => s.exchange_code(req).await,
            #[cfg(feature = "aws")]
            UpstreamTokenExchangerImpl::Http(s) => s.exchange_code(req).await,
        }
    }
}

/// secret 解析器端口枚举分发(spec 003 §4)。dev/测试 = Memory(预置引用名→明文);真机 = Secrets Manager。
#[derive(Clone)]
pub enum SecretResolverImpl {
    Memory(crate::adapters::memory::MemorySecretResolver),
    #[cfg(feature = "aws")]
    SecretsManager(crate::adapters::aws::SecretsManagerResolver),
}

impl crate::ports::SecretResolver for SecretResolverImpl {
    async fn resolve(&self, secret_ref: &str) -> Result<Option<String>, StoreError> {
        match self {
            SecretResolverImpl::Memory(s) => s.resolve(secret_ref).await,
            #[cfg(feature = "aws")]
            SecretResolverImpl::SecretsManager(s) => s.resolve(secret_ref).await,
        }
    }
}

/// 联邦 flow 状态存储端口枚举分发(spec 003 §4)。dev/测试 = Memory;真机 = Dynamo(条件删一次性 + TTL)。
#[derive(Clone)]
pub enum FederationFlowStoreImpl {
    Memory(crate::adapters::memory::MemoryFederationFlowStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoFederationFlowStore),
}

impl crate::ports::FederationFlowStore for FederationFlowStoreImpl {
    async fn put(&self, st: crate::ports::FederationFlowState) -> Result<(), StoreError> {
        match self {
            FederationFlowStoreImpl::Memory(s) => s.put(st).await,
            #[cfg(feature = "aws")]
            FederationFlowStoreImpl::Dynamo(s) => s.put(st).await,
        }
    }
    async fn consume(
        &self,
        state: &str,
    ) -> Result<Option<crate::ports::FederationFlowState>, StoreError> {
        match self {
            FederationFlowStoreImpl::Memory(s) => s.consume(state).await,
            #[cfg(feature = "aws")]
            FederationFlowStoreImpl::Dynamo(s) => s.consume(state).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            FederationFlowStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            FederationFlowStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant_id).await,
        }
    }
}

/// Admin OIDC configuration, one-time flow, and short-lived session store.
#[derive(Clone)]
pub enum AdminAuthStoreImpl {
    Memory(crate::adapters::memory::MemoryAdminAuthStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoAdminAuthStore),
}

impl AdminAuthStore for AdminAuthStoreImpl {
    async fn get_config(&self, tenant_id: &str) -> Result<Option<AdminOidcConfig>, StoreError> {
        match self {
            Self::Memory(store) => store.get_config(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_config(tenant_id).await,
        }
    }

    async fn put_config(
        &self,
        config: AdminOidcConfig,
        expected_revision: u64,
    ) -> Result<AdminOidcConfigPutOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.put_config(config, expected_revision).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_config(config, expected_revision).await,
        }
    }

    async fn delete_config(
        &self,
        tenant_id: &str,
        expected_revision: u64,
    ) -> Result<AdminOidcConfigDeleteOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.delete_config(tenant_id, expected_revision).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.delete_config(tenant_id, expected_revision).await,
        }
    }

    async fn put_flow(&self, flow: AdminOidcFlow) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.put_flow(flow).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_flow(flow).await,
        }
    }

    async fn consume_flow(
        &self,
        state_hash: &str,
        now: i64,
    ) -> Result<Option<AdminOidcFlow>, StoreError> {
        match self {
            Self::Memory(store) => store.consume_flow(state_hash, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.consume_flow(state_hash, now).await,
        }
    }

    async fn create_session(&self, session: AdminSessionRecord) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.create_session(session).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.create_session(session).await,
        }
    }

    async fn get_session(
        &self,
        session_hash: &str,
        now: i64,
    ) -> Result<Option<AdminSessionRecord>, StoreError> {
        match self {
            Self::Memory(store) => store.get_session(session_hash, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_session(session_hash, now).await,
        }
    }

    async fn delete_session(&self, tenant_id: &str, session_hash: &str) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.delete_session(tenant_id, session_hash).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.delete_session(tenant_id, session_hash).await,
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            Self::Memory(store) => store.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.delete_all_by_tenant(tenant_id).await,
        }
    }
}

/// passkey challenge 存储枚举分发(spec 003 §3)。dev/测试 = Memory;真机 = Dynamo(条件删一次性 + TTL)。
#[derive(Clone)]
pub enum PasskeyChallengeStoreImpl {
    Memory(crate::adapters::memory::MemoryPasskeyChallengeStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPasskeyChallengeStore),
}

impl crate::ports::PasskeyChallengeStore for PasskeyChallengeStoreImpl {
    async fn put(&self, ch: crate::ports::PasskeyChallenge) -> Result<(), StoreError> {
        match self {
            PasskeyChallengeStoreImpl::Memory(s) => s.put(ch).await,
            #[cfg(feature = "aws")]
            PasskeyChallengeStoreImpl::Dynamo(s) => s.put(ch).await,
        }
    }
    async fn consume(
        &self,
        tenant: &str,
        challenge_b64url: &str,
    ) -> Result<Option<crate::ports::PasskeyChallenge>, StoreError> {
        match self {
            PasskeyChallengeStoreImpl::Memory(s) => s.consume(tenant, challenge_b64url).await,
            #[cfg(feature = "aws")]
            PasskeyChallengeStoreImpl::Dynamo(s) => s.consume(tenant, challenge_b64url).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            PasskeyChallengeStoreImpl::Memory(s) => s.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            PasskeyChallengeStoreImpl::Dynamo(s) => s.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            PasskeyChallengeStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            PasskeyChallengeStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// PAR 存储枚举分发(spec 006 §7.3)。dev/测试 = Memory;真机 = Dynamo(条件删一次性 + fail-closed 校过期)。
#[derive(Clone)]
pub enum ParStoreImpl {
    Memory(crate::adapters::memory::MemoryParStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoParStore),
}

impl crate::ports::ParStore for ParStoreImpl {
    async fn put(&self, tenant: &str, record: crate::ports::ParRecord) -> Result<(), StoreError> {
        match self {
            ParStoreImpl::Memory(s) => s.put(tenant, record).await,
            #[cfg(feature = "aws")]
            ParStoreImpl::Dynamo(s) => s.put(tenant, record).await,
        }
    }
    async fn consume(
        &self,
        tenant: &str,
        request_uri: &str,
        now: i64,
    ) -> Result<Option<crate::ports::ParRecord>, StoreError> {
        match self {
            ParStoreImpl::Memory(s) => s.consume(tenant, request_uri, now).await,
            #[cfg(feature = "aws")]
            ParStoreImpl::Dynamo(s) => s.consume(tenant, request_uri, now).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            ParStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            ParStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// passkey 凭证存储枚举分发(spec 003 §3)。dev/测试 = Memory;真机 = Dynamo(条件写唯一 + CAS)。
#[derive(Clone)]
pub enum PasskeyStoreImpl {
    Memory(crate::adapters::memory::MemoryPasskeyStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPasskeyStore),
}

impl PasskeyStoreImpl {
    pub(crate) async fn put_new_authorized(
        &self,
        users: &UsersStoreImpl,
        sessions: &SessionStoreImpl,
        tenant: &str,
        session: &SessionRecord,
        credential: agent_auth_authn::passkey::PasskeyCredential,
        now: i64,
    ) -> Result<crate::ports::PasskeyRegistrationOutcome, StoreError> {
        match (self, users, sessions) {
            (
                PasskeyStoreImpl::Memory(passkeys),
                UsersStoreImpl::Memory(users),
                SessionStoreImpl::Memory(sessions),
            ) => {
                passkeys
                    .put_new_authorized(users, sessions, tenant, session, credential, now)
                    .await
            }
            #[cfg(feature = "aws")]
            (
                PasskeyStoreImpl::Dynamo(passkeys),
                UsersStoreImpl::Dynamo(users),
                SessionStoreImpl::Dynamo(sessions),
            ) => {
                passkeys
                    .put_new_authorized(users, sessions, tenant, session, credential, now)
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "passkey, user, and session stores use incompatible backends".to_string(),
            )),
        }
    }

    pub(crate) async fn delete_owned_and_complete(
        &self,
        users: &UsersStoreImpl,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        match (self, users) {
            (PasskeyStoreImpl::Memory(passkeys), UsersStoreImpl::Memory(users)) => {
                passkeys
                    .delete_owned_and_complete(
                        users,
                        tenant,
                        user_id,
                        credential_id,
                        owner,
                        updated_at,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (PasskeyStoreImpl::Dynamo(passkeys), UsersStoreImpl::Dynamo(users)) => {
                passkeys
                    .delete_owned_and_complete(
                        users,
                        tenant,
                        user_id,
                        credential_id,
                        owner,
                        updated_at,
                    )
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "passkey and user stores use incompatible backends".to_string(),
            )),
        }
    }
}

impl crate::ports::PasskeyStore for PasskeyStoreImpl {
    async fn put_new(
        &self,
        tenant: &str,
        cred: agent_auth_authn::passkey::PasskeyCredential,
    ) -> Result<bool, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.put_new(tenant, cred).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.put_new(tenant, cred).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> Result<Option<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.get(tenant, credential_id).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.get(tenant, credential_id).await,
        }
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.list_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.list_by_user(tenant, user_id).await,
        }
    }
    async fn update_sign_count(
        &self,
        tenant: &str,
        credential_id: &str,
        new_count: u32,
        expected_prev: u32,
    ) -> Result<bool, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => {
                s.update_sign_count(tenant, credential_id, new_count, expected_prev)
                    .await
            }
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => {
                s.update_sign_count(tenant, credential_id, new_count, expected_prev)
                    .await
            }
        }
    }
    async fn rename_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => {
                s.rename_owned(tenant, user_id, credential_id, name).await
            }
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => {
                s.rename_owned(tenant, user_id, credential_id, name).await
            }
        }
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.delete_owned(tenant, user_id, credential_id).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.delete_owned(tenant, user_id, credential_id).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            PasskeyStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            PasskeyStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 一次性 replay 缓存端口枚举分发(spec 012 C5.3②)。
pub enum ReplayStoreImpl {
    Memory(crate::adapters::memory::MemoryReplayStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoReplayStore),
}

impl crate::ports::ReplayStore for ReplayStoreImpl {
    async fn check_and_set(
        &self,
        tenant: &str,
        key: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        match self {
            ReplayStoreImpl::Memory(s) => s.check_and_set(tenant, key, expires_at).await,
            #[cfg(feature = "aws")]
            ReplayStoreImpl::Dynamo(s) => s.check_and_set(tenant, key, expires_at).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            ReplayStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            ReplayStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// per-client 令牌桶限流端口枚举分发(spec 005 C10.7)。
pub enum RateLimitStoreImpl {
    Memory(crate::adapters::memory::MemoryRateLimitStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoRateLimitStore),
}

impl crate::ports::RateLimitStore for RateLimitStoreImpl {
    async fn check_available(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        match self {
            RateLimitStoreImpl::Memory(s) => {
                s.check_available(key, now, capacity, refill_per_sec, cost)
                    .await
            }
            #[cfg(feature = "aws")]
            RateLimitStoreImpl::Dynamo(s) => {
                s.check_available(key, now, capacity, refill_per_sec, cost)
                    .await
            }
        }
    }

    async fn try_consume(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        match self {
            RateLimitStoreImpl::Memory(s) => {
                s.try_consume(key, now, capacity, refill_per_sec, cost)
                    .await
            }
            #[cfg(feature = "aws")]
            RateLimitStoreImpl::Dynamo(s) => {
                s.try_consume(key, now, capacity, refill_per_sec, cost)
                    .await
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        match self {
            RateLimitStoreImpl::Memory(store) => store.delete(key).await,
            #[cfg(feature = "aws")]
            RateLimitStoreImpl::Dynamo(store) => store.delete(key).await,
        }
    }
}

/// Grant 存储端口枚举分发(spec 011 §5.1)。
pub enum GrantStoreImpl {
    Memory(crate::adapters::memory::MemoryGrantStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoGrantStore),
}

impl GrantStoreImpl {
    pub async fn put_for_active_client(
        &self,
        clients: &ClientStoreImpl,
        tenant: &str,
        grant: agent_auth_grant::Grant,
    ) -> Result<bool, StoreError> {
        match (self, clients) {
            (GrantStoreImpl::Memory(grants), ClientStoreImpl::Memory(clients)) => {
                Box::pin(grants.put_for_active_client(clients, tenant, grant)).await
            }
            #[cfg(feature = "aws")]
            (GrantStoreImpl::Dynamo(grants), ClientStoreImpl::Dynamo(_)) => {
                Box::pin(grants.put_for_active_client(tenant, grant)).await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "Grant and Client stores use incompatible backends".into(),
            )),
        }
    }
}

impl crate::ports::GrantStore for GrantStoreImpl {
    async fn put(&self, tenant: &str, grant: agent_auth_grant::Grant) -> Result<(), StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.put(tenant, grant).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.put(tenant, grant).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> Result<Option<agent_auth_grant::Grant>, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.get(tenant, grant_id).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.get(tenant, grant_id).await,
        }
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_grant::Grant>, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.list_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.list_by_user(tenant, user_id).await,
        }
    }
    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.revoke(tenant, grant_id).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.revoke(tenant, grant_id).await,
        }
    }
    async fn revoke_if_epoch_before(
        &self,
        tenant: &str,
        grant_id: &str,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.revoke_if_epoch_before(tenant, grant_id, epoch).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.revoke_if_epoch_before(tenant, grant_id, epoch).await,
        }
    }
    async fn revoke_if_revision(
        &self,
        tenant: &str,
        grant_id: &str,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => {
                s.revoke_if_revision(tenant, grant_id, expected_revision)
                    .await
            }
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => {
                s.revoke_if_revision(tenant, grant_id, expected_revision)
                    .await
            }
        }
    }
    async fn put_conditional(
        &self,
        tenant: &str,
        grant: agent_auth_grant::Grant,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.put_conditional(tenant, grant, expected_revision).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.put_conditional(tenant, grant, expected_revision).await,
        }
    }
    async fn list_stale(
        &self,
        tenant: &str,
        current_pv: u64,
    ) -> Result<Vec<(String, agent_auth_grant::Grant)>, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.list_stale(tenant, current_pv).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.list_stale(tenant, current_pv).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.delete_by_client(tenant, client_id).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.delete_by_client(tenant, client_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            GrantStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            GrantStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 逐租户 policy_version 存储枚举分发(spec 005 §7)。
pub enum PolicyVersionStoreImpl {
    Memory(crate::adapters::memory::MemoryPolicyVersionStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPolicyVersionStore),
}

impl crate::ports::PolicyVersionStore for PolicyVersionStoreImpl {
    async fn get(&self, tenant: &str) -> Result<u64, StoreError> {
        match self {
            PolicyVersionStoreImpl::Memory(s) => s.get(tenant).await,
            #[cfg(feature = "aws")]
            PolicyVersionStoreImpl::Dynamo(s) => s.get(tenant).await,
        }
    }
    async fn bump(&self, tenant: &str) -> Result<u64, StoreError> {
        match self {
            PolicyVersionStoreImpl::Memory(s) => s.bump(tenant).await,
            #[cfg(feature = "aws")]
            PolicyVersionStoreImpl::Dynamo(s) => s.bump(tenant).await,
        }
    }
    async fn delete(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            PolicyVersionStoreImpl::Memory(s) => s.delete(tenant).await,
            #[cfg(feature = "aws")]
            PolicyVersionStoreImpl::Dynamo(s) => s.delete(tenant).await,
        }
    }
}

/// BYOD 域名映射存储枚举分发(spec 010 §5.4 / C8.1b)。
pub enum DomainMapStoreImpl {
    Memory(crate::adapters::memory::MemoryDomainMapStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoDomainMapStore),
}

impl crate::ports::DomainMapStore for DomainMapStoreImpl {
    async fn get(&self, domain: &str) -> Result<Option<crate::ports::DomainBinding>, StoreError> {
        match self {
            DomainMapStoreImpl::Memory(s) => s.get(domain).await,
            #[cfg(feature = "aws")]
            DomainMapStoreImpl::Dynamo(s) => s.get(domain).await,
        }
    }
    async fn put_if_absent(
        &self,
        binding: crate::ports::DomainBinding,
    ) -> Result<bool, StoreError> {
        match self {
            DomainMapStoreImpl::Memory(s) => s.put_if_absent(binding).await,
            #[cfg(feature = "aws")]
            DomainMapStoreImpl::Dynamo(s) => s.put_if_absent(binding).await,
        }
    }
    async fn delete_if_owner(&self, domain: &str, client_id: &str) -> Result<bool, StoreError> {
        match self {
            DomainMapStoreImpl::Memory(s) => s.delete_if_owner(domain, client_id).await,
            #[cfg(feature = "aws")]
            DomainMapStoreImpl::Dynamo(s) => s.delete_if_owner(domain, client_id).await,
        }
    }
    async fn list_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<crate::ports::DomainBinding>, StoreError> {
        match self {
            DomainMapStoreImpl::Memory(s) => s.list_by_client(client_id).await,
            #[cfg(feature = "aws")]
            DomainMapStoreImpl::Dynamo(s) => s.list_by_client(client_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            DomainMapStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            DomainMapStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant_id).await,
        }
    }
}

/// 不可变策略工件存储枚举分发(spec 005 §7)。
pub enum PolicyArtifactStoreImpl {
    Memory(crate::adapters::memory::MemoryPolicyArtifactStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPolicyArtifactStore),
}

impl crate::ports::PolicyArtifactStore for PolicyArtifactStoreImpl {
    async fn put(
        &self,
        tenant: &str,
        version: u64,
        text: String,
        digest: String,
    ) -> Result<(), StoreError> {
        match self {
            PolicyArtifactStoreImpl::Memory(s) => s.put(tenant, version, text, digest).await,
            #[cfg(feature = "aws")]
            PolicyArtifactStoreImpl::Dynamo(s) => s.put(tenant, version, text, digest).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        version: u64,
    ) -> Result<Option<(String, String)>, StoreError> {
        match self {
            PolicyArtifactStoreImpl::Memory(s) => s.get(tenant, version).await,
            #[cfg(feature = "aws")]
            PolicyArtifactStoreImpl::Dynamo(s) => s.get(tenant, version).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            PolicyArtifactStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            PolicyArtifactStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant).await,
        }
    }
}

/// jti→主体映射存储端口枚举分发(spec 011 C7.8)。
#[derive(Clone)]
pub enum JtiStoreImpl {
    Memory(crate::adapters::memory::MemoryJtiStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoJtiStore),
}

impl crate::ports::JtiStore for JtiStoreImpl {
    async fn put(&self, record: crate::ports::JtiRecord) -> Result<(), StoreError> {
        match self {
            JtiStoreImpl::Memory(s) => s.put(record).await,
            #[cfg(feature = "aws")]
            JtiStoreImpl::Dynamo(s) => s.put(record).await,
        }
    }
    async fn get(
        &self,
        tenant_id: &str,
        jti: &str,
    ) -> Result<Option<crate::ports::JtiRecord>, StoreError> {
        match self {
            JtiStoreImpl::Memory(s) => s.get(tenant_id, jti).await,
            #[cfg(feature = "aws")]
            JtiStoreImpl::Dynamo(s) => s.get(tenant_id, jti).await,
        }
    }
    async fn delete_by_user(&self, tenant_id: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            JtiStoreImpl::Memory(s) => s.delete_by_user(tenant_id, user_id).await,
            #[cfg(feature = "aws")]
            JtiStoreImpl::Dynamo(s) => s.delete_by_user(tenant_id, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            JtiStoreImpl::Memory(s) => s.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            JtiStoreImpl::Dynamo(s) => s.delete_all_by_tenant(tenant_id).await,
        }
    }
}

/// workload 信任绑定存储端口枚举分发(spec 012 C5.5)。
#[derive(Clone)]
pub enum WorkloadTrustStoreImpl {
    Memory(MemoryWorkloadTrustStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoWorkloadTrustStore),
}

impl WorkloadTrustStore for WorkloadTrustStoreImpl {
    async fn put(
        &self,
        tenant: &str,
        binding_id: String,
        binding: agent_auth_workload::TrustBinding,
    ) -> Result<(), StoreError> {
        match self {
            WorkloadTrustStoreImpl::Memory(m) => m.put(tenant, binding_id, binding).await,
            #[cfg(feature = "aws")]
            WorkloadTrustStoreImpl::Dynamo(m) => m.put(tenant, binding_id, binding).await,
        }
    }
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::ports::WorkloadTrustEntry>, StoreError> {
        match self {
            WorkloadTrustStoreImpl::Memory(m) => m.list_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            WorkloadTrustStoreImpl::Dynamo(m) => m.list_by_tenant(tenant_id).await,
        }
    }
    async fn delete(&self, tenant: &str, binding_id: &str) -> Result<(), StoreError> {
        match self {
            WorkloadTrustStoreImpl::Memory(m) => m.delete(tenant, binding_id).await,
            #[cfg(feature = "aws")]
            WorkloadTrustStoreImpl::Dynamo(m) => m.delete(tenant, binding_id).await,
        }
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            WorkloadTrustStoreImpl::Memory(store) => store.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            WorkloadTrustStoreImpl::Dynamo(store) => store.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 联邦配置存储枚举分发(spec 003 §4 Task 4.7)。Memory(本地/测试)/ Dynamo(真机,复合键隔离)。
#[derive(Clone)]
pub enum FederationConfigStoreImpl {
    Memory(crate::adapters::memory::MemoryFederationConfigStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoFederationConfigStore),
}

impl crate::ports::FederationConfigStore for FederationConfigStoreImpl {
    async fn get(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<agent_auth_authn::federation::FederationConfig>, StoreError> {
        match self {
            FederationConfigStoreImpl::Memory(m) => m.get(tenant_id, upstream_idp_id).await,
            #[cfg(feature = "aws")]
            FederationConfigStoreImpl::Dynamo(m) => m.get(tenant_id, upstream_idp_id).await,
        }
    }
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<agent_auth_authn::federation::FederationConfig>, StoreError> {
        match self {
            FederationConfigStoreImpl::Memory(m) => m.list_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            FederationConfigStoreImpl::Dynamo(m) => m.list_by_tenant(tenant_id).await,
        }
    }
    async fn put(
        &self,
        config: agent_auth_authn::federation::FederationConfig,
    ) -> Result<(), StoreError> {
        match self {
            FederationConfigStoreImpl::Memory(m) => m.put(config).await,
            #[cfg(feature = "aws")]
            FederationConfigStoreImpl::Dynamo(m) => m.put(config).await,
        }
    }
    async fn delete(&self, tenant_id: &str, upstream_idp_id: &str) -> Result<(), StoreError> {
        match self {
            FederationConfigStoreImpl::Memory(m) => m.delete(tenant_id, upstream_idp_id).await,
            #[cfg(feature = "aws")]
            FederationConfigStoreImpl::Dynamo(m) => m.delete(tenant_id, upstream_idp_id).await,
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            FederationConfigStoreImpl::Memory(store) => store.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            FederationConfigStoreImpl::Dynamo(store) => store.delete_all_by_tenant(tenant_id).await,
        }
    }
}

#[derive(Clone)]
pub enum FederationAttributeMappingsStoreImpl {
    Disabled,
    Memory(crate::adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoFederationAttributeMappingsStore),
}

fn federation_attribute_mappings_store_disabled() -> StoreError {
    StoreError::Permanent("federation attribute mappings are disabled".to_string())
}

impl FederationAttributeMappingsStore for FederationAttributeMappingsStoreImpl {
    async fn get_registry(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<crate::federation_attributes::MappingRegistry>, StoreError> {
        match self {
            Self::Disabled => Err(federation_attribute_mappings_store_disabled()),
            Self::Memory(store) => store.get_registry(tenant_id, upstream_idp_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_registry(tenant_id, upstream_idp_id).await,
        }
    }

    async fn change(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
        upstream_issuer: &str,
        change: crate::federation_attributes::MappingChange,
    ) -> Result<crate::federation_attributes::MappingChangeOutcome, StoreError> {
        match self {
            Self::Disabled => Err(federation_attribute_mappings_store_disabled()),
            Self::Memory(store) => {
                store
                    .change(tenant_id, upstream_idp_id, upstream_issuer, change)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .change(tenant_id, upstream_idp_id, upstream_issuer, change)
                    .await
            }
        }
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::federation_attributes::MappingRegistry>, StoreError> {
        match self {
            Self::Disabled => Err(federation_attribute_mappings_store_disabled()),
            Self::Memory(store) => store.list_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_by_tenant(tenant_id).await,
        }
    }

    async fn governance_count_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            Self::Disabled => Err(federation_attribute_mappings_store_disabled()),
            Self::Memory(store) => store.governance_count_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.governance_count_all_by_tenant(tenant_id).await,
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        match self {
            Self::Disabled => Err(federation_attribute_mappings_store_disabled()),
            Self::Memory(store) => store.delete_all_by_tenant(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.delete_all_by_tenant(tenant_id).await,
        }
    }
}

/// CIBA 授权请求存储端口枚举分发(spec 013)。
#[derive(Clone)]
pub enum CibaStoreImpl {
    Memory(MemoryCibaStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoCibaStore),
}

impl CibaStore for CibaStoreImpl {
    async fn put(&self, tenant: &str, r: CibaAuthRequest) -> Result<(), StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.put(tenant, r).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.put(tenant, r).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        auth_req_id: &str,
    ) -> Result<Option<CibaAuthRequest>, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.get(tenant, auth_req_id).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.get(tenant, auth_req_id).await,
        }
    }
    async fn update(&self, tenant: &str, r: CibaAuthRequest) -> Result<(), StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.update(tenant, r).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.update(tenant, r).await,
        }
    }
    async fn consume(&self, tenant: &str, auth_req_id: &str) -> Result<bool, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.consume(tenant, auth_req_id).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.consume(tenant, auth_req_id).await,
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        auth_req_id: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => {
                m.claim_poll(tenant, auth_req_id, observed_last_poll_at, now)
                    .await
            }
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => {
                m.claim_poll(tenant, auth_req_id, observed_last_poll_at, now)
                    .await
            }
        }
    }
    async fn decide(
        &self,
        tenant: &str,
        auth_req_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
    ) -> Result<bool, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => {
                m.decide(tenant, auth_req_id, password_credential_version, approve)
                    .await
            }
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => {
                m.decide(tenant, auth_req_id, password_credential_version, approve)
                    .await
            }
        }
    }
    async fn release_consume(&self, tenant: &str, auth_req_id: &str) -> Result<(), StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.release_consume(tenant, auth_req_id).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.release_consume(tenant, auth_req_id).await,
        }
    }
    async fn try_arm_throttle(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
        window_secs: i64,
    ) -> Result<bool, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.try_arm_throttle(tenant, user_id, now, window_secs).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.try_arm_throttle(tenant, user_id, now, window_secs).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            CibaStoreImpl::Memory(m) => m.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            CibaStoreImpl::Dynamo(m) => m.delete_all_by_tenant(tenant).await,
        }
    }
}

/// device 授权存储端口枚举分发(spec 013)。
#[derive(Clone)]
pub enum DeviceStoreImpl {
    Memory(MemoryDeviceStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoDeviceStore),
}

impl DeviceStore for DeviceStoreImpl {
    async fn put(&self, tenant: &str, r: DeviceAuthGrant) -> Result<(), StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.put(tenant, r).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.put(tenant, r).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        device_code: &str,
    ) -> Result<Option<DeviceAuthGrant>, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.get(tenant, device_code).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.get(tenant, device_code).await,
        }
    }
    async fn get_by_user_code(
        &self,
        tenant: &str,
        user_code: &str,
    ) -> Result<Option<DeviceAuthGrant>, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.get_by_user_code(tenant, user_code).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.get_by_user_code(tenant, user_code).await,
        }
    }
    async fn update(&self, tenant: &str, r: DeviceAuthGrant) -> Result<(), StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.update(tenant, r).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.update(tenant, r).await,
        }
    }
    async fn consume(&self, tenant: &str, device_code: &str, now: i64) -> Result<bool, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.consume(tenant, device_code, now).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.consume(tenant, device_code, now).await,
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        device_code: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => {
                m.claim_poll(tenant, device_code, observed_last_poll_at, now)
                    .await
            }
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => {
                m.claim_poll(tenant, device_code, observed_last_poll_at, now)
                    .await
            }
        }
    }
    async fn decide(
        &self,
        tenant: &str,
        device_code: &str,
        user_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => {
                m.decide(
                    tenant,
                    device_code,
                    user_id,
                    password_credential_version,
                    approve,
                    now,
                )
                .await
            }
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => {
                m.decide(
                    tenant,
                    device_code,
                    user_id,
                    password_credential_version,
                    approve,
                    now,
                )
                .await
            }
        }
    }
    async fn release_consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.release_consume(tenant, device_code, now).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.release_consume(tenant, device_code, now).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            DeviceStoreImpl::Memory(m) => m.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            DeviceStoreImpl::Dynamo(m) => m.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 会话存储端口枚举分发。
#[derive(Clone)]
pub enum SessionStoreImpl {
    Memory(MemorySessionStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoSessionStore),
}

impl SessionStore for SessionStoreImpl {
    async fn create(&self, tenant: &str, s: SessionRecord) -> Result<(), StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.create(tenant, s).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.create(tenant, s).await,
        }
    }
    async fn get(&self, tenant: &str, id: &str) -> Result<Option<SessionRecord>, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.get(tenant, id).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.get(tenant, id).await,
        }
    }
    async fn delete(&self, tenant: &str, id: &str) -> Result<(), StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.delete(tenant, id).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.delete(tenant, id).await,
        }
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.list_by_user(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.list_by_user(tenant, user_id, now).await,
        }
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        target_session_id: &str,
    ) -> Result<bool, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => {
                m.delete_owned(tenant, user_id, actor_session_id, target_session_id)
                    .await
            }
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => {
                m.delete_owned(tenant, user_id, actor_session_id, target_session_id)
                    .await
            }
        }
    }
    async fn delete_others_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
    ) -> Result<Option<usize>, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => {
                m.delete_others_by_user(tenant, user_id, retained_session_id)
                    .await
            }
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => {
                m.delete_others_by_user(tenant, user_id, retained_session_id)
                    .await
            }
        }
    }
    async fn revoke_all_by_actor(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
    ) -> Result<bool, StoreError> {
        match self {
            SessionStoreImpl::Memory(store) => {
                store
                    .revoke_all_by_actor(tenant, user_id, actor_session_id)
                    .await
            }
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(store) => {
                store
                    .revoke_all_by_actor(tenant, user_id, actor_session_id)
                    .await
            }
        }
    }
    async fn touch_last_used(
        &self,
        tenant: &str,
        session_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.touch_last_used(tenant, session_id, now).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.touch_last_used(tenant, session_id, now).await,
        }
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.delete_by_user(tenant, user_id).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.delete_by_user(tenant, user_id).await,
        }
    }
    async fn delete_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<usize, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => {
                m.delete_by_user_before_epoch(tenant, user_id, epoch).await
            }
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => {
                m.delete_by_user_before_epoch(tenant, user_id, epoch).await
            }
        }
    }
    async fn count_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.count_by_user(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.count_by_user(tenant, user_id, now).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            SessionStoreImpl::Memory(m) => m.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            SessionStoreImpl::Dynamo(m) => m.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 恢复码存储端口枚举分发。
#[derive(Clone)]
pub enum RecoveryStoreImpl {
    Memory(crate::adapters::memory::MemoryRecoveryStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoRecoveryStore),
}

impl RecoveryStoreImpl {
    pub(crate) async fn commit_rotation(
        &self,
        users: &UsersStoreImpl,
        tenant: &str,
        record: RecoveryRecord,
        expected_email: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        match (self, users) {
            (RecoveryStoreImpl::Memory(recovery), UsersStoreImpl::Memory(users)) => {
                recovery
                    .commit_rotation(users, tenant, record, expected_email, owner, updated_at)
                    .await
            }
            #[cfg(feature = "aws")]
            (RecoveryStoreImpl::Dynamo(recovery), UsersStoreImpl::Dynamo(users)) => {
                recovery
                    .commit_rotation(users, tenant, record, expected_email, owner, updated_at)
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "recovery and user stores use incompatible backends".to_string(),
            )),
        }
    }

    pub(crate) async fn verify_and_consume_at_epoch(
        &self,
        users: &UsersStoreImpl,
        passwords: &PasswordStoreImpl,
        sessions: &SessionStoreImpl,
        request: RecoveryConsumeRequest<'_>,
        session: SessionRecord,
        result: RecoverySuccessResult,
    ) -> Result<RecoveryAuthorityConsume, StoreError> {
        match (self, users, passwords, sessions) {
            (
                RecoveryStoreImpl::Memory(recovery),
                UsersStoreImpl::Memory(users),
                PasswordStoreImpl::Memory(passwords),
                SessionStoreImpl::Memory(sessions),
            ) => {
                recovery
                    .verify_and_consume_at_epoch(
                        users, passwords, sessions, request, session, result,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (
                RecoveryStoreImpl::Dynamo(recovery),
                UsersStoreImpl::Dynamo(users),
                PasswordStoreImpl::Dynamo(passwords),
                SessionStoreImpl::Dynamo(sessions),
            ) => {
                recovery
                    .verify_and_consume_at_epoch(
                        users, passwords, sessions, request, session, result,
                    )
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "recovery, user, password, and session stores use incompatible backends"
                    .to_string(),
            )),
        }
    }
}

impl RecoveryStore for RecoveryStoreImpl {
    async fn put(&self, tenant: &str, r: RecoveryRecord) -> Result<(), StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => m.put(tenant, r).await,
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => m.put(tenant, r).await,
        }
    }
    async fn get(&self, tenant: &str, user_id: &str) -> Result<Option<RecoveryRecord>, StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => m.get(tenant, user_id).await,
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => m.get(tenant, user_id).await,
        }
    }
    async fn get_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> Result<Option<RecoverySuccessResult>, StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => m.get_success_result(tenant, operation_key).await,
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => m.get_success_result(tenant, operation_key).await,
        }
    }
    async fn verify_and_consume(
        &self,
        tenant: &str,
        user_id: &str,
        presented_hash: &str,
        now: i64,
    ) -> Result<RecoveryConsume, StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => {
                m.verify_and_consume(tenant, user_id, presented_hash, now)
                    .await
            }
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => {
                m.verify_and_consume(tenant, user_id, presented_hash, now)
                    .await
            }
        }
    }
    async fn delete_by_lookup(&self, tenant: &str, user_lookup: &str) -> Result<(), StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => m.delete_by_lookup(tenant, user_lookup).await,
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => m.delete_by_lookup(tenant, user_lookup).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            RecoveryStoreImpl::Memory(m) => m.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            RecoveryStoreImpl::Dynamo(m) => m.delete_all_by_tenant(tenant).await,
        }
    }
}

/// magic-link 存储端口枚举分发。
#[derive(Clone)]
pub enum MagicLinkStoreImpl {
    Memory(MemoryMagicLinkStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoMagicLinkStore),
}

impl MagicLinkStore for MagicLinkStoreImpl {
    async fn put(&self, tenant: &str, link: MagicLinkRecord) -> Result<(), StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.put(tenant, link).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.put(tenant, link).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        link_id: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.get(tenant, link_id).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.get(tenant, link_id).await,
        }
    }
    async fn consume_bound(
        &self,
        tenant: &str,
        link_id: &str,
        expected_session_nonce: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => {
                m.consume_bound(tenant, link_id, expected_session_nonce)
                    .await
            }
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => {
                m.consume_bound(tenant, link_id, expected_session_nonce)
                    .await
            }
        }
    }
    async fn last_sent_at(&self, tenant: &str, email: &str) -> Result<Option<i64>, StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.last_sent_at(tenant, email).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.last_sent_at(tenant, email).await,
        }
    }
    async fn mark_sent(&self, tenant: &str, email: &str, now: i64) -> Result<(), StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.mark_sent(tenant, email, now).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.mark_sent(tenant, email, now).await,
        }
    }
    async fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.delete_by_user(tenant, user_id, aliases).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.delete_by_user(tenant, user_id, aliases).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            MagicLinkStoreImpl::Memory(m) => m.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            MagicLinkStoreImpl::Dynamo(m) => m.delete_all_by_tenant(tenant).await,
        }
    }
}

/// One-time invitation store enum dispatch. It remains a separate capability
/// from magic-link state even though both ultimately establish login sessions.
#[derive(Clone)]
pub enum InvitationStoreImpl {
    Memory(MemoryInvitationStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoInvitationStore),
}

impl InvitationStore for InvitationStoreImpl {
    async fn issue(
        &self,
        tenant: &str,
        record: InvitationRecord,
    ) -> Result<InvitationIssueOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.issue(tenant, record).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.issue(tenant, record).await,
        }
    }

    async fn accept(
        &self,
        tenant: &str,
        request: InvitationAcceptRequest,
    ) -> Result<InvitationAcceptOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.accept(tenant, request).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.accept(tenant, request).await,
        }
    }

    async fn invalidate(&self, tenant: &str, locator: &str) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.invalidate(tenant, locator).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.invalidate(tenant, locator).await,
        }
    }
}

/// 用户目录存储端口枚举分发(spec 003 §1.4)。
#[derive(Clone)]
pub enum AttributeNamespaceStoreImpl {
    Disabled,
    Memory(crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoAttributeNamespaceStore),
}

fn attribute_namespace_store_disabled() -> StoreError {
    StoreError::Permanent("attribute namespace registry is disabled".to_string())
}

impl AttributeNamespaceStore for AttributeNamespaceStoreImpl {
    async fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> Result<crate::attribute_namespace::AudienceResolution, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => store.resolve(tenant, verified_aud).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.resolve(tenant, verified_aud).await,
        }
    }

    async fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<crate::attribute_namespace::AttributeWriteResolution, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => store.resolve_write_authority(tenant, namespace).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.resolve_write_authority(tenant, namespace).await,
        }
    }

    async fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<crate::attribute_namespace::NamespaceRegistration>, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => store.get(tenant, canonical_namespace).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get(tenant, canonical_namespace).await,
        }
    }

    async fn list(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::attribute_namespace::NamespaceRegistration>, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => store.list(tenant).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list(tenant).await,
        }
    }

    async fn begin_change(
        &self,
        tenant: &str,
        request: crate::attribute_namespace::BeginNamespaceChange,
    ) -> Result<crate::attribute_namespace::BeginNamespaceChangeOutcome, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => store.begin_change(tenant, request).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.begin_change(tenant, request).await,
        }
    }

    async fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: crate::attribute_namespace::NamespaceOperationCheckpoint,
    ) -> Result<crate::attribute_namespace::NamespaceChangeOutcome, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => {
                store
                    .checkpoint(tenant, canonical_namespace, operation_id, checkpoint)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .checkpoint(tenant, canonical_namespace, operation_id, checkpoint)
                    .await
            }
        }
    }

    async fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<crate::attribute_namespace::NamespaceChangeOutcome, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => {
                store
                    .activate(
                        tenant,
                        canonical_namespace,
                        operation_id,
                        expected_operation_revision,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .activate(
                        tenant,
                        canonical_namespace,
                        operation_id,
                        expected_operation_revision,
                    )
                    .await
            }
        }
    }

    async fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<crate::attribute_namespace::NamespaceChangeOutcome, StoreError> {
        match self {
            Self::Disabled => Err(attribute_namespace_store_disabled()),
            Self::Memory(store) => {
                store
                    .cancel(
                        tenant,
                        canonical_namespace,
                        operation_id,
                        expected_operation_revision,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .cancel(
                        tenant,
                        canonical_namespace,
                        operation_id,
                        expected_operation_revision,
                    )
                    .await
            }
        }
    }
}

/// 用户目录存储端口枚举分发(spec 003 §1.4)。
#[derive(Clone)]
pub enum UsersStoreImpl {
    Memory(crate::adapters::memory::MemoryUsersStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoUsersStore),
}

impl UsersStoreImpl {
    pub(crate) async fn begin_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .begin_admin_credential_change(
                        tenant,
                        user_id,
                        expected_epoch,
                        operation_id,
                        now,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .begin_admin_credential_change(
                        tenant,
                        user_id,
                        expected_epoch,
                        operation_id,
                        now,
                    )
                    .await
            }
        }
    }

    pub(crate) async fn abort_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .abort_admin_credential_change(tenant, user_id, owner, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .abort_admin_credential_change(tenant, user_id, owner, now)
                    .await
            }
        }
    }
}

impl crate::ports::UsersStore for UsersStoreImpl {
    async fn create_or_get_by_email(
        &self,
        tenant: &str,
        email: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.create_or_get_by_email(tenant, email, user_id, now).await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.create_or_get_by_email(tenant, email, user_id, now).await
            }
        }
    }
    async fn create_or_get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.create_or_get_by_id(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.create_or_get_by_id(tenant, user_id, now).await,
        }
    }
    async fn get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.get_by_id(tenant, user_id).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.get_by_id(tenant, user_id).await,
        }
    }
    async fn get_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.get_by_email(tenant, email).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.get_by_email(tenant, email).await,
        }
    }
    async fn create_scim(
        &self,
        tenant: &str,
        input: crate::ports::ScimUserInput,
    ) -> Result<crate::ports::ScimCreateOutcome, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.create_scim(tenant, input).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.create_scim(tenant, input).await,
        }
    }
    async fn begin_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimCreateLifecycleStart, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.begin_scim_create_lifecycle(tenant, external_id, user_name, user_id, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.begin_scim_create_lifecycle(tenant, external_id, user_name, user_id, now)
                    .await
            }
        }
    }
    async fn complete_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> Result<(), StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.complete_scim_create_lifecycle(tenant, external_id, user_name, user_id)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.complete_scim_create_lifecycle(tenant, external_id, user_name, user_id)
                    .await
            }
        }
    }
    async fn get_scim_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.get_scim_by_external_id(tenant, external_id).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.get_scim_by_external_id(tenant, external_id).await,
        }
    }
    async fn get_scim_by_user_name(
        &self,
        tenant: &str,
        user_name: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.get_scim_by_user_name(tenant, user_name).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.get_scim_by_user_name(tenant, user_name).await,
        }
    }
    async fn list_scim(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::UserRecord>, usize), StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.list_scim(tenant, offset, limit).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.list_scim(tenant, offset, limit).await,
        }
    }
    async fn replace_scim(
        &self,
        tenant: &str,
        user_id: &str,
        input: crate::ports::ScimReplaceInput,
    ) -> Result<crate::ports::ScimReplaceOutcome, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.replace_scim(tenant, user_id, input).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.replace_scim(tenant, user_id, input).await,
        }
    }
    async fn list(
        &self,
        tenant: &str,
        limit: usize,
        cursor: Option<&str>,
        query: Option<&str>,
        status: crate::ports::UserListStatusFilter,
    ) -> Result<(Vec<crate::ports::UserRecord>, Option<String>), StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.list(tenant, limit, cursor, query, status).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.list(tenant, limit, cursor, query, status).await,
        }
    }
    async fn touch_last_login(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.touch_last_login(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.touch_last_login(tenant, user_id, now).await,
        }
    }
    async fn set_status(
        &self,
        tenant: &str,
        user_id: &str,
        status: crate::ports::UserStatus,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.set_status(tenant, user_id, status, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.set_status(tenant, user_id, status, now).await,
        }
    }
    async fn begin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .begin_credential_change(tenant, user_id, expected_epoch, operation_id, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .begin_credential_change(tenant, user_id, expected_epoch, operation_id, now)
                    .await
            }
        }
    }
    async fn complete_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .complete_credential_change(tenant, user_id, owner, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .complete_credential_change(tenant, user_id, owner, now)
                    .await
            }
        }
    }
    async fn recover_expired_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        started_before: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .recover_expired_credential_change(tenant, user_id, epoch, started_before, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .recover_expired_credential_change(tenant, user_id, epoch, started_before, now)
                    .await
            }
        }
    }
    async fn begin_disable(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::DisableStart, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.begin_disable(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.begin_disable(tenant, user_id, now).await,
        }
    }
    async fn complete_disable(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.complete_disable(tenant, user_id, epoch, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.complete_disable(tenant, user_id, epoch, now).await,
        }
    }
    async fn begin_legacy_disable_cleanup(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => m.begin_legacy_disable_cleanup(tenant, user_id, now).await,
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => m.begin_legacy_disable_cleanup(tenant, user_id, now).await,
        }
    }
    async fn enable_completed(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        now: i64,
    ) -> Result<crate::ports::EnableOutcome, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.enable_completed(tenant, user_id, expected_epoch, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.enable_completed(tenant, user_id, expected_epoch, now)
                    .await
            }
        }
    }
    async fn put_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<crate::ports::PutAttrOutcome, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.put_attributes(tenant, user_id, namespace, kv, expected_revision)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.put_attributes(tenant, user_id, namespace, kv, expected_revision)
                    .await
            }
        }
    }
    async fn migrate_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        canonical_namespace: &str,
        source_namespaces: &std::collections::BTreeSet<String>,
    ) -> Result<crate::ports::AttributeMigrationOutcome, StoreError> {
        match self {
            UsersStoreImpl::Memory(store) => {
                store
                    .migrate_attributes(tenant, user_id, canonical_namespace, source_namespaces)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(store) => {
                store
                    .migrate_attributes(tenant, user_id, canonical_namespace, source_namespaces)
                    .await
            }
        }
    }
    async fn fence_for_erasure(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.fence_for_erasure(tenant, user_id, target_epoch, now)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.fence_for_erasure(tenant, user_id, target_epoch, now)
                    .await
            }
        }
    }
    async fn delete_erased_identity(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
    ) -> Result<bool, StoreError> {
        match self {
            UsersStoreImpl::Memory(m) => {
                m.delete_erased_identity(tenant, user_id, target_epoch)
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(m) => {
                m.delete_erased_identity(tenant, user_id, target_epoch)
                    .await
            }
        }
    }
}

#[derive(Clone)]
pub enum ScimGroupsStoreImpl {
    Memory(crate::adapters::memory::MemoryScimGroupsStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoScimGroupsStore),
}

impl crate::ports::ScimGroupsStore for ScimGroupsStoreImpl {
    async fn create(
        &self,
        tenant: &str,
        input: crate::ports::ScimGroupCreateInput,
    ) -> Result<crate::ports::ScimGroupCreateOutcome, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.create(tenant, input).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.create(tenant, input).await,
        }
    }

    async fn get(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.get(tenant, group_id).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.get(tenant, group_id).await,
        }
    }

    async fn get_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => {
                store.get_by_external_id(tenant, external_id).await
            }
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => {
                store.get_by_external_id(tenant, external_id).await
            }
        }
    }

    async fn list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::ScimGroupRecord>, usize), StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.list(tenant, offset, limit).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.list(tenant, offset, limit).await,
        }
    }

    async fn mutate(
        &self,
        tenant: &str,
        group_id: &str,
        mutation: crate::ports::ScimGroupMutation,
    ) -> Result<crate::ports::ScimGroupMutationOutcome, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.mutate(tenant, group_id, mutation).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.mutate(tenant, group_id, mutation).await,
        }
    }

    async fn delete(
        &self,
        tenant: &str,
        group_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimGroupDeleteOutcome, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.delete(tenant, group_id, now).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.delete(tenant, group_id, now).await,
        }
    }

    async fn set_role_mapping(
        &self,
        tenant: &str,
        external_id: &str,
        role: Option<crate::ports::TenantRole>,
        now: i64,
    ) -> Result<crate::ports::ScimRoleMappingOutcome, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => {
                store.set_role_mapping(tenant, external_id, role, now).await
            }
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => {
                store.set_role_mapping(tenant, external_id, role, now).await
            }
        }
    }

    async fn list_role_mappings(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::ports::ScimGroupRoleMapping>, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.list_role_mappings(tenant).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.list_role_mappings(tenant).await,
        }
    }

    async fn mapped_role_for_member(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<crate::ports::MappedTenantRole, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => {
                store.mapped_role_for_member(tenant, user_id).await
            }
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => {
                store.mapped_role_for_member(tenant, user_id).await
            }
        }
    }
    async fn remove_member_from_all(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => {
                store.remove_member_from_all(tenant, user_id, now).await
            }
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => {
                store.remove_member_from_all(tenant, user_id, now).await
            }
        }
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            ScimGroupsStoreImpl::Memory(store) => store.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            ScimGroupsStoreImpl::Dynamo(store) => store.delete_all_by_tenant(tenant).await,
        }
    }
}

/// Password credential store enum dispatch(spec 003 C9.8-C9.10).
#[derive(Clone)]
pub enum PasswordStoreImpl {
    Memory(crate::adapters::memory::MemoryPasswordStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoPasswordStore),
}

impl PasswordStoreImpl {
    pub(crate) async fn commit_credential_change(
        &self,
        users: &UsersStoreImpl,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<bool, StoreError> {
        match (self, users) {
            (PasswordStoreImpl::Memory(passwords), UsersStoreImpl::Memory(users)) => {
                passwords
                    .commit_credential_change(users, mutation, owner)
                    .await
            }
            #[cfg(feature = "aws")]
            (PasswordStoreImpl::Dynamo(passwords), UsersStoreImpl::Dynamo(users)) => {
                passwords
                    .commit_credential_change(users, mutation, owner)
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "password and user stores use incompatible backends".to_string(),
            )),
        }
    }

    pub(crate) async fn stage_admin_reset(
        &self,
        users: &UsersStoreImpl,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<Option<u64>, StoreError> {
        match (self, users) {
            (PasswordStoreImpl::Memory(passwords), UsersStoreImpl::Memory(users)) => {
                passwords.stage_admin_reset(users, mutation, owner).await
            }
            #[cfg(feature = "aws")]
            (PasswordStoreImpl::Dynamo(passwords), UsersStoreImpl::Dynamo(users)) => {
                passwords.stage_admin_reset(users, mutation, owner).await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "password and user stores use incompatible backends".to_string(),
            )),
        }
    }

    pub(crate) async fn complete_admin_reset(
        &self,
        users: &UsersStoreImpl,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        match (self, users) {
            (PasswordStoreImpl::Memory(passwords), UsersStoreImpl::Memory(users)) => {
                passwords
                    .complete_admin_reset(
                        users,
                        tenant,
                        user_id,
                        expected_version,
                        owner,
                        updated_at,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (PasswordStoreImpl::Dynamo(passwords), UsersStoreImpl::Dynamo(users)) => {
                passwords
                    .complete_admin_reset(
                        users,
                        tenant,
                        user_id,
                        expected_version,
                        owner,
                        updated_at,
                    )
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Err(StoreError::Permanent(
                "password and user stores use incompatible backends".to_string(),
            )),
        }
    }
}

impl crate::ports::PasswordStore for PasswordStoreImpl {
    async fn get(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::PasswordCredential>, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => store.get(tenant, user_id).await,
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => store.get(tenant, user_id).await,
        }
    }

    async fn complete_reset_revocation(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => {
                store
                    .complete_reset_revocation(tenant, user_id, expected_version)
                    .await
            }
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => {
                store
                    .complete_reset_revocation(tenant, user_id, expected_version)
                    .await
            }
        }
    }

    async fn create_if_absent(
        &self,
        tenant: &str,
        credential: crate::ports::PasswordCredential,
    ) -> Result<bool, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => store.create_if_absent(tenant, credential).await,
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => store.create_if_absent(tenant, credential).await,
        }
    }

    async fn delete_if_version(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => {
                store
                    .delete_if_version(tenant, user_id, expected_version)
                    .await
            }
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => {
                store
                    .delete_if_version(tenant, user_id, expected_version)
                    .await
            }
        }
    }

    async fn replace_if_version_and_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: u64,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => {
                store
                    .replace_if_version_and_temporary(
                        tenant,
                        user_id,
                        new_hash,
                        expected_version,
                        updated_at,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => {
                store
                    .replace_if_version_and_temporary(
                        tenant,
                        user_id,
                        new_hash,
                        expected_version,
                        updated_at,
                    )
                    .await
            }
        }
    }

    async fn reset_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: Option<u64>,
        updated_at: i64,
    ) -> Result<Option<u64>, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => {
                store
                    .reset_temporary(tenant, user_id, new_hash, expected_version, updated_at)
                    .await
            }
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => {
                store
                    .reset_temporary(tenant, user_id, new_hash, expected_version, updated_at)
                    .await
            }
        }
    }

    async fn delete(&self, tenant: &str, user_id: &str) -> Result<(), StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => store.delete(tenant, user_id).await,
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => store.delete(tenant, user_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            PasswordStoreImpl::Memory(store) => store.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            PasswordStoreImpl::Dynamo(store) => store.delete_all_by_tenant(tenant).await,
        }
    }
}

/// Notifier 端口枚举分发。`Log`=纯打日志(轻量测试);`Outbox`=写内存 outbox(dev,可观测);
/// `Dynamo`=写 messages 表(真机,TTL=1 天,SES 未接前的模拟,spec 003 §1.5)。
#[derive(Clone)]
pub enum NotifierImpl {
    Log(LogNotifier),
    Outbox(MemoryOutboxNotifier),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoNotifier),
}

/// CIBA ping/push 回调投递枚举分发(spec 013 §4)。dev/测试 = Memory mock;真机 = reqwest(SSRF 复校+固定 IP)。
pub enum CibaCallbackDeliveryImpl {
    Memory(crate::adapters::memory::MemoryCibaCallbackDelivery),
    #[cfg(feature = "aws")]
    Http(crate::adapters::aws::HttpCibaCallbackDelivery),
}

impl crate::ports::CibaCallbackDelivery for CibaCallbackDeliveryImpl {
    async fn deliver(
        &self,
        req: crate::ports::CibaCallbackRequest,
    ) -> crate::ports::CibaDeliveryOutcome {
        match self {
            CibaCallbackDeliveryImpl::Memory(d) => d.deliver(req).await,
            #[cfg(feature = "aws")]
            CibaCallbackDeliveryImpl::Http(d) => d.deliver(req).await,
        }
    }
}

impl Notifier for NotifierImpl {
    async fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        match self {
            NotifierImpl::Log(n) => n.send_magic_link(tenant, email, link_url).await,
            NotifierImpl::Outbox(n) => n.send_magic_link(tenant, email, link_url).await,
            #[cfg(feature = "aws")]
            NotifierImpl::Dynamo(n) => n.send_magic_link(tenant, email, link_url).await,
        }
    }
    async fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        match self {
            NotifierImpl::Log(n) => {
                n.notify_recovery(
                    tenant,
                    notification_id,
                    recipient_email,
                    recovered_at,
                    client_ip,
                )
                .await
            }
            NotifierImpl::Outbox(n) => {
                n.notify_recovery(
                    tenant,
                    notification_id,
                    recipient_email,
                    recovered_at,
                    client_ip,
                )
                .await
            }
            #[cfg(feature = "aws")]
            NotifierImpl::Dynamo(n) => {
                n.notify_recovery(
                    tenant,
                    notification_id,
                    recipient_email,
                    recovered_at,
                    client_ip,
                )
                .await
            }
        }
    }
}

/// 消息 outbox 读端口枚举分发(观测"发了什么";与 Notifier 写端共用同一后端实例)。
#[derive(Clone)]
pub enum MessageOutboxImpl {
    Memory(MemoryOutboxNotifier),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoNotifier),
}

impl MessageOutbox for MessageOutboxImpl {
    async fn list_recent(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<SentMessage>, StoreError> {
        match self {
            MessageOutboxImpl::Memory(n) => n.list_recent(tenant, limit).await,
            #[cfg(feature = "aws")]
            MessageOutboxImpl::Dynamo(n) => n.list_recent(tenant, limit).await,
        }
    }
    async fn delete_by_recipients(
        &self,
        tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        match self {
            MessageOutboxImpl::Memory(n) => n.delete_by_recipients(tenant, recipients).await,
            #[cfg(feature = "aws")]
            MessageOutboxImpl::Dynamo(n) => n.delete_by_recipients(tenant, recipients).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            MessageOutboxImpl::Memory(n) => n.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            MessageOutboxImpl::Dynamo(n) => n.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 授权会话存储端口枚举分发(spec 004;内存 / DynamoDB)。
#[derive(Clone)]
pub enum AuthzSessionStoreImpl {
    Memory(MemoryAuthzSessionStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoAuthzSessionStore),
}

impl AuthzSessionStore for AuthzSessionStoreImpl {
    async fn create(&self, tenant: &str, r: AuthzSessionRecord) -> Result<(), StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(m) => m.create(tenant, r).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(m) => m.create(tenant, r).await,
        }
    }
    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(m) => m.get(tenant, session_id).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(m) => m.get(tenant, session_id).await,
        }
    }
    async fn transition(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(m) => {
                m.transition(tenant, session_id, new_state, last_error, now)
                    .await
            }
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(m) => {
                m.transition(tenant, session_id, new_state, last_error, now)
                    .await
            }
        }
    }
    async fn bind_user(
        &self,
        tenant: &str,
        session_id: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(store) => {
                store.bind_user(tenant, session_id, user_id, now).await
            }
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(store) => {
                store.bind_user(tenant, session_id, user_id, now).await
            }
        }
    }
    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(store) => store.delete(tenant, session_id).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(store) => store.delete(tenant, session_id).await,
        }
    }
    async fn list_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(m) => m.list_by_client(tenant, client_id).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(m) => m.list_by_client(tenant, client_id).await,
        }
    }
    async fn count_active(&self, tenant: &str, now: i64) -> Result<usize, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(m) => m.count_active(tenant, now).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(m) => m.count_active(tenant, now).await,
        }
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(store) => store.delete_by_client(tenant, client_id).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(store) => store.delete_by_client(tenant, client_id).await,
        }
    }
    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        match self {
            AuthzSessionStoreImpl::Memory(store) => store.delete_all_by_tenant(tenant).await,
            #[cfg(feature = "aws")]
            AuthzSessionStoreImpl::Dynamo(store) => store.delete_all_by_tenant(tenant).await,
        }
    }
}

/// 授权会话事件 sink 枚举分发(dev log / 真机 no-op,真发 EventBridge 留 P2)。
#[derive(Clone)]
pub enum AuthzEventSinkImpl {
    Log(LogAuthzEventSink),
    #[cfg(test)]
    Memory(Arc<tokio::sync::Mutex<Vec<agent_auth_authn::authz_session::ProjectionEvent>>>),
    #[cfg(feature = "aws")]
    Noop(crate::adapters::aws::NoopAuthzEventSink),
    #[cfg(feature = "aws")]
    EventBridge(crate::adapters::aws::EventBridgeAuthzEventSink),
}

impl AuthzEventSink for AuthzEventSinkImpl {
    async fn emit(&self, session_id: &str, sequence: u64, state: &str) -> Result<(), StoreError> {
        match self {
            AuthzEventSinkImpl::Log(s) => s.emit(session_id, sequence, state).await,
            #[cfg(test)]
            AuthzEventSinkImpl::Memory(events) => {
                events
                    .lock()
                    .await
                    .push(agent_auth_authn::authz_session::ProjectionEvent {
                        session_id: session_id.to_string(),
                        sequence,
                        state: state.to_string(),
                    });
                Ok(())
            }
            #[cfg(feature = "aws")]
            AuthzEventSinkImpl::Noop(s) => s.emit(session_id, sequence, state).await,
            #[cfg(feature = "aws")]
            AuthzEventSinkImpl::EventBridge(s) => s.emit(session_id, sequence, state).await,
        }
    }
}

#[derive(Clone)]
pub enum SecurityEventStoreImpl {
    Memory(MemorySecurityEventStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoSecurityEventStore),
}

#[derive(Clone)]
pub enum SecurityEventFallbackImpl {
    Disabled,
    #[cfg(test)]
    Memory(Arc<tokio::sync::Mutex<Vec<SecurityEventIngress>>>),
    #[cfg(feature = "aws")]
    Sqs(crate::adapters::aws::SqsSecurityEventFallback),
}

impl SecurityEventFallback for SecurityEventFallbackImpl {
    async fn enqueue(&self, ingress: &SecurityEventIngress) -> Result<(), StoreError> {
        match self {
            Self::Disabled => Err(StoreError::Permanent(format!(
                "security event fallback is disabled for {}",
                ingress.event.event_id
            ))),
            #[cfg(test)]
            Self::Memory(queue) => {
                queue.lock().await.push(ingress.clone());
                Ok(())
            }
            #[cfg(feature = "aws")]
            Self::Sqs(queue) => queue.enqueue(ingress).await,
        }
    }

    async fn enqueue_batch(
        &self,
        _ingresses: &[SecurityEventIngress],
    ) -> Result<Vec<SecurityEventFallbackOutcome>, StoreError> {
        match self {
            Self::Disabled => Err(StoreError::Permanent(
                "security event fallback is disabled for batch".to_string(),
            )),
            #[cfg(test)]
            Self::Memory(queue) => {
                queue.lock().await.extend_from_slice(_ingresses);
                Ok(vec![
                    SecurityEventFallbackOutcome::Enqueued;
                    _ingresses.len()
                ])
            }
            #[cfg(feature = "aws")]
            Self::Sqs(queue) => queue.enqueue_batch(_ingresses).await,
        }
    }
}

impl SecurityEventStore for SecurityEventStoreImpl {
    async fn put(&self, event: &SecurityEvent) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.put(event).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put(event).await,
        }
    }

    async fn put_with_delivery(
        &self,
        event: &SecurityEvent,
        delivery: &SecurityEventDelivery,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.put_with_delivery(event, delivery).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.put_with_delivery(event, delivery).await,
        }
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
    ) -> Result<Vec<StoredSecurityEvent>, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .list_by_tenant(tenant_id, from_inclusive, through_inclusive, limit)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .list_by_tenant(tenant_id, from_inclusive, through_inclusive, limit)
                    .await
            }
        }
    }

    async fn list_by_tenant_page(
        &self,
        tenant_id: &str,
        from_inclusive: i64,
        through_inclusive: i64,
        limit: usize,
        cursor: Option<&SecurityEventCursor>,
    ) -> Result<SecurityEventPage, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .list_by_tenant_page(
                        tenant_id,
                        from_inclusive,
                        through_inclusive,
                        limit,
                        cursor,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .list_by_tenant_page(
                        tenant_id,
                        from_inclusive,
                        through_inclusive,
                        limit,
                        cursor,
                    )
                    .await
            }
        }
    }
}

#[derive(Clone)]
pub enum SsfStoreImpl {
    Memory(MemorySsfStore),
    #[cfg(feature = "aws")]
    Dynamo(crate::adapters::aws::DynamoSsfStore),
}

impl SsfStore for SsfStoreImpl {
    async fn create_stream(&self, stream: SsfStream) -> Result<SsfStreamCreateOutcome, StoreError> {
        match self {
            Self::Memory(store) => store.create_stream(stream).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.create_stream(stream).await,
        }
    }

    async fn get_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Option<SsfStream>, StoreError> {
        match self {
            Self::Memory(store) => store.get_stream(tenant_id, stream_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.get_stream(tenant_id, stream_id).await,
        }
    }

    async fn list_streams(&self, tenant_id: &str) -> Result<Vec<SsfStream>, StoreError> {
        match self {
            Self::Memory(store) => store.list_streams(tenant_id).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.list_streams(tenant_id).await,
        }
    }

    async fn mutate_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        mutation: SsfStreamMutation,
        now: i64,
    ) -> Result<SsfStreamMutationOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .mutate_stream(tenant_id, stream_id, expected_revision, mutation, now)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .mutate_stream(tenant_id, stream_id, expected_revision, mutation, now)
                    .await
            }
        }
    }

    async fn enqueue_event(
        &self,
        event: &SecurityEvent,
        issuer: &str,
        now: i64,
    ) -> Result<Vec<SsfDelivery>, StoreError> {
        match self {
            Self::Memory(store) => store.enqueue_event(event, issuer, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.enqueue_event(event, issuer, now).await,
        }
    }

    async fn enqueue_verification(
        &self,
        tenant_id: &str,
        stream_id: &str,
        expected_revision: u64,
        event_id: &str,
        issuer: &str,
        verification_state: Option<&str>,
        now: i64,
    ) -> Result<SsfVerificationOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .enqueue_verification(
                        tenant_id,
                        stream_id,
                        expected_revision,
                        event_id,
                        issuer,
                        verification_state,
                        now,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .enqueue_verification(
                        tenant_id,
                        stream_id,
                        expected_revision,
                        event_id,
                        issuer,
                        verification_state,
                        now,
                    )
                    .await
            }
        }
    }

    async fn get_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .get_delivery(tenant_id, stream_id, stream_revision, event_id)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .get_delivery(tenant_id, stream_id, stream_revision, event_id)
                    .await
            }
        }
    }

    async fn list_deliveries(
        &self,
        tenant_id: &str,
        stream_id: &str,
        limit: usize,
        cursor: Option<&SsfDeliveryCursor>,
    ) -> Result<SsfDeliveryPage, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .list_deliveries(tenant_id, stream_id, limit, cursor)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .list_deliveries(tenant_id, stream_id, limit, cursor)
                    .await
            }
        }
    }

    async fn acquire_due(
        &self,
        now: i64,
        lease_duration_secs: i64,
        limit: usize,
    ) -> Result<Vec<SsfDeliveryLease>, StoreError> {
        match self {
            Self::Memory(store) => store.acquire_due(now, lease_duration_secs, limit).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.acquire_due(now, lease_duration_secs, limit).await,
        }
    }

    async fn persist_signed_set(
        &self,
        lease: &SsfDeliveryLease,
        signed: &SignedSet,
        issued_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .persist_signed_set(lease, signed, issued_at, now)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .persist_signed_set(lease, signed, issued_at, now)
                    .await
            }
        }
    }

    async fn finish_attempt(
        &self,
        lease: &SsfDeliveryLease,
        result: SsfAttemptResult,
        now: i64,
    ) -> Result<Option<SsfDelivery>, StoreError> {
        match self {
            Self::Memory(store) => store.finish_attempt(lease, result, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.finish_attempt(lease, result, now).await,
        }
    }

    async fn redrive_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        stream_revision: u64,
        event_id: &str,
        now: i64,
    ) -> Result<SsfRedriveOutcome, StoreError> {
        match self {
            Self::Memory(store) => {
                store
                    .redrive_delivery(tenant_id, stream_id, stream_revision, event_id, now)
                    .await
            }
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => {
                store
                    .redrive_delivery(tenant_id, stream_id, stream_revision, event_id, now)
                    .await
            }
        }
    }

    async fn revoke_all_by_tenant(&self, tenant_id: &str, now: i64) -> Result<usize, StoreError> {
        match self {
            Self::Memory(store) => store.revoke_all_by_tenant(tenant_id, now).await,
            #[cfg(feature = "aws")]
            Self::Dynamo(store) => store.revoke_all_by_tenant(tenant_id, now).await,
        }
    }
}

/// **subject_type 选定**(spec 020 / §2.8 / §11 #12):SelfHosted 可通过
/// `AGENT_AUTH_SUBJECT_TYPE` 覆盖部署级默认；SaaS 的请求级选择由
/// `tenant_subject_types` 完成，未覆盖的 tenant 保守回落 pairwise。
#[cfg(any(feature = "aws", test))]
pub(crate) fn resolve_subject_type(env_override: Option<&str>, form: &Form) -> SubjectType {
    match env_override
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("public") => SubjectType::Public,
        Some("pairwise") => SubjectType::Pairwise,
        _ => match form {
            Form::Saas { .. } => SubjectType::Pairwise,
            Form::SelfHosted { .. } => SubjectType::Public,
        },
    }
}

#[cfg(any(feature = "aws", test))]
fn validate_subject_type_override(env_override: Option<&str>, form: &Form) -> Result<(), String> {
    if matches!(form, Form::Saas { .. })
        && env_override.is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "SaaS 不得配置 deployment-level AGENT_AUTH_SUBJECT_TYPE; 使用 tenant_subject_types"
                .into(),
        );
    }
    Ok(())
}

#[cfg(any(feature = "aws", test))]
fn resolve_tenant_subject_types(
    configured: &std::collections::HashMap<String, String>,
    form: &Form,
    saas_tenants: &[String],
) -> Result<std::collections::BTreeMap<String, SubjectType>, String> {
    if !matches!(form, Form::Saas { .. }) {
        if configured.is_empty() {
            return Ok(std::collections::BTreeMap::new());
        }
        return Err("SelfHosted 不得配置 tenant_subject_types".into());
    }

    let configured_tenants: std::collections::HashSet<&str> =
        saas_tenants.iter().map(String::as_str).collect();
    let mut resolved = std::collections::BTreeMap::new();
    for (tenant, subject_type) in configured {
        if !configured_tenants.contains(tenant.as_str()) {
            return Err(format!(
                "tenant_subject_types 包含未配置的 SaaS tenant '{tenant}'"
            ));
        }
        let subject_type = match subject_type.as_str() {
            "public" => SubjectType::Public,
            "pairwise" => SubjectType::Pairwise,
            _ => {
                return Err(format!(
                    "tenant_subject_types.{tenant} 必须是 public 或 pairwise"
                ))
            }
        };
        resolved.insert(tenant.clone(), subject_type);
    }
    Ok(resolved)
}

#[cfg(any(feature = "aws", test))]
fn resolve_redirect_prefix_allowed_hosts(
    configured: &std::collections::HashMap<String, Vec<String>>,
    form: &Form,
    saas_tenants: &[String],
) -> Result<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>, String> {
    fn normalize_host(host: &str) -> Option<String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !host.is_ascii() || host.len() > 253 || host.contains(['/', ':', '*'])
        {
            return None;
        }
        if !matches!(url::Host::parse(&host).ok()?, url::Host::Domain(_)) {
            return None;
        }
        if !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return None;
        }
        Some(host)
    }

    let configured_tenants: std::collections::HashSet<&str> =
        saas_tenants.iter().map(String::as_str).collect();
    let mut resolved = std::collections::BTreeMap::new();
    for (tenant, hosts) in configured {
        if matches!(form, Form::Saas { .. }) {
            if !configured_tenants.contains(tenant.as_str()) {
                return Err(format!(
                    "redirect_prefix_allowed_hosts 包含未配置的 SaaS tenant '{tenant}'"
                ));
            }
        } else if tenant != "default" {
            return Err(
                "SelfHosted redirect_prefix_allowed_hosts 只允许 default tenant key".into(),
            );
        }
        let mut normalized = std::collections::BTreeSet::new();
        for host in hosts {
            let host = normalize_host(host).ok_or_else(|| {
                format!("redirect_prefix_allowed_hosts.{tenant} 包含非法精确 host")
            })?;
            if !normalized.insert(host) {
                return Err(format!(
                    "redirect_prefix_allowed_hosts.{tenant} 包含重复 host"
                ));
            }
        }
        resolved.insert(tenant.clone(), normalized);
    }
    Ok(resolved)
}

#[cfg(any(feature = "aws", test))]
fn resolve_deployment_form(
    form: Option<&str>,
    host: Option<String>,
    zone: Option<String>,
    control_host: Option<String>,
) -> Result<Form, String> {
    match form.unwrap_or_default().to_lowercase().as_str() {
        "saas" => Ok(Form::Saas {
            zone: zone
                .filter(|value| !value.is_empty())
                .ok_or("AGENT_AUTH_FORM=saas 须配 AGENT_AUTH_ZONE")?,
            control_host: control_host
                .filter(|value| !value.is_empty())
                .ok_or("AGENT_AUTH_FORM=saas 须配 AGENT_AUTH_CONTROL_HOST")?,
        }),
        _ => Ok(Form::SelfHosted {
            configured_host: host.ok_or("SelfHosted 缺 AGENT_AUTH_HOST")?,
        }),
    }
}

#[cfg(any(feature = "aws", test))]
fn validate_passkey_tenant_isolation(
    form: &Form,
    passkey_enabled: bool,
    tenant_partitioning: bool,
) -> Result<(), String> {
    if passkey_enabled && matches!(form, Form::Saas { .. }) {
        if !tenant_partitioning {
            return Err(
                "AGENT_AUTH_PASSKEY_ENABLED=1 in SaaS requires tenant partitioning".to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(any(feature = "aws", test))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBootstrapConfig {
    schema_version: u32,
    governance_hmac_secret_arn: String,
    admin_credential_secret_arn: Option<String>,
    passkey_origin_secret_arn: Option<String>,
    #[serde(default)]
    saas_tenants: Vec<String>,
    #[serde(default)]
    tenant_subject_types: std::collections::HashMap<String, String>,
    #[serde(default)]
    redirect_prefix_allowed_hosts: std::collections::HashMap<String, Vec<String>>,
    #[serde(default)]
    tenant_admin_secret_arns: std::collections::HashMap<String, String>,
    scim_credential_secret_arn: Option<String>,
    #[serde(default)]
    scim_tenant_secret_arns: std::collections::HashMap<String, String>,
    #[serde(default)]
    federation_attribute_mappings_table: Option<String>,
    tenant_residency: serde_json::Value,
    #[serde(default)]
    tenant_secret_dependencies:
        std::collections::BTreeMap<String, Vec<crate::governance::GovernanceSecretReference>>,
}

#[cfg(any(feature = "aws", test))]
impl RuntimeBootstrapConfig {
    fn parse(value: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(value)
            .map_err(|_| "runtime bootstrap config Secret contains invalid JSON".to_string())?;
        if config.schema_version != 1 {
            return Err("runtime bootstrap config Secret has an unsupported schema version".into());
        }
        if !is_secrets_manager_arn(&config.governance_hmac_secret_arn) {
            return Err(
                "runtime bootstrap config governance HMAC reference is not a Secret ARN".into(),
            );
        }
        if config
            .passkey_origin_secret_arn
            .as_deref()
            .is_some_and(|arn| !is_secrets_manager_arn(arn))
        {
            return Err(
                "runtime bootstrap config passkey origin reference is not a Secret ARN".into(),
            );
        }
        if !config.tenant_residency.is_object() {
            return Err("runtime bootstrap config tenant_residency must be an object".into());
        }
        Ok(config)
    }
}

#[cfg(any(feature = "aws", test))]
fn is_secrets_manager_arn(value: &str) -> bool {
    !value.is_empty() && value.contains(":secretsmanager:") && value.contains(":secret:")
}

#[cfg(feature = "aws")]
async fn load_secret_string(
    conf: &aws_config::SdkConfig,
    secret_arn: &str,
    label: &str,
) -> Result<String, String> {
    if !is_secrets_manager_arn(secret_arn) {
        return Err(format!("{label} is not a Secrets Manager ARN"));
    }
    load_secret_string_by_id(conf, secret_arn, label).await
}

#[cfg(feature = "aws")]
async fn load_secret_string_by_id(
    conf: &aws_config::SdkConfig,
    secret_id: &str,
    label: &str,
) -> Result<String, String> {
    let output = aws_sdk_secretsmanager::Client::new(conf)
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .map_err(|_| format!("{label} could not be read from Secrets Manager"))?;
    output
        .secret_string()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{label} must contain a non-empty SecretString"))
}

#[cfg(any(feature = "aws", test))]
fn secondary_origin_secret_name(primary_secret_arn: &str) -> Result<String, String> {
    if !is_secrets_manager_arn(primary_secret_arn) {
        return Err(
            "primary SaaS origin auth reference is not a Secrets Manager Secret ARN".into(),
        );
    }
    let resource_name = primary_secret_arn
        .split_once(":secret:")
        .map(|(_, resource_name)| resource_name)
        .filter(|resource_name| !resource_name.is_empty())
        .ok_or("primary SaaS origin auth reference is not a Secrets Manager Secret ARN")?;
    let base_name = if resource_name.ends_with("/cloudfront-origin-auth") {
        resource_name
    } else {
        let (candidate, suffix) = resource_name
            .rsplit_once('-')
            .ok_or("primary SaaS origin auth Secret name is not deployment managed")?;
        if suffix.len() != 6
            || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !candidate.ends_with("/cloudfront-origin-auth")
        {
            return Err("primary SaaS origin auth Secret name is not deployment managed".into());
        }
        candidate
    };
    Ok(format!("{base_name}-secondary"))
}

#[cfg(feature = "aws")]
async fn load_runtime_bootstrap_config(
    conf: &aws_config::SdkConfig,
) -> Result<Option<RuntimeBootstrapConfig>, String> {
    let Some(secret_arn) = std::env::var("AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let document = load_secret_string(conf, &secret_arn, "runtime bootstrap config Secret").await?;
    RuntimeBootstrapConfig::parse(&document).map(Some)
}

#[cfg(test)]
mod runtime_bootstrap_config_tests {
    use super::{secondary_origin_secret_name, RuntimeBootstrapConfig};

    const VALID: &str = r#"{
        "schema_version": 1,
        "governance_hmac_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:governance-AbCd12",
        "admin_credential_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:admin-AbCd12",
        "passkey_origin_secret_arn": null,
        "saas_tenants": [],
        "tenant_subject_types": {},
        "tenant_admin_secret_arns": {},
        "scim_credential_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:scim-AbCd12",
        "scim_tenant_secret_arns": {},
        "federation_attribute_mappings_table": "FederationAttributeMappings",
        "tenant_residency": {
            "default": {
                "jurisdiction": "us",
                "allowed_regions": ["us-east-1"],
                "governance_region": "us-east-1"
            }
        },
        "tenant_secret_dependencies": {}
    }"#;

    #[test]
    fn bootstrap_config_requires_the_supported_closed_schema() {
        let config = RuntimeBootstrapConfig::parse(VALID).unwrap();
        assert_eq!(config.schema_version, 1);
        assert_eq!(
            config.governance_hmac_secret_arn,
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:governance-AbCd12"
        );
        assert_eq!(
            config.federation_attribute_mappings_table.as_deref(),
            Some("FederationAttributeMappings")
        );

        assert!(RuntimeBootstrapConfig::parse(
            &VALID.replace("\"schema_version\": 1", "\"schema_version\": 2")
        )
        .is_err());
        assert!(RuntimeBootstrapConfig::parse(&VALID.replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"extra\": true,"
        ))
        .is_err());
    }

    #[test]
    fn secondary_origin_secret_name_accepts_complete_and_partial_primary_arns() {
        assert_eq!(
            secondary_origin_secret_name(
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:AgentAuthSaas/cloudfront-origin-auth-Ab12Cd"
            )
            .unwrap(),
            "AgentAuthSaas/cloudfront-origin-auth-secondary",
        );
        assert_eq!(
            secondary_origin_secret_name(
                "arn:aws:secretsmanager:us-west-2:123456789012:secret:AgentAuthSaas/cloudfront-origin-auth"
            )
            .unwrap(),
            "AgentAuthSaas/cloudfront-origin-auth-secondary",
        );
    }

    #[test]
    fn secondary_origin_secret_name_rejects_unmanaged_or_malformed_primary_arns() {
        for value in [
            "AgentAuthSaas/cloudfront-origin-auth",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:other-Ab12Cd",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:AgentAuthSaas/cloudfront-origin-auth-short",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:AgentAuthSaas/cloudfront-origin-auth-ABC_12",
        ] {
            assert!(secondary_origin_secret_name(value).is_err(), "{value}");
        }
    }

    #[test]
    fn bootstrap_config_rejects_non_secret_hmac_and_non_object_residency() {
        assert!(RuntimeBootstrapConfig::parse(&VALID.replace(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:governance-AbCd12",
            "not-a-secret"
        ))
        .is_err());
        assert!(RuntimeBootstrapConfig::parse(&VALID.replace(
            r#""tenant_residency": {
            "default": {
                "jurisdiction": "us",
                "allowed_regions": ["us-east-1"],
                "governance_region": "us-east-1"
            }
        }"#,
            r#""tenant_residency": []"#
        ))
        .is_err());
    }
}

#[cfg(any(feature = "aws", test))]
fn validate_web_base_url(value: Option<&str>) -> Result<String, String> {
    let raw = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "缺 WEB_BASE_URL:必须显式配置为前端 CloudFront/自定义域 origin".to_string()
        })?;
    let uri: axum::http::Uri = raw
        .parse()
        .map_err(|_| "WEB_BASE_URL 必须是绝对 HTTPS origin".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "WEB_BASE_URL 必须包含 host".to_string())?;
    if uri.scheme_str() != Some("https") || uri.path() != "/" || uri.query().is_some() {
        return Err("WEB_BASE_URL 必须是无 path/query/fragment 的 HTTPS origin".into());
    }
    let host = authority.host().to_ascii_lowercase();
    if host.contains(".execute-api.") && host.ends_with(".amazonaws.com") {
        return Err("WEB_BASE_URL 必须使用前端 CloudFront/自定义域,不得使用裸 API Gateway".into());
    }
    Ok(format!("https://{authority}"))
}

/// HTTP 层运行期状态(配置 + 服务端口)。
#[derive(Clone)]
pub struct AppState {
    pub form: Form,
    pub phase: Phase,
    /// Deployment-level subject type. SelfHosted uses this directly; SaaS uses
    /// the tenant profile resolver and defaults missing profiles to pairwise.
    pub subject_type: SubjectType,
    /// Explicit SaaS tenant subject profiles, validated against `saas_tenants`
    /// during startup.
    pub tenant_subject_types: Arc<std::collections::BTreeMap<String, SubjectType>>,
    /// Explicit exact host allowlist for confidential prefix redirects. SaaS
    /// keys are tenant ids; SelfHosted uses the `default` key.
    pub redirect_prefix_allowed_hosts:
        Arc<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>>,
    /// Single-writer active/passive fence and owner for Region-local replay artifacts.
    pub region: crate::region::RegionRuntime,
    /// Deployment-owned tenant residency map. Governance reads and destructive
    /// jobs fail closed when the local Region is outside this set.
    pub governance_config: Arc<crate::governance::GovernanceConfig>,
    /// Exact source revision injected by deployment automation.
    pub deployment_commit: String,
    /// Dedicated governance HMAC key for opaque job ids, cursors, and
    /// suppression digests. It is separate from protocol/session signing.
    pub governance_hmac_key: Arc<Vec<u8>>,
    /// Durable legal-hold, export-manifest, job, and suppression authority.
    pub governance: Arc<crate::governance::GovernanceStoreImpl>,
    /// Durable FIFO wake-up channel. Job state stays authoritative in
    /// GovernanceTable; the queue only resumes one expected revision.
    pub governance_jobs: Arc<crate::governance::GovernanceJobQueueImpl>,
    /// Explicit tenant Secret ownership inventory. Historical references that
    /// lack metadata are normalized to `external`; ownership is never inferred
    /// from an ARN or name prefix.
    pub tenant_secret_references:
        Arc<std::collections::BTreeMap<String, Vec<crate::governance::GovernanceSecretReference>>>,
    /// Purpose-built executor for claimed product-managed external resources.
    /// Ordinary runtime roles have no delete permission even though they share
    /// the same construction path.
    pub governance_resources: Arc<crate::governance_resources::GovernanceResourceBackendImpl>,
    /// Product assurance classes and configured high-risk actions (C12.4).
    pub assurance_policy: Arc<agent_auth_authn::assurance::AssurancePolicy>,
    /// **数据面 tenant 分区开关**(spec 020 §2.3,C10.19;env `AGENT_AUTH_ENABLE_TENANT_PARTITIONING`)。
    /// 默认 **false**(现网单租户):`tenant_or_400` 返空 tenant → `tpk` 透传 → 与分区前字节等价、零迁移。
    /// true(SaaS / 全 store 就绪后):handler 派生真 tenant,数据落 `{tenant}\x1f*` 分区。**全或无**
    /// (评审 Kiro H2:8 store 未全分区前 MUST 保持关,半迁移=新泄露面)。
    pub tenant_partitioning: bool,
    /// HMAC 服务端密钥(state/CSRF/宽限指纹;真机走 Secrets Manager,本地固定)。
    pub server_secret: Arc<Vec<u8>>,
    /// Managed CloudFront-to-origin authentication for every SaaS HTTP route.
    /// The two independent slots permit one-at-a-time rotation without an
    /// availability window. SelfHosted and local test fixtures use no edge gate.
    pub saas_origin_auth: Arc<crate::origin_auth::SaasOriginAuth>,
    /// 凭据生命周期审计只接受类型化非 secret 字段；AWS 写 stderr/CloudWatch，dev 留内存供集成测试。
    pub credential_audit: Arc<crate::credential::CredentialAuditSink>,
    /// 版本化安全事件的权威持久入口。调用方只提交类型化 draft；store 按 event_id 幂等。
    pub security_events: Arc<SecurityEventStoreImpl>,
    /// Tenant-authorized SSF streams and their durable delivery outbox.
    pub ssf: Arc<SsfStoreImpl>,
    /// Whether this runtime may mutate the Region-local SSF registry/outbox.
    /// Multi-Region standby keeps this false because SSF state is not replicated.
    pub ssf_management_enabled: bool,
    /// 热账本持续失败后的持久摄入队列；生产必须配置，本地内存模式不需要。
    pub security_event_fallback: Option<Arc<SecurityEventFallbackImpl>>,
    /// 平台与逐租户 break-glass admin credential registry。生产仅保存 Secret ARN，SecretString
    /// 在认证时从 Secrets Manager 解析并以有界 TTL 缓存；任何 owner/重复/轮换配置错误均 fail closed。
    pub admin_credentials: Arc<crate::admin_credentials::AdminCredentialResolver>,
    /// Tenant OIDC configuration, one-time login state, and short-lived
    /// attributable Admin sessions. This is intentionally separate from user
    /// login sessions and OAuth authorization sessions.
    pub admin_auth: Arc<AdminAuthStoreImpl>,
    /// SaaS 部署租户注册表。它独立于 token map,防止漏配 token 时把租户静默隐藏。
    pub saas_tenants: Arc<Vec<String>>,
    /// 🔴 安全护栏:是否允许 `/authorize` 的 `login_user` 占位(P0 未接真实登录时的 e2e 便利)。
    /// **仅本地/测试可为 true**;真机(from_env_aws)默认 false——防"任意 login_user 绕过认证"
    /// 的占位分支被误部署到生产可达(见 codex 评审 HIGH)。
    pub allow_login_placeholder: bool,
    /// DCR 准入档(C4.3/DESIGN §3.2):open(匿名或受控 IAT)/ initial_access_token(强制凭票)/
    /// software_statement(签名声明)。
    /// **缺省 fail-closed**(真机未显式配置即最严);dev()=Open 便于 e2e。评审 codex/Kiro:全枚举、无可写派生 bool。
    pub dcr_mode: DcrMode,
    /// 可签发、scope、过期、吊销、一次性且限速的 initial access token 独立存储。
    pub initial_access_tokens: Arc<InitialAccessTokenStoreImpl>,
    /// Authoritative per-tenant EC/RSA snapshot resolver. SelfHosted wraps the
    /// stack signer; SaaS resolves a complete generation from DynamoDB and never
    /// falls back to the stack-scoped signer.
    pub tenant_keys: Arc<crate::tenant_keys::TenantKeyService>,
    pub signer: Arc<SignerImpl>,
    pub codes: Arc<CodeStoreImpl>,
    pub clients: Arc<ClientStoreImpl>,
    /// MCP Client ID Metadata Document resolver. It is active only when the
    /// explicit runtime gate and a tenant-applicable domain policy both exist.
    pub cimd: Arc<crate::cimd::CimdResolver>,
    pub refresh: Arc<RefreshStoreImpl>,
    /// PAR 推送授权请求存储(spec 006 §7.3,RFC 9126)。dev = Memory;真机 = Dynamo(配 PAR_TABLE)。
    pub par: Arc<ParStoreImpl>,
    /// 宽限窗缓存(C3.2/C3.4/C3.5)。**None = 宽限窗关闭**(每次非当前版本一律按复用处理,更严的
    /// fail-closed);真机 item-level 信封加密适配器落地前维持此姿态(见 spec 001 P0 缺口#3)。
    pub grace: Option<Arc<GraceStoreImpl>>,
    /// 宽限窗时长(秒)。无 DPoP 的 public 客户端 SHOULD ≤5s(C3.3);默认 5s。
    pub grace_window_secs: i64,
    pub sessions: Arc<SessionStoreImpl>,
    pub magic_links: Arc<MagicLinkStoreImpl>,
    /// Admin-issued onboarding credentials. This store is independent of
    /// magic-link state and atomically creates `amr=["invite"]` sessions.
    pub invitations: Arc<InvitationStoreImpl>,
    /// Application-enforced validity; DynamoDB TTL is cleanup only.
    pub invitation_ttl_secs: i64,
    /// 用户目录(spec 003 §1.4:magic-link by email 定位 user)。
    pub users: Arc<UsersStoreImpl>,
    /// Exact audience to canonical user-attribute namespace authority.
    pub attribute_namespaces: Arc<AttributeNamespaceStoreImpl>,
    /// Serializes the Memory adapter's namespace authority check with begin-change blocking.
    /// Dynamo also takes this local lock, but correctness there comes from its cross-table CAS.
    pub attribute_namespace_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// SCIM Groups, membership index, and explicit tenant-role mappings.
    pub scim_groups: Arc<ScimGroupsStoreImpl>,
    /// Local password credentials, isolated from `UserRecord` and API schemas.
    pub passwords: Arc<PasswordStoreImpl>,
    /// Bounded Argon2 work slots. Handlers use non-blocking acquisition before
    /// `spawn_blocking`, preventing unbounded async/runtime and memory queues.
    pub password_workers: Arc<tokio::sync::Semaphore>,
    pub recovery: Arc<RecoveryStoreImpl>,
    pub notifier: Arc<NotifierImpl>,
    /// 消息 outbox 读端(SES 未接前的 messages 表模拟,spec 003 §1.5;观测"发了什么")。
    /// 与 `notifier` 共用同一后端实例(dev 内存 / 真机 messages 表)。
    pub messages: Arc<MessageOutboxImpl>,
    /// workload 信任绑定存储(spec 012 C5.5;管理面登记,MUST NOT 走 DCR)。
    pub workload_trust: Arc<WorkloadTrustStoreImpl>,
    /// 联邦上游 IdP 配置存储(spec 003 §4 C9.5b;管理面登记,复合键逐租户隔离)。
    pub federation_config: Arc<FederationConfigStoreImpl>,
    /// Versioned tenant/IdP claim-to-attribute mapping authority.
    pub federation_attribute_mappings: Arc<FederationAttributeMappingsStoreImpl>,
    /// 联邦上游 token 交换器(spec 003 §4;dev Memory / 真机 reqwest→上游 token_endpoint)。
    pub upstream_token_exchanger: Arc<UpstreamTokenExchangerImpl>,
    /// 联邦 client_secret 解析器(spec 003 §4;dev Memory / 真机 Secrets Manager)。
    pub secret_resolver: Arc<SecretResolverImpl>,
    /// 联邦 flow 短命状态存储(spec 003 §4;state/nonce/PKCE/下游续跑上下文,一次性)。
    pub federation_flow: Arc<FederationFlowStoreImpl>,
    /// 联邦登录路由**功能开关**(spec 003 §4 F10):false 时 `/authorize?idp_hint` 与 `/federation/callback`
    /// **不生效**(fail-closed:idp_hint 被忽略、callback 返 404)——e2e 全绿前默认关,防暴露不完整登录面。
    pub federation_enabled: bool,
    /// passkey challenge 短命存储(spec 003 §3;begin 存、finish 一次性 consume)。
    pub passkey_challenges: Arc<PasskeyChallengeStoreImpl>,
    /// passkey 凭证存储(spec 003 §3;credentialId 唯一 + signCount CAS)。
    pub passkeys: Arc<PasskeyStoreImpl>,
    /// passkey 登录路由**功能开关**(spec 003 §3 F10 同 federation):false 时 4 个 `/passkey/*` 端点返 404
    /// ——尤其 authenticate 签发全会话,e2e 全绿前默认关,防暴露不完整/不安全主认证面。
    pub passkey_enabled: bool,
    /// CIBA ping/push 投递模式**功能开关**(spec 013 §4 C7b.5,P3)。false 时:DCR 注册 ping/push 元数据
    /// 拒 `invalid_client_metadata`、discovery 只宣告 `["poll"]`——防暴露未上线/不完整的回调投递面。
    /// 需 Phase≥P3 **且** 此开关开才启用(与 passkey_enabled 同范式;dev 默认关,e2e 显式开)。
    pub ciba_ping_push_enabled: bool,
    /// CIBA ping/push 回调投递(spec 013 §4;dev/测试 = Memory mock,真机 = reqwest SSRF 复校+固定 IP)。
    pub ciba_delivery: Arc<CibaCallbackDeliveryImpl>,
    /// 平台 JWKS 取用(spec 012 workload_oidc_jwt 本地验签;dev 内存,真机 HTTP+缓存)。
    pub jwks_fetcher: Arc<JwksFetcherImpl>,
    /// STS caller(spec 012 C5.2 SigV4/STS 兜底)。**None = SigV4 路径未启用**(fail-closed:
    /// aws_sigv4_caller_identity 认证直接拒);Some 时配套熔断器 `sts_circuit`。
    pub sts_caller: Option<Arc<StsCallerImpl>>,
    /// STS 调用熔断器(spec 012 C5.4;`Arc<Mutex>` 跨请求共享状态)。仅 `sts_caller=Some` 时有意义。
    pub sts_circuit: Arc<tokio::sync::Mutex<agent_auth_workload::CircuitBreaker>>,
    /// SigV4 一次性 replay 缓存(spec 012 C5.3②)。**None = 不做 replay 去重**(fail-open 到"靠短 TTL
    /// 限窗";dev/真机均配 Some 时窗内重放拒)。key=HMAC(server_secret, 签名段)。
    pub replay_store: Option<Arc<ReplayStoreImpl>>,
    /// Grant 授权记录存储(spec 011 §5.1;P2 权威源)。dev/测试内存,真机 Dynamo。
    pub grants: Arc<GrantStoreImpl>,
    /// BYOD 域名映射(spec 010 §5.4 / C8.1b:domain→RS 绑定,数据面 well-known PRM 反查;全局键)。
    pub domain_map: Arc<DomainMapStoreImpl>,
    /// BYOD(投放方式 b)**功能开关**(spec 010 §5.4 / C8.1b,P3)。false 时:`GET /.well-known/oauth-protected-resource`
    /// 在触 store 前直接 404(短路,与"无此路由"同形,不给该路径加 store 往返);admin bind-domain 端点拒。
    /// 默认关 = 字节等价现网(不暴露未上线的数据面 PRM 托管)。需 flag 开才启用(与 passkey_enabled 同范式)。
    pub byod_enabled: bool,
    /// X.509-SVID / mTLS **功能开关**(spec 012 §1.4 / C5.7,P3)。false 时:token handler 不走 X.509 路径
    /// (即便连接层有证书也回落普通 client_credentials)、discovery 不宣告 `spiffe_svid_mtls`。默认关 = 字节等价。
    /// **仅 `Form::SelfHosted` 生效**(评审 B1:SaaS 单 mTLS 域名无法解析租户,SaaS X.509 = 独立后续切片);
    /// SaaS 形态即便 env 开也在 `from_env_aws` fail-closed 回落 false + startup 告警。
    pub mtls_svid_enabled: bool,
    /// Stable MCP EMA profile feature gate。默认关闭；仅 P2+ 且启动时依赖校验完整后才可激活。
    pub ema_enabled: bool,
    /// 启动时已完成结构校验的 tenant-scoped EMA policy。空集合时 capability 必须保持关闭。
    pub ema_policies: Arc<Vec<crate::ema_flow::TenantEmaPolicy>>,
    /// 逐租户 policy_version(spec 005 §7 / C10.17:Cedar 策略版本,bump 触发重算)。
    pub policy_versions: Arc<PolicyVersionStoreImpl>,
    /// 不可变策略工件(spec 005 §7:按 (tenant,version) 存已校验 Cedar 策略文本)。
    pub policy_artifacts: Arc<PolicyArtifactStoreImpl>,
    /// Cedar 授权引擎开关(spec 005 §7,C10.17;默认关 = 字节等价现网,不写 effective/pv、不 gate 热路径)。
    pub authz_enabled: bool,
    /// current_pv **进程内短 TTL 缓存**(spec 005 §7 补强 ⑭):热路径判 stale 只读本地缓存的 (tenant→(pv,取时))
    /// ,绝不每请求同步查 DynamoDB(否则新造热路径瓶颈)。冷启动/过期未预热 → 保守当 stale(fail-safe)。
    /// 后台/首次访问按 TTL 刷新。同 KMS 背压水位缓存(§8:689)。
    pub current_pv_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u64, i64)>>>,
    /// jti→主体映射(spec 011 C7.8:token-exchange subject 解析;3LO 签发时落,短命)。
    /// **None = 不落映射**(P1 无 token-exchange 消费者时避免死写;dev/测试与真机 P2 配置时 Some)。
    pub jti_store: Option<Arc<JtiStoreImpl>>,
    /// CIBA 授权请求存储(spec 013)。
    pub ciba: Arc<CibaStoreImpl>,
    /// device 授权存储(spec 013)。
    pub device: Arc<DeviceStoreImpl>,
    /// 授权会话状态机存储(spec 004;与 login `sessions` 独立)。
    pub authz_sessions: Arc<AuthzSessionStoreImpl>,
    /// 授权会话状态迁移事件 sink(C6.5 投影;dev log / 真机 no-op,真发 EventBridge 留 P2)。
    pub authz_events: Arc<AuthzEventSinkImpl>,
    /// magic-link 前端基址(链接指向前端 /login/callback;dev = SPA URL 或本地)。
    pub web_base_url: String,
    /// per-client 应用层令牌桶限流(spec 005 C10.7)。**None = 不限流**(fail-open;dev 测试默认 Some 内存桶,
    /// 真机配 Some Dynamo 桶)。/token 入口按 client_id 取 token,超额 429 + Retry-After。
    pub rate_limit: Option<Arc<RateLimitStoreImpl>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAuthorityDeleteOutcome {
    pub refresh_families: usize,
    pub deleted_grants: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAttributeWrite {
    pub canonical_namespace: String,
    pub outcome: crate::ports::PutAttrOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FederatedAttributeAuditTarget {
    mapping_id: String,
    mapping_revision: u64,
    namespace: String,
    key: String,
}

fn federated_attribute_audit_hmac(server_secret: &[u8], domain: &[u8], fields: &[&[u8]]) -> String {
    use base64::Engine as _;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(domain);
    for field in fields {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn federated_attribute_operation_reference(
    server_secret: &[u8],
    request: &crate::federation_attributes::FederationAttributeReconciliationRequest,
) -> String {
    format!(
        "far_{}",
        federated_attribute_audit_hmac(
            server_secret,
            b"federated-attribute-operation:v1",
            &[
                request.logical_tenant_id.as_bytes(),
                request.upstream_idp_id.as_bytes(),
                request.user_id.as_bytes(),
                request.operation_id.as_bytes(),
            ],
        )
    )
}

fn federated_attribute_value_summary(
    server_secret: &[u8],
    request: &crate::federation_attributes::FederationAttributeReconciliationRequest,
    target: &FederatedAttributeAuditTarget,
    value: Option<&str>,
) -> String {
    let presence = if value.is_some() {
        b"present".as_slice()
    } else {
        b"absent".as_slice()
    };
    format!(
        "fav_{}",
        federated_attribute_audit_hmac(
            server_secret,
            b"federated-attribute-value:v1",
            &[
                request.logical_tenant_id.as_bytes(),
                request.upstream_idp_id.as_bytes(),
                request.user_id.as_bytes(),
                target.mapping_id.as_bytes(),
                target.namespace.as_bytes(),
                target.key.as_bytes(),
                presence,
                value.unwrap_or_default().as_bytes(),
            ],
        )
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederationConfigMutationOutcome {
    Applied,
    MappingsPresent,
}

impl AppState {
    pub(crate) async fn change_federation_attribute_mapping(
        &self,
        config: &agent_auth_authn::federation::FederationConfig,
        change: crate::federation_attributes::MappingChange,
    ) -> Result<crate::federation_attributes::MappingChangeOutcome, StoreError> {
        use crate::federation_attributes::FederationAttributeMappingsStore as _;

        match (
            &*self.federation_config,
            &*self.federation_attribute_mappings,
        ) {
            (
                FederationConfigStoreImpl::Memory(_),
                FederationAttributeMappingsStoreImpl::Memory(mappings),
            ) => {
                mappings
                    .change(
                        &config.tenant_id,
                        &config.upstream_idp_id,
                        &config.upstream_issuer,
                        change,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            (
                FederationConfigStoreImpl::Dynamo(configs),
                FederationAttributeMappingsStoreImpl::Dynamo(mappings),
            ) => {
                let config_condition = configs.snapshot_condition(config)?;
                mappings
                    .change_authorized(
                        config_condition,
                        &config.tenant_id,
                        &config.upstream_idp_id,
                        &config.upstream_issuer,
                        change,
                    )
                    .await
            }
            _ => Err(StoreError::Permanent(
                "federation config and mapping authority are not co-located".into(),
            )),
        }
    }

    pub(crate) async fn put_federation_config(
        &self,
        next: agent_auth_authn::federation::FederationConfig,
    ) -> Result<FederationConfigMutationOutcome, StoreError> {
        use crate::federation_attributes::FederationAttributeMappingsStore as _;
        use crate::ports::FederationConfigStore as _;

        let _guard = self.attribute_namespace_write_lock.lock().await;
        let current = self
            .federation_config
            .get(&next.tenant_id, &next.upstream_idp_id)
            .await?;
        let registry = self
            .federation_attribute_mappings
            .get_registry(&next.tenant_id, &next.upstream_idp_id)
            .await?;
        let issuer_changes = current
            .as_ref()
            .is_some_and(|current| current.upstream_issuer != next.upstream_issuer);
        if registry
            .as_ref()
            .is_some_and(|registry| !registry.mappings.is_empty())
            && (current.is_none() || issuer_changes)
        {
            return Ok(FederationConfigMutationOutcome::MappingsPresent);
        }

        match (
            &*self.federation_config,
            &*self.federation_attribute_mappings,
        ) {
            (
                FederationConfigStoreImpl::Memory(configs),
                FederationAttributeMappingsStoreImpl::Memory(_),
            ) => {
                configs.put(next).await?;
                Ok(FederationConfigMutationOutcome::Applied)
            }
            #[cfg(feature = "aws")]
            (
                FederationConfigStoreImpl::Dynamo(configs),
                FederationAttributeMappingsStoreImpl::Dynamo(mappings),
            ) => {
                let mapping_condition = mappings.reconciliation_authority_condition(
                    &next.tenant_id,
                    &next.upstream_idp_id,
                    registry.as_ref(),
                )?;
                if configs
                    .put_authorized(mapping_condition, current.as_ref(), next)
                    .await?
                {
                    Ok(FederationConfigMutationOutcome::Applied)
                } else {
                    Ok(FederationConfigMutationOutcome::MappingsPresent)
                }
            }
            _ => Err(StoreError::Permanent(
                "federation config and mapping authority are not co-located".into(),
            )),
        }
    }

    pub(crate) async fn delete_federation_config(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<FederationConfigMutationOutcome, StoreError> {
        use crate::federation_attributes::FederationAttributeMappingsStore as _;
        use crate::ports::FederationConfigStore as _;

        let _guard = self.attribute_namespace_write_lock.lock().await;
        let current = self
            .federation_config
            .get(tenant_id, upstream_idp_id)
            .await?;
        let registry = self
            .federation_attribute_mappings
            .get_registry(tenant_id, upstream_idp_id)
            .await?;
        if registry
            .as_ref()
            .is_some_and(|registry| !registry.mappings.is_empty())
        {
            return Ok(FederationConfigMutationOutcome::MappingsPresent);
        }
        let Some(current) = current else {
            return Ok(FederationConfigMutationOutcome::Applied);
        };
        #[cfg(not(feature = "aws"))]
        let _ = &current;

        match (
            &*self.federation_config,
            &*self.federation_attribute_mappings,
        ) {
            (
                FederationConfigStoreImpl::Memory(configs),
                FederationAttributeMappingsStoreImpl::Memory(_),
            ) => {
                configs.delete(tenant_id, upstream_idp_id).await?;
                Ok(FederationConfigMutationOutcome::Applied)
            }
            #[cfg(feature = "aws")]
            (
                FederationConfigStoreImpl::Dynamo(configs),
                FederationAttributeMappingsStoreImpl::Dynamo(mappings),
            ) => {
                let mapping_condition = mappings.reconciliation_authority_condition(
                    tenant_id,
                    upstream_idp_id,
                    registry.as_ref(),
                )?;
                if configs
                    .delete_authorized(mapping_condition, &current)
                    .await?
                {
                    Ok(FederationConfigMutationOutcome::Applied)
                } else {
                    Ok(FederationConfigMutationOutcome::MappingsPresent)
                }
            }
            _ => Err(StoreError::Permanent(
                "federation config and mapping authority are not co-located".into(),
            )),
        }
    }

    pub async fn reconcile_federated_attributes(
        &self,
        request: crate::federation_attributes::FederationAttributeReconciliationRequest,
    ) -> Result<crate::federation_attributes::FederationAttributeReconciliationOutcome, StoreError>
    {
        let (registry, desired, result) = {
            let _guard = self.attribute_namespace_write_lock.lock().await;
            self.reconcile_federated_attributes_locked(&request).await
        };
        self.audit_federated_attribute_reconciliation(
            &request,
            registry.as_ref(),
            &desired,
            &result,
        )
        .await;
        result
    }

    async fn reconcile_federated_attributes_locked(
        &self,
        request: &crate::federation_attributes::FederationAttributeReconciliationRequest,
    ) -> (
        Option<crate::federation_attributes::MappingRegistry>,
        crate::federation_attributes::DesiredFederatedAttributes,
        Result<crate::federation_attributes::FederationAttributeReconciliationOutcome, StoreError>,
    ) {
        use crate::attribute_namespace::{
            AttributeNamespaceStore as _, AttributeWriteAuthority, AttributeWriteResolution,
        };
        use crate::federation_attributes::{
            DesiredFederatedAttribute, DesiredFederatedAttributes,
            FederationAttributeMappingsStore as _, FederationAttributeReconciliationOutcome,
            MappingEvaluation,
        };

        let registry = match self
            .federation_attribute_mappings
            .get_registry(&request.logical_tenant_id, &request.upstream_idp_id)
            .await
        {
            Ok(registry) => registry,
            Err(error) => return (None, DesiredFederatedAttributes::new(), Err(error)),
        };
        let registry_revision = registry
            .as_ref()
            .map(|registry| registry.revision)
            .unwrap_or(0);
        if registry.as_ref().is_some_and(|registry| {
            registry.upstream_issuer != request.upstream_issuer
                || registry.tenant_id != request.logical_tenant_id
                || registry.upstream_idp_id != request.upstream_idp_id
        }) {
            return (
                registry,
                DesiredFederatedAttributes::new(),
                Ok(FederationAttributeReconciliationOutcome::AuthorityChanged),
            );
        }

        let mut desired = DesiredFederatedAttributes::new();
        let mut namespace_authorities = std::collections::BTreeMap::new();
        if let Some(registry) = &registry {
            for mapping in registry.mappings.iter().filter(|mapping| mapping.enabled) {
                if let MappingEvaluation::Present(value) =
                    mapping.evaluate(&request.verified_claims)
                {
                    desired.insert(
                        (mapping.target_namespace.clone(), mapping.target_key.clone()),
                        DesiredFederatedAttribute {
                            namespace: mapping.target_namespace.clone(),
                            key: mapping.target_key.clone(),
                            value,
                            owner: crate::ports::FederatedAttributeOwner {
                                upstream_idp_id: request.upstream_idp_id.clone(),
                                upstream_issuer: request.upstream_issuer.clone(),
                                mapping_id: mapping.mapping_id.clone(),
                                mapping_revision: mapping.revision,
                            },
                        },
                    );
                }
            }
            for mapping in registry.mappings.iter().filter(|mapping| mapping.enabled) {
                let authority = match self
                    .attribute_namespaces
                    .resolve_write_authority(&request.storage_tenant_id, &mapping.target_namespace)
                    .await
                {
                    Err(error) => return (Some(registry.clone()), desired, Err(error)),
                    Ok(AttributeWriteResolution::Authorized(
                        authority @ AttributeWriteAuthority::ActiveCanonical { .. },
                    )) if authority.canonical_namespace() == mapping.target_namespace => authority,
                    _ => {
                        return (
                            Some(registry.clone()),
                            desired,
                            Ok(FederationAttributeReconciliationOutcome::NamespaceBlocked {
                                namespace: mapping.target_namespace.clone(),
                            }),
                        )
                    }
                };
                namespace_authorities
                    .entry(mapping.target_namespace.clone())
                    .or_insert(authority);
            }
        }
        #[cfg(feature = "aws")]
        let reconciliation_fingerprint =
            match crate::federation_attributes::reconciliation_fingerprint(
                request,
                registry.as_ref(),
                &desired,
            ) {
                Ok(fingerprint) => fingerprint,
                Err(error) => return (registry, desired, Err(error)),
            };

        let result = match &*self.users {
            UsersStoreImpl::Memory(users) => {
                users
                    .reconcile_federated_attributes(
                        &request.storage_tenant_id,
                        &request.user_id,
                        &request.upstream_idp_id,
                        &desired,
                        registry_revision,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(users) => {
                let (
                    AttributeNamespaceStoreImpl::Dynamo(namespaces),
                    FederationAttributeMappingsStoreImpl::Dynamo(mappings),
                ) = (
                    &*self.attribute_namespaces,
                    &*self.federation_attribute_mappings,
                )
                else {
                    return (
                        registry,
                        desired,
                        Err(StoreError::Permanent(
                            "federation attribute authority stores are not co-located".into(),
                        )),
                    );
                };
                let mapping_condition = match mappings.reconciliation_authority_condition(
                    &request.logical_tenant_id,
                    &request.upstream_idp_id,
                    registry.as_ref(),
                ) {
                    Ok(condition) => condition,
                    Err(error) => return (registry, desired, Err(error)),
                };
                let mut conditions = vec![mapping_condition];
                for authority in namespace_authorities.values() {
                    let condition = match namespaces
                        .write_authority_condition(&request.storage_tenant_id, authority)
                    {
                        Ok(condition) => condition,
                        Err(error) => return (registry, desired, Err(error)),
                    };
                    conditions.push(condition);
                }
                users
                    .reconcile_federated_attributes_authorized(
                        crate::adapters::aws::AuthorizedFederatedReconciliation {
                            tenant: &request.storage_tenant_id,
                            user_id: &request.user_id,
                            upstream_idp_id: &request.upstream_idp_id,
                            desired: &desired,
                            registry_revision,
                            operation_id: &request.operation_id,
                            fingerprint: &reconciliation_fingerprint,
                            authority_conditions: conditions,
                        },
                    )
                    .await
                    .map(|outcome| {
                        outcome
                            .unwrap_or(FederationAttributeReconciliationOutcome::AuthorityChanged)
                    })
            }
        };
        (registry, desired, result)
    }

    async fn audit_federated_attribute_reconciliation(
        &self,
        request: &crate::federation_attributes::FederationAttributeReconciliationRequest,
        registry: Option<&crate::federation_attributes::MappingRegistry>,
        desired: &crate::federation_attributes::DesiredFederatedAttributes,
        result: &Result<
            crate::federation_attributes::FederationAttributeReconciliationOutcome,
            StoreError,
        >,
    ) {
        use crate::ports::UsersStore as _;
        use crate::security_event::{
            SecurityActor, SecurityEventCategory, SecurityEventCorrelation, SecurityEventDraft,
            SecurityEventOutcome, SecuritySubject,
        };

        let outcome = match result {
            Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::Applied {
                    ..
                },
            ) => SecurityEventOutcome::Success,
            Ok(_) => SecurityEventOutcome::Denied,
            Err(_) => SecurityEventOutcome::Failure,
        };
        let (before, after) = match result {
            Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::Applied {
                    previous_user,
                    user,
                    ..
                },
            ) => (
                Some(previous_user.as_ref().clone()),
                Some(user.as_ref().clone()),
            ),
            _ => {
                let current = self
                    .users
                    .get_by_id(&request.storage_tenant_id, &request.user_id)
                    .await
                    .ok()
                    .flatten();
                (current.clone(), current)
            }
        };

        let mut targets = std::collections::BTreeMap::<
            (String, String, String),
            FederatedAttributeAuditTarget,
        >::new();
        if let Some(registry) = registry {
            for mapping in &registry.mappings {
                let key = (
                    mapping.target_namespace.clone(),
                    mapping.target_key.clone(),
                    mapping.mapping_id.clone(),
                );
                targets.insert(
                    key,
                    FederatedAttributeAuditTarget {
                        mapping_id: mapping.mapping_id.clone(),
                        mapping_revision: mapping.revision,
                        namespace: mapping.target_namespace.clone(),
                        key: mapping.target_key.clone(),
                    },
                );
            }
        }
        for user in [before.as_ref(), after.as_ref()].into_iter().flatten() {
            for (namespace, attributes) in &user.attributes {
                for (key, owner) in &attributes.federation_owners {
                    if owner.upstream_idp_id != request.upstream_idp_id {
                        continue;
                    }
                    targets
                        .entry((namespace.clone(), key.clone(), owner.mapping_id.clone()))
                        .or_insert_with(|| FederatedAttributeAuditTarget {
                            mapping_id: owner.mapping_id.clone(),
                            mapping_revision: owner.mapping_revision,
                            namespace: namespace.clone(),
                            key: key.clone(),
                        });
                }
            }
        }
        for desired_value in desired.values() {
            let owner = &desired_value.owner;
            targets
                .entry((
                    desired_value.namespace.clone(),
                    desired_value.key.clone(),
                    owner.mapping_id.clone(),
                ))
                .or_insert_with(|| FederatedAttributeAuditTarget {
                    mapping_id: owner.mapping_id.clone(),
                    mapping_revision: owner.mapping_revision,
                    namespace: desired_value.namespace.clone(),
                    key: desired_value.key.clone(),
                });
        }

        let operation_id = federated_attribute_operation_reference(&self.server_secret, request);
        if targets.is_empty() {
            self.record_security_event(
                SecurityEventDraft::new(
                    &request.logical_tenant_id,
                    SecurityActor::system("federation-reconciler"),
                    Some(SecuritySubject::user(&request.user_id)),
                    SecurityEventCategory::Authentication,
                    "federation.attribute_reconciliation",
                    outcome,
                )
                .correlated(SecurityEventCorrelation {
                    operation_id: Some(operation_id),
                    upstream_idp_id: Some(request.upstream_idp_id.clone()),
                    ..Default::default()
                }),
            )
            .await;
            return;
        }

        for target in targets.into_values() {
            let old_value = before
                .as_ref()
                .and_then(|user| user.attributes.get(&target.namespace))
                .and_then(|attributes| attributes.kv.get(&target.key))
                .map(String::as_str);
            let new_value = match result {
                Ok(
                    crate::federation_attributes::FederationAttributeReconciliationOutcome::Applied {
                        ..
                    },
                ) => after
                    .as_ref()
                    .and_then(|user| user.attributes.get(&target.namespace))
                    .and_then(|attributes| attributes.kv.get(&target.key))
                    .map(String::as_str),
                _ => desired
                    .get(&(target.namespace.clone(), target.key.clone()))
                    .map(|value| value.value.as_str()),
            };
            self.record_security_event(
                SecurityEventDraft::new(
                    &request.logical_tenant_id,
                    SecurityActor::system("federation-reconciler"),
                    Some(SecuritySubject::user(&request.user_id)),
                    SecurityEventCategory::Authentication,
                    "federation.attribute_reconciliation",
                    outcome,
                )
                .correlated(SecurityEventCorrelation {
                    operation_id: Some(operation_id.clone()),
                    upstream_idp_id: Some(request.upstream_idp_id.clone()),
                    mapping_id: Some(target.mapping_id.clone()),
                    mapping_revision: Some(target.mapping_revision),
                    target_namespace: Some(target.namespace.clone()),
                    target_key: Some(target.key.clone()),
                    old_value_summary: Some(federated_attribute_value_summary(
                        &self.server_secret,
                        request,
                        &target,
                        old_value,
                    )),
                    new_value_summary: Some(federated_attribute_value_summary(
                        &self.server_secret,
                        request,
                        &target,
                        new_value,
                    )),
                    ..Default::default()
                }),
            )
            .await;
        }
    }

    pub async fn purge_stale_federated_attribute_owner(
        &self,
        logical_tenant_id: &str,
        storage_tenant_id: &str,
        user_id: &str,
        namespace: &str,
        key: &str,
        expected_revision: u64,
    ) -> Result<crate::federation_attributes::FederationAttributeOwnerPurgeOutcome, StoreError>
    {
        use crate::federation_attributes::{
            federated_attribute_owner_is_active, FederationAttributeMappingsStore as _,
            FederationAttributeOwnerPurgeOutcome,
        };
        use crate::ports::UsersStore as _;

        let _guard = self.attribute_namespace_write_lock.lock().await;
        let Some(current) = self.users.get_by_id(storage_tenant_id, user_id).await? else {
            return Ok(FederationAttributeOwnerPurgeOutcome::NotFound);
        };
        if current.status == crate::ports::UserStatus::Tombstoned {
            return Ok(FederationAttributeOwnerPurgeOutcome::Tombstoned);
        }
        let Some(attributes) = current.attributes.get(namespace) else {
            return Ok(FederationAttributeOwnerPurgeOutcome::OwnerNotFound);
        };
        if attributes.revision != expected_revision {
            return Ok(FederationAttributeOwnerPurgeOutcome::RevisionConflict {
                current: attributes.revision,
            });
        }
        let Some(owner) = attributes.federation_owners.get(key).cloned() else {
            return Ok(FederationAttributeOwnerPurgeOutcome::OwnerNotFound);
        };
        let registry = self
            .federation_attribute_mappings
            .get_registry(logical_tenant_id, &owner.upstream_idp_id)
            .await?;
        if federated_attribute_owner_is_active(registry.as_ref(), &owner, namespace, key) {
            return Ok(FederationAttributeOwnerPurgeOutcome::ActiveOwner { owner });
        }

        match &*self.users {
            UsersStoreImpl::Memory(users) => {
                users
                    .purge_federated_attribute_owner(
                        storage_tenant_id,
                        user_id,
                        namespace,
                        key,
                        expected_revision,
                        &owner,
                    )
                    .await
            }
            #[cfg(feature = "aws")]
            UsersStoreImpl::Dynamo(users) => {
                let FederationAttributeMappingsStoreImpl::Dynamo(mappings) =
                    &*self.federation_attribute_mappings
                else {
                    return Err(StoreError::Permanent(
                        "federation mapping authority is not co-located".into(),
                    ));
                };
                let outcome = crate::federation_attributes::plan_federated_attribute_owner_purge(
                    &current,
                    namespace,
                    key,
                    expected_revision,
                    &owner,
                )?;
                let FederationAttributeOwnerPurgeOutcome::Purged { user: next, .. } = &outcome
                else {
                    return Ok(outcome);
                };
                let authority_condition = mappings.reconciliation_authority_condition(
                    logical_tenant_id,
                    &owner.upstream_idp_id,
                    registry.as_ref(),
                )?;
                if users
                    .purge_federated_attribute_owner_authorized(
                        storage_tenant_id,
                        &current,
                        next,
                        authority_condition,
                    )
                    .await?
                {
                    Ok(outcome)
                } else {
                    Ok(FederationAttributeOwnerPurgeOutcome::AuthorityChanged)
                }
            }
        }
    }

    pub async fn put_user_attributes_authorized(
        &self,
        tenant: &str,
        user_id: &str,
        requested_namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<AuthorizedAttributeWrite, StoreError> {
        use crate::attribute_namespace::{AttributeNamespaceStore as _, AttributeWriteResolution};
        use crate::ports::{PutAttrOutcome, UsersStore as _};

        let _guard = self.attribute_namespace_write_lock.lock().await;
        let authority = match self
            .attribute_namespaces
            .resolve_write_authority(tenant, requested_namespace)
            .await?
        {
            AttributeWriteResolution::Authorized(authority) => authority,
            AttributeWriteResolution::Blocked => {
                return Ok(AuthorizedAttributeWrite {
                    canonical_namespace: requested_namespace.to_string(),
                    outcome: PutAttrOutcome::NamespaceBlocked,
                })
            }
        };
        let canonical_namespace = authority.canonical_namespace().to_string();
        let outcome = match (&*self.users, &*self.attribute_namespaces) {
            (UsersStoreImpl::Memory(users), AttributeNamespaceStoreImpl::Memory(_)) => {
                users
                    .put_attributes(tenant, user_id, &canonical_namespace, kv, expected_revision)
                    .await?
            }
            #[cfg(feature = "aws")]
            (UsersStoreImpl::Dynamo(users), AttributeNamespaceStoreImpl::Dynamo(namespaces)) => {
                let condition = namespaces.write_authority_condition(tenant, &authority)?;
                match users
                    .put_attributes_authorized(
                        tenant,
                        user_id,
                        &canonical_namespace,
                        kv,
                        expected_revision,
                        condition,
                    )
                    .await?
                {
                    Some(outcome) => outcome,
                    None => PutAttrOutcome::NamespaceBlocked,
                }
            }
            _ => {
                return Err(StoreError::Permanent(
                    "attribute users and namespace stores are not co-located".into(),
                ))
            }
        };
        Ok(AuthorizedAttributeWrite {
            canonical_namespace,
            outcome,
        })
    }

    /// Resolve the subject type used by both metadata and signing for one
    /// request tenant. SaaS defaults to pairwise when no explicit profile
    /// exists; SelfHosted always uses the deployment-level setting.
    pub fn subject_type_for_tenant(&self, tenant: &str) -> SubjectType {
        if matches!(self.form, Form::Saas { .. }) {
            self.tenant_subject_types
                .get(tenant)
                .copied()
                .unwrap_or(SubjectType::Pairwise)
        } else {
            self.subject_type
        }
    }

    pub fn redirect_prefix_allowed_hosts_for_tenant(
        &self,
        tenant: &str,
    ) -> &std::collections::BTreeSet<String> {
        let key = if matches!(self.form, Form::Saas { .. }) {
            tenant
        } else {
            "default"
        };
        self.redirect_prefix_allowed_hosts
            .get(key)
            .unwrap_or_else(|| {
                static EMPTY: std::sync::OnceLock<std::collections::BTreeSet<String>> =
                    std::sync::OnceLock::new();
                EMPTY.get_or_init(std::collections::BTreeSet::new)
            })
    }

    pub fn put_grant_for_client<'a>(
        &'a self,
        tenant: &'a str,
        grant: agent_auth_grant::Grant,
        registered_client: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StoreError>> + Send + 'a>>
    {
        Box::pin(async move {
            if registered_client {
                self.grants
                    .put_for_active_client(self.clients.as_ref(), tenant, grant)
                    .await
            } else {
                self.grants.put(tenant, grant).await.map(|()| true)
            }
        })
    }

    pub async fn delete_registered_client_authority(
        &self,
        tenant: &str,
        snapshot: &ClientRecord,
    ) -> Result<ClientAuthorityDeleteOutcome, StoreError> {
        if !snapshot.is_tombstoned() {
            let fenced = self
                .clients
                .convert_to_tombstone(
                    tenant,
                    &snapshot.client_id,
                    crate::current_unix_secs(),
                    snapshot.last_used_day,
                    snapshot.authority_revision,
                )
                .await?;
            if !fenced {
                return Err(StoreError::Transient(
                    "client authority changed during deletion".into(),
                ));
            }
        }

        let family_ids = self
            .refresh
            .revoke_by_client(tenant, &snapshot.client_id)
            .await?;
        if let Some(grace) = &self.grace {
            for family_id in &family_ids {
                grace.delete_family(family_id).await?;
            }
        }
        let deleted_grants = self
            .grants
            .delete_by_client(tenant, &snapshot.client_id)
            .await?;
        self.clients.delete(tenant, &snapshot.client_id).await?;
        Ok(ClientAuthorityDeleteOutcome {
            refresh_families: family_ids.len(),
            deleted_grants,
        })
    }

    /// CIMD is a P1 capability and also requires its runtime gate plus a
    /// tenant-applicable trust policy.
    pub fn cimd_active_for_tenant(&self, tenant: &str) -> bool {
        self.phase.at_least(Phase::P1) && self.cimd.active_for_tenant(tenant)
    }

    /// CIBA ping/push 是否**实际启用**(spec 013 §4,C7b.5):Phase≥P3 **且** feature gate 开。
    /// 二者缺一即视为未上线——DCR 拒 ping/push 元数据、discovery 只宣告 poll(不暴露未上线的回调投递面)。
    pub fn ciba_ping_push_active(&self) -> bool {
        self.ciba_ping_push_enabled && self.phase.at_least(Phase::P3)
    }

    pub fn private_key_jwt_active(&self) -> bool {
        self.replay_store.is_some()
    }

    pub fn ema_active(&self) -> bool {
        self.ema_enabled
            && self.phase.at_least(Phase::P2)
            && self.replay_store.is_some()
            && self.jti_store.is_some()
            && (!matches!(self.form, Form::Saas { .. }) || self.tenant_partitioning)
            && !self.ema_policies.is_empty()
    }

    pub fn ema_active_for_tenant(&self, tenant: &str) -> bool {
        self.ema_active()
            && self
                .ema_policies
                .iter()
                .any(|configured| configured.agent_auth_tenant == tenant)
    }

    pub fn registered_client_auth_method(
        &self,
        value: &str,
    ) -> Option<agent_auth_client::RegisteredClientAuthMethod> {
        let method = agent_auth_client::RegisteredClientAuthMethod::parse_executable(value)?;
        if method == agent_auth_client::RegisteredClientAuthMethod::PrivateKeyJwt
            && !self.private_key_jwt_active()
        {
            return None;
        }
        Some(method)
    }

    /// Whether a registered client can authenticate an authorization-code
    /// exchange without PKCE under the current runtime capabilities.
    pub fn allows_authorization_code_without_pkce(&self, client: &ClientRecord) -> bool {
        use agent_auth_client::RegisteredClientAuthMethod;
        use agent_auth_workload::ClientType;

        let is_confidential = match client.client_type.as_deref() {
            Some(value) => ClientType::parse(value) == Some(ClientType::Confidential),
            None => matches!(
                ClientType::default_from_auth_method(&client.token_endpoint_auth_method),
                Ok(ClientType::Confidential)
            ),
        };

        is_confidential
            && matches!(
                self.registered_client_auth_method(&client.token_endpoint_auth_method),
                Some(method) if method != RegisteredClientAuthMethod::None
            )
    }

    pub fn registered_client_auth_method_names(&self) -> Vec<&'static str> {
        agent_auth_client::enabled_registered_client_auth_method_names(
            self.private_key_jwt_active(),
        )
    }

    /// 开发/本地默认:自部署形态、P0、pairwise、内存端口。真机由 `with_aws` 覆盖。
    pub fn dev(configured_host: &str) -> Self {
        // notifier 与 messages 共用同一内存 outbox 实例(clone 共享内部 Arc<Mutex<Vec>>)。
        let dev_outbox = MemoryOutboxNotifier::default();
        let signer = Arc::new(SignerImpl::Memory(MemorySigner::dev()));
        let governance_hmac_key = Arc::new(b"dev-governance-hmac-key-not-for-prod".to_vec());
        let governance_store = crate::adapters::memory::MemoryGovernanceStore::default();
        let users_store = crate::adapters::memory::MemoryUsersStore::default()
            .with_governance_suppression(governance_store.clone(), governance_hmac_key.clone());
        let dev_passwords = crate::adapters::memory::MemoryPasswordStore::default();
        let dev_sessions = MemorySessionStore::default();
        let dev_invitations = MemoryInvitationStore::new(
            users_store.clone(),
            dev_passwords.clone(),
            dev_sessions.clone(),
        );
        AppState {
            form: Form::SelfHosted {
                configured_host: configured_host.to_string(),
            },
            region: crate::region::RegionRuntime::single_region(),
            governance_config: Arc::new(crate::governance::GovernanceConfig::single_region(
                "default", "local", "local",
            )),
            deployment_commit: "dev".into(),
            governance_hmac_key,
            governance: Arc::new(crate::governance::GovernanceStoreImpl::Memory(
                governance_store,
            )),
            governance_jobs: Arc::new(crate::governance::GovernanceJobQueueImpl::Memory(
                crate::adapters::memory::MemoryGovernanceJobQueue::default(),
            )),
            tenant_secret_references: Arc::new(std::collections::BTreeMap::from([(
                "default".to_string(),
                vec![
                    crate::governance::GovernanceSecretReference::historical_external(
                        "scim",
                        "memory:default-scim",
                    ),
                ],
            )])),
            governance_resources: Arc::new(
                crate::governance_resources::GovernanceResourceBackendImpl::Memory(
                    crate::governance_resources::MemoryGovernanceResourceBackend::default(),
                ),
            ),
            // dev:默认关 tenant 分区(单租户 e2e 现状);构造 Saas 的测试自行覆盖为 true。
            tenant_partitioning: false,
            // 部署 phase = P1(spec 011 C7.6a):P1 discovery 宣告的三个端点 introspection(/introspect,
            // spec 010)、revocation(/revoke,本 spec)、end_session(/end-session,spec 003)现已全部落地,
            // 升 P1 不违反公理 1"落地才宣告"。P2(device/CIBA)、P3(PAR)仍 must_not_advertise。
            phase: Phase::P1,
            // 自部署形态默认 public(§2.8/§11 #12:首方 RS 需跨 RS 关联);pairwise 派生已实现(spec 001
            // C2.11),SaaS 形态(from_env_aws 按 Form 选)才默认 pairwise。dev=SelfHosted→public。
            subject_type: SubjectType::Public,
            tenant_subject_types: Arc::new(std::collections::BTreeMap::new()),
            redirect_prefix_allowed_hosts: Arc::new(std::collections::BTreeMap::new()),
            assurance_policy: Arc::new(agent_auth_authn::assurance::AssurancePolicy::default()),
            server_secret: Arc::new(b"dev-server-secret-not-for-prod".to_vec()),
            saas_origin_auth: Arc::new(crate::origin_auth::SaasOriginAuth::development_bypass()),
            credential_audit: Arc::new(crate::credential::CredentialAuditSink::memory()),
            security_events: Arc::new(SecurityEventStoreImpl::Memory(
                MemorySecurityEventStore::default(),
            )),
            ssf: Arc::new(SsfStoreImpl::Memory(MemorySsfStore::default())),
            ssf_management_enabled: true,
            security_event_fallback: None,
            // 本地/测试:内存 credential set；生产只配置 Secret ARN 并在运行时解析。
            admin_credentials: Arc::new(crate::admin_credentials::AdminCredentialResolver::dev(
                "dev-admin-token-not-for-prod",
                crate::token::current_unix_secs_pub(),
            )),
            admin_auth: Arc::new(AdminAuthStoreImpl::Memory(
                crate::adapters::memory::MemoryAdminAuthStore::default(),
            )),
            saas_tenants: Arc::new(vec![]),
            allow_login_placeholder: true, // 本地/测试:允许 login_user 占位
            dcr_mode: DcrMode::Open,       // 本地/测试:open 档便于 e2e
            initial_access_tokens: Arc::new(InitialAccessTokenStoreImpl::Memory(
                MemoryInitialAccessTokenStore::default(),
            )),
            tenant_keys: Arc::new(crate::tenant_keys::TenantKeyService::shared(signer.clone())),
            signer,
            codes: Arc::new(CodeStoreImpl::Memory(MemoryCodeStore::default())),
            clients: Arc::new(ClientStoreImpl::Memory(MemoryClientStore::default())),
            cimd: Arc::new(crate::cimd::CimdResolver::disabled()),
            refresh: Arc::new(RefreshStoreImpl::Memory(MemoryRefreshStore::default())),
            par: Arc::new(ParStoreImpl::Memory(
                crate::adapters::memory::MemoryParStore::default(),
            )),
            // 本地/测试:开宽限窗(内存明文)便于 e2e 验证 C3.2/C3.5。
            grace: Some(Arc::new(
                GraceStoreImpl::Memory(MemoryGraceStore::default()),
            )),
            grace_window_secs: 5,
            sessions: Arc::new(SessionStoreImpl::Memory(dev_sessions)),
            magic_links: Arc::new(MagicLinkStoreImpl::Memory(MemoryMagicLinkStore::default())),
            invitations: Arc::new(InvitationStoreImpl::Memory(dev_invitations)),
            invitation_ttl_secs: 86_400,
            users: Arc::new(UsersStoreImpl::Memory(users_store)),
            attribute_namespaces: Arc::new(AttributeNamespaceStoreImpl::Memory(
                crate::adapters::memory_attribute_namespaces::MemoryAttributeNamespaceStore::default(
                ),
            )),
            attribute_namespace_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            scim_groups: Arc::new(ScimGroupsStoreImpl::Memory(
                crate::adapters::memory::MemoryScimGroupsStore::default(),
            )),
            passwords: Arc::new(PasswordStoreImpl::Memory(dev_passwords)),
            password_workers: Arc::new(tokio::sync::Semaphore::new(2)),
            recovery: Arc::new(RecoveryStoreImpl::Memory(MemoryRecoveryStore::default())),
            // dev:内存 outbox notifier(写 outbox 可观测);notifier 与 messages 共用同一实例
            // (模拟 SES 未接前的消息落库,spec 003 §1.5)。
            notifier: Arc::new(NotifierImpl::Outbox(dev_outbox.clone())),
            messages: Arc::new(MessageOutboxImpl::Memory(dev_outbox)),
            workload_trust: Arc::new(WorkloadTrustStoreImpl::Memory(
                MemoryWorkloadTrustStore::default(),
            )),
            federation_config: Arc::new(FederationConfigStoreImpl::Memory(
                crate::adapters::memory::MemoryFederationConfigStore::default(),
            )),
            federation_attribute_mappings: Arc::new(
                FederationAttributeMappingsStoreImpl::Memory(
                    crate::adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore::default(),
                ),
            ),
            upstream_token_exchanger: Arc::new(UpstreamTokenExchangerImpl::Memory(
                crate::adapters::memory::MemoryUpstreamTokenExchanger::default(),
            )),
            secret_resolver: Arc::new(SecretResolverImpl::Memory(
                crate::adapters::memory::MemorySecretResolver::default(),
            )),
            federation_flow: Arc::new(FederationFlowStoreImpl::Memory(
                crate::adapters::memory::MemoryFederationFlowStore::default(),
            )),
            federation_enabled: false, // dev 默认关;测试用 with_federation 开
            passkey_challenges: Arc::new(PasskeyChallengeStoreImpl::Memory(
                crate::adapters::memory::MemoryPasskeyChallengeStore::default(),
            )),
            passkeys: Arc::new(PasskeyStoreImpl::Memory(
                crate::adapters::memory::MemoryPasskeyStore::default(),
            )),
            passkey_enabled: false,        // dev 默认关;测试显式开
            ciba_ping_push_enabled: false, // dev 默认关;测试/真机 P3 显式开
            ciba_delivery: Arc::new(CibaCallbackDeliveryImpl::Memory(
                crate::adapters::memory::MemoryCibaCallbackDelivery::default(),
            )),
            jwks_fetcher: Arc::new(JwksFetcherImpl::Memory(
                crate::adapters::memory::MemoryJwksFetcher::default(),
            )),
            // dev/测试:开 STS caller(内存 mock)便于 SigV4 路径 e2e;测试用 with_sts 覆盖预置。
            sts_caller: Some(Arc::new(StsCallerImpl::Memory(
                crate::adapters::memory::MemoryStsCaller::default(),
            ))),
            sts_circuit: Arc::new(tokio::sync::Mutex::new(
                agent_auth_workload::CircuitBreaker::default(),
            )),
            // dev/测试:开 replay 缓存(内存)便于 SigV4 重放拒 e2e。
            replay_store: Some(Arc::new(ReplayStoreImpl::Memory(
                crate::adapters::memory::MemoryReplayStore::default(),
            ))),
            grants: Arc::new(GrantStoreImpl::Memory(
                crate::adapters::memory::MemoryGrantStore::default(),
            )),
            domain_map: Arc::new(DomainMapStoreImpl::Memory(
                crate::adapters::memory::MemoryDomainMapStore::default(),
            )),
            byod_enabled: false, // dev 默认关;BYOD e2e 测试用 with_byod 显式开
            mtls_svid_enabled: false, // dev 默认关;X.509-mTLS e2e 测试显式开(仅 SelfHosted)
            ema_enabled: false,  // dev 默认关;EMA e2e 在完整依赖就绪后显式开
            ema_policies: Arc::new(vec![]),
            policy_versions: Arc::new(PolicyVersionStoreImpl::Memory(
                crate::adapters::memory::MemoryPolicyVersionStore::default(),
            )),
            policy_artifacts: Arc::new(PolicyArtifactStoreImpl::Memory(
                crate::adapters::memory::MemoryPolicyArtifactStore::default(),
            )),
            authz_enabled: false, // dev 默认关(个别 authz_e2e 测试内显式开)
            current_pv_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            // dev/测试:开 jti 映射(内存)便于 token-exchange e2e。
            jti_store: Some(Arc::new(JtiStoreImpl::Memory(
                crate::adapters::memory::MemoryJtiStore::default(),
            ))),
            ciba: Arc::new(CibaStoreImpl::Memory(MemoryCibaStore::default())),
            device: Arc::new(DeviceStoreImpl::Memory(MemoryDeviceStore::default())),
            authz_sessions: Arc::new(AuthzSessionStoreImpl::Memory(
                MemoryAuthzSessionStore::default(),
            )),
            authz_events: Arc::new(AuthzEventSinkImpl::Log(LogAuthzEventSink)),
            web_base_url: format!("https://{configured_host}"),
            // dev/测试:开 per-client 令牌桶(内存)便于限流 e2e。
            rate_limit: Some(Arc::new(RateLimitStoreImpl::Memory(
                crate::adapters::memory::MemoryRateLimitStore::default(),
            ))),
        }
    }

    /// 真机:从环境变量构造 AWS-backed 状态(KMS 签名 + DynamoDB 存储)。
    /// 环境变量:`AGENT_AUTH_HOST`(SelfHosted 配置 host)、`SIGNING_KEY_ID`(KMS CMK)、
    /// `CODES_TABLE`/`CLIENTS_TABLE`(DynamoDB 表名)。密钥/表名非敏感(仅标识),账号号不入此。
    #[cfg(feature = "aws")]
    pub async fn from_env_aws() -> Result<Self, String> {
        use crate::adapters::aws::{
            DynamoAuthzSessionStore, DynamoClientStore, DynamoCodeStore, DynamoGraceStore,
            DynamoInitialAccessTokenStore, DynamoInvitationStore, DynamoMagicLinkStore,
            DynamoNotifier, DynamoRecoveryStore, DynamoRefreshStore, DynamoSecurityEventStore,
            DynamoSessionStore, DynamoSsfStore, KmsSigner,
        };
        let key_id = std::env::var("SIGNING_KEY_ID")
            .ok()
            .filter(|value| !value.is_empty());
        // RSA 签名 CMK(RS256 id_token,spec 001 C2.7);可选——未配则无法签 RS256 id_token(降级)。
        let rsa_key_id = std::env::var("RSA_SIGNING_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty());
        // 轮换发布集(spec 005 §8 / C10.11b):全部**已发布** key ARN 逗号分隔(含活跃 + publish-ahead 新 + retiring 旧)。
        // 未配 → 退化为仅活跃(现状字节等价)。运维分阶段改此 env 编排三相轮换 / 紧急吊销。
        let published_ec_csv = std::env::var("SIGNING_KEY_IDS_PUBLISHED")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let published_rsa_csv = std::env::var("RSA_SIGNING_KEY_IDS_PUBLISHED")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let configured_form = std::env::var("AGENT_AUTH_FORM").ok();
        let form = resolve_deployment_form(
            configured_form.as_deref(),
            std::env::var("AGENT_AUTH_HOST").ok(),
            std::env::var("AGENT_AUTH_ZONE").ok(),
            std::env::var("AGENT_AUTH_CONTROL_HOST").ok(),
        )?;
        let scope = std::env::var("SCOPE").ok();
        let worker = std::env::var("WORKER").ok();
        let codes_table = std::env::var("CODES_TABLE").map_err(|_| "缺 CODES_TABLE")?;
        let clients_table = std::env::var("CLIENTS_TABLE").map_err(|_| "缺 CLIENTS_TABLE")?;
        let initial_access_tokens_table = std::env::var("INITIAL_ACCESS_TOKENS_TABLE")
            .map_err(|_| "缺 INITIAL_ACCESS_TOKENS_TABLE")?;
        let refresh_table = std::env::var("REFRESH_TABLE").map_err(|_| "缺 REFRESH_TABLE")?;
        let client_authority_refs_table =
            std::env::var("AUTH_REFS_TABLE").map_err(|_| "缺 AUTH_REFS_TABLE")?;
        // PAR 表(spec 006 §7.3)。可选:未配 → 内存(PAR 仅 P3 可达;真机 P3 栈须配 PAR_TABLE)。
        let par_table = std::env::var("PAR_TABLE").ok().filter(|s| !s.is_empty());
        let sessions_table = std::env::var("SESSIONS_TABLE").map_err(|_| "缺 SESSIONS_TABLE")?;
        let magic_table = std::env::var("MAGICLINK_TABLE").map_err(|_| "缺 MAGICLINK_TABLE")?;
        let invitations_table =
            std::env::var("INVITATIONS_TABLE").map_err(|_| "缺 INVITATIONS_TABLE")?;
        let invitation_ttl_secs = match std::env::var("AGENT_AUTH_INVITATION_TTL_SECS") {
            Ok(value) => value
                .parse::<i64>()
                .ok()
                .filter(|seconds| (300..=604_800).contains(seconds))
                .ok_or("AGENT_AUTH_INVITATION_TTL_SECS 必须是 300..=604800 秒")?,
            Err(_) => 86_400,
        };
        let users_table = std::env::var("USERS_TABLE").map_err(|_| "缺 USERS_TABLE")?;
        let attribute_namespaces_table = std::env::var("ATTRIBUTE_NAMESPACES_TABLE")
            .ok()
            .filter(|value| !value.is_empty());
        let scim_groups_table =
            std::env::var("SCIM_GROUPS_TABLE").map_err(|_| "缺 SCIM_GROUPS_TABLE")?;
        let admin_auth_table =
            std::env::var("ADMIN_AUTH_TABLE").map_err(|_| "缺 ADMIN_AUTH_TABLE")?;
        let admin_auth_runtime_table =
            std::env::var("ADMIN_AUTH_RUNTIME_TABLE").map_err(|_| "缺 ADMIN_AUTH_RUNTIME_TABLE")?;
        let governance_table =
            std::env::var("GOVERNANCE_TABLE").map_err(|_| "缺 GOVERNANCE_TABLE")?;
        let governance_suppression_table = std::env::var("GOVERNANCE_SUPPRESSION_TABLE")
            .map_err(|_| "缺 GOVERNANCE_SUPPRESSION_TABLE")?;
        let governance_queue_url = std::env::var("GOVERNANCE_QUEUE_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let password_credentials_table = std::env::var("PASSWORD_CREDENTIALS_TABLE")
            .map_err(|_| "缺 PASSWORD_CREDENTIALS_TABLE")?;
        let password_worker_count = match std::env::var("AGENT_AUTH_PASSWORD_WORKERS") {
            Ok(value) => value
                .parse::<usize>()
                .ok()
                .filter(|count| (1..=8).contains(count))
                .ok_or("AGENT_AUTH_PASSWORD_WORKERS 必须是 1..=8")?,
            Err(_) => 2,
        };
        let strong_max_age_secs = match std::env::var("AGENT_AUTH_STRONG_MAX_AGE_SECS") {
            Ok(value) => value
                .parse::<i64>()
                .map_err(|_| "AGENT_AUTH_STRONG_MAX_AGE_SECS 必须是整数秒")?,
            Err(_) => 300,
        };
        let configured_actions = |name: &str, default: &[&str]| -> Result<Vec<String>, String> {
            match std::env::var(name) {
                Ok(value) if value.trim().is_empty() => Ok(Vec::new()),
                Ok(value) => Ok(value.split(',').map(str::to_string).collect()),
                Err(_) => Ok(default.iter().map(|value| (*value).to_string()).collect()),
            }
        };
        let assurance_policy = agent_auth_authn::assurance::AssurancePolicy::new(
            strong_max_age_secs,
            configured_actions("AGENT_AUTH_HIGH_RISK_RAR_ACTIONS", &["transfer"])?,
            configured_actions("AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS", &["access.manage"])?,
        )
        .map_err(|error| format!("assurance policy 配置非法: {error}"))?;
        let recovery_table = std::env::var("RECOVERY_TABLE").map_err(|_| "缺 RECOVERY_TABLE")?;
        let authz_sessions_table =
            std::env::var("AUTHZ_SESSIONS_TABLE").map_err(|_| "缺 AUTHZ_SESSIONS_TABLE")?;
        // messages 表(SES 未接前的消息 outbox 模拟,TTL=1 天;spec 003 §1.5)。
        let messages_table = std::env::var("MESSAGES_TABLE").map_err(|_| "缺 MESSAGES_TABLE")?;
        // Security event 权威入口必须持久化；生产禁止静默回落到单实例内存。
        let security_events_table =
            std::env::var("SECURITY_EVENTS_TABLE").map_err(|_| "缺 SECURITY_EVENTS_TABLE")?;
        // SSF receiver registry + delivery outbox is authoritative production
        // state. A per-process memory fallback would lose subscriptions,
        // retries, and revocations across Lambda instances.
        let ssf_deliveries_table =
            std::env::var("SSF_DELIVERIES_TABLE").map_err(|_| "缺 SSF_DELIVERIES_TABLE")?;
        let ssf_management_enabled = match std::env::var("AGENT_AUTH_SSF_MANAGEMENT_ENABLED") {
            Ok(value) if value == "1" => true,
            Ok(value) if value == "0" => false,
            Ok(_) => {
                return Err("AGENT_AUTH_SSF_MANAGEMENT_ENABLED must be exactly 0 or 1".to_string())
            }
            Err(std::env::VarError::NotPresent) => true,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("AGENT_AUTH_SSF_MANAGEMENT_ENABLED must be UTF-8".to_string())
            }
        };
        let security_event_ingress_queue_url = std::env::var("SECURITY_EVENT_INGRESS_QUEUE_URL")
            .map_err(|_| "缺 SECURITY_EVENT_INGRESS_QUEUE_URL")?;
        // workload 信任绑定表(spec 012 C5.5)。
        let workload_trust_table =
            std::env::var("WORKLOAD_TRUST_TABLE").map_err(|_| "缺 WORKLOAD_TRUST_TABLE")?;
        // 联邦配置表(spec 003 §4)。**可选**:未配则内存(联邦 P1b 后端契约,callback 未上架时不强制建表)。
        let federation_config_table = std::env::var("FEDERATION_CONFIG_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        // 联邦 flow 状态表(spec 003 §4;短命 state/nonce/续跑上下文)。可选,未配则内存。
        let federation_flow_table = std::env::var("FEDERATION_FLOW_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        // 联邦登录功能开关(F10):默认关;仅 AGENT_AUTH_FEDERATION_ENABLED=1 显式开(e2e 全绿后)。
        let federation_enabled =
            std::env::var("AGENT_AUTH_FEDERATION_ENABLED").as_deref() == Ok("1");
        // passkey challenge/凭证表(spec 003 §3)。可选,未配则内存。
        let passkey_challenge_table = std::env::var("PASSKEY_CHALLENGE_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        let passkey_table = std::env::var("PASSKEY_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        // passkey 登录功能开关(F10):默认关;仅 AGENT_AUTH_PASSKEY_ENABLED=1 显式开(e2e 全绿后)。
        let passkey_enabled = std::env::var("AGENT_AUTH_PASSKEY_ENABLED").as_deref() == Ok("1");
        // fail-closed(评审 Kiro L2):启用 passkey 但漏配任一表 → 拒启动。否则真机 Lambda 会静默回落
        // **每实例内存 store**——凭证不持久、challenge 在 A 实例写 B 实例查不到,静默坏(偶发 400)而非 fail-fast。
        if passkey_enabled && (passkey_table.is_none() || passkey_challenge_table.is_none()) {
            return Err(
                "AGENT_AUTH_PASSKEY_ENABLED=1 但缺 PASSKEY_TABLE / PASSKEY_CHALLENGE_TABLE\
                 (Lambda 内存回落会使凭证不持久 + challenge 跨实例丢失,fail-closed 拒启动)"
                    .into(),
            );
        }
        // CIBA / device 授权表(spec 013)。
        let ciba_table = std::env::var("CIBA_TABLE").map_err(|_| "缺 CIBA_TABLE")?;
        let device_table = std::env::var("DEVICE_TABLE").map_err(|_| "缺 DEVICE_TABLE")?;
        // Grant 授权记录表(spec 011 §5.1;P2)。可选:未配则内存(P2 未启用 Grant 权威源时不建表)。
        let grants_table = std::env::var("GRANTS_TABLE").ok().filter(|s| !s.is_empty());
        // BYOD 域名映射表(spec 010 §5.4 / C8.1b;全局键 pk=domain,非 tenant 分区)。未配 → 内存(BYOD 未启用)。
        let domain_map_table = std::env::var("DOMAIN_MAP_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        // fail-closed(评审:同 passkey_enabled 漏表):启用 BYOD 但缺 DOMAIN_MAP_TABLE → 拒启动。否则真机 Lambda
        // 静默回落**每实例内存 map**——登记在 A 实例、well-known 查在 B 实例丢命中,BYOD PRM 静默坏(偶发 404)。
        if std::env::var("AGENT_AUTH_BYOD_ENABLED").as_deref() == Ok("1")
            && domain_map_table.is_none()
        {
            return Err("AGENT_AUTH_BYOD_ENABLED=1 但缺 DOMAIN_MAP_TABLE\
                 (Lambda 内存回落会使域名绑定跨实例丢失,fail-closed 拒启动)"
                .into());
        }
        // 发布阶段(C1.2):`AGENT_AUTH_PHASE` 显式配置,**缺省/无法识别 → fail-safe 回落 P1**
        // (不因误配意外过度暴露 P2/P3 面)。所有 P2 grant(client_credentials/token-exchange/
        // device/CIBA)已落地后可配 P2 使其可达 + discovery 如实宣告(公理 1)。
        let phase = std::env::var("AGENT_AUTH_PHASE")
            .ok()
            .and_then(|s| Phase::from_env_str(&s))
            .unwrap_or(Phase::P1);
        // jti→主体映射表(spec 011 C7.8;token-exchange subject 解析)。短命 TTL。**可选**:未配 = 不落映射
        // (P1 无 token-exchange 消费者时避免死写;P2 启用 token-exchange 时经 CDK 注入 JTI_TABLE)。
        // replay_store 复用此表(pk 前缀隔离)。
        let jti_table = std::env::var("JTI_TABLE").ok().filter(|s| !s.is_empty());
        let ema_enabled = std::env::var("AGENT_AUTH_EMA_ENABLED").as_deref() == Ok("1");
        // **P3 DPoP 启动守卫(评审 M2)**:Phase≥P3 时 DPoP proof 校验依赖 replay_store(jti 重放,B2),
        // 未配 JTI_TABLE 会使**所有** DPoP proof 被 fail-closed 全拒(静默坏:client 带 proof 反被拒)。
        // fail-fast 拒启动,而非上线后静默拒签——把配置错误暴露在部署期(与 passkey_enabled 漏表 fail-fast 同理)。
        if phase.at_least(Phase::P3) && jti_table.is_none() {
            return Err(
                "Phase≥P3(DPoP 启用)但缺 JTI_TABLE(DPoP proof 重放去重依赖 replay_store;\
                        未配会使所有 DPoP proof 被 fail-closed 全拒)——fail-fast 拒启动"
                    .into(),
            );
        }
        if ema_enabled && !phase.at_least(Phase::P2) {
            return Err("AGENT_AUTH_EMA_ENABLED=1 requires AGENT_AUTH_PHASE=p2 or later".into());
        }
        if ema_enabled && jti_table.is_none() {
            return Err(
                "AGENT_AUTH_EMA_ENABLED=1 requires JTI_TABLE for assertion replay and access-token identity mapping"
                    .into(),
            );
        }
        // per-client 限流令牌桶(C10.7):配了 RATE_LIMIT_TABLE 才启用;缺 → None(fail-open,不限流)。
        let rate_limit_table = std::env::var("RATE_LIMIT_TABLE")
            .ok()
            .filter(|s| !s.is_empty());
        // 宽限窗缓存(C3.2/C3.4):表 + 信封加密 CMK 都配齐才启用;缺任一 → None(fail-closed,
        // 非当前版本一律按复用处理)。GRACE_KMS_KEY_ID = SYMMETRIC_DEFAULT CMK(GenerateDataKey/Decrypt)。
        let grace_table = std::env::var("GRACE_TABLE").ok().filter(|s| !s.is_empty());
        let grace_kms_key = std::env::var("GRACE_KMS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty());
        // CIBA notification token 必须使用独立 CMK。禁止回落 grace key,否则非 token CIBA 路径会把
        // C3.4 的 grace Decrypt 权限重新带回主 AuthFn。
        let ciba_notification_kms_key = std::env::var("CIBA_KMS")
            .or_else(|_| std::env::var("CIBA_NOTIFICATION_KMS_KEY_ID"))
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or("缺 CIBA_KMS(CIBA 通知 token 需要独立对称 CMK)")?;
        // 浏览器回跳必须显式指向统一前端 origin。不能回落 issuer/API Gateway host:
        // __Host- nonce cookie 是 host-only,跨 host callback 会稳定触发 login-CSRF。
        let web_base_url = validate_web_base_url(std::env::var("WEB_BASE_URL").ok().as_deref())?;

        let conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let kms = aws_sdk_kms::Client::new(&conf);
        let db = aws_sdk_dynamodb::Client::new(&conf);
        let sqs = aws_sdk_sqs::Client::new(&conf);
        let runtime_bootstrap_config = load_runtime_bootstrap_config(&conf).await?;
        let federation_attribute_mappings_table = match scope.as_deref() {
            Some("non_token") if matches!(form, Form::SelfHosted { .. }) => {
                std::env::var("FEDERATION_ATTRIBUTE_MAPPINGS_TABLE")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        runtime_bootstrap_config
                            .as_ref()
                            .and_then(|config| config.federation_attribute_mappings_table.clone())
                    })
            }
            _ if worker.as_deref() == Some("governance") => runtime_bootstrap_config
                .as_ref()
                .and_then(|config| config.federation_attribute_mappings_table.clone()),
            _ => None,
        };
        if matches!(form, Form::SelfHosted { .. })
            && scope.as_deref() == Some("non_token")
            && (attribute_namespaces_table.is_none()
                || federation_attribute_mappings_table.is_none())
        {
            return Err(
                "SelfHosted non_token runtime 缺 ATTRIBUTE_NAMESPACES_TABLE / FEDERATION_ATTRIBUTE_MAPPINGS_TABLE"
                    .to_string(),
            );
        }
        if worker.as_deref() == Some("governance") && federation_attribute_mappings_table.is_none()
        {
            return Err(
                "governance worker bootstrap 缺 federation_attribute_mappings_table".to_string(),
            );
        }
        let saas_origin_auth = if matches!(form, Form::Saas { .. }) {
            let primary_arn = runtime_bootstrap_config
                .as_ref()
                .and_then(|config| config.passkey_origin_secret_arn.as_deref())
                .ok_or("SaaS runtime bootstrap is missing the primary origin Secret ARN")?;
            let secondary_name = secondary_origin_secret_name(primary_arn)?;
            let primary =
                load_secret_string(&conf, primary_arn, "primary SaaS origin auth Secret").await?;
            let secondary = load_secret_string_by_id(
                &conf,
                &secondary_name,
                "secondary SaaS origin auth Secret",
            )
            .await?;
            Arc::new(crate::origin_auth::SaasOriginAuth::required(
                primary, secondary,
            )?)
        } else {
            Arc::new(crate::origin_auth::SaasOriginAuth::development_bypass())
        };
        let governance_retention_config =
            match std::env::var("GOVERNANCE_RETENTION_CONFIG_SECRET_ARN")
                .ok()
                .filter(|value| !value.is_empty())
            {
                Some(secret_arn) => Some(
                    load_secret_string(&conf, &secret_arn, "governance retention config Secret")
                        .await?,
                ),
                None => std::env::var("GOVERNANCE_RETENTION_CONFIG")
                    .ok()
                    .filter(|value| !value.trim().is_empty()),
            };
        let region = match crate::region::resolve_control_region(
            std::env::var("AGENT_AUTH_REGION_ID")
                .ok()
                .filter(|value| !value.is_empty()),
            std::env::var("AWS_REGION")
                .ok()
                .filter(|value| !value.is_empty()),
            std::env::var("REGION_CONTROL_TABLE")
                .ok()
                .filter(|value| !value.is_empty()),
        )? {
            None => {
                let local_region = std::env::var("AWS_REGION")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .ok_or("single-Region AWS runtime requires AWS_REGION")?;
                crate::region::RegionRuntime::single_region_in(local_region)?
            }
            Some((region_id, table)) => crate::region::RegionRuntime::controlled(
                region_id,
                crate::region::RegionControlStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoRegionControlStore::new(db.clone(), table),
                ),
            )?,
        };

        // 授权会话事件投影 sink(spec 004 §3.3 / C6.5):配了 AUTHZ_EVENT_BUS → EventBridge 真发投影;
        // 未配 → Noop(fail-safe:投影是可观测旁路,缺 bus 时不发,权威源仍是 DynamoDB 会话记录)。
        let authz_event_sink = match std::env::var("AUTHZ_EVENT_BUS")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(bus) => AuthzEventSinkImpl::EventBridge(
                crate::adapters::aws::EventBridgeAuthzEventSink::new(
                    aws_sdk_eventbridge::Client::new(&conf),
                    bus,
                ),
            ),
            None => AuthzEventSinkImpl::Noop(crate::adapters::aws::NoopAuthzEventSink),
        };

        // 宽限缓存 store(表 + CMK 齐才装配;共用 kms/db 客户端)。
        let grace =
            match (grace_table, grace_kms_key) {
                (Some(t), Some(k)) => Some(Arc::new(GraceStoreImpl::Dynamo(
                    DynamoGraceStore::new(db.clone(), kms.clone(), t, k),
                ))),
                (Some(t), None) => Some(Arc::new(GraceStoreImpl::Dynamo(
                    DynamoGraceStore::new_delete_only(db.clone(), kms.clone(), t),
                ))),
                (None, _) => None,
            };

        let ciba_kms = kms.clone();
        let ciba_enc_key = ciba_notification_kms_key;

        let signer = match &form {
            Form::Saas { .. } => Arc::new(SignerImpl::Unavailable),
            Form::SelfHosted { .. } => Arc::new(SignerImpl::Kms(
                KmsSigner::new(
                    kms.clone(),
                    key_id.ok_or("SelfHosted 缺 SIGNING_KEY_ID")?,
                    rsa_key_id,
                    published_ec_csv,
                    published_rsa_csv,
                )
                .await
                .map_err(|e| format!("KmsSigner: {e:?}"))?,
            )),
        };

        // 消息 outbox notifier(messages 表);notifier 写端与 messages 读端共用同一实例。
        let dyn_notifier = DynamoNotifier::new(db.clone(), messages_table);

        // 🔴 login_user 占位默认**关**;仅当显式设 AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER=1 才开
        // (真机 e2e 用,生产 CDK 栈 MUST NOT 设此变量)。防占位认证绕过被误部署。
        let allow_login_placeholder =
            std::env::var("AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER").as_deref() == Ok("1");

        // 🔴 server_secret(magic-link tag + CSRF HMAC)MUST 从环境注入,**缺失即拒启动**(fail-closed,
        // 评审 HIGH:防真机静默回落公开 dev 常量)。真机由 CDK 从 Secrets Manager 注入 SERVER_SECRET;
        // 仅当显式 AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER=1(dev 栈)才允许缺失时用 dev 常量兜底(便于 e2e)。
        let server_secret = match std::env::var("SERVER_SECRET") {
            Ok(s) if !s.is_empty() => s.into_bytes(),
            _ if allow_login_placeholder => {
                eprintln!("⚠️  SERVER_SECRET 未设,dev 栈用不安全默认值(仅 e2e;生产 MUST 设)");
                b"dev-server-secret-not-for-prod".to_vec()
            }
            _ => {
                return Err(
                    "SERVER_SECRET 未设——生产 MUST 从 Secrets Manager 注入(fail-closed)".into(),
                )
            }
        };

        // Admin bearer 明文不再进入 Lambda env。平台与逐租户环境变量只保存 Secret ARN，
        // SecretString 在认证时按有界 TTL 从 Secrets Manager 刷新。
        let platform_admin_secret_ref = match &runtime_bootstrap_config {
            Some(config) => config.admin_credential_secret_arn.clone(),
            None => std::env::var("ADMIN_CREDENTIAL_SECRET_ARN")
                .ok()
                .filter(|value| !value.is_empty()),
        };
        let admin_credential_cache_ttl_secs = match std::env::var("ADMIN_CREDENTIAL_CACHE_TTL_SECS")
        {
            Ok(value) => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "ADMIN_CREDENTIAL_CACHE_TTL_SECS 必须是正整数秒".to_string())?;
                if parsed == 0
                    || parsed > crate::admin_credentials::MAX_ADMIN_CREDENTIAL_CACHE_TTL_SECS
                {
                    return Err(format!(
                        "ADMIN_CREDENTIAL_CACHE_TTL_SECS 必须在 1..={} 秒",
                        crate::admin_credentials::MAX_ADMIN_CREDENTIAL_CACHE_TTL_SECS
                    ));
                }
                parsed
            }
            Err(_) => crate::admin_credentials::DEFAULT_ADMIN_CREDENTIAL_CACHE_TTL_SECS,
        };
        let saas_tenants: Vec<String> = match &runtime_bootstrap_config {
            Some(config) => config.saas_tenants.clone(),
            None => match std::env::var("SAAS_TENANTS") {
                Ok(s) if !s.is_empty() => {
                    serde_json::from_str(&s).map_err(|e| format!("SAAS_TENANTS 非法 JSON:{e}"))?
                }
                _ => vec![],
            },
        };
        let tenant_admin_secret_refs: std::collections::HashMap<String, String> =
            match &runtime_bootstrap_config {
                Some(config) => config.tenant_admin_secret_arns.clone(),
                None => match std::env::var("TENANT_ADMIN_SECRET_ARNS") {
                    Ok(s) if !s.is_empty() => serde_json::from_str(&s)
                        .map_err(|e| format!("TENANT_ADMIN_SECRET_ARNS 非法 JSON:{e}"))?,
                    _ => std::collections::HashMap::new(),
                },
            };
        let self_hosted_scim_secret_ref = match &runtime_bootstrap_config {
            Some(config) => config.scim_credential_secret_arn.clone(),
            None => std::env::var("SCIM_CREDENTIAL_SECRET_ARN")
                .ok()
                .filter(|value| !value.is_empty()),
        };
        let configured_scim_tenant_secret_refs: std::collections::HashMap<String, String> =
            match &runtime_bootstrap_config {
                Some(config) => config.scim_tenant_secret_arns.clone(),
                None => match std::env::var("SCIM_TENANT_SECRET_ARNS") {
                    Ok(s) if !s.is_empty() => serde_json::from_str(&s)
                        .map_err(|e| format!("SCIM_TENANT_SECRET_ARNS 非法 JSON:{e}"))?,
                    _ => std::collections::HashMap::new(),
                },
            };

        // DCR 准入档(§3.2/C4.3):优先级链(评审 Kiro F1)——
        //   显式 AGENT_AUTH_DCR_MODE > 旧 AGENT_AUTH_DCR_OPEN=1(向后兼容 dev 栈) > 缺省 fail-closed(收紧档)。
        // 非法 AGENT_AUTH_DCR_MODE 值 → **拒启动**(不静默回落)。
        let dcr_mode = match std::env::var("AGENT_AUTH_DCR_MODE") {
            Ok(s) if !s.is_empty() => DcrMode::from_env_str(&s)
                .ok_or_else(|| format!("AGENT_AUTH_DCR_MODE 非法值 '{s}'(open/initial_access_token/software_statement)"))?,
            _ if std::env::var("AGENT_AUTH_DCR_OPEN").as_deref() == Ok("1") => DcrMode::Open,
            _ => DcrMode::InitialAccessToken, // fail-closed 缺省:收紧到凭票注册
        };
        if dcr_mode == DcrMode::SoftwareStatement {
            eprintln!(
                "AGENT_AUTH_DCR_MODE=software_statement is not implemented; /register fails closed"
            );
        }

        // db 在下方 authz_sessions 处 move;限流 store 若启用需在此前克隆一份句柄。
        let db_ratelimit = db.clone();

        let tenant_keys = match &form {
            Form::Saas { .. } => {
                let table = std::env::var("TENANT_KEYS_TABLE")
                    .map_err(|_| "AGENT_AUTH_FORM=saas 须配 TENANT_KEYS_TABLE")?;
                let registry =
                    crate::adapters::aws::DynamoTenantKeyRegistry::new(db.clone(), table);
                let service = if std::env::var("AGENT_AUTH_TENANT_KEY_COMMANDS_DISABLED").as_deref()
                    == Ok("1")
                {
                    crate::tenant_keys::TenantKeyService::dynamo_readonly(registry, kms.clone())
                } else {
                    let queue_url = std::env::var("TENANT_KEY_OPERATIONS_QUEUE_URL")
                        .map_err(|_| "AGENT_AUTH_FORM=saas 须配 TENANT_KEY_OPERATIONS_QUEUE_URL")?;
                    crate::tenant_keys::TenantKeyService::dynamo(
                        registry,
                        crate::adapters::aws::SqsTenantKeyCommandSink::new(sqs.clone(), queue_url),
                        kms.clone(),
                    )
                };
                Arc::new(service.with_region(region.clone()))
            }
            Form::SelfHosted { .. } => {
                Arc::new(crate::tenant_keys::TenantKeyService::shared(signer.clone()))
            }
        };
        // SelfHosted 可通过 deployment-level env 覆盖；SaaS 必须使用 versioned bootstrap
        // 中的逐租户 profile，未覆盖租户固定回落 pairwise。
        let subject_type_override = std::env::var("AGENT_AUTH_SUBJECT_TYPE").ok();
        validate_subject_type_override(subject_type_override.as_deref(), &form)?;
        let subject_type = resolve_subject_type(subject_type_override.as_deref(), &form);
        let configured_tenant_subject_types = runtime_bootstrap_config
            .as_ref()
            .map(|config| config.tenant_subject_types.clone())
            .unwrap_or_default();
        let tenant_subject_types =
            resolve_tenant_subject_types(&configured_tenant_subject_types, &form, &saas_tenants)?;
        let configured_redirect_prefix_allowed_hosts = runtime_bootstrap_config
            .as_ref()
            .map(|config| config.redirect_prefix_allowed_hosts.clone())
            .unwrap_or_default();
        let redirect_prefix_allowed_hosts = resolve_redirect_prefix_allowed_hosts(
            &configured_redirect_prefix_allowed_hosts,
            &form,
            &saas_tenants,
        )?;
        // **数据面 tenant 分区开关**(§2.3,默认关;全 store 就绪 + SaaS 部署才开)。SaaS 形态下强烈建议开
        // (否则多租户共享分区=跨租户越权),但仍由 env 显式控制以支持"Saas 路由灰度、分区未就绪"过渡。
        let tenant_partitioning = std::env::var("AGENT_AUTH_ENABLE_TENANT_PARTITIONING")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        validate_passkey_tenant_isolation(&form, passkey_enabled, tenant_partitioning)?;

        let cimd_enabled = std::env::var("AGENT_AUTH_CIMD_ENABLED").as_deref() == Ok("1");
        if cimd_enabled && matches!(form, Form::Saas { .. }) && !tenant_partitioning {
            return Err(
                "AGENT_AUTH_CIMD_ENABLED=1 in SaaS requires tenant partitioning".to_string(),
            );
        }
        let cimd_global_domains = std::env::var("AGENT_AUTH_CIMD_ALLOWED_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let cimd_tenant_domains: std::collections::HashMap<String, Vec<String>> =
            match std::env::var("AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS") {
                Ok(value) if !value.trim().is_empty() => {
                    serde_json::from_str(&value).map_err(|error| {
                        format!("AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS invalid JSON: {error}")
                    })?
                }
                _ => std::collections::HashMap::new(),
            };
        if matches!(form, Form::Saas { .. })
            && cimd_tenant_domains
                .keys()
                .any(|tenant| !saas_tenants.contains(tenant))
        {
            return Err(
                "CIMD tenant domain policy contains a tenant outside SAAS_TENANTS".to_string(),
            );
        }
        let cimd_policy =
            crate::cimd::CimdTrustPolicy::new(cimd_global_domains, cimd_tenant_domains)?;
        let cimd = crate::cimd::CimdResolver::new(
            cimd_enabled,
            cimd_policy,
            Arc::new(crate::cimd::HttpCimdHttpClient),
        )?;

        if platform_admin_secret_ref
            .as_deref()
            .is_some_and(|secret_ref| !is_secrets_manager_arn(secret_ref))
        {
            return Err("ADMIN_CREDENTIAL_SECRET_ARN 必须是合法 Secrets Manager ARN".into());
        }

        let scim_tenant_secret_refs;
        if matches!(form, Form::Saas { .. }) {
            use std::collections::HashSet;

            let tenant_set: HashSet<&str> = saas_tenants.iter().map(String::as_str).collect();
            if saas_tenants.is_empty()
                || tenant_set.len() != saas_tenants.len()
                || saas_tenants.iter().any(|tenant| {
                    tenant.is_empty()
                        || agent_auth_discovery::issuer_for_tenant(&form, tenant).is_err()
                })
            {
                return Err("SAAS_TENANTS 必须是非空、无重复且可重建 issuer 的租户标签数组".into());
            }
            let arn_tenants: HashSet<&str> = tenant_admin_secret_refs
                .keys()
                .map(String::as_str)
                .collect();
            if arn_tenants != tenant_set {
                return Err(
                    "SaaS 租户注册表与 TENANT_ADMIN_SECRET_ARNS 的 tenant 集合必须完全一致".into(),
                );
            }
            let unique_arns: HashSet<&str> = tenant_admin_secret_refs
                .values()
                .map(String::as_str)
                .collect();
            if unique_arns.len() != tenant_admin_secret_refs.len()
                || tenant_admin_secret_refs.values().any(|arn| {
                    arn.is_empty() || !arn.contains(":secretsmanager:") || !arn.contains(":secret:")
                })
            {
                return Err("SaaS 每租户 admin Secret ARN 必须非空、合法且互不相同".into());
            }
            let platform_ref = platform_admin_secret_ref
                .as_deref()
                .ok_or("SaaS 必须配置独立 ADMIN_CREDENTIAL_SECRET_ARN")?;
            if tenant_admin_secret_refs
                .values()
                .any(|tenant_ref| tenant_ref == platform_ref)
            {
                return Err("SaaS 平台与租户 admin 必须使用不同 Secret ARN".into());
            }
            if self_hosted_scim_secret_ref.is_some() {
                return Err("SaaS 不得配置 SCIM_CREDENTIAL_SECRET_ARN".into());
            }
            let scim_tenants: HashSet<&str> = configured_scim_tenant_secret_refs
                .keys()
                .map(String::as_str)
                .collect();
            if scim_tenants != tenant_set {
                return Err(
                    "SaaS 租户注册表与 SCIM_TENANT_SECRET_ARNS 的 tenant 集合必须完全一致".into(),
                );
            }
            scim_tenant_secret_refs = configured_scim_tenant_secret_refs;
        } else if !tenant_admin_secret_refs.is_empty() || !saas_tenants.is_empty() {
            return Err("SelfHosted 不得配置 SAAS_TENANTS 或 TENANT_ADMIN_SECRET_ARNS".into());
        } else {
            if !configured_scim_tenant_secret_refs.is_empty() {
                return Err("SelfHosted 不得配置 SCIM_TENANT_SECRET_ARNS".into());
            }
            let secret_ref = self_hosted_scim_secret_ref
                .ok_or("SelfHosted 必须配置 SCIM_CREDENTIAL_SECRET_ARN")?;
            scim_tenant_secret_refs =
                std::collections::HashMap::from([("default".to_string(), secret_ref)]);
        }

        {
            use std::collections::HashSet;

            let scim_arns: HashSet<&str> = scim_tenant_secret_refs
                .values()
                .map(String::as_str)
                .collect();
            if scim_arns.len() != scim_tenant_secret_refs.len()
                || scim_tenant_secret_refs.values().any(|arn| {
                    arn.is_empty() || !arn.contains(":secretsmanager:") || !arn.contains(":secret:")
                })
            {
                return Err("每租户 SCIM Secret ARN 必须非空、合法且互不相同".into());
            }
            let mut all_arns: HashSet<&str> = HashSet::new();
            if let Some(platform) = platform_admin_secret_ref.as_deref() {
                all_arns.insert(platform);
            }
            for arn in tenant_admin_secret_refs.values() {
                if !all_arns.insert(arn) {
                    return Err("平台、tenant Admin 与 SCIM target Secret ARN 必须全部互异".into());
                }
            }
            for arn in scim_tenant_secret_refs.values() {
                if !all_arns.insert(arn) {
                    return Err("平台、tenant Admin 与 SCIM target Secret ARN 必须全部互异".into());
                }
            }
        }
        let inline_ema_policy_json = std::env::var("AGENT_AUTH_EMA_POLICIES")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let ema_policy_secret_arn = std::env::var("AGENT_AUTH_EMA_POLICIES_SECRET_ARN")
            .ok()
            .filter(|value| !value.is_empty());
        if inline_ema_policy_json.is_some() && ema_policy_secret_arn.is_some() {
            return Err("EMA policy must use exactly one of inline JSON or Secrets Manager".into());
        }
        let ema_policy_json = match ema_policy_secret_arn {
            Some(secret_arn) => {
                Some(load_secret_string(&conf, &secret_arn, "EMA policies Secret").await?)
            }
            None => inline_ema_policy_json,
        };
        let ema_policies = crate::ema_flow::parse_tenant_policies(
            ema_policy_json.as_deref(),
            &form,
            &saas_tenants,
        )?;
        if ema_enabled && ema_policies.is_empty() {
            return Err("AGENT_AUTH_EMA_ENABLED=1 requires non-empty EMA policies".into());
        }
        if ema_enabled && matches!(form, Form::Saas { .. }) && !tenant_partitioning {
            return Err(
                "AGENT_AUTH_EMA_ENABLED=1 in SaaS requires AGENT_AUTH_ENABLE_TENANT_PARTITIONING=1"
                    .into(),
            );
        }

        let governance_hmac_key = match &runtime_bootstrap_config {
            Some(config) => {
                load_secret_string(
                    &conf,
                    &config.governance_hmac_secret_arn,
                    "governance HMAC Secret",
                )
                .await?
            }
            None => std::env::var("GOVERNANCE_HMAC_KEY")
                .map_err(|_| "GOVERNANCE_HMAC_KEY must contain at least 32 bytes")?,
        };
        if governance_hmac_key.len() < 32 {
            return Err("governance HMAC Secret must contain at least 32 bytes".into());
        }
        let governance_hmac_key = governance_hmac_key.into_bytes();
        if governance_hmac_key == server_secret {
            return Err("GOVERNANCE_HMAC_KEY must be independent from SERVER_SECRET".into());
        }
        let governance_tenants = match &form {
            Form::Saas { .. } => saas_tenants.clone(),
            Form::SelfHosted { .. } => vec!["default".to_string()],
        };
        let mut tenant_secret_references: std::collections::BTreeMap<
            String,
            Vec<crate::governance::GovernanceSecretReference>,
        > = match &runtime_bootstrap_config {
            Some(config) => config.tenant_secret_dependencies.clone(),
            None => match std::env::var("TENANT_SECRET_DEPENDENCIES") {
                Ok(value) if !value.is_empty() => serde_json::from_str(&value)
                    .map_err(|error| format!("TENANT_SECRET_DEPENDENCIES 非法 JSON: {error}"))?,
                _ => std::collections::BTreeMap::new(),
            },
        };
        if tenant_secret_references
            .keys()
            .any(|tenant| !governance_tenants.contains(tenant))
        {
            return Err(
                "TENANT_SECRET_DEPENDENCIES may contain only configured issuer tenants".into(),
            );
        }
        for tenant in &governance_tenants {
            let references = tenant_secret_references.entry(tenant.clone()).or_default();
            let runtime_refs = [
                tenant_admin_secret_refs
                    .get(tenant)
                    .map(|secret_ref| ("tenant_admin", secret_ref)),
                scim_tenant_secret_refs
                    .get(tenant)
                    .map(|secret_ref| ("scim", secret_ref)),
            ];
            for (purpose, secret_ref) in runtime_refs.into_iter().flatten() {
                if !references
                    .iter()
                    .any(|reference| reference.secret_ref == *secret_ref)
                {
                    references.push(
                        crate::governance::GovernanceSecretReference::historical_external(
                            purpose, secret_ref,
                        ),
                    );
                }
            }
            let mut normalized = Vec::with_capacity(references.len());
            let mut purposes = std::collections::HashSet::new();
            let mut resource_refs = std::collections::HashSet::new();
            for reference in std::mem::take(references) {
                let reference = reference.normalize().map_err(|error| {
                    format!("TENANT_SECRET_DEPENDENCIES tenant {tenant}: {error}")
                })?;
                if !purposes.insert(reference.purpose.clone())
                    || !resource_refs.insert(reference.secret_ref.clone())
                {
                    return Err(format!(
                        "TENANT_SECRET_DEPENDENCIES tenant {tenant} contains duplicate purpose or resource"
                    ));
                }
                normalized.push(reference);
            }
            normalized.sort_by(|left, right| left.purpose.cmp(&right.purpose));
            *references = normalized;
        }
        let governance_residency = match &runtime_bootstrap_config {
            Some(config) => serde_json::to_string(&config.tenant_residency)
                .map_err(|_| "runtime bootstrap tenant_residency could not be encoded")?,
            None => std::env::var("AGENT_AUTH_TENANT_RESIDENCY")
                .map_err(|_| "缺 AGENT_AUTH_TENANT_RESIDENCY")?,
        };
        let governance_config = crate::governance::GovernanceConfig::parse_json(
            &governance_residency,
            &governance_tenants,
        )
        .map_err(|error| format!("AGENT_AUTH_TENANT_RESIDENCY 非法: {error}"))?;
        let deployment_commit = std::env::var("AGENT_AUTH_DEPLOYMENT_COMMIT")
            .map_err(|_| "缺 AGENT_AUTH_DEPLOYMENT_COMMIT")?;
        if deployment_commit.len() != 40
            || !deployment_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA".into());
        }
        let authority_reference_coverage_version =
            crate::adapters::aws::authority_reference_migration_version(&deployment_commit);
        for tenant in &governance_tenants {
            if !governance_config.admits(tenant, region.local_region()) {
                return Err(format!(
                    "tenant {tenant} residency does not admit local Region {}",
                    region.local_region()
                ));
            }
        }

        // X.509-mTLS 开关(spec 012 §1.4 / C5.7,P3):**仅 SelfHosted + Phase≥P3 生效**(评审 B1 + 实现评审 H2)。
        // - SaaS 形态即便 env 开也 fail-closed(单 mTLS 域名 Host 不携带租户,无法解析 issuer/租户);
        // - **Phase<P3 也 fail-closed**(H2:否则 discovery 按 P3 门控不宣告 spiffe_svid_mtls、/token 却激活 =
        //   运行时能力超前于声明阶段,反向破公理 1;discovery 与 /token 由同一 flag 决定,不得分叉)。
        // 二者任一不满足即回落 false + startup 告警(误配显式暴露)。
        let mtls_svid_enabled = {
            let want = std::env::var("AGENT_AUTH_MTLS_SVID_ENABLED").as_deref() == Ok("1");
            match (&form, want) {
                (Form::SelfHosted { .. }, true) if phase.at_least(Phase::P3) => true,
                (Form::SelfHosted { .. }, true) => {
                    eprintln!("⚠️  AGENT_AUTH_MTLS_SVID_ENABLED=1 但 Phase<P3:X.509-mTLS 是 P3 能力,fail-closed 回落关闭(与 discovery 宣告门控一致)");
                    false
                }
                (Form::Saas { .. }, true) => {
                    eprintln!("⚠️  AGENT_AUTH_MTLS_SVID_ENABLED=1 但 FORM=saas:X.509-mTLS 本期仅 SelfHosted(SaaS 租户解析待独立切片),fail-closed 回落关闭");
                    false
                }
                _ => false,
            }
        };

        let client_store = DynamoClientStore::new(db.clone(), clients_table.clone());
        let initial_access_token_store =
            DynamoInitialAccessTokenStore::new(db.clone(), initial_access_tokens_table);
        let users_store =
            crate::adapters::aws::DynamoUsersStore::new(db.clone(), users_table.clone())
                .with_governance_suppression(
                    governance_suppression_table.clone(),
                    governance_hmac_key.clone(),
                );

        Ok(AppState {
            form,
            region,
            governance_config: Arc::new(governance_config),
            deployment_commit,
            governance_hmac_key: Arc::new(governance_hmac_key),
            governance: Arc::new(crate::governance::GovernanceStoreImpl::Dynamo(
                crate::adapters::aws::DynamoGovernanceStore::new(
                    db.clone(),
                    governance_table,
                    governance_suppression_table,
                ),
            )),
            governance_jobs: Arc::new(match governance_queue_url {
                Some(queue_url) => crate::governance::GovernanceJobQueueImpl::Sqs(
                    crate::adapters::aws::SqsGovernanceJobQueue::new(sqs.clone(), queue_url),
                ),
                None => crate::governance::GovernanceJobQueueImpl::Unavailable,
            }),
            tenant_secret_references: Arc::new(tenant_secret_references),
            governance_resources: Arc::new(
                crate::governance_resources::GovernanceResourceBackendImpl::SecretsManager(
                    crate::governance_resources::AwsGovernanceResourceBackend::new(
                        &conf,
                        governance_retention_config.as_deref(),
                    )?,
                ),
            ),
            tenant_partitioning,
            // 部署 phase:`AGENT_AUTH_PHASE` 配置(上文解析,缺省 fail-safe P1)。P2 使
            // client_credentials/token-exchange/device/CIBA 可达 + discovery 如实宣告。
            phase,
            // subject_type:上文按 Form 派生形态默认(SaaS→pairwise / SelfHosted→public)+ env 覆盖
            // (§2.8/§11 #12,SaaS 审计 G)。pairwise 派生见 token::derive_user_sub(spec 001 C2.11)。
            subject_type,
            tenant_subject_types: Arc::new(tenant_subject_types),
            redirect_prefix_allowed_hosts: Arc::new(redirect_prefix_allowed_hosts),
            assurance_policy: Arc::new(assurance_policy),
            server_secret: Arc::new(server_secret),
            saas_origin_auth,
            credential_audit: Arc::new(crate::credential::CredentialAuditSink::Stderr),
            security_events: Arc::new(SecurityEventStoreImpl::Dynamo(
                DynamoSecurityEventStore::new(db.clone(), security_events_table),
            )),
            ssf: Arc::new(SsfStoreImpl::Dynamo(DynamoSsfStore::new(
                db.clone(),
                ssf_deliveries_table,
            ))),
            ssf_management_enabled,
            security_event_fallback: Some(Arc::new(SecurityEventFallbackImpl::Sqs(
                crate::adapters::aws::SqsSecurityEventFallback::new(
                    sqs,
                    security_event_ingress_queue_url,
                ),
            ))),
            admin_credentials: Arc::new(
                crate::admin_credentials::AdminCredentialResolver::secrets_manager(
                    &conf,
                    platform_admin_secret_ref,
                    tenant_admin_secret_refs,
                    scim_tenant_secret_refs,
                    std::time::Duration::from_secs(admin_credential_cache_ttl_secs),
                ),
            ),
            admin_auth: Arc::new(AdminAuthStoreImpl::Dynamo(
                crate::adapters::aws::DynamoAdminAuthStore::new(
                    db.clone(),
                    admin_auth_table,
                    admin_auth_runtime_table,
                ),
            )),
            saas_tenants: Arc::new(saas_tenants),
            allow_login_placeholder,
            // DCR 准入档:上文按优先级链解析(显式 MODE > 旧 DCR_OPEN=1 > 缺省收紧)。
            dcr_mode,
            initial_access_tokens: Arc::new(InitialAccessTokenStoreImpl::Dynamo(
                initial_access_token_store,
            )),
            tenant_keys,
            signer,
            codes: Arc::new(CodeStoreImpl::Dynamo(DynamoCodeStore::new(
                db.clone(),
                codes_table,
                clients_table.clone(),
                client_authority_refs_table.clone(),
                authority_reference_coverage_version.clone(),
            ))),
            clients: Arc::new(ClientStoreImpl::Dynamo(client_store)),
            cimd: Arc::new(cimd),
            refresh: Arc::new(RefreshStoreImpl::Dynamo(DynamoRefreshStore::new(
                db.clone(),
                refresh_table,
                clients_table.clone(),
                client_authority_refs_table,
                authority_reference_coverage_version,
            ))),
            par: Arc::new(match par_table {
                Some(t) => {
                    ParStoreImpl::Dynamo(crate::adapters::aws::DynamoParStore::new(db.clone(), t))
                }
                None => ParStoreImpl::Memory(crate::adapters::memory::MemoryParStore::default()),
            }),
            // 宽限窗(C3.2/C3.4):TokenFn 配表+CMK,可 item-level 信封加解密;
            // 其他 runtime 只配表,构造 delete-only store 供撤销/治理级联,put/get fail closed。
            grace,
            grace_window_secs: 5,
            sessions: Arc::new(SessionStoreImpl::Dynamo(DynamoSessionStore::new(
                db.clone(),
                sessions_table.clone(),
            ))),
            magic_links: Arc::new(MagicLinkStoreImpl::Dynamo(DynamoMagicLinkStore::new(
                db.clone(),
                magic_table,
            ))),
            invitations: Arc::new(InvitationStoreImpl::Dynamo(DynamoInvitationStore::new(
                db.clone(),
                invitations_table,
                users_table.clone(),
                password_credentials_table.clone(),
                sessions_table.clone(),
            ))),
            invitation_ttl_secs,
            users: Arc::new(UsersStoreImpl::Dynamo(users_store)),
            attribute_namespaces: Arc::new(match attribute_namespaces_table {
                Some(table) => AttributeNamespaceStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoAttributeNamespaceStore::new(db.clone(), table),
                ),
                None => AttributeNamespaceStoreImpl::Disabled,
            }),
            attribute_namespace_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            scim_groups: Arc::new(ScimGroupsStoreImpl::Dynamo(
                crate::adapters::aws::DynamoScimGroupsStore::new(db.clone(), scim_groups_table),
            )),
            passwords: Arc::new(PasswordStoreImpl::Dynamo(
                crate::adapters::aws::DynamoPasswordStore::new(
                    db.clone(),
                    password_credentials_table,
                ),
            )),
            password_workers: Arc::new(tokio::sync::Semaphore::new(password_worker_count)),
            recovery: Arc::new(RecoveryStoreImpl::Dynamo(DynamoRecoveryStore::new(
                db.clone(),
                recovery_table,
            ))),
            // SES 未接前:消息落 messages 表(TTL=1 天);notifier 写端与 messages 读端共用同一实例。
            notifier: Arc::new(NotifierImpl::Dynamo(dyn_notifier.clone())),
            messages: Arc::new(MessageOutboxImpl::Dynamo(dyn_notifier)),
            workload_trust: Arc::new(WorkloadTrustStoreImpl::Dynamo(
                crate::adapters::aws::DynamoWorkloadTrustStore::new(
                    db.clone(),
                    workload_trust_table,
                ),
            )),
            // 联邦配置:配了表 → Dynamo(复合键隔离);未配 → 内存(联邦 callback 未上架前不强制建表)。
            federation_config: Arc::new(match federation_config_table {
                Some(t) => FederationConfigStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoFederationConfigStore::new(db.clone(), t),
                ),
                None => FederationConfigStoreImpl::Memory(
                    crate::adapters::memory::MemoryFederationConfigStore::default(),
                ),
            }),
            federation_attribute_mappings: Arc::new(match federation_attribute_mappings_table {
                Some(table) => FederationAttributeMappingsStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoFederationAttributeMappingsStore::new(
                        db.clone(),
                        table,
                    ),
                ),
                None => FederationAttributeMappingsStoreImpl::Disabled,
            }),
            upstream_token_exchanger: Arc::new(UpstreamTokenExchangerImpl::Http(
                crate::adapters::aws::HttpUpstreamTokenExchanger::new(),
            )),
            secret_resolver: Arc::new(SecretResolverImpl::SecretsManager(
                crate::adapters::aws::SecretsManagerResolver::new(&conf),
            )),
            federation_flow: Arc::new(match federation_flow_table {
                Some(t) => FederationFlowStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoFederationFlowStore::new(db.clone(), t),
                ),
                None => FederationFlowStoreImpl::Memory(
                    crate::adapters::memory::MemoryFederationFlowStore::default(),
                ),
            }),
            federation_enabled,
            passkey_challenges: Arc::new(match passkey_challenge_table {
                Some(t) => PasskeyChallengeStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoPasskeyChallengeStore::new(db.clone(), t),
                ),
                None => PasskeyChallengeStoreImpl::Memory(
                    crate::adapters::memory::MemoryPasskeyChallengeStore::default(),
                ),
            }),
            passkeys: Arc::new(match passkey_table {
                Some(t) => PasskeyStoreImpl::Dynamo(crate::adapters::aws::DynamoPasskeyStore::new(
                    db.clone(),
                    t,
                )),
                None => {
                    PasskeyStoreImpl::Memory(crate::adapters::memory::MemoryPasskeyStore::default())
                }
            }),
            passkey_enabled,
            // CIBA ping/push 投递开关(spec 013 §4,P3):默认关;仅 AGENT_AUTH_CIBA_PING_PUSH_ENABLED=1 显式开。
            ciba_ping_push_enabled: std::env::var("AGENT_AUTH_CIBA_PING_PUSH_ENABLED").as_deref()
                == Ok("1"),
            ciba_delivery: Arc::new(CibaCallbackDeliveryImpl::Http(
                crate::adapters::aws::HttpCibaCallbackDelivery::new(),
            )),
            jwks_fetcher: Arc::new(JwksFetcherImpl::Http(
                crate::adapters::aws::HttpJwksFetcher::new(),
            )),
            // SigV4/STS 真转发(reqwest→STS,超时 2s)。SigV4 路径的准入仍 fail-closed:无 SigV4
            // 信任绑定的 client 认证不了(match_sigv4 无匹配即拒),故 caller 恒 Some 无安全放松。
            sts_caller: Some(Arc::new(StsCallerImpl::Http(
                crate::adapters::aws::HttpStsCaller::new(),
            ))),
            sts_circuit: Arc::new(tokio::sync::Mutex::new(
                agent_auth_workload::CircuitBreaker::default(),
            )),
            // replay 缓存复用 JtiTable(同为短命 TTL 表,pk 加 "replay\x1f" 前缀不撞);未配 JTI_TABLE 则 None
            // (SigV4 replay 退化到"靠短 TTL 限窗",与 jti 死写规避同源)。
            replay_store: jti_table.clone().map(|t| {
                Arc::new(ReplayStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoReplayStore::new(db.clone(), t),
                ))
            }),
            // Grant 存储:配了 GRANTS_TABLE 走 Dynamo,否则内存(P2 未启用 Grant 权威源前的退化)。
            grants: Arc::new(match grants_table.clone() {
                Some(t) => GrantStoreImpl::Dynamo(crate::adapters::aws::DynamoGrantStore::new(
                    db.clone(),
                    t,
                    clients_table.clone(),
                )),
                None => {
                    GrantStoreImpl::Memory(crate::adapters::memory::MemoryGrantStore::default())
                }
            }),
            // BYOD 域名映射:配了 DOMAIN_MAP_TABLE 走 Dynamo(全局键),否则内存(BYOD 未启用,spec 010 §5.4)。
            domain_map: Arc::new(match domain_map_table.clone() {
                Some(t) => DomainMapStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoDomainMapStore::new(db.clone(), t),
                ),
                None => DomainMapStoreImpl::Memory(
                    crate::adapters::memory::MemoryDomainMapStore::default(),
                ),
            }),
            // BYOD 开关(spec 010 §5.4,P3):默认关;仅 AGENT_AUTH_BYOD_ENABLED=1 显式开。fail-closed(评审:
            // 启用但漏配 DOMAIN_MAP_TABLE → 每实例内存 map,登记在 A 实例查 B 实例丢 = 静默坏)。见下方 fail-fast 守卫。
            byod_enabled: std::env::var("AGENT_AUTH_BYOD_ENABLED").as_deref() == Ok("1"),
            mtls_svid_enabled, // 上文按 SelfHosted 门控解析(评审 B1)
            ema_enabled,
            ema_policies: Arc::new(ema_policies),
            // policy_version / 工件:复用 GRANTS_TABLE(单表少行);未配 → 内存(spec 005 §7)。
            policy_versions: Arc::new(match grants_table.clone() {
                Some(t) => PolicyVersionStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoPolicyVersionStore::new(db.clone(), t),
                ),
                None => PolicyVersionStoreImpl::Memory(
                    crate::adapters::memory::MemoryPolicyVersionStore::default(),
                ),
            }),
            policy_artifacts: Arc::new(match grants_table.clone() {
                Some(t) => PolicyArtifactStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoPolicyArtifactStore::new(db.clone(), t),
                ),
                None => PolicyArtifactStoreImpl::Memory(
                    crate::adapters::memory::MemoryPolicyArtifactStore::default(),
                ),
            }),
            // Cedar 授权引擎开关(C10.17;默认关字节等价)。
            authz_enabled: std::env::var("AGENT_AUTH_AUTHZ_ENABLED")
                .map(|v| v == "1")
                .unwrap_or(false),
            current_pv_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            jti_store: jti_table.map(|t| {
                Arc::new(JtiStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoJtiStore::new(db.clone(), t),
                ))
            }),
            ciba: Arc::new(CibaStoreImpl::Dynamo(
                crate::adapters::aws::DynamoCibaStore::new(
                    db.clone(),
                    ciba_kms.clone(),
                    ciba_table,
                    ciba_enc_key.clone(),
                ),
            )),
            device: Arc::new(DeviceStoreImpl::Dynamo(
                crate::adapters::aws::DynamoDeviceStore::new(db.clone(), device_table),
            )),
            authz_sessions: Arc::new(AuthzSessionStoreImpl::Dynamo(DynamoAuthzSessionStore::new(
                db,
                authz_sessions_table,
            ))),
            // P1:真机事件 sink no-op(权威源 DynamoDB;真发 EventBridge 留 P2,spec 005 补栈)。
            authz_events: Arc::new(authz_event_sink),
            web_base_url,
            // per-client 限流:配了 RATE_LIMIT_TABLE 走 Dynamo,否则 None(fail-open 不限流)。
            rate_limit: rate_limit_table.map(|t| {
                Arc::new(RateLimitStoreImpl::Dynamo(
                    crate::adapters::aws::DynamoRateLimitStore::new(db_ratelimit, t),
                ))
            }),
        })
    }

    fn prepare_security_event_with_id(
        event_id: String,
        draft: SecurityEventDraft,
    ) -> Option<SecurityEvent> {
        let event = match draft.into_event_at(event_id, crate::current_unix_secs()) {
            Ok(event) => event,
            Err(error) => {
                eprintln!("SECURITY_EVENT_INVALID error={error}");
                return None;
            }
        };
        eprintln!(
            "SECURITY_EVENT event_id={} tenant={} category={} action={} outcome={}",
            event.event_id,
            event.tenant_id,
            event.category.as_str(),
            event.action,
            event.outcome.as_str()
        );
        Some(event)
    }

    pub(crate) fn prepare_security_event(draft: SecurityEventDraft) -> Option<SecurityEvent> {
        Self::prepare_security_event_with_id(crate::security_event::new_event_id(), draft)
    }

    fn log_security_event_ingress(marker: &str, ingress: &SecurityEventIngress) -> bool {
        match crate::security_event::encode_emergency_ingress(ingress) {
            Ok(payload) => {
                eprintln!(
                    "{marker} event_id={} payload={payload}",
                    ingress.event.event_id
                );
                true
            }
            Err(error) => {
                eprintln!(
                    "SECURITY_EVENT_INVALID event_id={} source={} error={error:?}",
                    ingress.event.event_id, marker
                );
                false
            }
        }
    }

    /// Persist one immutable security event without changing the business outcome.
    ///
    /// Security-event storage is an observability path: failures are explicitly
    /// logged for CloudWatch alarms, but do not reverse a completed auth mutation.
    pub fn record_security_event(
        &self,
        draft: SecurityEventDraft,
    ) -> Pin<Box<dyn Future<Output = Option<SecurityEvent>> + Send + '_>> {
        Box::pin(async move {
            let event = Self::prepare_security_event(draft)?;
            self.record_prepared_security_event(event).await
        })
    }

    pub fn record_security_event_with_id(
        &self,
        event_id: String,
        draft: SecurityEventDraft,
    ) -> Pin<Box<dyn Future<Output = Option<SecurityEvent>> + Send + '_>> {
        Box::pin(async move {
            let event = Self::prepare_security_event_with_id(event_id, draft)?;
            self.record_prepared_security_event(event).await
        })
    }

    pub(crate) async fn record_prepared_security_event(
        &self,
        event: SecurityEvent,
    ) -> Option<SecurityEvent> {
        let mut ingress = SecurityEventIngress::new(event.clone());
        for attempt in 1..=3 {
            let now = crate::current_unix_secs();
            if attempt > 1 {
                ingress
                    .delivery
                    .record(SecurityEventDeliveryStatus::Retrying, now);
            }
            ingress.delivery.start_attempt(now);
            match bounded_security_event_io(
                "hot-ledger write",
                SECURITY_EVENT_IO_TIMEOUT,
                self.security_events
                    .put_with_delivery(&event, &ingress.delivery),
            )
            .await
            {
                Ok(inserted) => {
                    eprintln!(
                        "SECURITY_EVENT_DELIVERY event_id={} result={} attempt={attempt}",
                        event.event_id,
                        if inserted { "success" } else { "duplicate" }
                    );
                    return Some(event);
                }
                Err(error) => {
                    ingress.delivery.record(
                        SecurityEventDeliveryStatus::Failed,
                        crate::current_unix_secs(),
                    );
                    let retryable = matches!(&error, StoreError::Transient(_));
                    let exhausted = !retryable || attempt == 3;
                    eprintln!(
                        "SECURITY_EVENT_DELIVERY event_id={} result={} attempt={attempt} error={error:?}",
                        event.event_id,
                        if exhausted { "failed" } else { "attempt_failed" }
                    );
                    if exhausted {
                        break;
                    }
                    eprintln!(
                        "SECURITY_EVENT_DELIVERY event_id={} result=retrying attempt={}",
                        event.event_id,
                        attempt + 1
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(25 * attempt)).await;
                }
            }
        }
        let Some(fallback) = &self.security_event_fallback else {
            return None;
        };
        for attempt in 1..=3 {
            let now = crate::current_unix_secs();
            if attempt > 1 {
                ingress
                    .delivery
                    .record(SecurityEventDeliveryStatus::Retrying, now);
            }
            ingress.delivery.start_attempt(now);
            match bounded_security_event_io(
                "fallback enqueue",
                SECURITY_EVENT_IO_TIMEOUT,
                fallback.enqueue(&ingress),
            )
            .await
            {
                Ok(()) => {
                    eprintln!(
                        "SECURITY_EVENT_DELIVERY event_id={} result=queued attempt={attempt}",
                        event.event_id
                    );
                    return Some(event);
                }
                Err(error) => {
                    ingress.delivery.record(
                        SecurityEventDeliveryStatus::Failed,
                        crate::current_unix_secs(),
                    );
                    eprintln!(
                        "SECURITY_EVENT_FALLBACK event_id={} result={} attempt={attempt} error={error:?}",
                        event.event_id,
                        if attempt == 3 { "failed" } else { "attempt_failed" }
                    );
                    if attempt < 3 {
                        eprintln!(
                            "SECURITY_EVENT_FALLBACK event_id={} result=retrying attempt={}",
                            event.event_id,
                            attempt + 1
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(25 * attempt)).await;
                    }
                }
            }
        }
        // Lambda captures stderr before reporting the invocation result. Both
        // runtime log groups are retained for seven years.
        Self::log_security_event_ingress("SECURITY_EVENT_EMERGENCY", &ingress).then_some(event)
    }

    async fn enqueue_security_event_chunk<F>(
        fallback: Arc<F>,
        mut ingresses: Vec<SecurityEventIngress>,
    ) -> Vec<SecurityEventIngress>
    where
        F: SecurityEventFallback + 'static,
    {
        let mut emergency = Vec::new();
        for attempt in 1..=3 {
            let now = crate::current_unix_secs();
            for ingress in &mut ingresses {
                if attempt > 1 {
                    ingress
                        .delivery
                        .record(SecurityEventDeliveryStatus::Retrying, now);
                }
                ingress.delivery.start_attempt(now);
            }
            match bounded_security_event_io(
                "fallback batch enqueue",
                SECURITY_EVENT_IO_TIMEOUT,
                fallback.enqueue_batch(&ingresses),
            )
            .await
            {
                Ok(outcomes) if outcomes.len() == ingresses.len() => {
                    let failed_at = crate::current_unix_secs();
                    let mut retry = Vec::new();
                    for (mut ingress, outcome) in ingresses.into_iter().zip(outcomes) {
                        match outcome {
                            SecurityEventFallbackOutcome::Enqueued => {
                                eprintln!(
                                    "SECURITY_EVENT_DELIVERY event_id={} result=queued attempt={attempt} source=batch",
                                    ingress.event.event_id
                                );
                            }
                            SecurityEventFallbackOutcome::Retryable(error) => {
                                ingress
                                    .delivery
                                    .record(SecurityEventDeliveryStatus::Failed, failed_at);
                                let exhausted = attempt == 3;
                                eprintln!(
                                    "SECURITY_EVENT_FALLBACK event_id={} result={} attempt={attempt} source=batch error={error}",
                                    ingress.event.event_id,
                                    if exhausted { "failed" } else { "attempt_failed" }
                                );
                                if exhausted {
                                    if Self::log_security_event_ingress(
                                        "SECURITY_EVENT_EMERGENCY",
                                        &ingress,
                                    ) {
                                        emergency.push(ingress);
                                    }
                                } else {
                                    retry.push(ingress);
                                }
                            }
                            SecurityEventFallbackOutcome::Permanent(error) => {
                                ingress
                                    .delivery
                                    .record(SecurityEventDeliveryStatus::Failed, failed_at);
                                eprintln!(
                                    "SECURITY_EVENT_FALLBACK event_id={} result=failed attempt={attempt} source=batch error={error}",
                                    ingress.event.event_id
                                );
                                if Self::log_security_event_ingress(
                                    "SECURITY_EVENT_EMERGENCY",
                                    &ingress,
                                ) {
                                    emergency.push(ingress);
                                }
                            }
                        }
                    }
                    if retry.is_empty() {
                        return emergency;
                    }
                    ingresses = retry;
                }
                Ok(outcomes) => {
                    let error = StoreError::Transient(format!(
                        "security event fallback returned {} outcomes for {} entries",
                        outcomes.len(),
                        ingresses.len()
                    ));
                    let exhausted = attempt == 3;
                    let failed_at = crate::current_unix_secs();
                    for ingress in &mut ingresses {
                        ingress
                            .delivery
                            .record(SecurityEventDeliveryStatus::Failed, failed_at);
                        eprintln!(
                            "SECURITY_EVENT_FALLBACK event_id={} result={} attempt={attempt} source=batch error={error:?}",
                            ingress.event.event_id,
                            if exhausted { "failed" } else { "attempt_failed" }
                        );
                    }
                    if exhausted {
                        for ingress in &ingresses {
                            if Self::log_security_event_ingress("SECURITY_EVENT_EMERGENCY", ingress)
                            {
                                emergency.push(ingress.clone());
                            }
                        }
                        return emergency;
                    }
                }
                Err(error) => {
                    let retryable = matches!(&error, StoreError::Transient(_));
                    let exhausted = !retryable || attempt == 3;
                    let failed_at = crate::current_unix_secs();
                    for ingress in &mut ingresses {
                        ingress
                            .delivery
                            .record(SecurityEventDeliveryStatus::Failed, failed_at);
                        eprintln!(
                            "SECURITY_EVENT_FALLBACK event_id={} result={} attempt={attempt} source=batch error={error:?}",
                            ingress.event.event_id,
                            if exhausted { "failed" } else { "attempt_failed" }
                        );
                    }
                    if exhausted {
                        for ingress in &ingresses {
                            if Self::log_security_event_ingress("SECURITY_EVENT_EMERGENCY", ingress)
                            {
                                emergency.push(ingress.clone());
                            }
                        }
                        return emergency;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(25 * attempt)).await;
        }
        emergency
    }

    async fn enqueue_security_event_batch(
        fallback: Arc<SecurityEventFallbackImpl>,
        ingresses: Vec<SecurityEventIngress>,
    ) {
        let mut tasks = tokio::task::JoinSet::new();
        for chunk in ingresses.chunks(SECURITY_EVENT_FALLBACK_BATCH_SIZE) {
            if tasks.len() >= MAX_CONCURRENT_SECURITY_EVENT_DELIVERIES {
                if let Some(Err(error)) = tasks.join_next().await {
                    eprintln!("SECURITY_EVENT_INVALID source=batch_task error={error}");
                }
            }
            let fallback = fallback.clone();
            let chunk = chunk.to_vec();
            tasks.spawn(async move {
                Self::enqueue_security_event_chunk(fallback, chunk).await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                eprintln!("SECURITY_EVENT_INVALID source=batch_task error={error}");
            }
        }
    }

    /// Persist independent events concurrently so one business request pays one
    /// bounded observability budget instead of one budget per event.
    pub async fn record_security_events(
        &self,
        drafts: impl IntoIterator<Item = SecurityEventDraft>,
    ) {
        let drafts = drafts.into_iter().collect::<Vec<_>>();
        if drafts.len() > MAX_CONCURRENT_SECURITY_EVENT_DELIVERIES {
            if let Some(fallback) = &self.security_event_fallback {
                let ingresses = drafts
                    .into_iter()
                    .filter_map(Self::prepare_security_event)
                    .map(SecurityEventIngress::new)
                    .collect::<Vec<_>>();
                // Large business batches get a complete retained recovery copy
                // before any network I/O. This keeps every envelope auditable if
                // the Lambda deadline interrupts a later queue attempt.
                for ingress in &ingresses {
                    let _ =
                        Self::log_security_event_ingress("SECURITY_EVENT_BATCH_RECOVERY", ingress);
                }
                if tokio::time::timeout(
                    SECURITY_EVENT_BATCH_TIMEOUT,
                    Self::enqueue_security_event_batch(fallback.clone(), ingresses),
                )
                .await
                .is_err()
                {
                    eprintln!(
                        "SECURITY_EVENT_FALLBACK result=timeout source=batch deadline_ms={}",
                        SECURITY_EVENT_BATCH_TIMEOUT.as_millis()
                    );
                }
                return;
            }
        }

        let mut tasks = tokio::task::JoinSet::new();
        for draft in drafts {
            if tasks.len() >= MAX_CONCURRENT_SECURITY_EVENT_DELIVERIES {
                if let Some(Err(error)) = tasks.join_next().await {
                    eprintln!("SECURITY_EVENT_INVALID source=batch_task error={error}");
                }
            }
            let state = self.clone();
            tasks.spawn(async move {
                state.record_security_event(draft).await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                eprintln!("SECURITY_EVENT_INVALID source=batch_task error={error}");
            }
        }
    }

    pub async fn audit_credential_event(&self, event: crate::credential::CredentialAuditEvent<'_>) {
        let draft = event.security_event();
        self.credential_audit.emit(event);
        self.record_security_event(draft).await;
    }

    pub async fn audit_credential_event_with_id(
        &self,
        event_id: String,
        event: crate::credential::CredentialAuditEvent<'_>,
    ) {
        let draft = event.security_event();
        self.credential_audit.emit(event);
        self.record_security_event_with_id(event_id, draft).await;
    }

    /// 预置一个开发/测试用 client(register 端点接入前的本地 e2e 便利;真机不用)。
    pub async fn seed_dev_client(
        &self,
        client_id: &str,
        redirect_uri: &str,
        default_resource: Option<&str>,
    ) {
        let is_native =
            url::Url::parse(redirect_uri)
                .ok()
                .is_some_and(|redirect| match redirect.scheme() {
                    "http" => {
                        matches!(
                            redirect.host(),
                            Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST
                        ) || matches!(
                            redirect.host(),
                            Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST
                        )
                    }
                    "https" => false,
                    _ => true,
                });
        let application_type = if is_native { "native" } else { "web" };
        let _ = self
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: client_id.to_string(),
                    redirect_uris: vec![redirect_uri.to_string()],
                    application_type: Some(application_type.to_string()),
                    token_endpoint_auth_method: "none".to_string(),
                    client_secret: None,
                    client_secret_credentials: Default::default(),
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    default_resource: default_resource.map(String::from),
                    introspect_enabled: false,
                    resource_ids: vec![],
                    post_logout_redirect_uris: vec![],
                    reg_token_hash: None,
                    registration_token_credentials: Default::default(),
                    client_type: None,
                    id_token_signed_response_alg: None,
                    oidc_sector_identifier: None,
                    allowed_resources: vec![],
                    allowed_scopes: vec![],
                    redirect_mode: None,
                    // 回收元数据(spec 005 §9):dev seed,created_at=0(不参与判定)/未使用/未 tombstone。
                    created_at: 0,
                    last_used_day: None,
                    authority_revision: 0,
                    tombstoned_at: None,
                    backchannel_token_delivery_mode: None,
                    backchannel_client_notification_endpoint: None,
                    require_dpop: false,
                    prm_domains: vec![],
                },
            )
            .await;
    }

    /// Pre-provision a local user without a password for process-local tests
    /// that exercise magic-link, passkey, or recovery independently. Production
    /// onboarding must use the authenticated Admin API with an initial password.
    pub async fn seed_dev_user(&self, email: &str) {
        self.seed_dev_user_in_tenant("", email).await;
    }

    /// Tenant-aware variant for SaaS isolation tests.
    pub async fn seed_dev_user_in_tenant(&self, tenant: &str, email: &str) {
        use crate::ports::UsersStore;

        let normalized = email.trim().to_lowercase();
        let user_id = format!("user:{normalized}");
        let _ = self
            .users
            .create_or_get_by_email(
                tenant,
                &normalized,
                &user_id,
                crate::token::current_unix_secs_pub(),
            )
            .await;
    }

    /// 预置一个注册用户(users 表;CIBA login_hint 存在性校验的 e2e 便利,spec 013 §2b.5)。
    /// user_id 稳定派生 `user:{归一 email}`,与 magic-link 登录同源。返回归一后的 user_id。
    pub async fn seed_user(&self, email: &str, now: i64) -> String {
        use crate::ports::UsersStore;
        let norm = email.trim().to_lowercase();
        let uid = format!("user:{norm}");
        let rec = self
            .users
            .create_or_get_by_email("", &norm, &uid, now)
            .await
            .expect("seed_user");
        rec.user_id
    }

    /// 注册一个 dev `workload` client(spec 012 C5.6 测试用;client_type 显式 workload)。
    pub async fn seed_workload_client(&self, client_id: &str) {
        self.seed_workload_client_with_policy(client_id, vec![], vec![])
            .await;
    }

    /// 注册 workload client 并设 2LO 策略(spec 012 C7.5:allowed_resources/scopes;测试用)。
    pub async fn seed_workload_client_with_policy(
        &self,
        client_id: &str,
        allowed_resources: Vec<String>,
        allowed_scopes: Vec<String>,
    ) {
        let _ = self
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: client_id.to_string(),
                    redirect_uris: vec![],
                    application_type: None,
                    token_endpoint_auth_method: "none".to_string(),
                    client_secret: None,
                    client_secret_credentials: Default::default(),
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    default_resource: None,
                    introspect_enabled: false,
                    resource_ids: vec![],
                    post_logout_redirect_uris: vec![],
                    reg_token_hash: None,
                    registration_token_credentials: Default::default(),
                    client_type: Some("workload".to_string()),
                    id_token_signed_response_alg: None,
                    oidc_sector_identifier: None,
                    allowed_resources,
                    allowed_scopes,
                    redirect_mode: None,
                    // 回收元数据(spec 005 §9):dev seed,created_at=0(不参与判定)/未使用/未 tombstone。
                    created_at: 0,
                    last_used_day: None,
                    authority_revision: 0,
                    tombstoned_at: None,
                    backchannel_token_delivery_mode: None,
                    backchannel_client_notification_endpoint: None,
                    require_dpop: false,
                    prm_domains: vec![],
                },
            )
            .await;
    }

    /// 注册带 `post_logout_redirect_uris` 的 dev client(spec 003 C9.6 logout e2e 用)。
    pub async fn seed_dev_client_with_logout(
        &self,
        client_id: &str,
        redirect_uri: &str,
        post_logout_redirect_uris: &[&str],
    ) {
        let _ = self
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: client_id.to_string(),
                    redirect_uris: vec![redirect_uri.to_string()],
                    application_type: None,
                    token_endpoint_auth_method: "none".to_string(),
                    client_secret: None,
                    client_secret_credentials: Default::default(),
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    default_resource: None,
                    introspect_enabled: false,
                    resource_ids: vec![],
                    post_logout_redirect_uris: post_logout_redirect_uris
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    reg_token_hash: None,
                    registration_token_credentials: Default::default(),
                    client_type: None,
                    id_token_signed_response_alg: None,
                    oidc_sector_identifier: None,
                    allowed_resources: vec![],
                    allowed_scopes: vec![],
                    redirect_mode: None,
                    // 回收元数据(spec 005 §9):dev seed,created_at=0(不参与判定)/未使用/未 tombstone。
                    created_at: 0,
                    last_used_day: None,
                    authority_revision: 0,
                    tombstoned_at: None,
                    backchannel_token_delivery_mode: None,
                    backchannel_client_notification_endpoint: None,
                    require_dpop: false,
                    prm_domains: vec![],
                },
            )
            .await;
    }

    /// 注册一个 MCP RS 的 introspection 凭证(spec 010 C8.6):client_secret_basic 认证 +
    /// `introspect_enabled` + 绑定的 resource_id 集合。dev/测试用;真机走控制面注册。
    pub async fn seed_rs_introspect_client(
        &self,
        client_id: &str,
        client_secret: &str,
        resource_ids: &[&str],
    ) {
        let _ = self
            .clients
            .put(
                "",
                ClientRecord {
                    client_id: client_id.to_string(),
                    redirect_uris: vec![],
                    application_type: None,
                    token_endpoint_auth_method: "client_secret_basic".to_string(),
                    client_secret: Some(client_secret.to_string()),
                    client_secret_credentials: Default::default(),
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    default_resource: None,
                    introspect_enabled: true,
                    resource_ids: resource_ids.iter().map(|s| s.to_string()).collect(),
                    post_logout_redirect_uris: vec![],
                    reg_token_hash: None,
                    registration_token_credentials: Default::default(),
                    client_type: None,
                    id_token_signed_response_alg: None,
                    oidc_sector_identifier: None,
                    allowed_resources: vec![],
                    allowed_scopes: vec![],
                    redirect_mode: None,
                    // 回收元数据(spec 005 §9):dev seed,created_at=0(不参与判定)/未使用/未 tombstone。
                    created_at: 0,
                    last_used_day: None,
                    authority_revision: 0,
                    tombstoned_at: None,
                    backchannel_token_delivery_mode: None,
                    backchannel_client_notification_endpoint: None,
                    require_dpop: false,
                    prm_domains: vec![],
                },
            )
            .await;
    }

    /// 测试 helper:预置 secret 引用名→明文(仅 Memory resolver;spec 003 §4 联邦 e2e)。
    pub async fn secret_resolver_seed(&self, secret_ref: &str, plaintext: &str) {
        match self.secret_resolver.as_ref() {
            SecretResolverImpl::Memory(m) => m.seed(secret_ref, plaintext).await,
            #[cfg(feature = "aws")]
            _ => {}
        }
    }

    /// 测试 helper:注入某 jwks_uri 的 key 集(仅 Memory fetcher;联邦上游验签 e2e)。
    pub async fn jwks_fetcher_set(
        &self,
        jwks_uri: impl Into<String>,
        keys: Vec<crate::ports::PlatformJwk>,
    ) {
        match self.jwks_fetcher.as_ref() {
            JwksFetcherImpl::Memory(m) => m.set(jwks_uri, keys).await,
            #[cfg(feature = "aws")]
            _ => {}
        }
    }

    /// 测试 helper:为 Memory fetcher 预置一次强刷结果。
    pub async fn jwks_fetcher_set_fresh(
        &self,
        jwks_uri: impl Into<String>,
        keys: Vec<crate::ports::PlatformJwk>,
    ) {
        match self.jwks_fetcher.as_ref() {
            JwksFetcherImpl::Memory(m) => m.set_fresh(jwks_uri, keys).await,
            #[cfg(feature = "aws")]
            _ => {}
        }
    }

    /// 测试 helper:观察固定 URI 的强刷边界调用次数。
    pub async fn jwks_fetcher_fresh_calls(&self, jwks_uri: &str) -> Option<usize> {
        match self.jwks_fetcher.as_ref() {
            JwksFetcherImpl::Memory(m) => Some(m.fresh_calls(jwks_uri).await),
            #[cfg(feature = "aws")]
            _ => None,
        }
    }

    /// 测试 helper:观察固定 URI 的普通 JWKS 读取次数。
    pub async fn jwks_fetcher_calls(&self, jwks_uri: &str) -> Option<usize> {
        match self.jwks_fetcher.as_ref() {
            JwksFetcherImpl::Memory(m) => Some(m.fetch_calls(jwks_uri).await),
            #[cfg(feature = "aws")]
            _ => None,
        }
    }

    /// 测试 helper:预置上游 code→token(仅 Memory exchanger;联邦 e2e)。
    pub async fn upstream_exchanger_seed(&self, code: &str, set: crate::ports::UpstreamTokenSet) {
        match self.upstream_token_exchanger.as_ref() {
            UpstreamTokenExchangerImpl::Memory(m) => m.seed(code, set).await,
            #[cfg(feature = "aws")]
            _ => {}
        }
    }

    /// 测试 helper:读取去敏且有界的上游 token exchange 观测。
    pub async fn upstream_exchanger_requests(
        &self,
    ) -> Vec<crate::adapters::memory::MemoryUpstreamTokenExchange> {
        match self.upstream_token_exchanger.as_ref() {
            UpstreamTokenExchangerImpl::Memory(m) => m.requests().await,
            #[cfg(feature = "aws")]
            _ => Vec::new(),
        }
    }

    /// 测试 helper:让下一次 Memory Admin session 删除返回 transient failure。
    pub fn admin_auth_fail_next_delete_session(&self) -> bool {
        match self.admin_auth.as_ref() {
            AdminAuthStoreImpl::Memory(m) => {
                m.fail_next_delete_session();
                true
            }
            #[cfg(feature = "aws")]
            _ => false,
        }
    }

    /// 测试 helper:读取仍未消费的 Memory Admin OIDC flows。
    pub async fn admin_auth_flows(&self) -> Vec<crate::ports::AdminOidcFlow> {
        match self.admin_auth.as_ref() {
            AdminAuthStoreImpl::Memory(m) => m.flows().await,
            #[cfg(feature = "aws")]
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod security_event_io_tests {
    use super::*;

    #[derive(Clone)]
    struct ControlledBatchFallback {
        attempts: Arc<tokio::sync::Mutex<Vec<Vec<String>>>>,
        outcomes:
            Arc<tokio::sync::Mutex<std::collections::VecDeque<Vec<SecurityEventFallbackOutcome>>>>,
    }

    impl SecurityEventFallback for ControlledBatchFallback {
        async fn enqueue(&self, _ingress: &SecurityEventIngress) -> Result<(), StoreError> {
            Err(StoreError::Permanent(
                "single enqueue is not used by this test".to_string(),
            ))
        }

        async fn enqueue_batch(
            &self,
            ingresses: &[SecurityEventIngress],
        ) -> Result<Vec<SecurityEventFallbackOutcome>, StoreError> {
            self.attempts.lock().await.push(
                ingresses
                    .iter()
                    .map(|ingress| ingress.event.event_id.clone())
                    .collect(),
            );
            self.outcomes
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| StoreError::Permanent("missing controlled outcome".to_string()))
        }
    }

    fn batch_drafts(count: usize) -> Vec<SecurityEventDraft> {
        (0..count)
            .map(|index| {
                SecurityEventDraft::new(
                    "t1",
                    crate::security_event::SecurityActor::system("batch-test"),
                    None,
                    crate::security_event::SecurityEventCategory::Delivery,
                    format!("delivery.batch.{index}"),
                    crate::security_event::SecurityEventOutcome::Success,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn stalled_security_event_io_is_bounded() {
        let result = bounded_security_event_io(
            "test operation",
            Duration::from_millis(1),
            std::future::pending::<Result<(), StoreError>>(),
        )
        .await;

        assert_eq!(
            result,
            Err(StoreError::Transient(
                "security event test operation timed out".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn large_security_event_batch_uses_durable_batch_ingress() {
        let queued = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let mut state = AppState::dev("localhost");
        state.security_event_fallback =
            Some(Arc::new(SecurityEventFallbackImpl::Memory(queued.clone())));

        state.record_security_events(batch_drafts(17)).await;

        let queued = queued.lock().await;
        assert_eq!(queued.len(), 17);
        assert_eq!(
            queued
                .iter()
                .map(|ingress| ingress.event.event_id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            17
        );
        assert!(queued.iter().all(|ingress| ingress.delivery.attempts == 1));
        assert!(state
            .security_events
            .list_by_tenant("t1", 0, i64::MAX, 100)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn small_security_event_batch_keeps_hot_ledger_path() {
        let queued = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let mut state = AppState::dev("localhost");
        state.security_event_fallback =
            Some(Arc::new(SecurityEventFallbackImpl::Memory(queued.clone())));

        state.record_security_events(batch_drafts(16)).await;

        assert!(queued.lock().await.is_empty());
        assert_eq!(
            state
                .security_events
                .list_by_tenant("t1", 0, i64::MAX, 100)
                .await
                .unwrap()
                .len(),
            16
        );
    }

    #[tokio::test]
    async fn batch_partial_result_retries_only_transient_entries() {
        let attempts = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let outcomes = Arc::new(tokio::sync::Mutex::new(
            [
                vec![
                    SecurityEventFallbackOutcome::Enqueued,
                    SecurityEventFallbackOutcome::Permanent("invalid payload".to_string()),
                    SecurityEventFallbackOutcome::Retryable("SQS unavailable".to_string()),
                ],
                vec![SecurityEventFallbackOutcome::Enqueued],
            ]
            .into(),
        ));
        let fallback = Arc::new(ControlledBatchFallback {
            attempts: attempts.clone(),
            outcomes,
        });
        let ingresses = batch_drafts(3)
            .into_iter()
            .filter_map(AppState::prepare_security_event)
            .map(SecurityEventIngress::new)
            .collect::<Vec<_>>();
        let event_ids = ingresses
            .iter()
            .map(|ingress| ingress.event.event_id.clone())
            .collect::<Vec<_>>();

        let emergency = AppState::enqueue_security_event_chunk(fallback, ingresses).await;

        assert_eq!(
            *attempts.lock().await,
            vec![event_ids.clone(), vec![event_ids[2].clone()]]
        );
        assert_eq!(emergency.len(), 1);
        assert_eq!(emergency[0].event.event_id, event_ids[1]);
        assert_eq!(
            emergency[0].delivery.status,
            SecurityEventDeliveryStatus::Failed
        );
        assert_eq!(emergency[0].delivery.attempts, 1);
        assert_eq!(
            emergency[0].delivery.history.last().unwrap().status,
            SecurityEventDeliveryStatus::Failed
        );
    }
}

#[cfg(test)]
mod subject_type_tests {
    use super::*;
    use std::collections::HashMap;

    fn saas() -> Form {
        Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        }
    }
    fn selfhosted() -> Form {
        Form::SelfHosted {
            configured_host: "auth.example.com".into(),
        }
    }

    // 审计 G:形态默认——SaaS pairwise(隐私默认)、SelfHosted public。
    #[test]
    fn form_defaults() {
        assert_eq!(resolve_subject_type(None, &saas()), SubjectType::Pairwise);
        assert_eq!(
            resolve_subject_type(None, &selfhosted()),
            SubjectType::Public
        );
    }

    // 显式 env 覆盖优先(企业 SaaS 租户 opt-in public;自部署 opt-in pairwise);大小写/空白不敏感。
    #[test]
    fn env_override_wins() {
        assert_eq!(
            resolve_subject_type(Some("public"), &saas()),
            SubjectType::Public
        );
        assert_eq!(
            resolve_subject_type(Some(" Pairwise "), &selfhosted()),
            SubjectType::Pairwise
        );
    }

    // 非法覆盖值回落形态默认(fail-safe,不 panic)。
    #[test]
    fn bad_override_falls_back_to_form_default() {
        assert_eq!(
            resolve_subject_type(Some("bogus"), &saas()),
            SubjectType::Pairwise
        );
        assert_eq!(
            resolve_subject_type(Some(""), &selfhosted()),
            SubjectType::Public
        );
    }

    #[test]
    fn saas_tenant_profiles_are_explicit_overrides_on_pairwise_default() {
        let configured = HashMap::from([
            ("t1".to_string(), "pairwise".to_string()),
            ("t3".to_string(), "public".to_string()),
        ]);
        let resolved = resolve_tenant_subject_types(
            &configured,
            &saas(),
            &["t1".to_string(), "t3".to_string()],
        )
        .unwrap();
        assert_eq!(resolved.get("t1"), Some(&SubjectType::Pairwise));
        assert_eq!(resolved.get("t3"), Some(&SubjectType::Public));
        assert_eq!(resolved.get("missing"), None);
    }

    #[test]
    fn tenant_profiles_reject_unknown_tenants_invalid_values_and_self_hosted() {
        assert!(resolve_tenant_subject_types(
            &HashMap::from([("t9".to_string(), "public".to_string())]),
            &saas(),
            &["t1".to_string()],
        )
        .is_err());
        assert!(resolve_tenant_subject_types(
            &HashMap::from([("t1".to_string(), "PUBLIC".to_string())]),
            &saas(),
            &["t1".to_string()],
        )
        .is_err());
        assert!(resolve_tenant_subject_types(
            &HashMap::from([("t1".to_string(), "public".to_string())]),
            &selfhosted(),
            &[],
        )
        .is_err());
    }

    #[test]
    fn redirect_prefix_hosts_are_tenant_scoped_normalized_and_default_off() {
        let resolved = resolve_redirect_prefix_allowed_hosts(
            &HashMap::from([
                (
                    "t1".to_string(),
                    vec![
                        "Callbacks.Example.com.".to_string(),
                        "login.example.com".to_string(),
                    ],
                ),
                ("t3".to_string(), Vec::new()),
            ]),
            &saas(),
            &["t1".to_string(), "t3".to_string()],
        )
        .unwrap();

        assert_eq!(
            resolved.get("t1").unwrap(),
            &std::collections::BTreeSet::from([
                "callbacks.example.com".to_string(),
                "login.example.com".to_string(),
            ])
        );
        assert!(resolved.get("t3").unwrap().is_empty());
        assert_eq!(resolved.get("missing"), None);
    }

    #[test]
    fn redirect_prefix_hosts_reject_unknown_tenants_duplicates_and_invalid_hosts() {
        assert!(resolve_redirect_prefix_allowed_hosts(
            &HashMap::from([("t9".to_string(), vec!["callbacks.example.com".to_string()])]),
            &saas(),
            &["t1".to_string()],
        )
        .is_err());
        assert!(resolve_redirect_prefix_allowed_hosts(
            &HashMap::from([(
                "t1".to_string(),
                vec![
                    "Callbacks.Example.com".to_string(),
                    "callbacks.example.com.".to_string(),
                ],
            )]),
            &saas(),
            &["t1".to_string()],
        )
        .is_err());
        for host in [
            "https://callbacks.example.com",
            "*.example.com",
            "callbacks.example.com/path",
            "127.0.0.1",
            "-callbacks.example.com",
            "callbacks..example.com",
        ] {
            assert!(resolve_redirect_prefix_allowed_hosts(
                &HashMap::from([("t1".to_string(), vec![host.to_string()])]),
                &saas(),
                &["t1".to_string()],
            )
            .is_err());
        }
        assert!(resolve_redirect_prefix_allowed_hosts(
            &HashMap::from([("t1".to_string(), vec!["callbacks.example.com".to_string()],)]),
            &selfhosted(),
            &[],
        )
        .is_err());
        assert!(resolve_redirect_prefix_allowed_hosts(
            &HashMap::from([(
                "default".to_string(),
                vec!["callbacks.example.com".to_string()],
            )]),
            &selfhosted(),
            &[],
        )
        .is_ok());
    }

    #[test]
    fn saas_rejects_the_legacy_fleet_wide_subject_override() {
        assert!(validate_subject_type_override(Some("public"), &saas()).is_err());
        assert!(validate_subject_type_override(Some("  "), &saas()).is_ok());
        assert!(validate_subject_type_override(Some("pairwise"), &selfhosted()).is_ok());
    }

    #[test]
    fn every_user_subject_issuance_path_uses_the_tenant_resolver() {
        for (path, source) in [
            ("discovery", include_str!("discovery.rs")),
            ("authorize", include_str!("authorize.rs")),
            ("token", include_str!("token.rs")),
            ("refresh", include_str!("refresh_flow.rs")),
            ("device", include_str!("device_flow.rs")),
            ("ciba", include_str!("ciba_flow.rs")),
            ("exchange", include_str!("token_exchange.rs")),
            ("ema", include_str!("ema_flow.rs")),
            ("register", include_str!("register.rs")),
            ("admin", include_str!("admin.rs")),
        ] {
            assert!(
                source.contains("subject_type_for_tenant("),
                "{path} must resolve the request tenant subject profile"
            );
        }
    }

    #[test]
    fn saas_form_does_not_require_the_self_hosted_issuer_host() {
        assert_eq!(
            resolve_deployment_form(
                Some("SAAS"),
                None,
                Some("aws.example.com".into()),
                Some("c.aws.example.com".into()),
            )
            .unwrap(),
            saas()
        );
        assert!(resolve_deployment_form(
            Some("saas"),
            None,
            None,
            Some("c.aws.example.com".into()),
        )
        .is_err());
    }

    #[test]
    fn self_hosted_and_unknown_forms_still_require_an_issuer_host() {
        assert!(resolve_deployment_form(None, None, None, None).is_err());
        assert!(resolve_deployment_form(Some("unknown"), None, None, None).is_err());
        assert_eq!(
            resolve_deployment_form(None, Some("auth.example.com".into()), None, None,).unwrap(),
            selfhosted()
        );
    }

    #[test]
    fn saas_passkeys_require_tenant_partitioning() {
        assert!(validate_passkey_tenant_isolation(&saas(), true, false).is_err());
        assert!(validate_passkey_tenant_isolation(&saas(), true, true).is_ok());
        assert!(validate_passkey_tenant_isolation(&saas(), false, false).is_ok());
        assert!(validate_passkey_tenant_isolation(&selfhosted(), true, false).is_ok());
    }

    #[test]
    fn web_base_url_requires_public_https_origin() {
        assert_eq!(
            validate_web_base_url(Some("https://example.cloudfront.net/")).unwrap(),
            "https://example.cloudfront.net"
        );
        assert_eq!(
            validate_web_base_url(Some("https://auth.example.com")).unwrap(),
            "https://auth.example.com"
        );
        assert!(validate_web_base_url(None).is_err());
        assert!(validate_web_base_url(Some("http://auth.example.com")).is_err());
        assert!(validate_web_base_url(Some("https://auth.example.com/login")).is_err());
        assert!(
            validate_web_base_url(Some("https://example.execute-api.us-east-1.amazonaws.com"))
                .is_err()
        );
    }
}
