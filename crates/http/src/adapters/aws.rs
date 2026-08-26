//! AWS 适配器(`aws` feature)——真机:KMS 签名 + DynamoDB 存储。
//!
//! - `KmsSigner`:KMS `Sign`(ECDSA_SHA_256,RAW)→ `der_to_jose`(005 C10.3)→ JOSE r‖s;
//!   `GetPublicKey`(SPKI DER)→ `ec_jwk_from_spki_der`(C10.11a)→ EcJwk。KMS throttle → Transient(C10.2)。
//! - `DynamoCodeStore`:授权码落 DynamoDB,实现**两阶段 lease**(C10.1):`acquire_lease` 用
//!   条件 `UpdateItem` 原子占 signing lease(并发只一个成功)→ 校验 + 签名后 `finalize`(标 consumed);
//!   授权语义失败以单次 `TransactWriteItems` 同时 finalize code + 迁 authz session;
//!   签名前瞬时失败 `release_lease`(清 lease、不消费,可重试)。区分 Locked/AlreadyConsumed/NotFound。
//! - `DynamoClientStore`:client 记录。
//! - 错误分类 `ddb_err`:节流/内部错 → Transient(可重试),其余 → Permanent(不掩盖配置错)。
//!
//! 与内存适配器同 trait(`ports::*`),handler 零改切换。协议决策不在此;适配器只做 IO。

use crate::ports::{
    AuthzEventSink, AuthzSessionRecord, AuthzSessionStore, ClientRecord, ClientStore,
    CodeIssueOutcome, CodeRecord, CodeStore, GraceCacheEntry, GraceCachedResponse, GraceStore,
    InitialAccessTokenStore, InvitationAcceptOutcome, InvitationAcceptRequest,
    InvitationIssueOutcome, InvitationRecord, InvitationStore, LeaseAcquire, MagicLinkRecord,
    MagicLinkStore, MessageOutbox, Notifier, PasskeyRegistrationOutcome, PasskeyStore,
    PasswordStore, RecoveryAuthorityConsume, RecoveryCodeEntry, RecoveryConsume,
    RecoveryConsumeRequest, RecoveryRecord, RecoveryStore, RecoverySuccessResult,
    RefreshFamilyRecord, RefreshLeaseAcquire, RefreshStore, SentMessage, SessionRecord,
    SessionStore, Signer, SignerError, StoreError, UsersStore,
};
use agent_auth_infra_core::signature::der_to_jose;
use agent_auth_infra_core::{ec_jwk_from_spki_der, EcJwk};
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

mod signing;
pub use signing::KmsSigner;

/// DynamoDB 错误分类(修 Kiro#10):节流/内部错 → Transient(可重试);其余(校验错、
/// 资源不存在等配置/永久错)→ Permanent。用 SDK 的错误分类而非字符串匹配。
fn ddb_err<E, R>(e: aws_sdk_dynamodb::error::SdkError<E, R>) -> StoreError
where
    aws_sdk_dynamodb::error::SdkError<E, R>: ProvideErrorMetadata,
{
    if matches!(
        &e,
        aws_sdk_dynamodb::error::SdkError::TimeoutError(_)
            | aws_sdk_dynamodb::error::SdkError::DispatchFailure(_)
            | aws_sdk_dynamodb::error::SdkError::ResponseError(_)
    ) {
        return StoreError::Transient("DynamoDB request transport failure".to_string());
    }
    // 节流(ThrottlingException/ProvisionedThroughputExceeded/RequestLimitExceeded)→ Transient。
    let code = e.code().unwrap_or("");
    let throttle = code.contains("Throttling")
        || code.contains("ProvisionedThroughputExceeded")
        || code.contains("RequestLimitExceeded")
        || code.contains("InternalServerError")
        || code.contains("TransactionConflict")
        || code.contains("TransactionInProgress");
    if throttle {
        StoreError::Transient(code.to_string())
    } else {
        StoreError::Permanent(format!("{code}: {}", e.message().unwrap_or("")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionCancelAction {
    RetryCondition,
    Transient,
    Permanent,
}

const TRANSACTION_RETRY_ATTEMPTS: usize = 5;
const IDEMPOTENT_TRANSACTION_REPLAY_ATTEMPTS: usize = 2;

fn transaction_retry_delay(attempt: usize) -> Option<std::time::Duration> {
    (attempt + 1 < TRANSACTION_RETRY_ATTEMPTS)
        .then(|| std::time::Duration::from_millis(10u64 << attempt))
}

fn transaction_request_token() -> String {
    let mut bytes = [0u8; 27];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn send_idempotent_transaction(
    request: aws_sdk_dynamodb::operation::transact_write_items::builders::TransactWriteItemsFluentBuilder,
) -> Result<bool, StoreError> {
    send_idempotent_transaction_with_token(request, transaction_request_token()).await
}

async fn send_idempotent_transaction_with_token(
    request: aws_sdk_dynamodb::operation::transact_write_items::builders::TransactWriteItemsFluentBuilder,
    token: String,
) -> Result<bool, StoreError> {
    let request = request.client_request_token(token);
    for attempt in 0..IDEMPOTENT_TRANSACTION_REPLAY_ATTEMPTS {
        match request.clone().send().await {
            Ok(_) => return Ok(true),
            Err(error) => {
                let classified = match classify_transact_write_error(&error) {
                    Some((TransactionCancelAction::RetryCondition, _)) => return Ok(false),
                    Some((TransactionCancelAction::Permanent, classified)) => {
                        return Err(classified)
                    }
                    Some((TransactionCancelAction::Transient, classified)) => classified,
                    None => ddb_err(error),
                };
                if !matches!(classified, StoreError::Transient(_))
                    || attempt + 1 == IDEMPOTENT_TRANSACTION_REPLAY_ATTEMPTS
                {
                    return Err(classified);
                }
            }
        }
    }
    unreachable!("idempotent transaction replay loop always returns")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityConflictAction {
    Noop,
    Retry(std::time::Duration),
    Exhausted,
}

fn owned_delete_conflict_action(
    attempt: usize,
    actor_is_authoritative: bool,
    target_is_authoritative: bool,
) -> AuthorityConflictAction {
    if !actor_is_authoritative || !target_is_authoritative {
        AuthorityConflictAction::Noop
    } else if let Some(delay) = transaction_retry_delay(attempt) {
        AuthorityConflictAction::Retry(delay)
    } else {
        AuthorityConflictAction::Exhausted
    }
}

fn retained_fence_conflict_action(
    attempt: usize,
    attempted_generation: u64,
    observed_generation: u64,
    retained_is_authoritative: bool,
) -> AuthorityConflictAction {
    if observed_generation != attempted_generation || !retained_is_authoritative {
        AuthorityConflictAction::Noop
    } else if let Some(delay) = transaction_retry_delay(attempt) {
        AuthorityConflictAction::Retry(delay)
    } else {
        AuthorityConflictAction::Exhausted
    }
}

fn classify_transaction_cancellation(
    canceled: &aws_sdk_dynamodb::types::error::TransactionCanceledException,
) -> TransactionCancelAction {
    let codes: Vec<_> = canceled
        .cancellation_reasons()
        .iter()
        .filter_map(|reason| reason.code())
        .filter(|code| *code != "None")
        .collect();
    if codes
        .iter()
        .any(|code| matches!(*code, "ValidationError" | "ItemCollectionSizeLimitExceeded"))
    {
        return TransactionCancelAction::Permanent;
    }
    if !codes.is_empty() && codes.iter().all(|code| *code == "ConditionalCheckFailed") {
        return TransactionCancelAction::RetryCondition;
    }
    TransactionCancelAction::Transient
}

fn transaction_cancellation_error(
    canceled: &aws_sdk_dynamodb::types::error::TransactionCanceledException,
    action: TransactionCancelAction,
) -> StoreError {
    let mut codes: Vec<_> = canceled
        .cancellation_reasons()
        .iter()
        .filter_map(|reason| reason.code())
        .filter(|code| *code != "None")
        .collect();
    codes.sort_unstable();
    codes.dedup();
    let summary = if codes.is_empty() {
        "no cancellation reasons".to_string()
    } else {
        codes.join(",")
    };
    match action {
        TransactionCancelAction::Permanent => {
            StoreError::Permanent(format!("DynamoDB transaction canceled: {summary}"))
        }
        TransactionCancelAction::RetryCondition | TransactionCancelAction::Transient => {
            StoreError::Transient(format!("DynamoDB transaction canceled: {summary}"))
        }
    }
}

fn classify_transact_write_error<R>(
    error: &aws_sdk_dynamodb::error::SdkError<
        aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError,
        R,
    >,
) -> Option<(TransactionCancelAction, StoreError)> {
    let aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException(
        canceled,
    ) = error.as_service_error()?
    else {
        return None;
    };
    let action = classify_transaction_cancellation(canceled);
    Some((action, transaction_cancellation_error(canceled, action)))
}

fn s(v: Option<&AttributeValue>) -> Option<String> {
    v.and_then(|a| a.as_s().ok()).cloned()
}
fn n_i64(v: Option<&AttributeValue>) -> Option<i64> {
    v.and_then(|a| a.as_n().ok()).and_then(|s| s.parse().ok())
}
fn n_f64(v: Option<&AttributeValue>) -> Option<f64> {
    v.and_then(|a| a.as_n().ok()).and_then(|s| s.parse().ok())
}
fn ss(v: Option<&AttributeValue>) -> Vec<String> {
    v.and_then(|a| a.as_l().ok())
        .map(|l| l.iter().filter_map(|x| x.as_s().ok().cloned()).collect())
        .unwrap_or_default()
}

fn insert_cimd_snapshot(
    item: &mut HashMap<String, AttributeValue>,
    snapshot: Option<crate::cimd::CimdClientSnapshot>,
    record_type: &str,
) -> Result<(), StoreError> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let value = serde_json::to_string(&snapshot).map_err(|error| {
        StoreError::Permanent(format!(
            "failed to serialize {record_type} CIMD snapshot: {error}"
        ))
    })?;
    item.insert("cimd_snapshot".to_string(), AttributeValue::S(value));
    Ok(())
}

fn read_cimd_snapshot(
    item: &HashMap<String, AttributeValue>,
    record_type: &str,
) -> Result<Option<crate::cimd::CimdClientSnapshot>, StoreError> {
    let Some(value) = item.get("cimd_snapshot") else {
        return Ok(None);
    };
    let value = value.as_s().map_err(|_| {
        StoreError::Permanent(format!("{record_type} CIMD snapshot is not a string"))
    })?;
    serde_json::from_str(value).map(Some).map_err(|error| {
        StoreError::Permanent(format!("invalid {record_type} CIMD snapshot: {error}"))
    })
}

/// **tenant-scoped 物理分区键**(spec 020 §2.3 D1):`{tenant}\x1f{key}`;**空 tenant → 原样 key**
/// (flag 关 = 与分区前字节等价,现网旧表旧数据零迁移)。复用 `crate::tenant::tpk` 同一编码。
/// 属性名不变(仍 `client_id`/`user_id`…),只是**值**带 tenant 前缀——故 flag 关时既有表零 schema 变更。
fn tpk(tenant: &str, key: &str) -> String {
    crate::tenant::tpk(tenant, key)
}
/// 从物理键剥回逻辑 key(读路径):有 `\x1f` → 取分隔符后段;无 → 原样(空 tenant 存的旧值)。
fn strip_tpk(physical: &str) -> String {
    match physical.split_once('\u{1f}') {
        Some((_tenant, key)) => key.to_string(),
        None => physical.to_string(),
    }
}

fn tenant_from_tpk(physical: &str) -> String {
    physical
        .split_once(crate::tenant::SEP)
        .map(|(tenant, _key)| tenant.to_string())
        .unwrap_or_default()
}

fn json_attr<T: serde::Serialize>(value: &T) -> Result<AttributeValue, StoreError> {
    serde_json::to_string(value)
        .map(AttributeValue::S)
        .map_err(|error| StoreError::Permanent(format!("serialize credential record: {error}")))
}

fn json_from_attr<T: serde::de::DeserializeOwned>(value: Option<&AttributeValue>) -> Option<T> {
    value
        .and_then(|value| value.as_s().ok())
        .and_then(|value| serde_json::from_str(value).ok())
}

mod credential_authority;
use credential_authority::n_u64;
pub use credential_authority::{
    DynamoCodeStore, DynamoInvitationStore, DynamoMagicLinkStore, DynamoNotifier,
    DynamoPasskeyChallengeStore, DynamoPasskeyStore, DynamoPasswordStore, DynamoRecoveryStore,
    DynamoRefreshStore, DynamoSessionStore,
};
mod attribute_namespaces;
#[cfg(test)]
mod authority_reference_atomicity_tests;
mod authority_refs;
mod federation_attribute_mappings;
#[cfg(test)]
mod recovery_rotation_idempotency_tests;
#[cfg(test)]
mod recovery_success_idempotency_tests;
use authority_refs::DynamoAuthorityReferenceStore;
pub use authority_refs::{
    authority_reference_migration_version, AuthorityReferenceMigrationProgress,
    AuthorityReferenceMigrationStats, DynamoAuthorityReferenceMigrator,
    AUTHORITY_REFERENCE_SCHEMA_VERSION,
};

mod clients;
pub use clients::{DynamoClientStore, DynamoInitialAccessTokenStore};

mod identity_federation;
pub use identity_federation::{
    DynamoAdminAuthStore, DynamoFederationConfigStore, DynamoFederationFlowStore,
    DynamoWorkloadTrustStore, HttpJwksFetcher, HttpStsCaller, HttpUpstreamTokenExchanger,
    SecretsManagerResolver,
};

mod ciba_device;
#[cfg(all(test, feature = "transport-test"))]
pub(crate) use ciba_device::pinned_https_client_builder_for_addrs;
pub(crate) use ciba_device::{pinned_https_client, PinnedHttpsClientError};
pub use ciba_device::{DynamoCibaStore, DynamoDeviceStore, HttpCibaCallbackDelivery};

mod authorization;
pub use authorization::{
    DynamoAuthzSessionStore, DynamoDomainMapStore, DynamoGraceStore, DynamoGrantStore,
    DynamoJtiStore, DynamoParStore, DynamoPolicyArtifactStore, DynamoPolicyVersionStore,
    DynamoRateLimitStore, DynamoReplayStore, EventBridgeAuthzEventSink, NoopAuthzEventSink,
};

mod governance;
mod governance_queue;
mod governance_resources;
use governance_resources::{governance_delete_by_subject, governance_delete_by_tenant_key};
mod kms_regions;
mod region;
mod scim_groups;
mod security_events;
mod ssf;
mod ssf_push;
mod tenant_key_provisioner;
mod tenant_keys;
mod users;

pub use attribute_namespaces::DynamoAttributeNamespaceStore;
pub use federation_attribute_mappings::DynamoFederationAttributeMappingsStore;
pub use governance::DynamoGovernanceStore;
pub use governance_queue::SqsGovernanceJobQueue;
pub use region::DynamoRegionControlStore;
pub use scim_groups::DynamoScimGroupsStore;
pub use security_events::{DynamoSecurityEventStore, SqsSecurityEventFallback};
pub use ssf::DynamoSsfStore;
pub use ssf_push::HttpSsfPushClient;
pub use tenant_key_provisioner::AwsTenantKeyProvisioningBackend;
pub use tenant_keys::{DynamoTenantKeyRegistry, SqsTenantKeyCommandSink};
pub(crate) use users::AuthorizedFederatedReconciliation;
pub use users::DynamoUsersStore;

#[cfg(test)]
mod transaction_cancellation_tests {
    use super::{
        classify_transaction_cancellation, ddb_err, owned_delete_conflict_action,
        retained_fence_conflict_action, transaction_cancellation_error, transaction_retry_delay,
        AuthorityConflictAction, TransactionCancelAction,
    };
    use crate::ports::StoreError;
    use aws_sdk_dynamodb::types::{error::TransactionCanceledException, CancellationReason};

    fn canceled(codes: &[Option<&str>]) -> TransactionCanceledException {
        let mut builder = TransactionCanceledException::builder();
        for code in codes {
            let reason = match code {
                Some(code) => CancellationReason::builder()
                    .code(*code)
                    .message("sensitive backend detail")
                    .build(),
                None => CancellationReason::builder().build(),
            };
            builder = builder.cancellation_reasons(reason);
        }
        builder.build()
    }

    #[test]
    fn only_conditional_failures_are_retried_for_business_reclassification() {
        let error = canceled(&[None, Some("ConditionalCheckFailed")]);
        assert_eq!(
            classify_transaction_cancellation(&error),
            TransactionCancelAction::RetryCondition
        );
    }

    #[test]
    fn capacity_conflicts_and_missing_reasons_are_transient() {
        for codes in [
            vec![Some("TransactionConflict")],
            vec![Some("ProvisionedThroughputExceeded")],
            vec![Some("ThrottlingError")],
            vec![],
        ] {
            assert_eq!(
                classify_transaction_cancellation(&canceled(&codes)),
                TransactionCancelAction::Transient
            );
        }
    }

    #[test]
    fn validation_and_collection_limit_failures_are_permanent_and_redacted() {
        for code in ["ValidationError", "ItemCollectionSizeLimitExceeded"] {
            let canceled = canceled(&[Some("ConditionalCheckFailed"), Some(code)]);
            assert_eq!(
                classify_transaction_cancellation(&canceled),
                TransactionCancelAction::Permanent
            );
            let error =
                transaction_cancellation_error(&canceled, TransactionCancelAction::Permanent);
            assert_eq!(
                error,
                StoreError::Permanent(format!(
                    "DynamoDB transaction canceled: ConditionalCheckFailed,{code}"
                ))
            );
        }
    }

    #[test]
    fn transaction_backoff_is_exponential_and_bounded() {
        let delays: Vec<_> = (0..5).map(transaction_retry_delay).collect();
        assert_eq!(
            delays,
            vec![
                Some(std::time::Duration::from_millis(10)),
                Some(std::time::Duration::from_millis(20)),
                Some(std::time::Duration::from_millis(40)),
                Some(std::time::Duration::from_millis(80)),
                None,
            ]
        );
    }

    #[test]
    fn owned_delete_conflicts_retry_only_while_both_sessions_are_authoritative() {
        assert_eq!(
            owned_delete_conflict_action(0, true, true),
            AuthorityConflictAction::Retry(std::time::Duration::from_millis(10))
        );
        assert_eq!(
            owned_delete_conflict_action(0, false, true),
            AuthorityConflictAction::Noop
        );
        assert_eq!(
            owned_delete_conflict_action(0, true, false),
            AuthorityConflictAction::Noop
        );
        assert_eq!(
            owned_delete_conflict_action(4, true, true),
            AuthorityConflictAction::Exhausted
        );
    }

    #[test]
    fn retained_fence_conflicts_noop_after_another_authority_change() {
        assert_eq!(
            retained_fence_conflict_action(0, 4, 5, true),
            AuthorityConflictAction::Noop
        );
        assert_eq!(
            retained_fence_conflict_action(0, 4, 4, false),
            AuthorityConflictAction::Noop
        );
        assert_eq!(
            retained_fence_conflict_action(0, 4, 4, true),
            AuthorityConflictAction::Retry(std::time::Duration::from_millis(10))
        );
        assert_eq!(
            retained_fence_conflict_action(4, 4, 4, true),
            AuthorityConflictAction::Exhausted
        );
    }

    #[test]
    fn sdk_transport_failures_are_transient_but_construction_failures_are_permanent() {
        use aws_sdk_dynamodb::{
            error::{ConnectorError, SdkError},
            operation::get_item::GetItemError,
        };

        let timeout = SdkError::<GetItemError, ()>::timeout_error(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout detail",
        ));
        assert_eq!(
            ddb_err(timeout),
            StoreError::Transient("DynamoDB request transport failure".to_string())
        );

        let response = SdkError::<GetItemError, ()>::response_error(
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "response detail"),
            (),
        );
        assert_eq!(
            ddb_err(response),
            StoreError::Transient("DynamoDB request transport failure".to_string())
        );

        let dispatch =
            SdkError::<GetItemError, ()>::dispatch_failure(ConnectorError::io(Box::new(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "dispatch detail"),
            )));
        assert_eq!(
            ddb_err(dispatch),
            StoreError::Transient("DynamoDB request transport failure".to_string())
        );

        let construction = SdkError::<GetItemError, ()>::construction_failure(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "construction detail",
        ));
        assert!(matches!(ddb_err(construction), StoreError::Permanent(_)));
    }
}

#[cfg(test)]
mod federation_attribute_mappings_tests;

#[cfg(test)]
mod federation_attribute_reconciliation_tests;
