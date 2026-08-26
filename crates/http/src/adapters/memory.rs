//! 内存/进程内适配器 —— 本地开发 + 确定性测试用,**无 AWS 依赖**。
//!
//! - `MemorySigner`:进程内 P-256 ES256 签名(等价 KMS 的签名产物:裸 r‖s;公钥 JWK)。
//!   真机换 `adapters::aws::KmsSigner`(KMS Sign + der_to_jose)。
//! - `MemoryCodeStore` / `MemoryClientStore`:`Mutex<HashMap>`,真机换 DynamoDB 适配器。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Barrier, Mutex};

use crate::ports::{
    AuthzEventSink, AuthzSessionRecord, AuthzSessionStore, ClientRecord, ClientStore, CodeRecord,
    CodeStore, GovernanceJobQueue, GovernanceStore, GraceCacheEntry, GraceStore,
    InitialAccessTokenStore, InvitationAcceptOutcome, InvitationAcceptRequest,
    InvitationIssueOutcome, InvitationRecord, InvitationStore, LeaseAcquire, MagicLinkRecord,
    MagicLinkStore, MessageOutbox, Notifier, PasskeyRegistrationOutcome, RecoveryAuthorityConsume,
    RecoveryConsume, RecoveryConsumeRequest, RecoveryRecord, RecoveryStore, RecoverySuccessResult,
    RefreshFamilyRecord, RefreshLeaseAcquire, RefreshStore, SentMessage, SessionRecord,
    SessionStore, Signer, SignerError, StoreError,
};
use agent_auth_infra_core::jwks::{ec_kid, EcJwk};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

use crate::federation_attributes::FederationAttributeMappingsStore;

#[derive(Clone, Default)]
pub struct MemoryGovernanceJobQueue {
    commands: Arc<Mutex<Vec<crate::governance::GovernanceJobCommand>>>,
}

impl MemoryGovernanceJobQueue {
    pub async fn commands(&self) -> Vec<crate::governance::GovernanceJobCommand> {
        self.commands.lock().await.clone()
    }
}

impl GovernanceJobQueue for MemoryGovernanceJobQueue {
    async fn enqueue(
        &self,
        command: crate::governance::GovernanceJobCommand,
    ) -> Result<(), StoreError> {
        self.commands.lock().await.push(command);
        Ok(())
    }
}

/// 进程内 P-256 签名器(本地/测试)。
#[derive(Clone)]
pub struct MemorySigner {
    key: Arc<SigningKey>,
    kid: String,
    /// RSA 私钥(RS256 id_token;本地开发用,种子确定性生成)+ 其 kid。
    rsa_key: Arc<rsa::RsaPrivateKey>,
    rsa_kid: String,
    fail_next_es256: Arc<AtomicU8>,
    es256_sign_count: Arc<AtomicUsize>,
    published_ec_jwks: Vec<EcJwk>,
    published_rsa_jwks: Vec<agent_auth_infra_core::RsaJwk>,
}

impl MemorySigner {
    /// 从固定 32 字节种子构造(测试可复现);种子非密码学随机,仅本地用。
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed.into()).expect("valid P-256 scalar");
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false); // 未压缩 04||X||Y
        let x_b64 = URL_SAFE_NO_PAD.encode(point.x().expect("x"));
        let y_b64 = URL_SAFE_NO_PAD.encode(point.y().expect("y"));
        let kid = ec_kid("P-256", &x_b64, &y_b64);
        // RSA-2048(RS256 id_token):从种子确定性生成(仅本地/测试;真机走 KMS RSA CMK)。
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let (rsa_n, rsa_e) = {
            use rsa::traits::PublicKeyParts;
            (rsa_key.n().to_bytes_be(), rsa_key.e().to_bytes_be())
        };
        let rsa_jwk = agent_auth_infra_core::rsa_jwk_from_ne(&rsa_n, &rsa_e);
        let own_ec_jwk = EcJwk {
            kty: "EC",
            crv: "P-256",
            x: x_b64.clone(),
            y: y_b64.clone(),
            kid: kid.clone(),
            alg: "ES256",
            r#use: "sig",
        };
        MemorySigner {
            key: Arc::new(key),
            kid,
            rsa_key: Arc::new(rsa_key),
            rsa_kid: rsa_jwk.kid.clone(),
            fail_next_es256: Arc::new(AtomicU8::new(0)),
            es256_sign_count: Arc::new(AtomicUsize::new(0)),
            published_ec_jwks: vec![own_ec_jwk],
            published_rsa_jwks: vec![rsa_jwk],
        }
    }

    /// 开发默认种子(仅本地;真机绝不用固定种子)。**缓存单例**:RSA-2048 keygen 慢,固定种子的
    /// dev signer 全进程复用一把(避免每个 `AppState::dev()`/每条测试都重算 RSA key,DX 提速)。
    pub fn dev() -> Self {
        use std::sync::OnceLock;
        static DEV_SIGNER: OnceLock<MemorySigner> = OnceLock::new();
        DEV_SIGNER
            .get_or_init(|| Self::from_seed([7u8; 32]))
            .clone()
    }

    /// Test-only fault injection for the next ES256 signing call.
    pub fn fail_next_es256(&self, transient: bool) {
        self.fail_next_es256
            .store(if transient { 1 } else { 2 }, Ordering::SeqCst);
    }

    pub fn es256_sign_count(&self) -> usize {
        self.es256_sign_count.load(Ordering::SeqCst)
    }

    pub fn with_tenant_snapshot(
        mut self,
        snapshot: &agent_auth_infra_core::TenantKeySnapshot,
    ) -> Result<Self, SignerError> {
        if snapshot.ec.active.public_jwk.kid != self.kid
            || snapshot.rsa.active.public_jwk.kid != self.rsa_kid
        {
            return Err(SignerError::Permanent(
                "memory signer does not match tenant active EC/RSA generation".to_string(),
            ));
        }
        self.published_ec_jwks = snapshot
            .ec
            .published
            .iter()
            .map(|key| agent_auth_infra_core::EcJwk {
                kty: "EC",
                crv: "P-256",
                x: key.public_jwk.x.clone(),
                y: key.public_jwk.y.clone(),
                kid: key.public_jwk.kid.clone(),
                alg: "ES256",
                r#use: "sig",
            })
            .collect();
        self.published_rsa_jwks = snapshot
            .rsa
            .published
            .iter()
            .map(|key| agent_auth_infra_core::RsaJwk {
                kty: "RSA",
                n: key.public_jwk.n.clone(),
                e: key.public_jwk.e.clone(),
                kid: key.public_jwk.kid.clone(),
                alg: "RS256",
                r#use: "sig",
            })
            .collect();
        Ok(self)
    }
}

impl Signer for MemorySigner {
    async fn sign_es256(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.es256_sign_count.fetch_add(1, Ordering::SeqCst);
        match self.fail_next_es256.swap(0, Ordering::SeqCst) {
            1 => return Err(SignerError::Transient("injected signing failure".into())),
            2 => return Err(SignerError::Permanent("injected signing failure".into())),
            _ => {}
        }
        // p256 ecdsa 的 Signature::to_bytes() 即 JOSE 裸 r‖s(64 字节),与 KMS der_to_jose 产物一致。
        let sig: Signature = self.key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }

    async fn public_jwks(&self) -> Result<Vec<EcJwk>, SignerError> {
        Ok(self.published_ec_jwks.clone())
    }

    async fn active_kid(&self) -> Result<String, SignerError> {
        Ok(self.kid.clone())
    }

    async fn sign_rs256(&self, signing_input: &[u8]) -> Result<(String, Vec<u8>), SignerError> {
        use rsa::signature::{SignatureEncoding, Signer as _};
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new((*self.rsa_key).clone());
        let sig = signing_key.sign(signing_input);
        Ok((self.rsa_kid.clone(), sig.to_bytes().to_vec()))
    }

    async fn public_rsa_jwks(&self) -> Result<Vec<agent_auth_infra_core::RsaJwk>, SignerError> {
        Ok(self.published_rsa_jwks.clone())
    }

    async fn active_rsa_kid(&self) -> Result<String, SignerError> {
        Ok(self.rsa_kid.clone()) // 本地单 RSA key,活跃 kid 即它(与 sign_rs256 一致)
    }
}

/// 内存授权码存储(本地/测试),实现两阶段 lease(C10.1)。
/// 内部记录带 lease 状态:None=未占、Some(exp)=signing 到期时刻;consumed=已 finalize。
#[derive(Clone, Debug, PartialEq, Eq)]
struct CodeEntry {
    record: CodeRecord,
    lease_until: Option<i64>,
    lease_owner: Option<String>,
    consumed: bool,
    issued_grant_id: Option<String>,
    replay_detected: bool,
}

#[derive(Clone, Default)]
pub struct MemoryCodeStore {
    // **复合 tenant 键**(spec 020 §2.3 D1):键=(tenant, code)。
    map: Arc<Mutex<HashMap<(String, String), CodeEntry>>>,
    fail_next_finalize: Arc<AtomicU8>,
    fail_next_exchange_failure: Arc<AtomicU8>,
    fail_next_release: Arc<AtomicU8>,
    fail_next_release_permanent: Arc<AtomicU8>,
}

impl CodeStore for MemoryCodeStore {
    async fn put(&self, tenant: &str, record: CodeRecord) -> Result<(), StoreError> {
        self.map.lock().await.insert(
            (tenant.to_string(), record.code.clone()),
            CodeEntry {
                record,
                lease_until: None,
                lease_owner: None,
                consumed: false,
                issued_grant_id: None,
                replay_detected: false,
            },
        );
        Ok(())
    }

    async fn acquire_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<LeaseAcquire, StoreError> {
        let mut map = self.map.lock().await;
        let Some(entry) = map.get_mut(&(tenant.to_string(), code.to_string())) else {
            return Ok(LeaseAcquire::NotFound);
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, entry.record.expires_at) {
            return Ok(LeaseAcquire::NotFound);
        }
        if entry.consumed {
            return Ok(LeaseAcquire::AlreadyConsumed {
                record: entry.record.clone(),
                issued_grant_id: entry.issued_grant_id.clone(),
            });
        }
        // 有未过期的 signing lease → Locked(别人在签)。
        if let Some(until) = entry.lease_until {
            if now < until {
                return Ok(LeaseAcquire::Locked);
            }
        }
        // 占 lease(条件:无 lease 或已过期)。
        entry.lease_until = Some(lease_expires_at);
        entry.lease_owner = Some(lease_owner.to_string());
        Ok(LeaseAcquire::Acquired(entry.record.clone()))
    }

    async fn finalize(
        &self,
        tenant: &str,
        code: &str,
        _client_id: &str,
        _expires_at: i64,
        now: i64,
        lease_owner: &str,
        issued_grant_id: Option<&str>,
    ) -> Result<(), StoreError> {
        if self.fail_next_finalize.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected authorization code finalize failure".into(),
            ));
        }
        let mut map = self.map.lock().await;
        let Some(entry) = map.get_mut(&(tenant.to_string(), code.to_string())) else {
            return Err(StoreError::Permanent(
                "cannot finalize a missing authorization code".into(),
            ));
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, entry.record.expires_at)
            || entry.consumed
            || entry.lease_owner.as_deref() != Some(lease_owner)
        {
            return Err(StoreError::Transient(
                "authorization code lease ownership was lost".into(),
            ));
        }
        entry.consumed = true;
        entry.lease_until = None;
        entry.lease_owner = None;
        entry.issued_grant_id = issued_grant_id.map(str::to_string);
        Ok(())
    }

    async fn release_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        if self.fail_next_release_permanent.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Permanent(
                "injected permanent authorization code lease release failure".into(),
            ));
        }
        if self.fail_next_release.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected authorization code lease release failure".into(),
            ));
        }
        let mut map = self.map.lock().await;
        let Some(entry) = map.get_mut(&(tenant.to_string(), code.to_string())) else {
            return Err(StoreError::Permanent(
                "cannot release a missing authorization code lease".into(),
            ));
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, entry.record.expires_at)
            || entry.consumed
            || entry.lease_owner.as_deref() != Some(lease_owner)
        {
            return Err(StoreError::Transient(
                "authorization code lease ownership was lost".into(),
            ));
        }
        entry.lease_until = None;
        entry.lease_owner = None;
        Ok(())
    }

    async fn record_replay(&self, tenant: &str, code: &str, now: i64) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let Some(entry) = map.get_mut(&(tenant.to_string(), code.to_string())) else {
            return Err(StoreError::Permanent(
                "cannot mark replay for a missing authorization code".into(),
            ));
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, entry.record.expires_at) {
            return Ok(false);
        }
        if !entry.consumed {
            return Err(StoreError::Permanent(
                "cannot mark replay for an unconsumed authorization code".into(),
            ));
        }
        entry.replay_detected = true;
        Ok(true)
    }

    async fn replay_detected(&self, tenant: &str, code: &str) -> Result<bool, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), code.to_string()))
            .is_some_and(|entry| entry.replay_detected))
    }

    async fn has_unexpired_by_client(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        // 未消费 + 未过期 + 归属该 client + 本租户(内存强一致天然)。
        Ok(self.map.lock().await.iter().any(|((t, _), e)| {
            t == tenant
                && !e.consumed
                && e.record.client_id == client_id
                && e.record.expires_at > now
        }))
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), entry| {
            entry_tenant != tenant || entry.record.user_id != user_id
        });
        Ok(before - map.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

impl MemoryCodeStore {
    pub fn fail_next_finalize(&self) {
        self.fail_next_finalize.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_release_lease(&self) {
        self.fail_next_release.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_release_lease_permanently(&self) {
        self.fail_next_release_permanent.store(1, Ordering::SeqCst);
    }

    pub(crate) async fn finalize_exchange_failure(
        &self,
        authz_sessions: &MemoryAuthzSessionStore,
        tenant: &str,
        code: &str,
        _client_id: &str,
        _expires_at: i64,
        now: i64,
        lease_owner: &str,
        authz_session_id: Option<&str>,
        last_error: String,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let mut codes = self.map.lock().await;
        let code_key = (tenant.to_string(), code.to_string());
        let Some(code_entry) = codes.get_mut(&code_key) else {
            return Err(StoreError::Transient(
                "cannot finalize a missing authorization code".into(),
            ));
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(
            now,
            code_entry.record.expires_at,
        ) || code_entry.consumed
            || code_entry.lease_owner.as_deref() != Some(lease_owner)
        {
            return Err(StoreError::Transient(
                "authorization code lease ownership was lost".into(),
            ));
        }

        let Some(session_id) = authz_session_id else {
            if self.fail_next_exchange_failure.swap(0, Ordering::SeqCst) != 0 {
                return Err(StoreError::Transient(
                    "injected exchange failure commit failure".into(),
                ));
            }
            code_entry.consumed = true;
            code_entry.lease_until = None;
            code_entry.lease_owner = None;
            code_entry.issued_grant_id = None;
            return Ok(None);
        };
        if code_entry.record.authz_session_id.as_deref() != Some(session_id) {
            return Err(StoreError::Transient(
                "authorization code session binding changed during exchange failure".into(),
            ));
        }

        let mut sessions = authz_sessions.map.lock().await;
        let session_key = (tenant.to_string(), session_id.to_string());
        let Some(session) = sessions.get_mut(&session_key) else {
            return Err(StoreError::Transient(
                "authorization session is unavailable for exchange failure".into(),
            ));
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, session.expires_at) {
            return Err(StoreError::Transient(
                "authorization session expired during exchange failure".into(),
            ));
        }
        let next =
            crate::authz_session::prepare_exchange_failure_transition(session.clone(), last_error)?;
        if self.fail_next_exchange_failure.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected exchange failure commit failure".into(),
            ));
        }

        code_entry.consumed = true;
        code_entry.lease_until = None;
        code_entry.lease_owner = None;
        code_entry.issued_grant_id = None;
        *session = next.clone();
        Ok(Some(next))
    }

    pub fn fail_next_exchange_failure(&self) {
        self.fail_next_exchange_failure.store(1, Ordering::SeqCst);
    }

    pub(crate) async fn put_authorized(
        &self,
        users: &MemoryUsersStore,
        tenant: &str,
        record: CodeRecord,
        expected_epoch: u64,
    ) -> Result<crate::ports::CodeIssueOutcome, StoreError> {
        let users = if crate::user_gate::is_human_user(&record.user_id) {
            Some(users.by_id.lock().await)
        } else {
            None
        };
        if let Some(users) = users.as_ref() {
            let Some(user) = users.get(&(tenant.to_string(), record.user_id.clone())) else {
                return Ok(crate::ports::CodeIssueOutcome::AuthorityChanged);
            };
            if user.status != crate::ports::UserStatus::Active
                || user.revocation_pending
                || user.credential_epoch != expected_epoch
            {
                return Ok(crate::ports::CodeIssueOutcome::AuthorityChanged);
            }
        }

        let mut codes = self.map.lock().await;
        let key = (tenant.to_string(), record.code.clone());
        if codes.contains_key(&key) {
            return Ok(crate::ports::CodeIssueOutcome::CodeExists);
        }
        codes.insert(
            key,
            CodeEntry {
                record,
                lease_until: None,
                lease_owner: None,
                consumed: false,
                issued_grant_id: None,
                replay_detected: false,
            },
        );
        Ok(crate::ports::CodeIssueOutcome::Stored)
    }
}

/// 硬删审计留存条目(内存;spec 005 §9.5):(client_id, created_at, tombstoned_at, hard_deleted_at, last_used_day)。
type ClientAuditEntry = (String, i64, Option<i64>, i64, Option<i64>);

/// 内存 PAR 存储(本地/测试,spec 006 §7.3)。consume **fail-closed 校 expires_at**(不靠 TTL)。
#[derive(Clone, Default)]
pub struct MemoryParStore {
    map: Arc<Mutex<HashMap<(String, String), crate::ports::ParRecord>>>,
}

impl crate::ports::ParStore for MemoryParStore {
    async fn put(&self, tenant: &str, record: crate::ports::ParRecord) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.request_uri.clone()), record);
        Ok(())
    }
    async fn consume(
        &self,
        tenant: &str,
        request_uri: &str,
        now: i64,
    ) -> Result<Option<crate::ports::ParRecord>, StoreError> {
        // 一次性:取出即删。fail-closed:过期(expires_at <= now)视作无效(不靠 TTL,C10.4/H4)。
        match self
            .map
            .lock()
            .await
            .remove(&(tenant.to_string(), request_uri.to_string()))
        {
            Some(r) if r.expires_at > now => Ok(Some(r)),
            _ => Ok(None), // 不存在/已消费/过期
        }
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 BYOD 域名映射存储(本地/测试;spec 010 §5.4 / C8.1b)。**全局键 = 归一小写 domain**(非 tenant 分区)。
#[derive(Clone, Default)]
pub struct MemoryDomainMapStore {
    map: Arc<Mutex<HashMap<String, crate::ports::DomainBinding>>>,
}

impl crate::ports::DomainMapStore for MemoryDomainMapStore {
    async fn get(&self, domain: &str) -> Result<Option<crate::ports::DomainBinding>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&domain.to_ascii_lowercase())
            .cloned())
    }
    async fn put_if_absent(
        &self,
        binding: crate::ports::DomainBinding,
    ) -> Result<bool, StoreError> {
        // conditional put:仅当 domain 未被任何租户登记(全局唯一,防跨租户抢注)。
        let mut m = self.map.lock().await;
        let key = binding.domain.to_ascii_lowercase();
        if m.contains_key(&key) {
            return Ok(false); // 已被(他人)登记
        }
        m.insert(key, binding);
        Ok(true)
    }
    async fn delete_if_owner(&self, domain: &str, client_id: &str) -> Result<bool, StoreError> {
        // CAS on owner:仅当 owner 匹配才删(防删他人 / 换租户悬空)。
        let mut m = self.map.lock().await;
        let key = domain.to_ascii_lowercase();
        match m.get(&key) {
            Some(b) if b.client_id == client_id => {
                m.remove(&key);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn list_by_client(
        &self,
        client_id: &str,
    ) -> Result<Vec<crate::ports::DomainBinding>, StoreError> {
        // 反查 owner 的全部绑定(权威源;模拟 client_id-index GSI 全表过滤)。
        let m = self.map.lock().await;
        Ok(m.values()
            .filter(|b| b.client_id == client_id)
            .cloned()
            .collect())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, binding| binding.tenant_id != tenant_id);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存客户端存储(本地/测试)。`audit` 保留硬删的审计元数据(独立于 client 记录,C10.5;测试可观测)。
#[derive(Clone, Default)]
pub struct MemoryClientStore {
    // **复合 tenant 键**(spec 020 §2.3 D1,Kiro B1):键 = (tenant, client_id),与 Dynamo `{tenant}\x1f{pk}`
    // 分区语义同构——list/reclaim 遍历按 tenant 过滤,跨租户物理隔离(空 tenant = 现网单租户分区)。
    map: Arc<Mutex<HashMap<(String, String), ClientRecord>>>,
    audit: Arc<Mutex<Vec<ClientAuditEntry>>>,
    fail_next_touch_last_used: Arc<AtomicU8>,
}

impl MemoryClientStore {
    pub fn fail_next_touch_last_used(&self) {
        self.fail_next_touch_last_used.store(1, Ordering::SeqCst);
    }

    /// 测试观测:硬删审计条数。
    pub async fn audit_len(&self) -> usize {
        self.audit.lock().await.len()
    }
}

impl ClientStore for MemoryClientStore {
    async fn get(&self, tenant: &str, client_id: &str) -> Result<Option<ClientRecord>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), client_id.to_string()))
            .cloned())
    }

    async fn put(&self, tenant: &str, record: ClientRecord) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.client_id.clone()), record);
        Ok(())
    }

    async fn put_if_credential_versions(
        &self,
        tenant: &str,
        record: ClientRecord,
        expected_client_secret_version: u64,
        expected_registration_token_version: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), record.client_id.clone());
        let Some(stored) = map.get(&key) else {
            return Ok(false);
        };
        if stored.tombstoned_at.is_some()
            || stored.client_secret_credentials.version != expected_client_secret_version
            || stored.registration_token_credentials.version != expected_registration_token_version
            || stored.authority_revision != record.authority_revision
            || stored.last_used_day != record.last_used_day
        {
            return Ok(false);
        }
        map.insert(key, record);
        Ok(true)
    }

    async fn replace_credential_set(
        &self,
        tenant: &str,
        client_id: &str,
        kind: crate::credential::CredentialKind,
        expected_version: u64,
        credentials: crate::credential::CredentialSet,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), client_id.to_string())) else {
            return Ok(false);
        };
        if record.tombstoned_at.is_some() {
            return Ok(false);
        }
        match kind {
            crate::credential::CredentialKind::ClientSecret => {
                if record.client_secret_credentials.version != expected_version {
                    return Ok(false);
                }
                record.client_secret_credentials = credentials;
                record.client_secret = None;
                Ok(true)
            }
            crate::credential::CredentialKind::RegistrationAccessToken => {
                if record.registration_token_credentials.version != expected_version {
                    return Ok(false);
                }
                record.registration_token_credentials = credentials;
                record.reg_token_hash = None;
                Ok(true)
            }
            crate::credential::CredentialKind::InitialAccessToken => Ok(false),
        }
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ClientRecord>, StoreError> {
        // 仅本租户(按复合键第一元过滤);按 client_id 字典序稳定(spec 025)。
        let mut v: Vec<ClientRecord> = self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), _)| t == tenant)
            .map(|(_, r)| r.clone())
            .collect();
        v.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(v)
    }

    async fn delete(&self, tenant: &str, client_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), client_id.to_string()));
        Ok(())
    }

    async fn touch_last_used(
        &self,
        tenant: &str,
        client_id: &str,
        today: i64,
    ) -> Result<(), StoreError> {
        if self.fail_next_touch_last_used.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected client activity observation failure".into(),
            ));
        }
        // 条件写:仅当缺失或 < today 才写(同日仅一次;内存持锁天然原子)。
        if let Some(r) = self
            .map
            .lock()
            .await
            .get_mut(&(tenant.to_string(), client_id.to_string()))
        {
            if r.last_used_day.is_none_or(|d| d < today) {
                r.last_used_day = Some(today);
            }
        }
        Ok(())
    }

    async fn convert_to_tombstone(
        &self,
        tenant: &str,
        client_id: &str,
        tombstoned_at: i64,
        snapshot_day: Option<i64>,
        snapshot_authority_revision: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let Some(r) = map.get_mut(&(tenant.to_string(), client_id.to_string())) else {
            return Ok(false);
        };
        // 并发守卫:已 tombstone、last_used_day 前进或 authority 创建版本变化均跳过。
        if r.tombstoned_at.is_some()
            || r.last_used_day > snapshot_day
            || r.authority_revision != snapshot_authority_revision
        {
            return Ok(false);
        }
        r.tombstoned_at = Some(tombstoned_at);
        Ok(true)
    }

    async fn list_reclaim_candidates(
        &self,
        tenant: &str,
        older_than_day: i64,
    ) -> Result<Vec<(String, ClientRecord)>, StoreError> {
        // last_used_day 有值且 <= older_than_day(含已 tombstone,供判猶予期硬删);None(从未使用)不含。
        // **空 tenant = 全局回收扫描**(现网单租户 / D3b:reclaim 跨租户维护作业);非空 = 仅该租户。
        // 返回 (tenant, record):调用方后续按记录所属 tenant 回写(convert_to_tombstone/hard_delete)。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), _)| tenant.is_empty() || t == tenant)
            .filter(|(_, r)| r.last_used_day.is_some_and(|d| d <= older_than_day))
            .map(|((t, _), r)| (t.clone(), r.clone()))
            .collect())
    }

    async fn hard_delete_with_audit(
        &self,
        tenant: &str,
        record: &ClientRecord,
        hard_deleted_at: i64,
    ) -> Result<(), StoreError> {
        // 原子(内存持锁):先留审计,再删(审计"失败"内存不会发生,真机走 TransactWriteItems)。
        self.audit.lock().await.push((
            record.client_id.clone(),
            record.created_at,
            record.tombstoned_at,
            hard_deleted_at,
            record.last_used_day,
        ));
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), record.client_id.clone()));
        Ok(())
    }
}

/// 内存 initial access token 存储。复合 tenant key 与真机 tpk 语义一致。
#[derive(Clone, Default)]
pub struct MemoryInitialAccessTokenStore {
    map: Arc<Mutex<HashMap<(String, String), crate::credential::InitialAccessTokenRecord>>>,
}

impl InitialAccessTokenStore for MemoryInitialAccessTokenStore {
    async fn get(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> Result<Option<crate::credential::InitialAccessTokenRecord>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), token_id.to_string()))
            .cloned())
    }

    async fn put_new(
        &self,
        tenant: &str,
        record: crate::credential::InitialAccessTokenRecord,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), record.token_id.clone());
        if map.contains_key(&key) {
            return Ok(false);
        }
        map.insert(key, record);
        Ok(true)
    }

    async fn list(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::credential::InitialAccessTokenRecord>, StoreError> {
        let mut records: Vec<_> = self
            .map
            .lock()
            .await
            .iter()
            .filter(|((record_tenant, _), _)| record_tenant == tenant)
            .map(|(_, record)| record.clone())
            .collect();
        records.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        Ok(records)
    }

    async fn revoke(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), token_id.to_string())) else {
            return Ok(false);
        };
        if record.credential.status == crate::credential::CredentialStatus::Revoked {
            return Ok(true);
        }
        if record.version != expected_version {
            return Ok(false);
        }
        record.credential.status = crate::credential::CredentialStatus::Revoked;
        record.credential.expires_at = record.credential.expires_at.min(revoked_at);
        record.version = record.version.saturating_add(1);
        Ok(true)
    }

    async fn consume_once(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        used_at: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), token_id.to_string())) else {
            return Ok(false);
        };
        if record.version != expected_version
            || !record.one_time
            || record.used_at.is_some()
            || record.credential.status != crate::credential::CredentialStatus::Active
            || record.credential.expires_at <= used_at
        {
            return Ok(false);
        }
        record.used_at = Some(used_at);
        record.credential.status = crate::credential::CredentialStatus::Consumed;
        record.version = record.version.saturating_add(1);
        Ok(true)
    }

    async fn delete(&self, tenant: &str, token_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), token_id.to_string()));
        Ok(())
    }
}

/// 内存 workload 信任绑定存储(本地/测试,spec 012 C5.5)。
/// **复合 tenant 键**(spec 020 §2.3,评审 codex Low):键=(tenant, binding_id);binding_id 是 SPIFFE
/// 派生哈希(非随机),跨租户可碰撞,故写路径按 tenant 隔离。list_by_tenant 仍按记录 tenant_id 过滤。
#[derive(Clone, Default)]
pub struct MemoryWorkloadTrustStore {
    map: Arc<Mutex<HashMap<(String, String), agent_auth_workload::TrustBinding>>>,
}

impl crate::ports::WorkloadTrustStore for MemoryWorkloadTrustStore {
    async fn put(
        &self,
        tenant: &str,
        binding_id: String,
        binding: agent_auth_workload::TrustBinding,
    ) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), binding_id), binding);
        Ok(())
    }
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::ports::WorkloadTrustEntry>, StoreError> {
        // 按记录自身 tenant_id 过滤(认证路径口径不变;与物理键 tenant 一致)。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|(_, binding)| binding.tenant_id == tenant_id)
            .map(
                |((_, binding_id), binding)| crate::ports::WorkloadTrustEntry {
                    binding_id: binding_id.clone(),
                    binding: binding.clone(),
                },
            )
            .collect())
    }
    async fn delete(&self, tenant: &str, binding_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), binding_id.to_string()));
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, binding| binding.tenant_id != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存用户目录(本地/测试,spec 003 §1.4)。**复合 tenant 键 = (tenant, user_id)**(与 Dynamo pk 同构;
/// spec 020 §2.3 D1)。email 查询走扫描(email 只是次级定位;user_id 才是主键)。这样本地 email 用户
/// (`user:{email}`)与联邦用户(`user:fed:*`,email 空,审计 K)统一按 user_id 存,联邦用户不再因 email
/// 为空而键碰撞。幂等 upsert:同 user_id 复用。
#[derive(Clone, Default)]
pub struct MemoryUsersStore {
    by_id: Arc<Mutex<HashMap<(String, String), crate::ports::UserRecord>>>,
    credential_change_ids: Arc<Mutex<HashMap<(String, String), String>>>,
    scim_create_claims: Arc<Mutex<HashMap<ScimCreateClaimKey, MemoryScimCreateClaim>>>,
    governance_suppression: Option<MemoryGovernanceStore>,
    governance_hmac_key: Option<Arc<Vec<u8>>>,
    get_by_email_calls: Arc<AtomicUsize>,
    fail_next_get_by_id: Arc<AtomicU8>,
    get_by_id_status_transition: Arc<Mutex<Option<(u8, crate::ports::UserStatus)>>>,
    fail_next_get_by_email: Arc<AtomicU8>,
    fail_next_touch_last_login: Arc<AtomicU8>,
}

type ScimCreateClaimKey = (String, String, String);

#[derive(Clone)]
struct MemoryScimCreateClaim {
    user_id: String,
    pending_initial_epoch: Option<u64>,
}

fn find_user_by_email<'a>(
    map: &'a HashMap<(String, String), crate::ports::UserRecord>,
    tenant: &str,
    email: &str,
) -> Option<&'a crate::ports::UserRecord> {
    if email.is_empty() {
        return None;
    }
    map.iter()
        .find(|((t, _), record)| t == tenant && record.email == email)
        .map(|(_, record)| record)
}

impl MemoryUsersStore {
    pub fn fail_get_by_id_after(&self, successful_calls: u8) {
        self.fail_next_get_by_id
            .store(successful_calls.saturating_add(1), Ordering::SeqCst);
    }

    pub async fn transition_status_after_get_by_id(
        &self,
        successful_calls: u8,
        status: crate::ports::UserStatus,
    ) {
        *self.get_by_id_status_transition.lock().await =
            Some((successful_calls.saturating_add(1), status));
    }

    pub fn fail_next_get_by_email(&self) {
        self.fail_next_get_by_email.store(1, Ordering::SeqCst);
    }

    pub fn get_by_email_calls(&self) -> usize {
        self.get_by_email_calls.load(Ordering::SeqCst)
    }

    pub fn fail_next_touch_last_login(&self) {
        self.fail_next_touch_last_login.store(1, Ordering::SeqCst);
    }

    pub fn with_governance_suppression(
        mut self,
        governance: MemoryGovernanceStore,
        hmac_key: Arc<Vec<u8>>,
    ) -> Self {
        self.governance_suppression = Some(governance);
        self.governance_hmac_key = Some(hmac_key);
        self
    }

    pub(crate) async fn reconcile_federated_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        upstream_idp_id: &str,
        desired: &crate::federation_attributes::DesiredFederatedAttributes,
        registry_revision: u64,
    ) -> Result<crate::federation_attributes::FederationAttributeReconciliationOutcome, StoreError>
    {
        let mut users = self.by_id.lock().await;
        let Some(current) = users.get(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(
                crate::federation_attributes::FederationAttributeReconciliationOutcome::UserNotFound,
            );
        };
        let outcome = crate::federation_attributes::plan_federated_user_reconciliation(
            current,
            upstream_idp_id,
            desired,
            registry_revision,
        )?;
        if let crate::federation_attributes::FederationAttributeReconciliationOutcome::Applied {
            user,
            changed: true,
            ..
        } = &outcome
        {
            users.insert(
                (tenant.to_string(), user_id.to_string()),
                user.as_ref().clone(),
            );
        }
        Ok(outcome)
    }

    pub(crate) async fn purge_federated_attribute_owner(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        key: &str,
        expected_revision: u64,
        expected_owner: &crate::ports::FederatedAttributeOwner,
    ) -> Result<crate::federation_attributes::FederationAttributeOwnerPurgeOutcome, StoreError>
    {
        use crate::federation_attributes::FederationAttributeOwnerPurgeOutcome;

        let mut users = self.by_id.lock().await;
        let Some(current) = users.get(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(FederationAttributeOwnerPurgeOutcome::NotFound);
        };
        let outcome = crate::federation_attributes::plan_federated_attribute_owner_purge(
            current,
            namespace,
            key,
            expected_revision,
            expected_owner,
        )?;
        if let FederationAttributeOwnerPurgeOutcome::Purged { user, .. } = &outcome {
            users.insert(
                (tenant.to_string(), user_id.to_string()),
                user.as_ref().clone(),
            );
        }
        Ok(outcome)
    }

    async fn lock_suppression_guard(
        &self,
        tenant: &str,
        aliases: &[(crate::governance::GovernanceAliasKind, &str)],
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<MemoryGovernanceState>>, StoreError> {
        let (Some(governance), Some(hmac_key)) =
            (&self.governance_suppression, &self.governance_hmac_key)
        else {
            return Ok(None);
        };
        let logical_tenant = if tenant.is_empty() { "default" } else { tenant };
        let guard = governance.state.clone().lock_owned().await;
        for (kind, value) in aliases {
            let digest = crate::governance::suppression_digest(
                hmac_key,
                logical_tenant,
                "user",
                kind.as_str(),
                crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
                value,
            );
            if guard
                .suppressions
                .iter()
                .any(|(stored_tenant, class, stored_digest, _)| {
                    stored_tenant == logical_tenant && class == "user" && stored_digest == &digest
                })
            {
                return Err(StoreError::Permanent(
                    "identity alias is permanently suppressed".into(),
                ));
            }
        }
        Ok(Some(guard))
    }

    pub(crate) async fn begin_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        use crate::ports::{CredentialChangeStart, UserStatus};

        let epoch = expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(CredentialChangeStart::NotFound);
        };
        if record.revocation_pending
            && record.credential_epoch == epoch
            && operation_ids.get(&key).map(String::as_str) == Some(operation_id)
        {
            return Ok(CredentialChangeStart::Started { epoch });
        }
        if record.status == UserStatus::Tombstoned {
            return Ok(CredentialChangeStart::Ineligible);
        }
        if record.revocation_pending || record.credential_epoch != expected_epoch {
            return Ok(CredentialChangeStart::ConcurrentChange);
        }
        record.credential_epoch = epoch;
        record.revocation_pending = true;
        record.updated_at = now;
        operation_ids.insert(key, operation_id.to_string());
        Ok(CredentialChangeStart::Started { epoch })
    }

    pub(crate) async fn abort_admin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(false);
        };
        if record.status == crate::ports::UserStatus::Tombstoned
            || !record.revocation_pending
            || record.credential_epoch != owner.epoch
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(false);
        }
        record.revocation_pending = false;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(true)
    }
}

impl crate::ports::UsersStore for MemoryUsersStore {
    async fn create_or_get_by_email(
        &self,
        tenant: &str,
        email: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        let key = email.trim().to_lowercase();
        let _suppression_guard = self
            .lock_suppression_guard(
                tenant,
                &[
                    (crate::governance::GovernanceAliasKind::Email, &key),
                    (crate::governance::GovernanceAliasKind::CanonicalId, user_id),
                ],
            )
            .await?;
        let mut map = self.by_id.lock().await;
        // 幂等 upsert-by-email(与 Dynamo GSI email-index 语义等价):**先按 email 扫本租户命中即复用**
        // (不覆盖 created_at,即便传入了不同的 user_id——保持归一 email→同一记录);未命中再按传入
        // user_id 建。K 后 map 主键改为 user_id,故 by-email 复用必须显式扫描本租户(不能仅按 user_id 桶
        // 打开——那会让传不同 user_id 的两次调用建两条,违反归一 email 幂等)。
        if let Some(rec) = find_user_by_email(&map, tenant, &key).cloned() {
            return Ok(rec);
        }
        let storage_key = (tenant.to_string(), user_id.to_string());
        if map.contains_key(&storage_key) {
            return Err(StoreError::Permanent(
                "canonical user id is already bound to a different email".into(),
            ));
        }
        let rec = crate::ports::UserRecord {
            user_id: user_id.to_string(),
            email: key,
            created_at: now,
            updated_at: now,
            last_login_at: None,
            status: crate::ports::UserStatus::Active,
            credential_epoch: 0,
            revocation_pending: false,
            scim_external_id: None,
            scim_user_name: None,
            scim_display_name: None,
            attributes_generation: 0,
            attributes: Default::default(),
        };
        map.insert(storage_key, rec.clone());
        Ok(rec)
    }
    async fn create_or_get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::UserRecord, StoreError> {
        let _suppression_guard = self
            .lock_suppression_guard(
                tenant,
                &[(crate::governance::GovernanceAliasKind::CanonicalId, user_id)],
            )
            .await?;
        // 按 user_id 主键幂等 upsert(审计 K:联邦用户落表;email 空,不走 email 定位)。
        let rec = self
            .by_id
            .lock()
            .await
            .entry((tenant.to_string(), user_id.to_string()))
            .or_insert_with(|| crate::ports::UserRecord {
                user_id: user_id.to_string(),
                email: String::new(), // 联邦用户无 email 语义(F2:email 不参与身份)
                created_at: now,
                updated_at: now,
                last_login_at: None,
                status: crate::ports::UserStatus::Active,
                credential_epoch: 0,
                revocation_pending: false,
                scim_external_id: None,
                scim_user_name: None,
                scim_display_name: None,
                attributes_generation: 0,
                attributes: Default::default(),
            })
            .clone();
        Ok(rec)
    }
    async fn get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let failure_countdown = self.fail_next_get_by_id.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |remaining| remaining.checked_sub(1),
        );
        if matches!(failure_countdown, Ok(1)) {
            return Err(StoreError::Transient(
                "injected canonical user lookup failure".into(),
            ));
        }
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let result = map.get(&key).cloned();
        let mut transition = self.get_by_id_status_transition.lock().await;
        if let Some((remaining, status)) = transition.as_mut() {
            if *remaining == 1 {
                if let Some(record) = map.get_mut(&key) {
                    record.status = *status;
                }
                *transition = None;
            } else {
                *remaining -= 1;
            }
        }
        Ok(result)
    }
    async fn get_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        self.get_by_email_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next_get_by_email.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected email alias lookup failure".into(),
            ));
        }
        // 只读:按归一 email 扫描本租户(email 非主键;未注册 → None,绝不 create)。
        let key = email.trim().to_lowercase();
        let map = self.by_id.lock().await;
        Ok(find_user_by_email(&map, tenant, &key).cloned())
    }
    async fn create_scim(
        &self,
        tenant: &str,
        input: crate::ports::ScimUserInput,
    ) -> Result<crate::ports::ScimCreateOutcome, StoreError> {
        use crate::ports::{ScimCreateOutcome, UserStatus};

        let user_name = input.user_name.trim().to_lowercase();
        let _suppression_guard = self
            .lock_suppression_guard(
                tenant,
                &[
                    (
                        crate::governance::GovernanceAliasKind::CanonicalId,
                        &input.user_id,
                    ),
                    (
                        crate::governance::GovernanceAliasKind::ScimExternalId,
                        &input.external_id,
                    ),
                    (
                        crate::governance::GovernanceAliasKind::ScimUserName,
                        &user_name,
                    ),
                    (crate::governance::GovernanceAliasKind::Email, &user_name),
                ],
            )
            .await?;
        let active = input.active;
        let claim_key = (
            tenant.to_string(),
            input.external_id.clone(),
            user_name.clone(),
        );
        let mut claims = self.scim_create_claims.lock().await;
        let mut map = self.by_id.lock().await;
        if let Some(claim) = claims.get(&claim_key) {
            let record = map
                .get(&(tenant.to_string(), claim.user_id.clone()))
                .cloned()
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "SCIM create claim references a missing canonical user".into(),
                    )
                })?;
            return if record.status == UserStatus::Tombstoned {
                Ok(ScimCreateOutcome::Tombstoned)
            } else {
                Ok(ScimCreateOutcome::Existing {
                    record,
                    pending_initial_epoch: claim.pending_initial_epoch,
                })
            };
        }
        let external_match = map
            .iter()
            .find(|((t, _), record)| {
                t == tenant
                    && record.scim_external_id.as_deref() == Some(input.external_id.as_str())
            })
            .map(|(_, record)| record.clone());
        let user_name_match = map
            .iter()
            .find(|((t, _), record)| {
                t == tenant && record.scim_user_name.as_deref() == Some(user_name.as_str())
            })
            .map(|(_, record)| record.clone());
        match (external_match, user_name_match) {
            (Some(left), Some(right)) if left.user_id == right.user_id => {
                if left.status == UserStatus::Tombstoned {
                    return Ok(ScimCreateOutcome::Tombstoned);
                }
                claims.insert(
                    claim_key,
                    MemoryScimCreateClaim {
                        user_id: left.user_id.clone(),
                        pending_initial_epoch: None,
                    },
                );
                return Ok(ScimCreateOutcome::Existing {
                    record: left,
                    pending_initial_epoch: None,
                });
            }
            (Some(_), _) | (_, Some(_)) => return Ok(ScimCreateOutcome::Conflict),
            (None, None) => {}
        }

        let adopted_id =
            find_user_by_email(&map, tenant, &user_name).map(|record| record.user_id.clone());
        let user_id = adopted_id.unwrap_or(input.user_id);
        let key = (tenant.to_string(), user_id.clone());
        let record = map.entry(key).or_insert_with(|| crate::ports::UserRecord {
            user_id: user_id.clone(),
            email: user_name.clone(),
            created_at: input.now,
            updated_at: input.now,
            last_login_at: None,
            status: UserStatus::Active,
            credential_epoch: 0,
            revocation_pending: false,
            scim_external_id: None,
            scim_user_name: None,
            scim_display_name: None,
            attributes_generation: 0,
            attributes: Default::default(),
        });
        if record.status == UserStatus::Tombstoned {
            return Ok(ScimCreateOutcome::Tombstoned);
        }
        if record.scim_external_id.is_some() || record.scim_user_name.is_some() {
            return Ok(ScimCreateOutcome::Conflict);
        }
        let initial_epoch = record.credential_epoch;
        let disable_epoch = (!active)
            .then(|| crate::ports::next_disable_epoch(record.status, record.credential_epoch))
            .transpose()?;
        record.email = user_name.clone();
        record.updated_at = input.now;
        record.scim_external_id = Some(input.external_id);
        record.scim_user_name = Some(user_name);
        record.scim_display_name = input.display_name;
        if let Some(disable_epoch) = disable_epoch {
            record.credential_epoch = disable_epoch;
            record.status = UserStatus::Disabled;
            record.revocation_pending = true;
        }
        claims.insert(
            claim_key,
            MemoryScimCreateClaim {
                user_id: record.user_id.clone(),
                pending_initial_epoch: (!active).then_some(initial_epoch),
            },
        );
        Ok(ScimCreateOutcome::Created(record.clone()))
    }

    async fn begin_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimCreateLifecycleStart, StoreError> {
        use crate::ports::{ScimCreateLifecycleStart, UserStatus};

        let key = (
            tenant.to_string(),
            external_id.to_string(),
            user_name.trim().to_lowercase(),
        );
        let claims = self.scim_create_claims.lock().await;
        let Some(claim) = claims.get(&key) else {
            return Ok(ScimCreateLifecycleStart::Complete);
        };
        if claim.user_id != user_id {
            return Err(StoreError::Permanent(
                "SCIM create claim is bound to another canonical user".into(),
            ));
        }
        let Some(initial_epoch) = claim.pending_initial_epoch else {
            return Ok(ScimCreateLifecycleStart::Complete);
        };
        let mut map = self.by_id.lock().await;
        let record = map
            .get_mut(&(tenant.to_string(), user_id.to_string()))
            .ok_or_else(|| {
                StoreError::Permanent(
                    "SCIM create claim references a missing canonical user".into(),
                )
            })?;
        if record.status == UserStatus::Tombstoned {
            return Ok(ScimCreateLifecycleStart::Tombstoned);
        }
        if !record.revocation_pending
            && (record.credential_epoch != initial_epoch
                || (record.status == UserStatus::Disabled && record.credential_epoch != 0))
        {
            return Ok(ScimCreateLifecycleStart::Complete);
        }
        record.credential_epoch =
            crate::ports::next_disable_epoch(record.status, record.credential_epoch)?;
        record.status = UserStatus::Disabled;
        record.revocation_pending = true;
        record.updated_at = now;
        Ok(ScimCreateLifecycleStart::Ready {
            record: record.clone(),
            epoch: record.credential_epoch,
        })
    }

    async fn complete_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> Result<(), StoreError> {
        let key = (
            tenant.to_string(),
            external_id.to_string(),
            user_name.trim().to_lowercase(),
        );
        let mut claims = self.scim_create_claims.lock().await;
        let Some(claim) = claims.get_mut(&key) else {
            return Ok(());
        };
        if claim.user_id != user_id {
            return Err(StoreError::Permanent(
                "SCIM create claim is bound to another canonical user".into(),
            ));
        }
        claim.pending_initial_epoch = None;
        Ok(())
    }

    async fn get_scim_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        Ok(self
            .by_id
            .lock()
            .await
            .iter()
            .find(|((t, _), record)| {
                t == tenant && record.scim_external_id.as_deref() == Some(external_id)
            })
            .map(|(_, record)| record.clone()))
    }

    async fn get_scim_by_user_name(
        &self,
        tenant: &str,
        user_name: &str,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let user_name = user_name.trim().to_lowercase();
        Ok(self
            .by_id
            .lock()
            .await
            .iter()
            .find(|((t, _), record)| {
                t == tenant && record.scim_user_name.as_deref() == Some(user_name.as_str())
            })
            .map(|(_, record)| record.clone()))
    }

    async fn list_scim(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::UserRecord>, usize), StoreError> {
        let mut records: Vec<_> = self
            .by_id
            .lock()
            .await
            .iter()
            .filter(|((t, _), record)| {
                t == tenant
                    && record.scim_external_id.is_some()
                    && record.status != crate::ports::UserStatus::Tombstoned
            })
            .map(|(_, record)| record.clone())
            .collect();
        records.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        let total_results = records.len();
        Ok((
            records.into_iter().skip(offset).take(limit).collect(),
            total_results,
        ))
    }

    async fn replace_scim(
        &self,
        tenant: &str,
        user_id: &str,
        input: crate::ports::ScimReplaceInput,
    ) -> Result<crate::ports::ScimReplaceOutcome, StoreError> {
        use crate::ports::{ScimReplaceInput, ScimReplaceOutcome, UserStatus};

        let ScimReplaceInput {
            external_id,
            user_name,
            display_name,
            active,
            now,
        } = input;
        let user_name = user_name.trim().to_lowercase();
        let _suppression_guard = self
            .lock_suppression_guard(
                tenant,
                &[
                    (
                        crate::governance::GovernanceAliasKind::ScimExternalId,
                        &external_id,
                    ),
                    (
                        crate::governance::GovernanceAliasKind::ScimUserName,
                        &user_name,
                    ),
                    (crate::governance::GovernanceAliasKind::Email, &user_name),
                ],
            )
            .await?;
        let mut map = self.by_id.lock().await;
        if map.iter().any(|((t, id), record)| {
            t == tenant
                && id != user_id
                && (record.email == user_name
                    || record.scim_external_id.as_deref() == Some(external_id.as_str())
                    || record.scim_user_name.as_deref() == Some(user_name.as_str()))
        }) {
            return Ok(ScimReplaceOutcome::Conflict);
        }
        let Some(record) = map.get_mut(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(ScimReplaceOutcome::NotFound);
        };
        if record.scim_external_id.is_none() {
            return Ok(ScimReplaceOutcome::NotFound);
        }
        if record.status == UserStatus::Tombstoned {
            return Ok(ScimReplaceOutcome::Tombstoned);
        }
        let disable_epoch = (!active
            && (record.status == UserStatus::Active || record.credential_epoch == 0))
            .then(|| crate::ports::next_disable_epoch(record.status, record.credential_epoch))
            .transpose()?;
        record.email = user_name.clone();
        record.updated_at = now;
        record.scim_external_id = Some(external_id);
        record.scim_user_name = Some(user_name);
        record.scim_display_name = display_name;
        if let Some(disable_epoch) = disable_epoch {
            record.credential_epoch = disable_epoch;
            record.status = UserStatus::Disabled;
            record.revocation_pending = true;
        }
        Ok(ScimReplaceOutcome::Updated(record.clone()))
    }
    async fn list(
        &self,
        tenant: &str,
        limit: usize,
        cursor: Option<&str>,
        query: Option<&str>,
        status: crate::ports::UserListStatusFilter,
    ) -> Result<(Vec<crate::ports::UserRecord>, Option<String>), StoreError> {
        // 内存:仅本租户 + 按 email 稳定排序 + 偏移游标(cursor = 已返回条数的十进制串;非法 → Permanent→400)。
        let offset: usize = match cursor {
            None => 0,
            Some(c) => c
                .parse()
                .map_err(|_| StoreError::Permanent("bad cursor".into()))?,
        };
        let map = self.by_id.lock().await;
        let mut all: Vec<crate::ports::UserRecord> = map
            .iter()
            .filter(|((t, _), _)| t == tenant)
            .map(|(_, r)| r.clone())
            .collect();
        let query = query
            .map(|q| q.trim().to_lowercase())
            .filter(|q| !q.is_empty());
        if let Some(query) = query.as_deref() {
            all.retain(|record| {
                record.email.to_lowercase().contains(query)
                    || record.user_id.to_lowercase().contains(query)
            });
        }
        all.retain(|record| status.matches(record.status));
        all.sort_by(|a, b| a.user_id.cmp(&b.user_id)); // 按主键稳定排序(email 可空=联邦用户,不能靠 email)
        let page: Vec<_> = all.iter().skip(offset).take(limit).cloned().collect();
        let next = if offset + page.len() < all.len() {
            Some((offset + page.len()).to_string())
        } else {
            None
        };
        Ok((page, next))
    }
    async fn touch_last_login(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        if self.fail_next_touch_last_login.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected last-login observation failure".into(),
            ));
        }
        if let Some(rec) = self
            .by_id
            .lock()
            .await
            .get_mut(&(tenant.to_string(), user_id.to_string()))
        {
            if rec.status == crate::ports::UserStatus::Active
                && rec.last_login_at.is_none_or(|previous| previous < now)
            {
                rec.last_login_at = Some(now);
            }
        }
        Ok(())
    }
    async fn set_status(
        &self,
        tenant: &str,
        user_id: &str,
        status: crate::ports::UserStatus,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.by_id.lock().await;
        for ((t, _), rec) in map.iter_mut() {
            if t == tenant && rec.user_id == user_id {
                // **tombstone 终态(评审 codex Blocker)**:已 Tombstoned 拒改成其它态(仅允许幂等
                // 再置 Tombstoned)——防 delete→disable→enable 复活。返回 false(调用方按未改处理)。
                if rec.status == crate::ports::UserStatus::Tombstoned
                    && status != crate::ports::UserStatus::Tombstoned
                {
                    return Ok(false);
                }
                rec.status = status;
                rec.updated_at = now;
                // GDPR 级联(spec 007 §6.1):tombstone(admin 删除)时清空 attributes,不留孤儿个人数据。
                if status == crate::ports::UserStatus::Tombstoned {
                    rec.attributes.clear();
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn begin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> Result<crate::ports::CredentialChangeStart, StoreError> {
        use crate::ports::{CredentialChangeStart, UserStatus};

        let epoch = expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(CredentialChangeStart::NotFound);
        };
        if record.revocation_pending
            && record.credential_epoch == epoch
            && operation_ids.get(&key).map(String::as_str) == Some(operation_id)
        {
            return Ok(CredentialChangeStart::Started { epoch });
        }
        if record.status != UserStatus::Active {
            return Ok(CredentialChangeStart::Ineligible);
        }
        if record.revocation_pending || record.credential_epoch != expected_epoch {
            return Ok(CredentialChangeStart::ConcurrentChange);
        }
        record.credential_epoch = epoch;
        record.revocation_pending = true;
        record.updated_at = now;
        operation_ids.insert(key, operation_id.to_string());
        Ok(CredentialChangeStart::Started { epoch })
    }

    async fn complete_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(false);
        };
        if record.status != crate::ports::UserStatus::Active
            || record.credential_epoch != owner.epoch
            || !record.revocation_pending
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(false);
        }
        record.revocation_pending = false;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(true)
    }

    async fn recover_expired_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        started_before: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(false);
        };
        if record.status == crate::ports::UserStatus::Tombstoned
            || record.credential_epoch != epoch
            || !record.revocation_pending
            || record.updated_at > started_before
            || !operation_ids.contains_key(&key)
        {
            return Ok(false);
        }
        record.revocation_pending = false;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(true)
    }

    async fn begin_disable(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<crate::ports::DisableStart, StoreError> {
        use crate::ports::{DisableStart, UserStatus};

        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(DisableStart::NotFound);
        };
        if record.status == UserStatus::Tombstoned {
            return Ok(DisableStart::Tombstoned);
        }
        record.credential_epoch =
            crate::ports::next_disable_epoch(record.status, record.credential_epoch)?;
        record.status = UserStatus::Disabled;
        record.revocation_pending = true;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(DisableStart::Ready {
            record: record.clone(),
            epoch: record.credential_epoch,
        })
    }

    async fn complete_disable(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(false);
        };
        if record.status != crate::ports::UserStatus::Disabled || record.credential_epoch != epoch {
            return Ok(false);
        }
        record.revocation_pending = false;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(true)
    }

    async fn begin_legacy_disable_cleanup(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let mut operation_ids = self.credential_change_ids.lock().await;
        let Some(record) = map.get_mut(&key) else {
            return Ok(None);
        };
        if record.status != crate::ports::UserStatus::Disabled || record.credential_epoch != 0 {
            return Ok(None);
        }
        record.credential_epoch = 1;
        record.revocation_pending = true;
        record.updated_at = now;
        operation_ids.remove(&key);
        Ok(Some(record.clone()))
    }

    async fn enable_completed(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        now: i64,
    ) -> Result<crate::ports::EnableOutcome, StoreError> {
        use crate::ports::{EnableOutcome, UserStatus};

        let mut map = self.by_id.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(EnableOutcome::NotFound);
        };
        if record.status == UserStatus::Tombstoned {
            return Ok(EnableOutcome::Tombstoned);
        }
        if record.status == UserStatus::Active && record.credential_epoch == expected_epoch {
            return Ok(EnableOutcome::Enabled(record.clone()));
        }
        if record.status != UserStatus::Disabled || record.credential_epoch != expected_epoch {
            return Ok(EnableOutcome::ConcurrentChange);
        }
        if record.revocation_pending {
            return Ok(EnableOutcome::RevocationPending);
        }
        record.status = UserStatus::Active;
        record.updated_at = now;
        Ok(EnableOutcome::Enabled(record.clone()))
    }

    async fn put_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
    ) -> Result<crate::ports::PutAttrOutcome, StoreError> {
        use crate::ports::{NamespaceAttrs, PutAttrOutcome};
        let mut map = self.by_id.lock().await;
        let Some((_, rec)) = map
            .iter_mut()
            .find(|((t, _), r)| t == tenant && r.user_id == user_id)
        else {
            return Ok(PutAttrOutcome::NotFound);
        };
        // Tombstoned 用户拒写(不复活,与 set_status 终态一致)。
        if rec.status == crate::ports::UserStatus::Tombstoned {
            return Ok(PutAttrOutcome::Tombstoned);
        }
        // 乐观锁:当前 revision(namespace 不存在视为 0)与 expected 不符 → 冲突。
        let current = rec
            .attributes
            .get(namespace)
            .map(|n| n.revision)
            .unwrap_or(0);
        if current != expected_revision {
            if expected_revision.checked_add(1) == Some(current)
                && rec
                    .attributes
                    .get(namespace)
                    .is_some_and(|attributes| attributes.kv == kv)
            {
                return Ok(PutAttrOutcome::Ok { revision: current });
            }
            return Ok(PutAttrOutcome::RevisionConflict { current });
        }
        let federation_owners = rec
            .attributes
            .get(namespace)
            .map(|attributes| attributes.federation_owners.clone())
            .unwrap_or_default();
        if federation_owners.keys().any(|key| {
            rec.attributes
                .get(namespace)
                .and_then(|attributes| attributes.kv.get(key))
                != kv.get(key)
        }) {
            return Ok(PutAttrOutcome::OwnershipConflict);
        }
        // 原子内体积校验:先在候选副本上应用改动,序列化超上限则整体拒(不部分写)。
        let next_generation = rec
            .attributes_generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user attributes generation exhausted".into()))?;
        let mut candidate = rec.attributes.clone();
        let next_revision = current.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("namespace attributes revision exhausted".into())
        })?;
        candidate.insert(
            namespace.to_string(),
            NamespaceAttrs {
                revision: next_revision,
                kv: kv.clone(),
                federation_owners,
            },
        );
        if attributes_serialized_len(&candidate) > crate::ports::ATTRIBUTES_MAX_BYTES {
            return Ok(PutAttrOutcome::TooLarge);
        }
        rec.attributes = candidate;
        rec.attributes_generation = next_generation;
        Ok(PutAttrOutcome::Ok {
            revision: next_revision,
        })
    }

    async fn migrate_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        canonical_namespace: &str,
        source_namespaces: &std::collections::BTreeSet<String>,
    ) -> Result<crate::ports::AttributeMigrationOutcome, StoreError> {
        use crate::attribute_namespace::{plan_attribute_migration, MigrationDecision};
        use crate::ports::AttributeMigrationOutcome;

        let mut map = self.by_id.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(AttributeMigrationOutcome::NotFound);
        };
        if record.status == crate::ports::UserStatus::Tombstoned {
            return Ok(AttributeMigrationOutcome::Tombstoned);
        }
        let attributes = match plan_attribute_migration(
            &record.attributes,
            canonical_namespace,
            source_namespaces,
        ) {
            MigrationDecision::Noop => return Ok(AttributeMigrationOutcome::Noop),
            MigrationDecision::Conflict { namespaces } => {
                return Ok(AttributeMigrationOutcome::Conflict { namespaces });
            }
            MigrationDecision::RevisionExhausted => {
                return Ok(AttributeMigrationOutcome::RevisionExhausted);
            }
            MigrationDecision::Replace { attributes } => attributes,
        };
        if attributes_serialized_len(&attributes) > crate::ports::ATTRIBUTES_MAX_BYTES {
            return Ok(AttributeMigrationOutcome::TooLarge);
        }
        let generation = record
            .attributes_generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user attributes generation exhausted".into()))?;
        record.attributes = attributes;
        record.attributes_generation = generation;
        Ok(AttributeMigrationOutcome::Migrated { generation })
    }

    async fn fence_for_erasure(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let mut map = self.by_id.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(None);
        };
        if record.status == crate::ports::UserStatus::Tombstoned
            && record.credential_epoch == target_epoch
        {
            return Ok(Some(record.clone()));
        }
        if record.status == crate::ports::UserStatus::Tombstoned
            || record.credential_epoch.checked_add(1) != Some(target_epoch)
        {
            return Err(StoreError::Permanent(
                "user erasure fence no longer matches the target epoch".into(),
            ));
        }
        record.status = crate::ports::UserStatus::Tombstoned;
        record.credential_epoch = target_epoch;
        record.revocation_pending = true;
        record.attributes.clear();
        record.updated_at = now;
        Ok(Some(record.clone()))
    }

    async fn delete_erased_identity(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut map = self.by_id.lock().await;
        let Some(record) = map.get(&key) else {
            return Ok(true);
        };
        if record.status != crate::ports::UserStatus::Tombstoned
            || record.credential_epoch != target_epoch
        {
            return Err(StoreError::Permanent(
                "user identity is not fenced for this erasure epoch".into(),
            ));
        }
        map.remove(&key);
        drop(map);
        self.scim_create_claims
            .lock()
            .await
            .retain(|claim_key, claim| claim_key.0 != tenant || claim.user_id != user_id);
        Ok(true)
    }
}

#[derive(Clone)]
struct MemoryScimGroup {
    record: crate::ports::ScimGroupRecord,
    role: Option<crate::ports::TenantRole>,
    role_updated_at: Option<i64>,
    deleted: bool,
}

#[derive(Clone, Default)]
pub struct MemoryScimGroupsStore {
    groups: Arc<Mutex<HashMap<(String, String), MemoryScimGroup>>>,
    by_external_id: Arc<Mutex<HashMap<(String, String), String>>>,
}

impl crate::ports::ScimGroupsStore for MemoryScimGroupsStore {
    async fn create(
        &self,
        tenant: &str,
        input: crate::ports::ScimGroupCreateInput,
    ) -> Result<crate::ports::ScimGroupCreateOutcome, StoreError> {
        use crate::ports::{ScimGroupCreateOutcome, ScimGroupRecord};

        let members = crate::ports::canonical_scim_group_members(input.members);
        if members.len() > crate::ports::SCIM_GROUP_MAX_MEMBERS {
            return Err(StoreError::Permanent(
                "SCIM Group exceeds the supported member limit".into(),
            ));
        }
        let external_key = (tenant.to_string(), input.external_id.clone());
        let mut aliases = self.by_external_id.lock().await;
        let mut groups = self.groups.lock().await;
        if let Some(group_id) = aliases.get(&external_key) {
            let existing = groups
                .get(&(tenant.to_string(), group_id.clone()))
                .filter(|entry| !entry.deleted)
                .ok_or_else(|| {
                    StoreError::Permanent(
                        "SCIM Group externalId references a missing canonical Group".into(),
                    )
                })?;
            return Ok(ScimGroupCreateOutcome::Existing(existing.record.clone()));
        }
        let key = (tenant.to_string(), input.group_id.clone());
        if groups.contains_key(&key) {
            return Err(StoreError::Permanent(
                "SCIM Group id is already bound".into(),
            ));
        }
        let record = ScimGroupRecord {
            group_id: input.group_id,
            external_id: input.external_id,
            display_name: input.display_name,
            members,
            version: 1,
            created_at: input.now,
            updated_at: input.now,
        };
        aliases.insert(external_key, record.group_id.clone());
        groups.insert(
            key,
            MemoryScimGroup {
                record: record.clone(),
                role: None,
                role_updated_at: None,
                deleted: false,
            },
        );
        Ok(ScimGroupCreateOutcome::Created(record))
    }

    async fn get(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        Ok(self
            .groups
            .lock()
            .await
            .get(&(tenant.to_string(), group_id.to_string()))
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.record.clone()))
    }

    async fn get_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> Result<Option<crate::ports::ScimGroupRecord>, StoreError> {
        let aliases = self.by_external_id.lock().await;
        let Some(group_id) = aliases.get(&(tenant.to_string(), external_id.to_string())) else {
            return Ok(None);
        };
        Ok(self
            .groups
            .lock()
            .await
            .get(&(tenant.to_string(), group_id.clone()))
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.record.clone()))
    }

    async fn list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::ports::ScimGroupRecord>, usize), StoreError> {
        let mut records: Vec<_> = self
            .groups
            .lock()
            .await
            .iter()
            .filter(|((entry_tenant, _), entry)| entry_tenant == tenant && !entry.deleted)
            .map(|(_, entry)| entry.record.clone())
            .collect();
        records.sort_by(|left, right| left.group_id.cmp(&right.group_id));
        let total = records.len();
        Ok((
            records.into_iter().skip(offset).take(limit).collect(),
            total,
        ))
    }

    async fn mutate(
        &self,
        tenant: &str,
        group_id: &str,
        mutation: crate::ports::ScimGroupMutation,
    ) -> Result<crate::ports::ScimGroupMutationOutcome, StoreError> {
        use crate::ports::ScimGroupMutationOutcome;

        let mut groups = self.groups.lock().await;
        let Some(entry) = groups.get_mut(&(tenant.to_string(), group_id.to_string())) else {
            return Ok(ScimGroupMutationOutcome::NotFound);
        };
        if entry.deleted {
            return Ok(ScimGroupMutationOutcome::NotFound);
        }
        let (mut next, now) = crate::ports::apply_scim_group_mutation(&entry.record, mutation);
        if next.members.len() > crate::ports::SCIM_GROUP_MAX_MEMBERS {
            return Ok(ScimGroupMutationOutcome::TooManyMembers);
        }
        if next.display_name == entry.record.display_name && next.members == entry.record.members {
            return Ok(ScimGroupMutationOutcome::Updated(entry.record.clone()));
        }
        next.version = entry
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
        next.updated_at = now;
        entry.record = next.clone();
        Ok(ScimGroupMutationOutcome::Updated(next))
    }

    async fn delete(
        &self,
        tenant: &str,
        group_id: &str,
        now: i64,
    ) -> Result<crate::ports::ScimGroupDeleteOutcome, StoreError> {
        use crate::ports::ScimGroupDeleteOutcome;

        let mut aliases = self.by_external_id.lock().await;
        let mut groups = self.groups.lock().await;
        let Some(entry) = groups.get_mut(&(tenant.to_string(), group_id.to_string())) else {
            return Ok(ScimGroupDeleteOutcome::NotFound);
        };
        if entry.deleted {
            return Ok(ScimGroupDeleteOutcome::Deleted);
        }
        aliases.remove(&(tenant.to_string(), entry.record.external_id.clone()));
        entry.deleted = true;
        entry.role = None;
        entry.role_updated_at = None;
        entry.record.members.clear();
        entry.record.updated_at = now;
        entry.record.version = entry
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
        Ok(ScimGroupDeleteOutcome::Deleted)
    }

    async fn set_role_mapping(
        &self,
        tenant: &str,
        external_id: &str,
        role: Option<crate::ports::TenantRole>,
        now: i64,
    ) -> Result<crate::ports::ScimRoleMappingOutcome, StoreError> {
        use crate::ports::{ScimGroupRoleMapping, ScimRoleMappingOutcome};

        let aliases = self.by_external_id.lock().await;
        let Some(group_id) = aliases.get(&(tenant.to_string(), external_id.to_string())) else {
            return Ok(ScimRoleMappingOutcome::GroupNotFound);
        };
        let mut groups = self.groups.lock().await;
        let Some(entry) = groups.get_mut(&(tenant.to_string(), group_id.clone())) else {
            return Err(StoreError::Permanent(
                "SCIM Group externalId references a missing canonical Group".into(),
            ));
        };
        if entry.deleted {
            return Ok(ScimRoleMappingOutcome::GroupNotFound);
        }
        match role {
            Some(role) => {
                if entry.role != Some(role) {
                    entry.record.version =
                        entry.record.version.checked_add(1).ok_or_else(|| {
                            StoreError::Permanent("SCIM Group version exhausted".into())
                        })?;
                    entry.record.updated_at = now;
                    entry.role = Some(role);
                    entry.role_updated_at = Some(now);
                }
                Ok(ScimRoleMappingOutcome::Updated(ScimGroupRoleMapping {
                    group_id: entry.record.group_id.clone(),
                    external_id: entry.record.external_id.clone(),
                    role,
                    updated_at: entry.role_updated_at.unwrap_or(now),
                }))
            }
            None => {
                if entry.role.is_some() {
                    entry.record.version =
                        entry.record.version.checked_add(1).ok_or_else(|| {
                            StoreError::Permanent("SCIM Group version exhausted".into())
                        })?;
                    entry.record.updated_at = now;
                    entry.role = None;
                    entry.role_updated_at = None;
                }
                Ok(ScimRoleMappingOutcome::Removed)
            }
        }
    }

    async fn list_role_mappings(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::ports::ScimGroupRoleMapping>, StoreError> {
        let mut mappings: Vec<_> = self
            .groups
            .lock()
            .await
            .iter()
            .filter(|((entry_tenant, _), entry)| entry_tenant == tenant && !entry.deleted)
            .filter_map(|(_, entry)| {
                Some(crate::ports::ScimGroupRoleMapping {
                    group_id: entry.record.group_id.clone(),
                    external_id: entry.record.external_id.clone(),
                    role: entry.role?,
                    updated_at: entry.role_updated_at?,
                })
            })
            .collect();
        mappings.sort_by(|left, right| left.external_id.cmp(&right.external_id));
        Ok(mappings)
    }

    async fn mapped_role_for_member(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<crate::ports::MappedTenantRole, StoreError> {
        let mut mappings: Vec<_> = self
            .groups
            .lock()
            .await
            .iter()
            .filter(|((entry_tenant, _), entry)| {
                entry_tenant == tenant
                    && !entry.deleted
                    && entry.record.members.iter().any(|member| member == user_id)
            })
            .filter_map(|(_, entry)| {
                Some(crate::ports::ScimGroupRoleMapping {
                    group_id: entry.record.group_id.clone(),
                    external_id: entry.record.external_id.clone(),
                    role: entry.role?,
                    updated_at: entry.role_updated_at?,
                })
            })
            .collect();
        mappings.sort_by(|left, right| left.external_id.cmp(&right.external_id));
        let role = mappings.iter().map(|mapping| mapping.role).max();
        Ok(crate::ports::MappedTenantRole { role, mappings })
    }

    async fn remove_member_from_all(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let mut groups = self.groups.lock().await;
        let mut removed = 0;
        for ((entry_tenant, _), entry) in groups.iter_mut() {
            if entry_tenant != tenant || entry.deleted {
                continue;
            }
            let before = entry.record.members.len();
            entry.record.members.retain(|member| member != user_id);
            if entry.record.members.len() != before {
                entry.record.version =
                    entry.record.version.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("SCIM Group version exhausted".into())
                    })?;
                entry.record.updated_at = now;
                removed += 1;
            }
        }
        Ok(removed)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut groups = self.groups.lock().await;
        let before = groups.len();
        groups.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        let removed = before.saturating_sub(groups.len());
        drop(groups);
        self.by_external_id
            .lock()
            .await
            .retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(removed)
    }
}

/// In-memory password credential store. The compound key mirrors the Dynamo
/// tenant-prefixed partition key; replacement is a single lock-held CAS.
#[derive(Clone, Default)]
pub struct MemoryPasswordStore {
    map: Arc<Mutex<HashMap<(String, String), crate::ports::PasswordCredential>>>,
    get_calls: Arc<AtomicUsize>,
    get_requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl MemoryPasswordStore {
    pub fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }

    pub async fn get_requests(&self) -> Vec<(String, String)> {
        self.get_requests.lock().await.clone()
    }

    pub(crate) async fn commit_credential_change(
        &self,
        users: &MemoryUsersStore,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<bool, StoreError> {
        let crate::ports::FencedPasswordMutation {
            tenant,
            user_id,
            password_hash: new_hash,
            expected_version,
            credential_epoch: epoch,
            updated_at,
        } = mutation;
        let key = (tenant.to_string(), user_id.to_string());
        let mut user_records = users.by_id.lock().await;
        let mut operation_ids = users.credential_change_ids.lock().await;
        let Some(user) = user_records.get_mut(&key) else {
            return Ok(false);
        };
        if epoch != owner.epoch
            || user.status != crate::ports::UserStatus::Active
            || !user.revocation_pending
            || user.credential_epoch != owner.epoch
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(false);
        }

        let mut passwords = self.map.lock().await;
        match (passwords.get_mut(&key), expected_version) {
            (None, None) => {
                passwords.insert(
                    key.clone(),
                    crate::ports::PasswordCredential {
                        user_id: user_id.to_string(),
                        password_hash: new_hash,
                        must_change: false,
                        revocation_pending: false,
                        credential_change_id: None,
                        version: 1,
                        updated_at,
                    },
                );
            }
            (Some(credential), Some(expected))
                if credential.version == expected
                    && !credential.must_change
                    && !credential.revocation_pending =>
            {
                let next_version = credential
                    .version
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Permanent("password version overflow".into()))?;
                credential.password_hash = new_hash;
                credential.credential_change_id = None;
                credential.version = next_version;
                credential.updated_at = updated_at;
            }
            _ => return Ok(false),
        }
        user.revocation_pending = false;
        user.updated_at = updated_at;
        operation_ids.remove(&key);
        Ok(true)
    }

    pub(crate) async fn stage_admin_reset(
        &self,
        users: &MemoryUsersStore,
        mutation: crate::ports::FencedPasswordMutation<'_>,
        owner: crate::ports::CredentialChangeOwner<'_>,
    ) -> Result<Option<u64>, StoreError> {
        let crate::ports::FencedPasswordMutation {
            tenant,
            user_id,
            password_hash: new_hash,
            expected_version,
            credential_epoch: epoch,
            updated_at,
        } = mutation;
        let key = (tenant.to_string(), user_id.to_string());
        let user_records = users.by_id.lock().await;
        let operation_ids = users.credential_change_ids.lock().await;
        let Some(user) = user_records.get(&key) else {
            return Ok(None);
        };
        if epoch != owner.epoch
            || user.status == crate::ports::UserStatus::Tombstoned
            || !user.revocation_pending
            || user.credential_epoch != owner.epoch
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(None);
        }

        let mut passwords = self.map.lock().await;
        let version = match (passwords.get_mut(&key), expected_version) {
            (Some(credential), Some(expected)) if credential.version == expected => {
                credential.password_hash = new_hash;
                credential.must_change = true;
                credential.revocation_pending = true;
                credential.credential_change_id = Some(owner.operation_id.to_string());
                credential.version = credential
                    .version
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Permanent("password version overflow".into()))?;
                credential.updated_at = updated_at;
                credential.version
            }
            (None, None) => {
                passwords.insert(
                    key,
                    crate::ports::PasswordCredential {
                        user_id: user_id.to_string(),
                        password_hash: new_hash,
                        must_change: true,
                        revocation_pending: true,
                        credential_change_id: Some(owner.operation_id.to_string()),
                        version: 1,
                        updated_at,
                    },
                );
                1
            }
            _ => return Ok(None),
        };
        Ok(Some(version))
    }

    pub(crate) async fn complete_admin_reset(
        &self,
        users: &MemoryUsersStore,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), user_id.to_string());
        let mut user_records = users.by_id.lock().await;
        let mut operation_ids = users.credential_change_ids.lock().await;
        let Some(user) = user_records.get_mut(&key) else {
            return Ok(false);
        };
        if user.status == crate::ports::UserStatus::Tombstoned
            || !user.revocation_pending
            || user.credential_epoch != owner.epoch
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(false);
        }
        let mut passwords = self.map.lock().await;
        let Some(credential) = passwords.get_mut(&(tenant.to_string(), user_id.to_string())) else {
            return Ok(false);
        };
        if credential.version != expected_version
            || !credential.must_change
            || !credential.revocation_pending
            || credential.credential_change_id.as_deref() != Some(owner.operation_id)
        {
            return Ok(false);
        }
        credential.revocation_pending = false;
        credential.credential_change_id = None;
        user.revocation_pending = false;
        user.updated_at = updated_at;
        operation_ids.remove(&key);
        Ok(true)
    }
}

impl crate::ports::PasswordStore for MemoryPasswordStore {
    async fn get(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Option<crate::ports::PasswordCredential>, StoreError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.get_requests
            .lock()
            .await
            .push((tenant.to_string(), user_id.to_string()));
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), user_id.to_string()))
            .cloned())
    }

    async fn create_if_absent(
        &self,
        tenant: &str,
        credential: crate::ports::PasswordCredential,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), credential.user_id.clone());
        if map.contains_key(&key) {
            return Ok(false);
        }
        map.insert(key, credential);
        Ok(true)
    }

    async fn delete_if_version(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), user_id.to_string());
        if map
            .get(&key)
            .is_none_or(|credential| credential.version != expected_version)
        {
            return Ok(false);
        }
        map.remove(&key);
        Ok(true)
    }

    async fn replace_if_version_and_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: u64,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), user_id.to_string())) {
            Some(credential)
                if credential.must_change
                    && !credential.revocation_pending
                    && credential.version == expected_version =>
            {
                credential.password_hash = new_hash;
                credential.must_change = false;
                credential.credential_change_id = None;
                credential.version += 1;
                credential.updated_at = updated_at;
                Ok(true)
            }
            _ => Ok(false),
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
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), user_id.to_string());
        let version = match (map.get_mut(&key), expected_version) {
            (Some(credential), Some(expected)) if credential.version == expected => {
                credential.password_hash = new_hash;
                credential.must_change = true;
                credential.revocation_pending = true;
                credential.credential_change_id = None;
                credential.version = credential
                    .version
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Permanent("password version overflow".into()))?;
                credential.updated_at = updated_at;
                credential.version
            }
            (None, None) => {
                map.insert(
                    key,
                    crate::ports::PasswordCredential {
                        user_id: user_id.to_string(),
                        password_hash: new_hash,
                        must_change: true,
                        revocation_pending: true,
                        credential_change_id: None,
                        version: 1,
                        updated_at,
                    },
                );
                1
            }
            _ => return Ok(None),
        };
        Ok(Some(version))
    }

    async fn complete_reset_revocation(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), user_id.to_string())) {
            Some(credential)
                if credential.must_change
                    && credential.revocation_pending
                    && credential.version == expected_version =>
            {
                credential.revocation_pending = false;
                credential.credential_change_id = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete(&self, tenant: &str, user_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), user_id.to_string()));
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// Dedicated invitation state backed by the same user, password, and session
/// maps as `AppState`. The bearer secret never enters this structure.
#[derive(Clone, Default)]
pub struct MemoryInvitationStore {
    map: Arc<Mutex<HashMap<(String, String), InvitationRecord>>>,
    users: MemoryUsersStore,
    passwords: MemoryPasswordStore,
    sessions: MemorySessionStore,
}

impl MemoryInvitationStore {
    pub fn new(
        users: MemoryUsersStore,
        passwords: MemoryPasswordStore,
        sessions: MemorySessionStore,
    ) -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
            users,
            passwords,
            sessions,
        }
    }

    fn eligible_user(user: &crate::ports::UserRecord, record: &InvitationRecord) -> bool {
        user.status == crate::ports::UserStatus::Active
            && !user.revocation_pending
            && user.user_id == record.user_id
            && user.email == record.email
            && user.credential_epoch == record.credential_epoch
            && crate::local_identity::is_valid_email(&user.email)
            && crate::local_identity::is_password_capable_user_id(&user.user_id)
    }
}

impl InvitationStore for MemoryInvitationStore {
    async fn issue(
        &self,
        tenant: &str,
        record: InvitationRecord,
    ) -> Result<InvitationIssueOutcome, StoreError> {
        let users = self.users.by_id.lock().await;
        let Some(user) = users.get(&(tenant.to_string(), record.user_id.clone())) else {
            return Ok(InvitationIssueOutcome::Ineligible);
        };
        if !Self::eligible_user(user, &record) {
            return Ok(InvitationIssueOutcome::Ineligible);
        }
        let passwords = self.passwords.map.lock().await;
        if passwords.contains_key(&(tenant.to_string(), record.user_id.clone())) {
            return Ok(InvitationIssueOutcome::PasswordConfigured);
        }
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.locator.clone()), record);
        Ok(InvitationIssueOutcome::Issued)
    }

    async fn accept(
        &self,
        tenant: &str,
        request: InvitationAcceptRequest,
    ) -> Result<InvitationAcceptOutcome, StoreError> {
        let key = (tenant.to_string(), request.locator.clone());
        let Some(snapshot) = self.map.lock().await.get(&key).cloned() else {
            return Ok(InvitationAcceptOutcome::Invalid);
        };
        if !crate::invitation::verifier_matches(&snapshot.verifier_hash, &request.verifier_hash) {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        if snapshot.activation_id != request.activation_id {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        if snapshot.expires_at <= request.now {
            return Ok(InvitationAcceptOutcome::Expired {
                user_id: snapshot.user_id,
            });
        }

        // Lock order matches issuance (users -> passwords -> invitations).
        let users = self.users.by_id.lock().await;
        let Some(user) = users.get(&(tenant.to_string(), snapshot.user_id.clone())) else {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: snapshot.user_id,
            });
        };
        if !Self::eligible_user(user, &snapshot) {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: snapshot.user_id,
            });
        }
        let passwords = self.passwords.map.lock().await;
        if passwords.contains_key(&(tenant.to_string(), snapshot.user_id.clone())) {
            return Ok(InvitationAcceptOutcome::Ineligible {
                user_id: snapshot.user_id,
            });
        }
        let mut invitations = self.map.lock().await;
        if invitations.get(&key) != Some(&snapshot) {
            return Ok(InvitationAcceptOutcome::Invalid);
        }
        let mut sessions = self.sessions.state.lock().await;
        let session_key = (tenant.to_string(), request.session_id.clone());
        if sessions.sessions.contains_key(&session_key) {
            return Err(StoreError::Transient("session id collision".to_string()));
        }
        let generation = sessions
            .generations
            .get(&(tenant.to_string(), snapshot.user_id.clone()))
            .copied()
            .unwrap_or(0);
        let session = SessionRecord {
            session_id: request.session_id.clone(),
            user_id: snapshot.user_id.clone(),
            credential_epoch: snapshot.credential_epoch,
            auth_time: request.now,
            created_at: request.now,
            last_used_at: request.now,
            device: request.device,
            expires_at: request.now + crate::login::SESSION_TTL_SECS,
            acr: None,
            amr: vec!["invite".to_string()],
        };
        invitations.remove(&key);
        sessions.sessions.insert(
            session_key,
            MemoryStoredSession {
                record: session,
                generation,
            },
        );
        Ok(InvitationAcceptOutcome::Accepted {
            user_id: snapshot.user_id,
            session_id: request.session_id,
        })
    }

    async fn invalidate(&self, tenant: &str, locator: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), locator.to_string()));
        Ok(())
    }
}

/// attributes 全量序列化字节数(与 Dynamo 侧同口径,稳定 BTreeMap 顺序)。
/// spec 007 §6.1 体积上限判定用。
pub(crate) fn attributes_serialized_len(
    attrs: &std::collections::BTreeMap<String, crate::ports::NamespaceAttrs>,
) -> usize {
    #[derive(serde::Serialize)]
    struct NamespaceView<'a> {
        kv: &'a std::collections::BTreeMap<String, String>,
        federation_owners:
            &'a std::collections::BTreeMap<String, crate::ports::FederatedAttributeOwner>,
    }
    let view: std::collections::BTreeMap<&String, NamespaceView<'_>> = attrs
        .iter()
        .map(|(namespace, attributes)| {
            (
                namespace,
                NamespaceView {
                    kv: &attributes.kv,
                    federation_owners: &attributes.federation_owners,
                },
            )
        })
        .collect();
    serde_json::to_vec(&view)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
}

/// 内存联邦配置存储(本地/测试,spec 003 §4.1 / C10.19)。
/// **键 = 复合 `(tenant_id, upstream_idp_id)`**——tenant_id 进 key 即物理隔离(与真机 tenant 分区键同构):
/// A 租户永远查不到 B 的配置(key 不同)。put 用 config 自带的 (tenant_id, upstream_idp_id) 作 key。
#[derive(Clone, Default)]
pub struct MemoryFederationConfigStore {
    map: Arc<Mutex<HashMap<(String, String), agent_auth_authn::federation::FederationConfig>>>,
}

impl crate::ports::FederationConfigStore for MemoryFederationConfigStore {
    async fn get(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> Result<Option<agent_auth_authn::federation::FederationConfig>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant_id.to_string(), upstream_idp_id.to_string()))
            .cloned())
    }
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<agent_auth_authn::federation::FederationConfig>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn put(
        &self,
        config: agent_auth_authn::federation::FederationConfig,
    ) -> Result<(), StoreError> {
        let key = (config.tenant_id.clone(), config.upstream_idp_id.clone());
        self.map.lock().await.insert(key, config);
        Ok(())
    }
    async fn delete(&self, tenant_id: &str, upstream_idp_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant_id.to_string(), upstream_idp_id.to_string()));
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant_id);
        Ok(before.saturating_sub(map.len()))
    }
}

/// Dedicated in-memory Admin OIDC state. Configuration, flow, and session maps
/// are disjoint to mirror the production table's typed key prefixes.
#[derive(Clone, Default)]
pub struct MemoryAdminAuthStore {
    configs: Arc<Mutex<HashMap<String, crate::ports::AdminOidcConfig>>>,
    flows: Arc<Mutex<HashMap<String, crate::ports::AdminOidcFlow>>>,
    sessions: Arc<Mutex<HashMap<String, crate::ports::AdminSessionRecord>>>,
    fail_next_delete_session: Arc<AtomicU8>,
}

impl MemoryAdminAuthStore {
    pub fn fail_next_delete_session(&self) {
        self.fail_next_delete_session.store(1, Ordering::SeqCst);
    }

    pub async fn flows(&self) -> Vec<crate::ports::AdminOidcFlow> {
        self.flows.lock().await.values().cloned().collect()
    }
}

impl crate::ports::AdminAuthStore for MemoryAdminAuthStore {
    async fn get_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::ports::AdminOidcConfig>, StoreError> {
        Ok(self.configs.lock().await.get(tenant_id).cloned())
    }

    async fn put_config(
        &self,
        config: crate::ports::AdminOidcConfig,
        expected_revision: u64,
    ) -> Result<crate::ports::AdminOidcConfigPutOutcome, StoreError> {
        let mut configs = self.configs.lock().await;
        let current_revision = configs
            .get(&config.tenant_id)
            .map(|current| current.revision)
            .unwrap_or(0);
        if current_revision != expected_revision
            || config.revision != expected_revision.saturating_add(1)
        {
            return Ok(crate::ports::AdminOidcConfigPutOutcome::Conflict);
        }
        configs.insert(config.tenant_id.clone(), config.clone());
        Ok(crate::ports::AdminOidcConfigPutOutcome::Stored(config))
    }

    async fn delete_config(
        &self,
        tenant_id: &str,
        expected_revision: u64,
    ) -> Result<crate::ports::AdminOidcConfigDeleteOutcome, StoreError> {
        let mut configs = self.configs.lock().await;
        if configs
            .get(tenant_id)
            .is_none_or(|config| config.revision != expected_revision)
        {
            return Ok(crate::ports::AdminOidcConfigDeleteOutcome::Conflict);
        }
        configs.remove(tenant_id);
        Ok(crate::ports::AdminOidcConfigDeleteOutcome::Deleted)
    }

    async fn put_flow(&self, flow: crate::ports::AdminOidcFlow) -> Result<(), StoreError> {
        self.flows
            .lock()
            .await
            .insert(flow.state_hash.clone(), flow);
        Ok(())
    }

    async fn consume_flow(
        &self,
        state_hash: &str,
        now: i64,
    ) -> Result<Option<crate::ports::AdminOidcFlow>, StoreError> {
        let flow = self.flows.lock().await.remove(state_hash);
        Ok(flow.filter(|flow| flow.expires_at > now))
    }

    async fn create_session(
        &self,
        session: crate::ports::AdminSessionRecord,
    ) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .await
            .insert(session.session_hash.clone(), session);
        Ok(())
    }

    async fn get_session(
        &self,
        session_hash: &str,
        now: i64,
    ) -> Result<Option<crate::ports::AdminSessionRecord>, StoreError> {
        let mut sessions = self.sessions.lock().await;
        match sessions.get(session_hash) {
            Some(session) if session.expires_at > now => Ok(Some(session.clone())),
            Some(_) => {
                sessions.remove(session_hash);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn delete_session(&self, tenant_id: &str, session_hash: &str) -> Result<(), StoreError> {
        if self.fail_next_delete_session.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected Admin session delete failure".into(),
            ));
        }
        let mut sessions = self.sessions.lock().await;
        if sessions
            .get(session_hash)
            .is_some_and(|session| session.tenant_id == tenant_id)
        {
            sessions.remove(session_hash);
        }
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let removed_config = usize::from(self.configs.lock().await.remove(tenant_id).is_some());
        let mut flows = self.flows.lock().await;
        let flows_before = flows.len();
        flows.retain(|_, flow| flow.tenant_id != tenant_id);
        let removed_flows = flows_before.saturating_sub(flows.len());
        drop(flows);
        let mut sessions = self.sessions.lock().await;
        let sessions_before = sessions.len();
        sessions.retain(|_, session| session.tenant_id != tenant_id);
        Ok(removed_config
            .saturating_add(removed_flows)
            .saturating_add(sessions_before.saturating_sub(sessions.len())))
    }
}

/// 内存 CIBA 授权请求存储(本地/测试,spec 013)。
/// **复合 tenant 键**(spec 020 §2.3 D1,照 MemoryDeviceStore):键=(tenant, auth_req_id);
/// throttle 键=(tenant, user_id)——否则跨租户 CIBA 请求可被他租户审批/签发(隔离漏洞)。空 tenant 透传单租户。
#[derive(Clone, Default)]
pub struct MemoryCibaStore {
    map: Arc<Mutex<HashMap<(String, String), crate::ports::CibaAuthRequest>>>,
    /// per-login_hint(归一 user_id)上次 /bc-authorize 受理时刻(防批准疲劳节流,C7b.6);tenant-scope。
    last_authorize: Arc<Mutex<HashMap<(String, String), i64>>>,
}

impl crate::ports::CibaStore for MemoryCibaStore {
    async fn put(&self, tenant: &str, r: crate::ports::CibaAuthRequest) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), r.auth_req_id.clone()), r);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        auth_req_id: &str,
    ) -> Result<Option<crate::ports::CibaAuthRequest>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), auth_req_id.to_string()))
            .cloned())
    }
    async fn update(
        &self,
        tenant: &str,
        r: crate::ports::CibaAuthRequest,
    ) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), r.auth_req_id.clone()), r);
        Ok(())
    }
    async fn consume(&self, tenant: &str, auth_req_id: &str) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), auth_req_id.to_string())) {
            Some(r) if !r.consumed => {
                r.consumed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        auth_req_id: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), auth_req_id.to_string())) {
            Some(r) if r.last_poll_at == observed_last_poll_at => {
                r.last_poll_at = Some(now);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn decide(
        &self,
        tenant: &str,
        auth_req_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), auth_req_id.to_string())) {
            Some(r) if r.status == "pending" => {
                r.status = if approve { "approved" } else { "denied" }.to_string();
                r.password_credential_version = password_credential_version;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn release_consume(&self, tenant: &str, auth_req_id: &str) -> Result<(), StoreError> {
        if let Some(r) = self
            .map
            .lock()
            .await
            .get_mut(&(tenant.to_string(), auth_req_id.to_string()))
        {
            r.consumed = false;
        }
        Ok(())
    }
    async fn try_arm_throttle(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
        window_secs: i64,
    ) -> Result<bool, StoreError> {
        // 临界区内 check+mark 原子(评审 codex MEDIUM:并发不可分离);键 tenant-scope(防跨租户冷却串扰)。
        let mut map = self.last_authorize.lock().await;
        let key = (tenant.to_string(), user_id.to_string());
        match map.get(&key) {
            // 窗内(上次 + window > now)→ 拒,不覆盖(窗口不因被拒请求延长)。
            Some(&last) if last + window_secs > now => Ok(false),
            // 无记录或窗外 → 占用,写 now,放行。
            _ => {
                map.insert(key, now);
                Ok(true)
            }
        }
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), request| {
            entry_tenant != tenant || request.user_id != user_id
        });
        let removed = before - map.len();
        self.last_authorize
            .lock()
            .await
            .remove(&(tenant.to_string(), user_id.to_string()));
        Ok(removed)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);

        let mut last_authorize = self.last_authorize.lock().await;
        let throttle_before = last_authorize.len();
        last_authorize.retain(|(entry_tenant, _), _| entry_tenant != tenant);

        Ok(before
            .saturating_sub(map.len())
            .saturating_add(throttle_before.saturating_sub(last_authorize.len())))
    }
}

/// 内存 device 授权存储(本地/测试,spec 013)。user_code → device_code 靠遍历(量小)。
#[derive(Clone, Default)]
/// **复合 tenant 键**(spec 020 §2.3,评审 codex Medium):键=(tenant, device_code);
/// get_by_user_code 在同 tenant 内按 user_code 线性查(与 Dynamo GSI tpk 隔离同构)。
pub struct MemoryDeviceStore {
    map: Arc<Mutex<HashMap<(String, String), crate::ports::DeviceAuthGrant>>>,
}

impl crate::ports::DeviceStore for MemoryDeviceStore {
    async fn put(&self, tenant: &str, r: crate::ports::DeviceAuthGrant) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), r.device_code.clone()), r);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        device_code: &str,
    ) -> Result<Option<crate::ports::DeviceAuthGrant>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), device_code.to_string()))
            .cloned())
    }
    async fn get_by_user_code(
        &self,
        tenant: &str,
        user_code: &str,
    ) -> Result<Option<crate::ports::DeviceAuthGrant>, StoreError> {
        // 仅在本 tenant 分区内按 user_code 查(user_code 跨租户会碰撞,MUST tenant-scope)。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .find(|((t, _), g)| t == tenant && g.user_code == user_code)
            .map(|(_, g)| g.clone()))
    }
    async fn update(
        &self,
        tenant: &str,
        r: crate::ports::DeviceAuthGrant,
    ) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), r.device_code.clone()), r);
        Ok(())
    }
    async fn consume(&self, tenant: &str, device_code: &str, now: i64) -> Result<bool, StoreError> {
        // 原子 CAS(锁内):仅当 consumed==false 时置 true 并返 true;否则(不存在/已消费)返 false。
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), device_code.to_string())) {
            Some(g)
                if !g.consumed
                    && agent_auth_infra_core::lifecycle::shortlived_is_valid(now, g.expires_at) =>
            {
                g.consumed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn claim_poll(
        &self,
        tenant: &str,
        device_code: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), device_code.to_string())) {
            Some(g)
                if g.last_poll_at == observed_last_poll_at
                    && agent_auth_infra_core::lifecycle::shortlived_is_valid(now, g.expires_at) =>
            {
                g.last_poll_at = Some(now);
                Ok(true)
            }
            _ => Ok(false),
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
        // 原子 CAS(锁内):仅当 status=="pending" 时转 approved/denied 并填 user_id;不碰 consumed。
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), device_code.to_string())) {
            Some(g)
                if g.status == "pending"
                    && agent_auth_infra_core::lifecycle::shortlived_is_valid(now, g.expires_at) =>
            {
                g.user_id = Some(user_id.to_string());
                g.status = if approve { "approved" } else { "denied" }.to_string();
                g.password_credential_version = password_credential_version;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn release_consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        // 字段级(锁内):仅有效期内把 consumed 置回 false;不存在/过期则忽略(best-effort)。
        if let Some(g) = self
            .map
            .lock()
            .await
            .get_mut(&(tenant.to_string(), device_code.to_string()))
        {
            if agent_auth_infra_core::lifecycle::shortlived_is_valid(now, g.expires_at) {
                g.consumed = false;
            }
        }
        Ok(())
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), grant| {
            entry_tenant != tenant || grant.user_id.as_deref() != Some(user_id)
        });
        Ok(before - map.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 refresh family 存储(本地/测试),实现原子 rotation(C3.1)。
/// **复合 tenant 键**(spec 020 §2.3 D1):键=(tenant, family_id)。
type RefreshCreatePause = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);
type RefreshRotateBarrier = (Arc<Barrier>, Arc<AtomicUsize>);

#[derive(Clone)]
struct RefreshSigningLease {
    owner: String,
    version: u64,
    expires_at: i64,
}

#[derive(Clone, Default)]
pub struct MemoryRefreshStore {
    map: Arc<Mutex<HashMap<(String, String), RefreshFamilyRecord>>>,
    leases: Arc<Mutex<HashMap<(String, String), RefreshSigningLease>>>,
    fail_next_create: Arc<AtomicU8>,
    fail_next_revoke: Arc<AtomicU8>,
    fail_next_finalize: Arc<AtomicU8>,
    pause_next_create: Arc<Mutex<Option<RefreshCreatePause>>>,
    next_rotate_barrier: Arc<Mutex<Option<RefreshRotateBarrier>>>,
}

impl MemoryRefreshStore {
    pub fn fail_next_create(&self) {
        self.fail_next_create.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_revoke(&self, transient: bool) {
        self.fail_next_revoke
            .store(if transient { 1 } else { 2 }, Ordering::SeqCst);
    }

    pub fn fail_next_finalize(&self, transient: bool) {
        self.fail_next_finalize
            .store(if transient { 1 } else { 2 }, Ordering::SeqCst);
    }

    pub async fn pause_next_create(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let started = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *self.pause_next_create.lock().await = Some((started.clone(), resume.clone()));
        (started, resume)
    }

    pub async fn synchronize_next_lease_acquisitions(&self, participants: usize) {
        assert!(participants > 1, "lease barrier requires concurrency");
        *self.next_rotate_barrier.lock().await = Some((
            Arc::new(Barrier::new(participants)),
            Arc::new(AtomicUsize::new(participants)),
        ));
    }

    pub async fn replace_pkce_code_challenge_for_test(
        &self,
        tenant: &str,
        family_id: &str,
        challenge: Option<String>,
    ) {
        let mut map = self.map.lock().await;
        let family = map
            .get_mut(&(tenant.to_string(), family_id.to_string()))
            .expect("test refresh family must exist");
        family.pkce_code_challenge = challenge;
    }

    pub async fn finalize_rotation_with_grace(
        &self,
        grace: Option<&MemoryGraceStore>,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        grace_entry: Option<GraceCacheEntry>,
    ) -> Result<bool, StoreError> {
        match self.fail_next_finalize.swap(0, Ordering::SeqCst) {
            1 => {
                return Err(StoreError::Transient(
                    "injected refresh finalize failure".into(),
                ))
            }
            2 => {
                return Err(StoreError::Permanent(
                    "injected permanent refresh finalize failure".into(),
                ))
            }
            _ => {}
        }
        if grace.is_some() != grace_entry.is_some() {
            return Err(StoreError::Permanent(
                "refresh finalize grace store and entry must be configured together".into(),
            ));
        }
        if grace_entry
            .as_ref()
            .is_some_and(|entry| entry.family_id != family_id || entry.version != expected_version)
        {
            return Err(StoreError::Permanent(
                "refresh finalize grace entry does not match the leased version".into(),
            ));
        }

        let key = (tenant.to_string(), family_id.to_string());
        let mut families = self.map.lock().await;
        let mut leases = self.leases.lock().await;
        let mut grace_entries = match grace {
            Some(store) => Some(store.map.lock().await),
            None => None,
        };
        let Some(family) = families.get_mut(&key) else {
            return Ok(false);
        };
        let lease_matches = leases.get(&key).is_some_and(|lease| {
            lease.owner == lease_owner
                && lease.version == expected_version
                && lease.expires_at > now
        });
        if family.revoked || family.current_version != expected_version || !lease_matches {
            return Ok(false);
        }

        family.current_version = expected_version + 1;
        leases.remove(&key);
        if let (Some(entries), Some(entry)) = (grace_entries.as_mut(), grace_entry) {
            entries.insert(grace_key(&entry.family_id, entry.version), entry);
        }
        Ok(true)
    }
}

impl RefreshStore for MemoryRefreshStore {
    async fn create(&self, tenant: &str, record: RefreshFamilyRecord) -> Result<(), StoreError> {
        let pause = self.pause_next_create.lock().await.take();
        if let Some((started, resume)) = pause {
            started.notify_one();
            resume.notified().await;
        }
        if self.fail_next_create.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected refresh family persistence failure".into(),
            ));
        }
        let key = (tenant.to_string(), record.family_id.clone());
        self.map.lock().await.insert(key.clone(), record);
        self.leases.lock().await.remove(&key);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> Result<Option<RefreshFamilyRecord>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), family_id.to_string()))
            .cloned())
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
        if lease_owner.is_empty() || lease_expires_at <= now {
            return Err(StoreError::Permanent(
                "invalid refresh signing lease request".into(),
            ));
        }
        let synchronization = self.next_rotate_barrier.lock().await.clone();
        if let Some((barrier, remaining)) = synchronization {
            if remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                self.next_rotate_barrier.lock().await.take();
            }
            barrier.wait().await;
        }

        let key = (tenant.to_string(), family_id.to_string());
        let families = self.map.lock().await;
        let Some(family) = families.get(&key) else {
            return Ok(RefreshLeaseAcquire::NotFound);
        };
        if family.revoked {
            return Ok(RefreshLeaseAcquire::Revoked);
        }
        if family.current_version != expected_version {
            return Ok(RefreshLeaseAcquire::VersionMismatch);
        }
        let mut leases = self.leases.lock().await;
        if let Some(lease) = leases.get(&key) {
            if lease.expires_at > now {
                return Ok(RefreshLeaseAcquire::Locked {
                    retry_after_secs: lease.expires_at.saturating_sub(now).max(1) as u64,
                });
            }
        }
        leases.insert(
            key,
            RefreshSigningLease {
                owner: lease_owner.to_string(),
                version: expected_version,
                expires_at: lease_expires_at,
            },
        );
        Ok(RefreshLeaseAcquire::Acquired)
    }

    async fn finalize_rotation(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.finalize_rotation_with_grace(
            None,
            tenant,
            family_id,
            expected_version,
            lease_owner,
            now,
            None,
        )
        .await
    }

    async fn release_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), family_id.to_string());
        let families = self.map.lock().await;
        if families
            .get(&key)
            .is_none_or(|family| family.current_version != expected_version)
        {
            return Ok(false);
        }
        let mut leases = self.leases.lock().await;
        if !leases
            .get(&key)
            .is_some_and(|lease| lease.owner == lease_owner && lease.version == expected_version)
        {
            return Ok(false);
        }
        leases.remove(&key);
        Ok(true)
    }

    async fn revoke(&self, tenant: &str, family_id: &str) -> Result<(), StoreError> {
        match self.fail_next_revoke.swap(0, Ordering::SeqCst) {
            1 => {
                return Err(StoreError::Transient(
                    "injected refresh family revocation failure".into(),
                ))
            }
            2 => {
                return Err(StoreError::Permanent(
                    "injected permanent refresh family revocation failure".into(),
                ))
            }
            _ => {}
        }
        if let Some(fam) = self
            .map
            .lock()
            .await
            .get_mut(&(tenant.to_string(), family_id.to_string()))
        {
            fam.revoked = true;
        }
        Ok(())
    }

    async fn revoke_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let mut map = self.map.lock().await;
        let mut revoked = Vec::new();
        for ((t, _), fam) in map.iter_mut() {
            if t == tenant && fam.user_id == user_id {
                fam.revoked = true;
                revoked.push(fam.family_id.clone());
            }
        }
        Ok(revoked)
    }

    async fn revoke_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<Vec<String>, StoreError> {
        let mut map = self.map.lock().await;
        let mut revoked = Vec::new();
        for ((t, _), family) in map.iter_mut() {
            if t == tenant && family.user_id == user_id && family.credential_epoch < epoch {
                family.revoked = true;
                revoked.push(family.family_id.clone());
            }
        }
        Ok(revoked)
    }

    async fn revoke_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let mut map = self.map.lock().await;
        let mut family_ids = Vec::new();
        for ((t, _), fam) in map.iter_mut() {
            if t == tenant && fam.client_id == client_id {
                if !fam.revoked {
                    fam.revoked = true;
                }
                family_ids.push(fam.family_id.clone());
            }
        }
        Ok(family_ids)
    }

    async fn has_active_family_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        // 只读(不 mutate,区别于 revoke_by_client):本租户任一未吊销 family 归属该 client。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .any(|((t, _), fam)| t == tenant && fam.client_id == client_id && !fam.revoked))
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let mut map = self.map.lock().await;
        let removed = map
            .iter()
            .filter(|((entry_tenant, _), family)| {
                entry_tenant == tenant && family.user_id == user_id
            })
            .map(|(_, family)| family.family_id.clone())
            .collect::<Vec<_>>();
        map.retain(|(entry_tenant, _), family| entry_tenant != tenant || family.user_id != user_id);
        let removed_ids = removed.iter().collect::<std::collections::HashSet<_>>();
        self.leases
            .lock()
            .await
            .retain(|(entry_tenant, family_id), _| {
                entry_tenant != tenant || !removed_ids.contains(family_id)
            });
        Ok(removed)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<Vec<String>, StoreError> {
        let mut map = self.map.lock().await;
        let removed = map
            .iter()
            .filter(|((entry_tenant, _), _)| entry_tenant == tenant)
            .map(|(_, family)| family.family_id.clone())
            .collect::<Vec<_>>();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        self.leases
            .lock()
            .await
            .retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(removed)
    }
}

/// 内存宽限窗缓存(本地/测试;明文)。真机换 `adapters::aws::DynamoGraceStore`(item-level 信封加密,C3.4)。
/// 键 = `family_id.version`。
#[derive(Clone, Default)]
pub struct MemoryGraceStore {
    map: Arc<Mutex<HashMap<String, GraceCacheEntry>>>,
    fail_next_delete_family: Arc<AtomicU8>,
}

impl MemoryGraceStore {
    pub fn fail_next_delete_family(&self, transient: bool) {
        self.fail_next_delete_family
            .store(if transient { 1 } else { 2 }, Ordering::SeqCst);
    }
}

fn grace_key(family_id: &str, version: u64) -> String {
    format!("{family_id}.{version}")
}

impl GraceStore for MemoryGraceStore {
    async fn put(&self, entry: GraceCacheEntry) -> Result<(), StoreError> {
        let k = grace_key(&entry.family_id, entry.version);
        self.map.lock().await.insert(k, entry);
        Ok(())
    }

    async fn get(
        &self,
        family_id: &str,
        version: u64,
    ) -> Result<Option<GraceCacheEntry>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&grace_key(family_id, version))
            .cloned())
    }

    async fn delete_family(&self, family_id: &str) -> Result<(), StoreError> {
        match self.fail_next_delete_family.swap(0, Ordering::SeqCst) {
            1 => {
                return Err(StoreError::Transient(
                    "injected grace family deletion failure".into(),
                ))
            }
            2 => {
                return Err(StoreError::Permanent(
                    "injected permanent grace family deletion failure".into(),
                ))
            }
            _ => {}
        }
        // 条件删:删该 family 所有版本的缓存项(C3.5)。
        let prefix = format!("{family_id}.");
        self.map.lock().await.retain(|k, _| !k.starts_with(&prefix));
        Ok(())
    }
}

/// 内存平台 JWKS(本地/测试;按 jwks_uri 预置 key 集)。真机换 HTTP 适配器(缓存 TTL + 负缓存)。
#[derive(Clone, Default)]
pub struct MemoryJwksFetcher {
    map: Arc<Mutex<HashMap<String, Vec<crate::ports::PlatformJwk>>>>,
    fresh: Arc<Mutex<HashMap<String, Vec<crate::ports::PlatformJwk>>>>,
    fetch_calls: Arc<Mutex<HashMap<String, usize>>>,
    fresh_calls: Arc<Mutex<HashMap<String, usize>>>,
}

impl MemoryJwksFetcher {
    /// 预置某 jwks_uri 的 key 集(测试装配用)。
    pub async fn set(&self, jwks_uri: impl Into<String>, keys: Vec<crate::ports::PlatformJwk>) {
        self.map.lock().await.insert(jwks_uri.into(), keys);
    }

    pub async fn set_fresh(
        &self,
        jwks_uri: impl Into<String>,
        keys: Vec<crate::ports::PlatformJwk>,
    ) {
        self.fresh.lock().await.insert(jwks_uri.into(), keys);
    }

    pub async fn fresh_calls(&self, jwks_uri: &str) -> usize {
        self.fresh_calls
            .lock()
            .await
            .get(jwks_uri)
            .copied()
            .unwrap_or(0)
    }

    pub async fn fetch_calls(&self, jwks_uri: &str) -> usize {
        self.fetch_calls
            .lock()
            .await
            .get(jwks_uri)
            .copied()
            .unwrap_or(0)
    }
}

impl crate::ports::JwksFetcher for MemoryJwksFetcher {
    async fn fetch(&self, jwks_uri: &str) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        *self
            .fetch_calls
            .lock()
            .await
            .entry(jwks_uri.to_string())
            .or_default() += 1;
        // 未预置 = 空集(上层按 kid 选不到 key → 认证失败,fail-closed)。
        Ok(self
            .map
            .lock()
            .await
            .get(jwks_uri)
            .cloned()
            .unwrap_or_default())
    }
    async fn fetch_fresh(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        *self
            .fresh_calls
            .lock()
            .await
            .entry(jwks_uri.to_string())
            .or_default() += 1;
        let fresh = self.fresh.lock().await.get(jwks_uri).cloned();
        if let Some(keys) = fresh {
            self.map
                .lock()
                .await
                .insert(jwks_uri.to_string(), keys.clone());
            return Ok(keys);
        }
        self.fetch(jwks_uri).await
    }
}

/// 内存 STS caller(本地/测试):按 assertion 的 `Signature=` 段预置身份。真机换 reqwest 适配器。
/// 未预置 = STS 拒(Ok(None));预置 `Transient` 触发器可模拟 STS 超时(测熔断)。
#[derive(Clone, Default)]
pub struct MemoryStsCaller {
    /// signature 段 → 身份(STS 200);None 值表示"该 signature STS 拒"(4xx)。
    map: Arc<Mutex<HashMap<String, Option<agent_auth_workload::StsCallerIdentity>>>>,
    /// 若 signature ∈ 此集合,`get_caller_identity` 返 Transient(模拟 STS 超时/5xx,测熔断)。
    transient: Arc<Mutex<std::collections::HashSet<String>>>,
    calls: Arc<AtomicUsize>,
}

impl MemoryStsCaller {
    /// 预置:该 assertion signature 转发 STS 后返回 `id`(STS 200)。
    pub async fn set(
        &self,
        signature: impl Into<String>,
        id: agent_auth_workload::StsCallerIdentity,
    ) {
        self.map.lock().await.insert(signature.into(), Some(id));
    }
    /// 预置:该 signature STS 拒(4xx / 签名无效)→ Ok(None)。
    pub async fn set_rejected(&self, signature: impl Into<String>) {
        self.map.lock().await.insert(signature.into(), None);
    }
    /// 预置:该 signature 转发时 STS 瞬时失败(超时/5xx)→ Err(Transient),用于测熔断。
    pub async fn set_transient(&self, signature: impl Into<String>) {
        self.transient.lock().await.insert(signature.into());
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl crate::ports::StsCaller for MemoryStsCaller {
    async fn get_caller_identity(
        &self,
        assertion: &agent_auth_workload::SigV4Assertion,
    ) -> Result<Option<agent_auth_workload::StsCallerIdentity>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // 取 assertion 的 Signature= 段作 key(与真机"转发这枚预签名请求"一一对应)。
        let sig = assertion
            .headers
            .get("authorization")
            .and_then(|a| agent_auth_workload::replay::extract_signature(a))
            .unwrap_or_default();
        if self.transient.lock().await.contains(&sig) {
            return Err(StoreError::Transient("STS 模拟超时".into()));
        }
        // 未预置 = STS 拒(Ok(None),fail-closed)。
        Ok(self.map.lock().await.get(&sig).cloned().flatten())
    }
}

/// 内存一次性 replay 缓存(本地/测试,spec 012 C5.3②)。key→expires_at;check_and_set 原子(锁内)。
#[derive(Clone, Default)]
pub struct MemoryReplayStore {
    map: Arc<Mutex<HashMap<(String, String), i64>>>,
}

impl crate::ports::ReplayStore for MemoryReplayStore {
    async fn check_and_set(
        &self,
        tenant: &str,
        key: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        // 锁内 CAS:key 不存在(或已过期)→ 记录返 true(接受);仍有效存在 → false(重放拒)。
        // 边界 inclusive(`>=`,评审 codex/Kiro H1):`exp == now` 仍视为有效存在 → 拒(不在过期瞬间放行重放)。
        let now = crate::token::current_unix_secs_pub();
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), key.to_string());
        match map.get(&key) {
            Some(exp) if *exp >= now => Ok(false), // 窗内已见(含边界)→ 重放拒
            _ => {
                map.insert(key, expires_at);
                Ok(true)
            }
        }
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 secret 解析器(本地/测试,spec 003 §4 Task 4.6)。预置 引用名→明文 映射(真机走 Secrets Manager/SSM)。
#[derive(Clone, Default)]
pub struct MemorySecretResolver {
    map: Arc<Mutex<HashMap<String, String>>>,
}

impl MemorySecretResolver {
    /// 预置一条 引用名→明文(仅测试用)。
    pub async fn seed(&self, secret_ref: &str, plaintext: &str) {
        self.map
            .lock()
            .await
            .insert(secret_ref.to_string(), plaintext.to_string());
    }
}

impl crate::ports::SecretResolver for MemorySecretResolver {
    async fn resolve(&self, secret_ref: &str) -> Result<Option<String>, StoreError> {
        Ok(self.map.lock().await.get(secret_ref).cloned())
    }
}

/// 内存上游 token 交换器(本地/测试,spec 003 §4 Task 4.6)。预置 code→UpstreamTokenSet(真机走 reqwest→上游)。
/// 只按 `code` 命中(测试注入);真机 adapter 会用 token_endpoint/client 凭证真 POST。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryUpstreamTokenExchange {
    pub token_endpoint: String,
    pub client_id: String,
    pub code_sha256: String,
    pub code_challenge: String,
    pub redirect_uri: String,
}

#[derive(Clone, Default)]
pub struct MemoryUpstreamTokenExchanger {
    map: Arc<Mutex<HashMap<String, crate::ports::UpstreamTokenSet>>>,
    requests: Arc<Mutex<Vec<MemoryUpstreamTokenExchange>>>,
}

impl MemoryUpstreamTokenExchanger {
    const MAX_RECORDED_REQUESTS: usize = 64;

    /// 预置一条 code→token set(仅测试用)。
    pub async fn seed(&self, code: &str, set: crate::ports::UpstreamTokenSet) {
        self.map.lock().await.insert(code.to_string(), set);
    }

    pub async fn requests(&self) -> Vec<MemoryUpstreamTokenExchange> {
        self.requests.lock().await.clone()
    }
}

impl crate::ports::UpstreamTokenExchanger for MemoryUpstreamTokenExchanger {
    async fn exchange_code(
        &self,
        req: &crate::ports::UpstreamTokenExchangeRequest<'_>,
    ) -> Result<Option<crate::ports::UpstreamTokenSet>, StoreError> {
        let mut requests = self.requests.lock().await;
        if requests.len() == Self::MAX_RECORDED_REQUESTS {
            requests.remove(0);
        }
        requests.push(MemoryUpstreamTokenExchange {
            token_endpoint: req.token_endpoint.to_string(),
            client_id: req.client_id.to_string(),
            code_sha256: agent_auth_client::s256_challenge(req.code),
            code_challenge: agent_auth_client::s256_challenge(req.code_verifier),
            redirect_uri: req.redirect_uri.to_string(),
        });
        // 测试语义:命中预置 code → 返 token set;否则 None(模拟上游拒)。
        Ok(self.map.lock().await.get(req.code).cloned())
    }
}

/// 内存联邦 flow 状态存储(本地/测试,spec 003 §4 Task 4.7)。key = state;consume 一次性(取出即删)。
#[derive(Clone, Default)]
pub struct MemoryFederationFlowStore {
    map: Arc<Mutex<HashMap<String, crate::ports::FederationFlowState>>>,
}

impl crate::ports::FederationFlowStore for MemoryFederationFlowStore {
    async fn put(&self, state: crate::ports::FederationFlowState) -> Result<(), StoreError> {
        self.map.lock().await.insert(state.state.clone(), state);
        Ok(())
    }

    async fn consume(
        &self,
        state: &str,
    ) -> Result<Option<crate::ports::FederationFlowState>, StoreError> {
        // 一次性:锁内 remove(取出即删,防 state 重放)+ 过期校验(过期即视作 None)。
        let now = crate::token::current_unix_secs_pub();
        let mut map = self.map.lock().await;
        match map.remove(state) {
            Some(s) if s.expires_at > now => Ok(Some(s)),
            // 已过期:remove 已删,返 None(fail-closed)。
            _ => Ok(None),
        }
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, flow| flow.tenant_id != tenant_id);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 passkey challenge 存储(本地/测试,spec 003 §3)。key=challenge 值;consume 一次性 + 过期校验。
#[derive(Clone, Default)]
pub struct MemoryPasskeyChallengeStore {
    map: Arc<Mutex<HashMap<String, crate::ports::PasskeyChallenge>>>,
}

impl crate::ports::PasskeyChallengeStore for MemoryPasskeyChallengeStore {
    async fn put(&self, ch: crate::ports::PasskeyChallenge) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert(ch.challenge_b64url.clone(), ch);
        Ok(())
    }
    async fn consume(
        &self,
        tenant: &str,
        challenge_b64url: &str,
    ) -> Result<Option<crate::ports::PasskeyChallenge>, StoreError> {
        let now = crate::token::current_unix_secs_pub();
        let mut map = self.map.lock().await;
        if map
            .get(challenge_b64url)
            .is_some_and(|challenge| challenge.tenant != tenant)
        {
            return Ok(None);
        }
        match map.remove(challenge_b64url) {
            Some(c) if c.expires_at > now => Ok(Some(c)),
            _ => Ok(None), // 无/已用/过期 → fail-closed
        }
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, challenge| {
            challenge.tenant != tenant || challenge.user_id.as_deref() != Some(user_id)
        });
        Ok(before - map.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, challenge| challenge.tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 passkey 凭证存储(本地/测试,spec 003 §3)。map: credential_id → PasskeyCredential。
/// put_new 条件写(credentialId 已存在拒);update_sign_count 锁内 CAS(防克隆)。
/// **复合 tenant 键**(spec 020 §2.3 D1):键=(tenant, credential_id)。
#[derive(Clone, Default)]
pub struct MemoryPasskeyStore {
    map: Arc<Mutex<HashMap<(String, String), agent_auth_authn::passkey::PasskeyCredential>>>,
}

impl MemoryPasskeyStore {
    pub(crate) async fn put_new_authorized(
        &self,
        users: &MemoryUsersStore,
        sessions: &MemorySessionStore,
        tenant: &str,
        session: &SessionRecord,
        credential: agent_auth_authn::passkey::PasskeyCredential,
        now: i64,
    ) -> Result<PasskeyRegistrationOutcome, StoreError> {
        if credential.user_id != session.user_id
            || !crate::account_credentials::session_is_reauthenticated(session, now)
            || session.expires_at <= now
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }
        let users = users.by_id.lock().await;
        let Some(user) = users.get(&(tenant.to_string(), session.user_id.clone())) else {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        };
        if user.status != crate::ports::UserStatus::Active
            || user.revocation_pending
            || user.credential_epoch != session.credential_epoch
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }

        let session_state = sessions.state.lock().await;
        let current_generation = session_state
            .generations
            .get(&(tenant.to_string(), session.user_id.clone()))
            .copied()
            .unwrap_or(0);
        let Some(stored) = session_state
            .sessions
            .get(&(tenant.to_string(), session.session_id.clone()))
        else {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        };
        if stored.record.user_id != session.user_id
            || stored.record.credential_epoch != session.credential_epoch
            || stored.record.expires_at <= now
            || !crate::account_credentials::session_is_reauthenticated(&stored.record, now)
            || stored.generation != current_generation
        {
            return Ok(PasskeyRegistrationOutcome::AuthorityChanged);
        }

        let mut passkeys = self.map.lock().await;
        let key = (tenant.to_string(), credential.credential_id.clone());
        if passkeys.contains_key(&key) {
            return Ok(PasskeyRegistrationOutcome::CredentialExists);
        }
        passkeys.insert(key, credential);
        Ok(PasskeyRegistrationOutcome::Created)
    }

    pub(crate) async fn delete_owned_and_complete(
        &self,
        users: &MemoryUsersStore,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let user_key = (tenant.to_string(), user_id.to_string());
        let mut user_records = users.by_id.lock().await;
        let mut operation_ids = users.credential_change_ids.lock().await;
        let Some(user) = user_records.get_mut(&user_key) else {
            return Ok(false);
        };
        if user.status != crate::ports::UserStatus::Active
            || !user.revocation_pending
            || user.credential_epoch != owner.epoch
            || operation_ids.get(&user_key).map(String::as_str) != Some(owner.operation_id)
        {
            return Ok(false);
        }

        let mut passkeys = self.map.lock().await;
        let key = (tenant.to_string(), credential_id.to_string());
        if passkeys
            .get(&key)
            .is_none_or(|credential| credential.user_id != user_id)
        {
            return Ok(false);
        }
        passkeys.remove(&key);
        user.revocation_pending = false;
        user.updated_at = updated_at;
        operation_ids.remove(&user_key);
        Ok(true)
    }
}

impl crate::ports::PasskeyStore for MemoryPasskeyStore {
    async fn put_new(
        &self,
        tenant: &str,
        cred: agent_auth_authn::passkey::PasskeyCredential,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let k = (tenant.to_string(), cred.credential_id.clone());
        // 条件写:credentialId 已存在 → false(拒覆盖,防伪造/碰撞,评审 Kiro)。
        if map.contains_key(&k) {
            return Ok(false);
        }
        map.insert(k, cred);
        Ok(true)
    }
    async fn get(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> Result<Option<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), credential_id.to_string()))
            .cloned())
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_authn::passkey::PasskeyCredential>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), c)| t == tenant && c.user_id == user_id)
            .map(|(_, c)| c.clone())
            .collect())
    }
    async fn update_sign_count(
        &self,
        tenant: &str,
        credential_id: &str,
        new_count: u32,
        expected_prev: u32,
    ) -> Result<bool, StoreError> {
        // 锁内 CAS:仅当当前 sign_count == expected_prev 才写 new(防克隆并发/回退)。
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), credential_id.to_string())) {
            Some(c) if c.sign_count == expected_prev => {
                c.sign_count = new_count;
                Ok(true)
            }
            _ => Ok(false), // 竞态/回退/不存在 → 拒
        }
    }
    async fn rename_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), credential_id.to_string())) {
            Some(credential) if credential.user_id == user_id => {
                credential.name = name.to_string();
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), credential_id.to_string());
        if map
            .get(&key)
            .is_none_or(|credential| credential.user_id != user_id)
        {
            return Ok(false);
        }
        map.remove(&key);
        Ok(true)
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(t, _), c| !(t == tenant && c.user_id == user_id));
        Ok(before - map.len())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 Grant 存储(本地/测试,spec 011 §5.1)。**复合 tenant 键**:键=(tenant, grant_id);list_by_user 遍历(量小)。
#[derive(Clone, Default)]
pub struct MemoryGrantStore {
    map: Arc<Mutex<HashMap<(String, String), agent_auth_grant::Grant>>>,
    fail_next_put: Arc<AtomicU8>,
    fail_next_get_permanent: Arc<AtomicU8>,
    conflict_next_put_conditional: Arc<AtomicU8>,
    conflict_next_revoke_if_revision: Arc<AtomicU8>,
}

impl MemoryGrantStore {
    pub fn fail_next_put(&self) {
        self.fail_next_put.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_get_permanent(&self) {
        self.fail_next_get_permanent.store(1, Ordering::SeqCst);
    }

    pub fn conflict_next_put_conditional(&self) {
        self.conflict_next_put_conditional
            .store(1, Ordering::SeqCst);
    }

    pub fn conflict_next_revoke_if_revision(&self) {
        self.conflict_next_revoke_if_revision
            .store(1, Ordering::SeqCst);
    }

    pub async fn record_count(&self) -> usize {
        self.map.lock().await.len()
    }

    pub(crate) async fn put_for_active_client(
        &self,
        clients: &MemoryClientStore,
        tenant: &str,
        grant: agent_auth_grant::Grant,
    ) -> Result<bool, StoreError> {
        if self.fail_next_put.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected Grant persistence failure".into(),
            ));
        }
        let today = crate::current_unix_secs().div_euclid(86_400);
        let mut client_map = clients.map.lock().await;
        let Some(client) = client_map.get_mut(&(tenant.to_string(), grant.client_id.clone()))
        else {
            return Ok(false);
        };
        if client.tombstoned_at.is_some() || client.last_used_day.is_some_and(|day| day > today) {
            return Ok(false);
        }
        client.last_used_day = Some(client.last_used_day.unwrap_or(today).max(today));
        client.authority_revision = client.authority_revision.saturating_add(1);
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), grant.grant_id.clone()), grant);
        Ok(true)
    }
}

impl crate::ports::GrantStore for MemoryGrantStore {
    async fn put(&self, tenant: &str, grant: agent_auth_grant::Grant) -> Result<(), StoreError> {
        if self.fail_next_put.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected Grant persistence failure".into(),
            ));
        }
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), grant.grant_id.clone()), grant);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> Result<Option<agent_auth_grant::Grant>, StoreError> {
        if self.fail_next_get_permanent.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Permanent(
                "injected permanent Grant read failure".into(),
            ));
        }
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), grant_id.to_string()))
            .cloned())
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<agent_auth_grant::Grant>, StoreError> {
        let mut v: Vec<agent_auth_grant::Grant> = self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), g)| t == tenant && g.user_id == user_id)
            .map(|(_, g)| g.clone())
            .collect();
        v.sort_by(|a, b| a.grant_id.cmp(&b.grant_id)); // 稳定顺序
        Ok(v)
    }
    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), grant_id.to_string())) {
            Some(g) => {
                g.status = agent_auth_grant::GrantStatus::Revoked;
                g.revision += 1; // bump:使 put_conditional 的 expected 不符 → 重算不复活已吊销(⑫)。
                Ok(true)
            }
            None => Ok(false),
        }
    }
    async fn revoke_if_epoch_before(
        &self,
        tenant: &str,
        grant_id: &str,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        match map.get_mut(&(tenant.to_string(), grant_id.to_string())) {
            Some(grant) if grant.credential_epoch < epoch => {
                grant.status = agent_auth_grant::GrantStatus::Revoked;
                grant.revision += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn revoke_if_revision(
        &self,
        tenant: &str,
        grant_id: &str,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), grant_id.to_string());
        if self
            .conflict_next_revoke_if_revision
            .swap(0, Ordering::SeqCst)
            != 0
        {
            if let Some(grant) = map.get_mut(&key) {
                grant.revision = grant.revision.saturating_add(1);
            }
        }
        match map.get_mut(&key) {
            Some(grant)
                if grant.revision == expected_revision
                    && grant.status == agent_auth_grant::GrantStatus::Active =>
            {
                grant.status = agent_auth_grant::GrantStatus::Revoked;
                grant.revision = expected_revision.saturating_add(1);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn put_conditional(
        &self,
        tenant: &str,
        mut grant: agent_auth_grant::Grant,
        expected_revision: u64,
    ) -> Result<bool, StoreError> {
        // 临界区内 CAS(锁内 check+write 原子):仅当当前 revision==expected 且未 Revoked 才写,revision+1。
        let mut map = self.map.lock().await;
        let key = (tenant.to_string(), grant.grant_id.clone());
        if self.conflict_next_put_conditional.swap(0, Ordering::SeqCst) != 0 {
            if let Some(current) = map.get_mut(&key) {
                current.revision = current.revision.saturating_add(1);
            }
        }
        match map.get(&key) {
            Some(cur)
                if cur.revision == expected_revision
                    && cur.status != agent_auth_grant::GrantStatus::Revoked =>
            {
                grant.revision = expected_revision + 1;
                map.insert(key, grant);
                Ok(true)
            }
            // revision 不符 / 已 Revoked / 不存在 → 冲突,不写(重算下轮再处理)。
            _ => Ok(false),
        }
    }
    async fn list_stale(
        &self,
        tenant: &str,
        current_pv: u64,
    ) -> Result<Vec<(String, agent_auth_grant::Grant)>, StoreError> {
        // 本租户内 effective_pv < current_pv 的 Grant(重算候选);跳过已终态(Revoked/Expired 无需重算)。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), g)| {
                t == tenant
                    && g.effective_pv < current_pv
                    && g.status == agent_auth_grant::GrantStatus::Active
            })
            .map(|((t, _), g)| (t.clone(), g.clone()))
            .collect())
    }

    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), grant| entry_tenant != tenant || grant.user_id != user_id);
        Ok(before - map.len())
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), grant| {
            entry_tenant != tenant || grant.client_id != client_id
        });
        Ok(before.saturating_sub(map.len()))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存逐租户 policy_version(本地/测试,spec 005 §7)。键 = tenant;无记录 → 0。
#[derive(Clone, Default)]
pub struct MemoryPolicyVersionStore {
    map: Arc<Mutex<HashMap<String, u64>>>,
}

impl crate::ports::PolicyVersionStore for MemoryPolicyVersionStore {
    async fn get(&self, tenant: &str) -> Result<u64, StoreError> {
        Ok(self.map.lock().await.get(tenant).copied().unwrap_or(0))
    }
    async fn bump(&self, tenant: &str) -> Result<u64, StoreError> {
        let mut map = self.map.lock().await;
        let v = map.entry(tenant.to_string()).or_insert(0);
        *v += 1;
        Ok(*v)
    }
    async fn delete(&self, tenant: &str) -> Result<usize, StoreError> {
        Ok(usize::from(self.map.lock().await.remove(tenant).is_some()))
    }
}

/// 工件表:键=(tenant, version) → 值=(text, digest)。
type ArtifactMap = HashMap<(String, u64), (String, String)>;

/// 内存不可变策略工件(本地/测试,spec 005 §7)。键 = (tenant, version) → (text, digest)。
#[derive(Clone, Default)]
pub struct MemoryPolicyArtifactStore {
    map: Arc<Mutex<ArtifactMap>>,
    fail_next_put: Arc<AtomicU8>,
    fail_next_get: Arc<AtomicU8>,
    get_count: Arc<AtomicUsize>,
}

impl MemoryPolicyArtifactStore {
    pub fn fail_next_put(&self) {
        self.fail_next_put.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_get(&self) {
        self.fail_next_get.store(1, Ordering::SeqCst);
    }

    pub fn get_count(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
}

impl crate::ports::PolicyArtifactStore for MemoryPolicyArtifactStore {
    async fn put(
        &self,
        tenant: &str,
        version: u64,
        text: String,
        digest: String,
    ) -> Result<(), StoreError> {
        if self.fail_next_put.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected policy artifact persistence failure".into(),
            ));
        }
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), version), (text, digest));
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        version: u64,
    ) -> Result<Option<(String, String)>, StoreError> {
        self.get_count.fetch_add(1, Ordering::SeqCst);
        if self.fail_next_get.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected policy artifact read failure".into(),
            ));
        }
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), version))
            .cloned())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 jti→主体映射(本地/测试)。键 = `tenant_id\x1fjti`(按 tenant 分区,跨租户查不到)。
#[derive(Clone, Default)]
pub struct MemoryJtiStore {
    map: Arc<Mutex<HashMap<String, crate::ports::JtiRecord>>>,
    fail_next_get: Arc<AtomicU8>,
}

impl MemoryJtiStore {
    pub fn fail_next_get(&self) {
        self.fail_next_get.store(1, Ordering::SeqCst);
    }
}

fn jti_key(tenant_id: &str, jti: &str) -> String {
    format!("{tenant_id}\u{1f}{jti}")
}

impl crate::ports::JtiStore for MemoryJtiStore {
    async fn put(&self, record: crate::ports::JtiRecord) -> Result<(), StoreError> {
        let k = jti_key(&record.tenant_id, &record.jti);
        self.map.lock().await.insert(k, record);
        Ok(())
    }
    async fn get(
        &self,
        tenant_id: &str,
        jti: &str,
    ) -> Result<Option<crate::ports::JtiRecord>, StoreError> {
        if self.fail_next_get.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient("injected jti read failure".into()));
        }
        Ok(self.map.lock().await.get(&jti_key(tenant_id, jti)).cloned())
    }

    async fn delete_by_user(&self, tenant_id: &str, user_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, record| record.tenant_id != tenant_id || record.user_id != user_id);
        Ok(before - map.len())
    }

    async fn delete_all_by_tenant(&self, tenant_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|_, record| record.tenant_id != tenant_id);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存会话存储(本地/测试)。**复合 tenant 键**(spec 020 §2.3 D1):键=(tenant, session_id)。
#[derive(Clone)]
struct MemoryStoredSession {
    record: SessionRecord,
    generation: u64,
}

#[derive(Default)]
struct MemorySessionState {
    sessions: HashMap<(String, String), MemoryStoredSession>,
    generations: HashMap<(String, String), u64>,
}

#[derive(Clone, Default)]
pub struct MemorySessionStore {
    state: Arc<Mutex<MemorySessionState>>,
    fail_next_create: Arc<AtomicU8>,
}

impl MemorySessionStore {
    pub fn fail_next_create(&self) {
        self.fail_next_create.store(1, Ordering::SeqCst);
    }
}

impl SessionStore for MemorySessionStore {
    async fn create(&self, tenant: &str, s: SessionRecord) -> Result<(), StoreError> {
        if self.fail_next_create.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected login session persistence failure".into(),
            ));
        }
        let mut state = self.state.lock().await;
        let generation = state
            .generations
            .get(&(tenant.to_string(), s.user_id.clone()))
            .copied()
            .unwrap_or(0);
        state.sessions.insert(
            (tenant.to_string(), s.session_id.clone()),
            MemoryStoredSession {
                record: s,
                generation,
            },
        );
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let state = self.state.lock().await;
        let Some(stored) = state
            .sessions
            .get(&(tenant.to_string(), session_id.to_string()))
        else {
            return Ok(None);
        };
        let current_generation = state
            .generations
            .get(&(tenant.to_string(), stored.record.user_id.clone()))
            .copied()
            .unwrap_or(0);
        Ok((stored.generation == current_generation).then(|| stored.record.clone()))
    }
    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        self.state
            .lock()
            .await
            .sessions
            .remove(&(tenant.to_string(), session_id.to_string()));
        Ok(())
    }
    async fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        let state = self.state.lock().await;
        let generation = state
            .generations
            .get(&(tenant.to_string(), user_id.to_string()))
            .copied()
            .unwrap_or(0);
        Ok(state
            .sessions
            .iter()
            .filter(|((t, _), stored)| {
                t == tenant
                    && stored.record.user_id == user_id
                    && stored.record.expires_at > now
                    && stored.generation == generation
            })
            .map(|(_, stored)| stored.record.clone())
            .collect())
    }
    async fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        target_session_id: &str,
    ) -> Result<bool, StoreError> {
        let mut state = self.state.lock().await;
        let user_key = (tenant.to_string(), user_id.to_string());
        let current_generation = state.generations.get(&user_key).copied().unwrap_or(0);
        let actor_key = (tenant.to_string(), actor_session_id.to_string());
        if !state.sessions.get(&actor_key).is_some_and(|stored| {
            stored.record.user_id == user_id && stored.generation == current_generation
        }) {
            return Ok(false);
        }
        let key = (tenant.to_string(), target_session_id.to_string());
        if state.sessions.get(&key).is_some_and(|stored| {
            stored.record.user_id == user_id && stored.generation == current_generation
        }) {
            state.sessions.remove(&key);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn delete_others_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
    ) -> Result<Option<usize>, StoreError> {
        let mut state = self.state.lock().await;
        let user_key = (tenant.to_string(), user_id.to_string());
        let current_generation = state.generations.get(&user_key).copied().unwrap_or(0);
        let retained_key = (tenant.to_string(), retained_session_id.to_string());
        let Some(retained) = state.sessions.get(&retained_key) else {
            return Ok(Some(0));
        };
        if retained.record.user_id != user_id || retained.generation != current_generation {
            return Ok(Some(0));
        }
        let affected = state
            .sessions
            .iter()
            .filter(|((t, id), stored)| {
                t == tenant
                    && id != retained_session_id
                    && stored.record.user_id == user_id
                    && stored.generation == current_generation
            })
            .count();
        let next_generation = current_generation.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("login session generation exhausted".to_string())
        })?;
        state
            .sessions
            .get_mut(&retained_key)
            .expect("retained session remained locked")
            .generation = next_generation;
        state.generations.insert(user_key, next_generation);
        // Keep stale records in memory to exercise the authority fence itself.
        // DynamoDB removes them best-effort and TTL is the final physical GC.
        Ok(Some(affected))
    }
    async fn revoke_all_by_actor(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
    ) -> Result<bool, StoreError> {
        let mut state = self.state.lock().await;
        let user_key = (tenant.to_string(), user_id.to_string());
        let current_generation = state.generations.get(&user_key).copied().unwrap_or(0);
        let actor_key = (tenant.to_string(), actor_session_id.to_string());
        if !state.sessions.get(&actor_key).is_some_and(|stored| {
            stored.record.user_id == user_id && stored.generation == current_generation
        }) {
            return Ok(false);
        }
        let next_generation = current_generation.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("login session generation exhausted".to_string())
        })?;
        state.generations.insert(user_key, next_generation);
        state.sessions.remove(&actor_key);
        Ok(true)
    }
    async fn touch_last_used(
        &self,
        tenant: &str,
        session_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut state = self.state.lock().await;
        let key = (tenant.to_string(), session_id.to_string());
        let Some(stored) = state.sessions.get(&key) else {
            return Ok(false);
        };
        let user_key = (tenant.to_string(), stored.record.user_id.clone());
        let generation = state.generations.get(&user_key).copied().unwrap_or(0);
        if stored.generation != generation {
            return Ok(false);
        }
        let stored = state
            .sessions
            .get_mut(&key)
            .expect("session remained locked");
        stored.record.last_used_at = stored.record.last_used_at.max(now);
        Ok(true)
    }
    async fn delete_by_user(&self, tenant: &str, user_id: &str) -> Result<usize, StoreError> {
        // 仅本租户会话(复合键第一元 == tenant),再按 user_id 过滤删。
        let mut state = self.state.lock().await;
        let before = state.sessions.len();
        state
            .sessions
            .retain(|(t, _), stored| !(t == tenant && stored.record.user_id == user_id));
        Ok(before - state.sessions.len())
    }
    async fn delete_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> Result<usize, StoreError> {
        let mut state = self.state.lock().await;
        let before = state.sessions.len();
        state.sessions.retain(|(t, _), stored| {
            !(t == tenant
                && stored.record.user_id == user_id
                && stored.record.credential_epoch < epoch)
        });
        Ok(before - state.sessions.len())
    }
    async fn count_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let state = self.state.lock().await;
        let generation = state
            .generations
            .get(&(tenant.to_string(), user_id.to_string()))
            .copied()
            .unwrap_or(0);
        Ok(state
            .sessions
            .iter()
            .filter(|((t, _), stored)| {
                t == tenant
                    && stored.record.user_id == user_id
                    && stored.record.expires_at > now
                    && stored.generation == generation
            })
            .count())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut state = self.state.lock().await;
        let sessions_before = state.sessions.len();
        state
            .sessions
            .retain(|(entry_tenant, _), _| entry_tenant != tenant);
        let generations_before = state.generations.len();
        state
            .generations
            .retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(sessions_before
            .saturating_sub(state.sessions.len())
            .saturating_add(generations_before.saturating_sub(state.generations.len())))
    }
}

/// 内存恢复码存储(本地/测试);verify_and_consume 在锁内原子完成(等价 DynamoDB 条件写)。
/// **复合 tenant 键**(spec 020 §2.3 D1):键=(tenant, user_lookup)。
#[derive(Clone, Default)]
pub struct MemoryRecoveryStore {
    map: Arc<Mutex<HashMap<(String, String), RecoveryRecord>>>,
    results: Arc<Mutex<HashMap<(String, String), RecoverySuccessResult>>>,
}

fn consume_recovery_record(
    record: &mut RecoveryRecord,
    presented_hash: &str,
    now: i64,
) -> RecoveryConsume {
    use agent_auth_authn::recovery::{hash_eq_b64, is_locked, on_failed_attempt};

    if is_locked(record.locked_until, now) {
        return RecoveryConsume::Locked {
            retry_after_secs: record.locked_until - now,
        };
    }
    if let Some(entry) = record
        .code_hashes
        .iter_mut()
        .find(|entry| !entry.consumed && hash_eq_b64(&entry.hash_b64, presented_hash))
    {
        entry.consumed = true;
        record.attempt_count = 0;
        record.locked_until = 0;
        RecoveryConsume::Valid
    } else {
        let (attempt_count, locked_until) = on_failed_attempt(record.attempt_count, now);
        record.attempt_count = attempt_count;
        record.locked_until = locked_until;
        if is_locked(locked_until, now) {
            RecoveryConsume::Locked {
                retry_after_secs: locked_until - now,
            }
        } else {
            RecoveryConsume::Invalid
        }
    }
}

impl MemoryRecoveryStore {
    pub(crate) async fn commit_rotation(
        &self,
        users: &MemoryUsersStore,
        tenant: &str,
        record: RecoveryRecord,
        expected_email: &str,
        owner: crate::ports::CredentialChangeOwner<'_>,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let key = (tenant.to_string(), record.user_id.clone());
        let mut user_records = users.by_id.lock().await;
        let mut operation_ids = users.credential_change_ids.lock().await;
        let Some(user) = user_records.get_mut(&key) else {
            return Ok(false);
        };
        if user.status != crate::ports::UserStatus::Active
            || !user.revocation_pending
            || user.credential_epoch != owner.epoch
            || operation_ids.get(&key).map(String::as_str) != Some(owner.operation_id)
            || user.email != expected_email
        {
            return Ok(false);
        }

        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.user_lookup.clone()), record);
        user.revocation_pending = false;
        user.updated_at = updated_at;
        operation_ids.remove(&key);
        Ok(true)
    }

    pub(crate) async fn verify_and_consume_at_epoch(
        &self,
        users: &MemoryUsersStore,
        passwords: &MemoryPasswordStore,
        sessions: &MemorySessionStore,
        request: RecoveryConsumeRequest<'_>,
        session: SessionRecord,
        result: RecoverySuccessResult,
    ) -> Result<RecoveryAuthorityConsume, StoreError> {
        let next_epoch = request
            .expected_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".to_string()))?;
        if session.user_id != request.user_id
            || session.credential_epoch != next_epoch
            || result.operation_key.is_empty()
            || result.user_lookup != request.user_lookup
            || result.user_id != request.user_id
            || !agent_auth_authn::recovery::hash_eq_b64(
                &result.presented_hash,
                request.presented_hash,
            )
            || result.credential_epoch != next_epoch
            || result.session_id != session.session_id
            || result.created_at != session.created_at
            || result.created_at > request.now
            || result.expires_at <= request.now
            || result.expires_at > session.expires_at
        {
            return Err(StoreError::Permanent(
                "recovery result does not match recovery authority".to_string(),
            ));
        }
        let mut users = users.by_id.lock().await;
        let passwords = passwords.map.lock().await;
        let password_authority = if let Some(credential) =
            passwords.get(&(request.tenant.to_string(), request.user_id.to_string()))
        {
            if credential.user_id != request.user_id {
                None
            } else {
                Some(!credential.must_change && !credential.revocation_pending)
            }
        } else {
            Some(true)
        };
        let mut session_state = sessions.state.lock().await;
        let mut records = self.map.lock().await;
        let mut results = self.results.lock().await;
        let user_key = (request.tenant.to_string(), request.user_id.to_string());
        let result_key = (request.tenant.to_string(), result.operation_key.to_string());
        if let Some(existing) = results.get(&result_key) {
            let binding_matches = existing.user_lookup == request.user_lookup
                && existing.user_id == request.user_id
                && agent_auth_authn::recovery::hash_eq_b64(
                    &existing.presented_hash,
                    request.presented_hash,
                )
                && existing.created_at < existing.expires_at
                && existing.expires_at > request.now;
            if !binding_matches {
                return Ok(RecoveryAuthorityConsume::Invalid);
            }
            if password_authority.is_none() {
                return Err(StoreError::Permanent(
                    "password credential user does not match recovery authority".to_string(),
                ));
            }
            if password_authority == Some(false) {
                return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
            }
            let session_key = (request.tenant.to_string(), existing.session_id.to_string());
            let current_generation = session_state
                .generations
                .get(&user_key)
                .copied()
                .unwrap_or(0);
            let result_is_authoritative = users.get(&user_key).is_some_and(|user| {
                user.status == crate::ports::UserStatus::Active
                    && !user.revocation_pending
                    && user.credential_epoch == existing.credential_epoch
                    && user.email == request.expected_email
            }) && session_state
                .sessions
                .get(&session_key)
                .is_some_and(|stored| {
                    stored.record.user_id == existing.user_id
                        && stored.record.credential_epoch == existing.credential_epoch
                        && stored.record.created_at == existing.created_at
                        && stored.record.expires_at > request.now
                        && existing.expires_at <= stored.record.expires_at
                        && stored.generation == current_generation
                });
            return Ok(if result_is_authoritative {
                RecoveryAuthorityConsume::Replayed {
                    result: existing.clone(),
                }
            } else {
                RecoveryAuthorityConsume::AuthorityChanged
            });
        }
        let Some(user) = users.get_mut(&user_key) else {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        };
        if user.status != crate::ports::UserStatus::Active
            || user.revocation_pending
            || user.credential_epoch != request.expected_epoch
            || user.email != request.expected_email
        {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        }
        let Some(record) =
            records.get_mut(&(request.tenant.to_string(), request.user_lookup.to_string()))
        else {
            return Ok(RecoveryAuthorityConsume::NotFound);
        };
        if record.user_id != request.user_id {
            return Ok(RecoveryAuthorityConsume::AuthorityChanged);
        }
        let code_is_valid =
            !agent_auth_authn::recovery::is_locked(record.locked_until, request.now)
                && record.code_hashes.iter().any(|entry| {
                    !entry.consumed
                        && agent_auth_authn::recovery::hash_eq_b64(
                            &entry.hash_b64,
                            request.presented_hash,
                        )
                });
        let session_key = (request.tenant.to_string(), session.session_id.clone());
        if code_is_valid && password_authority.is_none() {
            return Err(StoreError::Permanent(
                "password credential user does not match recovery authority".to_string(),
            ));
        }
        if code_is_valid && password_authority == Some(false) {
            return Ok(RecoveryAuthorityConsume::PasswordChangeRequired);
        }
        if code_is_valid && session_state.sessions.contains_key(&session_key) {
            return Err(StoreError::Transient(
                "recovered session id collision".to_string(),
            ));
        }
        let next_generation = if code_is_valid {
            let generation = session_state
                .generations
                .get(&user_key)
                .copied()
                .unwrap_or(0);
            Some((
                user_key,
                generation.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("login session generation exhausted".to_string())
                })?,
            ))
        } else {
            None
        };
        let outcome = consume_recovery_record(record, request.presented_hash, request.now);
        Ok(match outcome {
            RecoveryConsume::Valid => {
                let (generation_key, next_generation) =
                    next_generation.expect("valid recovery precomputed its session generation");
                user.credential_epoch = next_epoch;
                user.updated_at = request.now;
                session_state
                    .generations
                    .insert(generation_key, next_generation);
                session_state.sessions.insert(
                    session_key,
                    MemoryStoredSession {
                        record: session,
                        generation: next_generation,
                    },
                );
                results.insert(result_key, result);
                RecoveryAuthorityConsume::Valid {
                    credential_epoch: next_epoch,
                }
            }
            RecoveryConsume::Invalid => RecoveryAuthorityConsume::Invalid,
            RecoveryConsume::Locked { retry_after_secs } => {
                RecoveryAuthorityConsume::Locked { retry_after_secs }
            }
            RecoveryConsume::NotFound => RecoveryAuthorityConsume::NotFound,
            RecoveryConsume::AuthorityChanged => RecoveryAuthorityConsume::AuthorityChanged,
        })
    }
}

impl RecoveryStore for MemoryRecoveryStore {
    async fn put(&self, tenant: &str, record: RecoveryRecord) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.user_lookup.clone()), record);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        user_lookup: &str,
    ) -> Result<Option<RecoveryRecord>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), user_lookup.to_string()))
            .cloned())
    }
    async fn get_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> Result<Option<RecoverySuccessResult>, StoreError> {
        Ok(self
            .results
            .lock()
            .await
            .get(&(tenant.to_string(), operation_key.to_string()))
            .cloned())
    }
    async fn verify_and_consume(
        &self,
        tenant: &str,
        user_lookup: &str,
        presented_hash: &str,
        now: i64,
    ) -> Result<RecoveryConsume, StoreError> {
        let mut map = self.map.lock().await;
        let Some(rec) = map.get_mut(&(tenant.to_string(), user_lookup.to_string())) else {
            return Ok(RecoveryConsume::NotFound);
        };
        Ok(consume_recovery_record(rec, presented_hash, now))
    }
    async fn delete_by_lookup(&self, tenant: &str, user_lookup: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), user_lookup.to_string()));
        Ok(())
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// 内存 magic-link 存储 + per-email 冷却时间戳(本地/测试)。
/// 复合键 `(tenant, key)` 与 Dynamo `tpk(tenant,key)` 分区同构(评审 codex High:link_id + 冷却
/// 键都按 tenant 隔离,否则跨租户冷却耦合 / link 跨租户消费)。
#[derive(Clone, Default)]
pub struct MemoryMagicLinkStore {
    links: Arc<Mutex<HashMap<(String, String), MagicLinkRecord>>>, // (tenant, link_id)
    cooldown: Arc<Mutex<HashMap<(String, String), i64>>>,          // (tenant, email) → last_sent_at
}

impl MagicLinkStore for MemoryMagicLinkStore {
    async fn put(&self, tenant: &str, link: MagicLinkRecord) -> Result<(), StoreError> {
        self.links
            .lock()
            .await
            .insert((tenant.to_string(), link.link_id.clone()), link);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        link_id: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        Ok(self
            .links
            .lock()
            .await
            .get(&(tenant.to_string(), link_id.to_string()))
            .cloned())
    }
    async fn consume_bound(
        &self,
        tenant: &str,
        link_id: &str,
        expected_session_nonce: &str,
    ) -> Result<Option<MagicLinkRecord>, StoreError> {
        let key = (tenant.to_string(), link_id.to_string());
        let mut links = self.links.lock().await;
        if links
            .get(&key)
            .is_none_or(|link| link.session_nonce != expected_session_nonce)
        {
            return Ok(None);
        }
        // nonce 匹配后在同一锁内取出即删,同时保持一次性与浏览器绑定。
        Ok(links.remove(&key))
    }
    async fn last_sent_at(&self, tenant: &str, email: &str) -> Result<Option<i64>, StoreError> {
        Ok(self
            .cooldown
            .lock()
            .await
            .get(&(tenant.to_string(), email.to_string()))
            .copied())
    }
    async fn mark_sent(&self, tenant: &str, email: &str, now: i64) -> Result<(), StoreError> {
        self.cooldown
            .lock()
            .await
            .insert((tenant.to_string(), email.to_string()), now);
        Ok(())
    }

    async fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<usize, StoreError> {
        let mut links = self.links.lock().await;
        let before = links.len();
        links.retain(|(entry_tenant, _), link| entry_tenant != tenant || link.user_id != user_id);
        let removed = before - links.len();
        drop(links);
        let mut cooldown = self.cooldown.lock().await;
        for alias in aliases {
            cooldown.remove(&(tenant.to_string(), alias.to_string()));
        }
        Ok(removed)
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut links = self.links.lock().await;
        let links_before = links.len();
        links.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        let removed_links = links_before.saturating_sub(links.len());
        drop(links);

        let mut cooldown = self.cooldown.lock().await;
        let cooldown_before = cooldown.len();
        cooldown.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(removed_links.saturating_add(cooldown_before.saturating_sub(cooldown.len())))
    }
}

/// dev Notifier:不真发,把 magic-link URL 打日志(stderr → CloudWatch)。真机换 SES/SNS 适配器。
#[derive(Clone, Default)]
pub struct LogNotifier;

impl Notifier for LogNotifier {
    async fn send_magic_link(
        &self,
        _tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        // dev:不发真信,仅记录(便于本地/e2e 拿到链接);真机 SES 适配器替换此实现。
        eprintln!("[dev-notifier] magic-link for {email}: {link_url}");
        Ok(())
    }
    async fn notify_recovery(
        &self,
        _tenant: &str,
        _notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        eprintln!(
            "[dev-notifier] account recovered: recipient={recipient_email} at={recovered_at} ip={}",
            client_ip.unwrap_or("-")
        );
        Ok(())
    }
}

/// 内存 outbox notifier(SES 未接前的 DynamoDB 模拟的**本地对应物**,spec 003 §1.5):把每封
/// magic-link / recovery 通知写进内存 outbox(不真发),既实现 `Notifier`(写)又实现 `MessageOutbox`
/// (读)。真机换 `adapters::aws::DynamoNotifier`(落 messages 表,TTL=1 天)。
///
/// `created_at` 用 `SystemTime`(dev/测试便利,非确定性时间在此可接受);id 用单调计数器。
#[derive(Clone, Default)]
pub struct MemoryOutboxNotifier {
    outbox: Arc<Mutex<Vec<SentMessage>>>,
    seq: Arc<Mutex<u64>>,
}

impl MemoryOutboxNotifier {
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    async fn record(
        &self,
        tenant: &str,
        kind: &str,
        recipient: &str,
        body: &str,
        notification_id: Option<&str>,
    ) {
        let created_at = Self::now_secs();
        let message_id = match notification_id {
            Some(id) => format!("recovery#{id}"),
            None => {
                let mut sequence = self.seq.lock().await;
                *sequence += 1;
                format!("msg-{sequence}")
            }
        };
        let mut outbox = self.outbox.lock().await;
        if notification_id.is_some()
            && outbox
                .iter()
                .any(|message| message.tenant == tenant && message.message_id == message_id)
        {
            return;
        }
        outbox.push(SentMessage {
            message_id,
            tenant: tenant.to_string(),
            kind: kind.to_string(),
            recipient: recipient.to_string(),
            body: body.to_string(),
            created_at,
            ttl: created_at + 86_400, // 1 天
        });
    }
}

impl Notifier for MemoryOutboxNotifier {
    async fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> Result<(), StoreError> {
        self.record(tenant, "magic_link", email, link_url, None)
            .await;
        Ok(())
    }
    async fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> Result<(), StoreError> {
        let body = format!(
            "account recovered at={recovered_at} ip={}",
            client_ip.unwrap_or("-")
        );
        self.record(
            tenant,
            "recovery",
            recipient_email,
            &body,
            Some(notification_id),
        )
        .await;
        Ok(())
    }
}

impl MessageOutbox for MemoryOutboxNotifier {
    async fn list_recent(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<SentMessage>, StoreError> {
        let v = self.outbox.lock().await;
        // **tenant-scope(C10.19)**:只取本租户消息,防跨租户泄露。再按 created_at 倒序取 limit。
        let mut out: Vec<SentMessage> = v
            .iter()
            .rev()
            .filter(|m| m.tenant == tenant)
            .take(limit)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(b.message_id.cmp(&a.message_id))
        });
        Ok(out)
    }

    async fn delete_by_recipients(
        &self,
        tenant: &str,
        recipients: &[String],
    ) -> Result<usize, StoreError> {
        let mut outbox = self.outbox.lock().await;
        let before = outbox.len();
        outbox.retain(|message| {
            message.tenant != tenant || !recipients.iter().any(|value| value == &message.recipient)
        });
        Ok(before.saturating_sub(outbox.len()))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut outbox = self.outbox.lock().await;
        let before = outbox.len();
        outbox.retain(|message| message.tenant != tenant);
        Ok(before.saturating_sub(outbox.len()))
    }
}

/// 内存 CIBA 回调投递 mock(spec 013 §4;e2e 断言"投了什么" + 可注入结果模拟失败/SSRF)。
/// **不做真出站**——记录每次 deliver 的请求供断言;`forced_outcome` 注入后所有投递返回它(默认 Delivered)。
#[derive(Clone, Default)]
pub struct MemoryCibaCallbackDelivery {
    /// 记录已投递的请求(供 e2e 断言 endpoint/body/token)。
    delivered: Arc<Mutex<Vec<crate::ports::CibaCallbackRequest>>>,
    /// 注入的强制结果(None=Delivered);测 ping/push 失败、SSRF 阻断时设。
    forced_outcome: Arc<Mutex<Option<crate::ports::CibaDeliveryOutcome>>>,
}

impl MemoryCibaCallbackDelivery {
    /// 注入下次(及之后)所有投递的结果(测失败/SSRF)。
    pub async fn set_outcome(&self, outcome: crate::ports::CibaDeliveryOutcome) {
        *self.forced_outcome.lock().await = Some(outcome);
    }
    /// 取已投递记录快照(e2e 断言用)。
    pub async fn delivered(&self) -> Vec<crate::ports::CibaCallbackRequest> {
        self.delivered.lock().await.clone()
    }
}

impl crate::ports::CibaCallbackDelivery for MemoryCibaCallbackDelivery {
    async fn deliver(
        &self,
        req: crate::ports::CibaCallbackRequest,
    ) -> crate::ports::CibaDeliveryOutcome {
        let outcome = self
            .forced_outcome
            .lock()
            .await
            .clone()
            .unwrap_or(crate::ports::CibaDeliveryOutcome::Delivered);
        // SSRF 阻断视为"未发出"——不记录投递(与真机 adapter 复校拒后不发请求一致)。
        if outcome != crate::ports::CibaDeliveryOutcome::BlockedBySsrf {
            self.delivered.lock().await.push(req);
        }
        outcome
    }
}

/// 内存授权会话存储(本地/测试,spec 004)。transition 在锁内做终态/合法性判定(等价 DynamoDB 条件写)。
/// **复合 tenant 键**(spec 020 §2.3,codex Blocker):键=(tenant, session_id);list_by_client 按 tenant 过滤。
#[derive(Clone, Default)]
pub struct MemoryAuthzSessionStore {
    map: Arc<Mutex<HashMap<(String, String), AuthzSessionRecord>>>,
    fail_next_create: Arc<AtomicU8>,
}

impl MemoryAuthzSessionStore {
    pub fn fail_next_create(&self) {
        self.fail_next_create.store(1, Ordering::SeqCst);
    }
}

impl AuthzSessionStore for MemoryAuthzSessionStore {
    async fn create(&self, tenant: &str, record: AuthzSessionRecord) -> Result<(), StoreError> {
        if self.fail_next_create.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected authorization session persistence failure".into(),
            ));
        }
        self.map
            .lock()
            .await
            .insert((tenant.to_string(), record.session_id.clone()), record);
        Ok(())
    }
    async fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .get(&(tenant.to_string(), session_id.to_string()))
            .cloned())
    }
    async fn transition(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        use agent_auth_authn::authz_session::AuthzState;
        let mut map = self.map.lock().await;
        let Some(rec) = map.get_mut(&(tenant.to_string(), session_id.to_string())) else {
            return Ok(None);
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, rec.expires_at) {
            return Ok(None);
        }
        let (Some(from), Some(to)) = (AuthzState::parse(&rec.state), AuthzState::parse(new_state))
        else {
            return Ok(None);
        };
        // 合法性 + 终态判定由纯逻辑保证(终态不可迁出;非法迁移拒)。
        if !from.can_transition_to(to) {
            return Ok(None);
        }
        rec.state = new_state.to_string();
        rec.sequence += 1;
        if last_error.is_some() {
            rec.last_error = last_error;
        }
        Ok(Some(rec.clone()))
    }
    async fn bind_user(
        &self,
        tenant: &str,
        session_id: &str,
        user_id: &str,
        now: i64,
    ) -> Result<Option<AuthzSessionRecord>, StoreError> {
        let mut map = self.map.lock().await;
        let Some(record) = map.get_mut(&(tenant.to_string(), session_id.to_string())) else {
            return Ok(None);
        };
        if agent_auth_infra_core::lifecycle::shortlived_is_expired(now, record.expires_at) {
            return Ok(None);
        }
        match record.user_id.as_deref() {
            Some(bound) if bound != user_id => Ok(None),
            Some(_) => Ok(Some(record.clone())),
            None => {
                record.user_id = Some(user_id.to_string());
                Ok(Some(record.clone()))
            }
        }
    }
    async fn delete(&self, tenant: &str, session_id: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .await
            .remove(&(tenant.to_string(), session_id.to_string()));
        Ok(())
    }
    async fn list_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), r)| t == tenant && r.client_id == client_id)
            .map(|(_, r)| r.session_id.clone())
            .collect())
    }

    async fn count_active(&self, tenant: &str, now: i64) -> Result<usize, StoreError> {
        use agent_auth_authn::authz_session::AuthzState;
        // 活跃 = 状态非终态 + 未过期(fail-closed 过期判定走 expires_at,C10.4)。
        // **tenant 过滤 MUST 与 Dynamo count_active 逐字节同构**(评审 Kiro B1:否则 Memory 测试
        // 谎报隔离):非空 → 仅该租户;**空 tenant → 仅"无前缀"分区(现网单租户/default),排除他租户
        // 前缀行**——不是"全租户求和"(Dynamo 侧 `None if phys.contains('\x1f') => continue`)。
        // SaaS 控制面 overview 走 tenant_or_400 会 400、到不了这里;空 tenant 只在 flag 关(全无前缀)出现。
        Ok(self
            .map
            .lock()
            .await
            .iter()
            .filter(|((t, _), _)| {
                if tenant.is_empty() {
                    t.is_empty() // 空 tenant:仅无前缀分区(与 Dynamo 排除 \x1f 前缀行等价)
                } else {
                    t == tenant
                }
            })
            .map(|(_, r)| r)
            .filter(|r| {
                r.expires_at > now
                    && AuthzState::parse(&r.state)
                        .map(|s| !s.is_terminal())
                        .unwrap_or(false)
            })
            .count())
    }

    async fn delete_by_client(&self, tenant: &str, client_id: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), record| {
            entry_tenant != tenant || record.client_id != client_id
        });
        Ok(before.saturating_sub(map.len()))
    }

    async fn delete_all_by_tenant(&self, tenant: &str) -> Result<usize, StoreError> {
        let mut map = self.map.lock().await;
        let before = map.len();
        map.retain(|(entry_tenant, _), _| entry_tenant != tenant);
        Ok(before.saturating_sub(map.len()))
    }
}

/// dev 事件 sink:把授权会话状态迁移打日志(stderr → CloudWatch)。真机换 EventBridge(P2)。
#[derive(Clone, Default)]
pub struct LogAuthzEventSink;

impl AuthzEventSink for LogAuthzEventSink {
    async fn emit(&self, session_id: &str, sequence: u64, state: &str) -> Result<(), StoreError> {
        eprintln!("[authz-event] session={session_id} seq={sequence} state={state}");
        Ok(())
    }
}

/// 内存 per-key 令牌桶限流(本地/测试,spec 005 C10.7)。临界区内读-补-取-写(等价 Dynamo 的原子条件写)。
#[derive(Clone, Default)]
pub struct MemoryRateLimitStore {
    buckets: Arc<Mutex<HashMap<String, agent_auth_infra_core::BucketState>>>,
    fail_next_check_available: Arc<AtomicU8>,
    fail_next_account_consume: Arc<AtomicU8>,
}

impl MemoryRateLimitStore {
    pub fn fail_next_check_available(&self) {
        self.fail_next_check_available.store(1, Ordering::SeqCst);
    }

    pub fn fail_next_account_consume(&self) {
        self.fail_next_account_consume.store(1, Ordering::SeqCst);
    }
}

impl crate::ports::RateLimitStore for MemoryRateLimitStore {
    async fn check_available(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        if self.fail_next_check_available.swap(0, Ordering::SeqCst) != 0 {
            return Err(StoreError::Transient(
                "injected rate-limit availability failure".into(),
            ));
        }
        use agent_auth_infra_core::{retry_after_secs, try_acquire, BucketConfig, BucketState};
        let cfg = BucketConfig::new(capacity, refill_per_sec);
        let state = self
            .buckets
            .lock()
            .await
            .get(key)
            .copied()
            .unwrap_or_else(|| BucketState::full(&cfg, now as f64));
        let decision = try_acquire(&cfg, state, now as f64, cost);
        Ok(crate::ports::RateLimitDecision {
            allowed: decision.allowed,
            retry_after_secs: if decision.allowed {
                None
            } else {
                retry_after_secs(&cfg, decision.state, cost).map(|s| s.ceil() as i64)
            },
        })
    }

    async fn try_consume(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> Result<crate::ports::RateLimitDecision, StoreError> {
        if key.starts_with("pwd:account:")
            && self.fail_next_account_consume.swap(0, Ordering::SeqCst) != 0
        {
            return Err(StoreError::Transient(
                "injected account rate-limit consume failure".into(),
            ));
        }
        use agent_auth_infra_core::{retry_after_secs, try_acquire, BucketConfig, BucketState};
        let cfg = BucketConfig::new(capacity, refill_per_sec);
        let now_f = now as f64;
        // 临界区内 check+write 原子(与 Dynamo 条件写等价语义)。
        let mut map = self.buckets.lock().await;
        let state = map
            .get(key)
            .copied()
            .unwrap_or_else(|| BucketState::full(&cfg, now_f));
        let decision = try_acquire(&cfg, state, now_f, cost);
        map.insert(key.to_string(), decision.state);
        let retry = if decision.allowed {
            None
        } else {
            retry_after_secs(&cfg, decision.state, cost).map(|s| s.ceil() as i64)
        };
        Ok(crate::ports::RateLimitDecision {
            allowed: decision.allowed,
            retry_after_secs: retry,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.buckets.lock().await.remove(key);
        Ok(())
    }
}

pub(crate) struct MemoryGovernanceUserDataPlane<'a> {
    pub(crate) governance: &'a MemoryGovernanceStore,
    pub(crate) users: &'a MemoryUsersStore,
    pub(crate) codes: &'a MemoryCodeStore,
    pub(crate) sessions: &'a MemorySessionStore,
    pub(crate) refresh: &'a MemoryRefreshStore,
    pub(crate) grace: Option<&'a MemoryGraceStore>,
    pub(crate) passkey_challenges: &'a MemoryPasskeyChallengeStore,
    pub(crate) passkeys: &'a MemoryPasskeyStore,
    pub(crate) grants: &'a MemoryGrantStore,
    pub(crate) jtis: Option<&'a MemoryJtiStore>,
    pub(crate) ciba: &'a MemoryCibaStore,
    pub(crate) device: &'a MemoryDeviceStore,
    pub(crate) recovery: &'a MemoryRecoveryStore,
    pub(crate) passwords: &'a MemoryPasswordStore,
    pub(crate) magic_links: &'a MemoryMagicLinkStore,
    pub(crate) invitations: &'a MemoryInvitationStore,
    pub(crate) messages: &'a MemoryOutboxNotifier,
    pub(crate) scim_groups: &'a MemoryScimGroupsStore,
    pub(crate) admin_auth: &'a MemoryAdminAuthStore,
    pub(crate) authz_sessions: &'a MemoryAuthzSessionStore,
}

impl MemoryGovernanceUserDataPlane<'_> {
    pub(crate) async fn fence_identity(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        user_id: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<Option<crate::ports::UserRecord>, StoreError> {
        let _guard = self
            .governance
            .acquire_destructive_guard(logical_tenant, fence, now)
            .await?;
        let target_epoch = fence.target_epoch.ok_or_else(|| {
            StoreError::Permanent("user erasure fence is missing target epoch".into())
        })?;
        let mut users = self.users.by_id.lock().await;
        let Some(record) = users.get_mut(&(data_tenant.to_string(), user_id.to_string())) else {
            return Ok(None);
        };
        let transition = crate::governance::classify_user_erasure_fence_transition(
            record.status,
            record.credential_epoch,
            target_epoch,
        )?;
        if transition == crate::governance::UserErasureFenceTransition::AlreadyFenced {
            return Ok(Some(record.clone()));
        }
        record.status = crate::ports::UserStatus::Tombstoned;
        record.credential_epoch = target_epoch;
        record.revocation_pending = true;
        record.attributes.clear();
        record.updated_at = now;
        Ok(Some(record.clone()))
    }

    pub(crate) async fn cleanup_user(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        user_id: &str,
        aliases: &[String],
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<u64, StoreError> {
        let _guard = self
            .governance
            .acquire_destructive_guard(logical_tenant, fence, now)
            .await?;
        let target_epoch = fence.target_epoch.ok_or_else(|| {
            StoreError::Permanent("user erasure fence is missing target epoch".into())
        })?;
        if self
            .users
            .by_id
            .lock()
            .await
            .get(&(data_tenant.to_string(), user_id.to_string()))
            .is_none_or(|record| {
                record.status != crate::ports::UserStatus::Tombstoned
                    || record.credential_epoch != target_epoch
            })
        {
            return Err(StoreError::Transient(
                MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT.into(),
            ));
        }

        {
            let groups = self.scim_groups.groups.lock().await;
            for entry in groups
                .iter()
                .filter(|((tenant, _), entry)| {
                    tenant == data_tenant
                        && !entry.deleted
                        && entry.record.members.iter().any(|member| member == user_id)
                })
                .map(|(_, entry)| entry)
            {
                entry
                    .record
                    .version
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Permanent("SCIM Group version exhausted".into()))?;
            }
        }

        let mut removed = 0usize;
        let authz_session_ids = self
            .codes
            .map
            .lock()
            .await
            .iter()
            .filter(|((tenant, _), entry)| tenant == data_tenant && entry.record.user_id == user_id)
            .filter_map(|(_, entry)| entry.record.authz_session_id.clone())
            .collect::<BTreeSet<_>>();
        removed = removed.saturating_add(
            retain_count(&self.authz_sessions.map, |(tenant, session_id), record| {
                tenant != data_tenant
                    || (record.user_id.as_deref() != Some(user_id)
                        && !authz_session_ids.contains(session_id))
            })
            .await,
        );
        {
            let mut map = self.codes.map.lock().await;
            let before = map.len();
            map.retain(|(tenant, _), entry| {
                tenant != data_tenant || entry.record.user_id != user_id
            });
            removed = removed.saturating_add(before.saturating_sub(map.len()));
        }
        {
            let mut state = self.sessions.state.lock().await;
            let before = state.sessions.len();
            state.sessions.retain(|(tenant, _), stored| {
                tenant != data_tenant || stored.record.user_id != user_id
            });
            removed = removed.saturating_add(before.saturating_sub(state.sessions.len()));
            removed = removed.saturating_add(usize::from(
                state
                    .generations
                    .remove(&(data_tenant.to_string(), user_id.to_string()))
                    .is_some(),
            ));
        }
        let family_ids = {
            let mut map = self.refresh.map.lock().await;
            let family_ids = map
                .iter()
                .filter(|((tenant, _), family)| tenant == data_tenant && family.user_id == user_id)
                .map(|(_, family)| family.family_id.clone())
                .collect::<Vec<_>>();
            map.retain(|(tenant, _), family| tenant != data_tenant || family.user_id != user_id);
            removed = removed.saturating_add(family_ids.len());
            family_ids
        };
        if let Some(grace) = self.grace {
            let mut map = grace.map.lock().await;
            let before = map.len();
            map.retain(|_, entry| !family_ids.iter().any(|id| id == &entry.family_id));
            removed = removed.saturating_add(before.saturating_sub(map.len()));
        }
        removed = removed.saturating_add(
            retain_count(&self.passkey_challenges.map, |_, challenge| {
                challenge.tenant != data_tenant || challenge.user_id.as_deref() != Some(user_id)
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.passkeys.map, |(tenant, _), credential| {
                tenant != data_tenant || credential.user_id != user_id
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.grants.map, |(tenant, _), grant| {
                tenant != data_tenant || grant.user_id != user_id
            })
            .await,
        );
        if let Some(jtis) = self.jtis {
            removed = removed.saturating_add(
                retain_count(&jtis.map, |_, record| {
                    record.tenant_id != logical_tenant || record.user_id != user_id
                })
                .await,
            );
        }
        {
            let mut map = self.ciba.map.lock().await;
            let before = map.len();
            map.retain(|(tenant, _), request| tenant != data_tenant || request.user_id != user_id);
            removed = removed.saturating_add(before.saturating_sub(map.len()));
            removed = removed.saturating_add(usize::from(
                self.ciba
                    .last_authorize
                    .lock()
                    .await
                    .remove(&(data_tenant.to_string(), user_id.to_string()))
                    .is_some(),
            ));
        }
        removed = removed.saturating_add(
            retain_count(&self.device.map, |(tenant, _), grant| {
                tenant != data_tenant || grant.user_id.as_deref() != Some(user_id)
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.recovery.map, |(tenant, _), record| {
                tenant != data_tenant || record.user_id != user_id
            })
            .await,
        );
        removed = removed.saturating_add(usize::from(
            self.passwords
                .map
                .lock()
                .await
                .remove(&(data_tenant.to_string(), user_id.to_string()))
                .is_some(),
        ));
        removed = removed.saturating_add(
            retain_count(&self.invitations.map, |(tenant, _), invitation| {
                tenant != data_tenant || invitation.user_id != user_id
            })
            .await,
        );
        {
            let mut links = self.magic_links.links.lock().await;
            let before = links.len();
            links.retain(|(tenant, _), link| tenant != data_tenant || link.user_id != user_id);
            removed = removed.saturating_add(before.saturating_sub(links.len()));
            let mut cooldown = self.magic_links.cooldown.lock().await;
            for alias in aliases {
                removed = removed.saturating_add(usize::from(
                    cooldown
                        .remove(&(data_tenant.to_string(), alias.clone()))
                        .is_some(),
                ));
            }
        }
        {
            let mut outbox = self.messages.outbox.lock().await;
            let before = outbox.len();
            outbox.retain(|message| {
                message.tenant != data_tenant
                    || !aliases.iter().any(|alias| alias == &message.recipient)
            });
            removed = removed.saturating_add(before.saturating_sub(outbox.len()));
        }
        {
            let mut groups = self.scim_groups.groups.lock().await;
            for ((tenant, _), entry) in groups.iter_mut() {
                if tenant != data_tenant || entry.deleted {
                    continue;
                }
                let before = entry.record.members.len();
                entry.record.members.retain(|member| member != user_id);
                if entry.record.members.len() != before {
                    entry.record.version += 1;
                    entry.record.updated_at = now;
                    removed = removed.saturating_add(1);
                }
            }
        }
        removed = removed.saturating_add(
            retain_count(&self.admin_auth.sessions, |_, session| {
                session.tenant_id != logical_tenant || session.user_id != user_id
            })
            .await,
        );
        u64::try_from(removed)
            .map_err(|_| StoreError::Permanent("user cleanup count exceeds u64".into()))
    }

    pub(crate) async fn delete_identity(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        user_id: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let _guard = self
            .governance
            .acquire_destructive_guard(logical_tenant, fence, now)
            .await?;
        let target_epoch = fence.target_epoch.ok_or_else(|| {
            StoreError::Permanent("user erasure fence is missing target epoch".into())
        })?;
        let key = (data_tenant.to_string(), user_id.to_string());
        let mut users = self.users.by_id.lock().await;
        let Some(record) = users.get(&key) else {
            return Ok(true);
        };
        if record.status != crate::ports::UserStatus::Tombstoned
            || record.credential_epoch != target_epoch
        {
            return Err(StoreError::Permanent(
                "user identity is not fenced for this erasure epoch".into(),
            ));
        }
        users.remove(&key);
        drop(users);
        self.users
            .scim_create_claims
            .lock()
            .await
            .retain(|claim_key, claim| claim_key.0 != data_tenant || claim.user_id != user_id);
        Ok(true)
    }

    pub(crate) async fn inventory_user(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> Result<BTreeMap<String, u64>, StoreError> {
        let mut inventory = BTreeMap::new();
        let users = self.users.by_id.lock().await;
        let identity = users.get(&(data_tenant.to_string(), user_id.to_string()));
        inventory_count(&mut inventory, "identity", usize::from(identity.is_some()))?;
        let embedded_aliases = identity.map_or(0, |record| {
            usize::from(!record.email.is_empty())
                + usize::from(record.scim_external_id.is_some())
                + usize::from(record.scim_user_name.is_some())
        });
        drop(users);
        let scim_claims = self
            .users
            .scim_create_claims
            .lock()
            .await
            .iter()
            .filter(|((tenant, _, _), claim)| tenant == data_tenant && claim.user_id == user_id)
            .count();
        inventory_count(
            &mut inventory,
            "identity_aliases",
            embedded_aliases.saturating_add(scim_claims),
        )?;
        let codes = self.codes.map.lock().await;
        let user_codes = codes
            .iter()
            .filter(|((tenant, _), entry)| tenant == data_tenant && entry.record.user_id == user_id)
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        inventory_count(&mut inventory, "codes", user_codes.len())?;
        let authz_session_ids = user_codes
            .iter()
            .filter_map(|entry| entry.record.authz_session_id.clone())
            .collect::<BTreeSet<_>>();
        drop(codes);
        inventory_count(
            &mut inventory,
            "authz_sessions",
            self.authz_sessions
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, session_id), record)| {
                    tenant == data_tenant
                        && (record.user_id.as_deref() == Some(user_id)
                            || authz_session_ids.contains(session_id))
                })
                .count(),
        )?;
        let sessions = self.sessions.state.lock().await;
        inventory_count(
            &mut inventory,
            "sessions",
            sessions
                .sessions
                .iter()
                .filter(|((tenant, _), stored)| {
                    tenant == data_tenant && stored.record.user_id == user_id
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "session_generations",
            usize::from(
                sessions
                    .generations
                    .contains_key(&(data_tenant.to_string(), user_id.to_string())),
            ),
        )?;
        drop(sessions);
        let refresh = self.refresh.map.lock().await;
        let family_ids = refresh
            .iter()
            .filter(|((tenant, _), family)| tenant == data_tenant && family.user_id == user_id)
            .map(|(_, family)| family.family_id.as_str())
            .collect::<BTreeSet<_>>();
        inventory_count(&mut inventory, "refresh_families", family_ids.len())?;
        if let Some(grace) = self.grace {
            inventory_count(
                &mut inventory,
                "refresh_grace",
                grace
                    .map
                    .lock()
                    .await
                    .values()
                    .filter(|entry| family_ids.contains(entry.family_id.as_str()))
                    .count(),
            )?;
        } else {
            inventory_count(&mut inventory, "refresh_grace", 0)?;
        }
        drop(refresh);
        inventory_count(
            &mut inventory,
            "passkey_challenges",
            self.passkey_challenges
                .map
                .lock()
                .await
                .values()
                .filter(|challenge| {
                    challenge.tenant == data_tenant && challenge.user_id.as_deref() == Some(user_id)
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "passkeys",
            self.passkeys
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), credential)| {
                    tenant == data_tenant && credential.user_id == user_id
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "grants",
            self.grants
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), grant)| tenant == data_tenant && grant.user_id == user_id)
                .count(),
        )?;
        let jtis = if let Some(jtis) = self.jtis {
            jtis.map
                .lock()
                .await
                .values()
                .filter(|record| record.tenant_id == logical_tenant && record.user_id == user_id)
                .count()
        } else {
            0
        };
        inventory_count(&mut inventory, "jtis", jtis)?;
        inventory_count(
            &mut inventory,
            "ciba_requests",
            self.ciba
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), request)| {
                    tenant == data_tenant && request.user_id == user_id
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "ciba_throttles",
            usize::from(
                self.ciba
                    .last_authorize
                    .lock()
                    .await
                    .contains_key(&(data_tenant.to_string(), user_id.to_string())),
            ),
        )?;
        inventory_count(
            &mut inventory,
            "device_grants",
            self.device
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), grant)| {
                    tenant == data_tenant && grant.user_id.as_deref() == Some(user_id)
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "recovery",
            self.recovery
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), record)| tenant == data_tenant && record.user_id == user_id)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "passwords",
            usize::from(
                self.passwords
                    .map
                    .lock()
                    .await
                    .contains_key(&(data_tenant.to_string(), user_id.to_string())),
            ),
        )?;
        inventory_count(
            &mut inventory,
            "invitations",
            self.invitations
                .map
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), invitation)| {
                    tenant == data_tenant && invitation.user_id == user_id
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "magic_links",
            self.magic_links
                .links
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), link)| tenant == data_tenant && link.user_id == user_id)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "magic_cooldowns",
            self.magic_links
                .cooldown
                .lock()
                .await
                .keys()
                .filter(|(tenant, recipient)| {
                    tenant == data_tenant && aliases.iter().any(|alias| alias == recipient)
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "messages",
            self.messages
                .outbox
                .lock()
                .await
                .iter()
                .filter(|message| {
                    message.tenant == data_tenant
                        && aliases.iter().any(|alias| alias == &message.recipient)
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "scim_memberships",
            self.scim_groups
                .groups
                .lock()
                .await
                .iter()
                .filter(|((tenant, _), entry)| {
                    tenant == data_tenant
                        && !entry.deleted
                        && entry.record.members.iter().any(|member| member == user_id)
                })
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "admin_sessions",
            self.admin_auth
                .sessions
                .lock()
                .await
                .values()
                .filter(|session| session.tenant_id == logical_tenant && session.user_id == user_id)
                .count(),
        )?;
        Ok(inventory)
    }
}

pub(crate) struct MemoryGovernanceTenantDataPlane<'a> {
    pub(crate) governance: &'a MemoryGovernanceStore,
    pub(crate) users: &'a MemoryUsersStore,
    pub(crate) clients: &'a MemoryClientStore,
    pub(crate) initial_access_tokens: &'a MemoryInitialAccessTokenStore,
    pub(crate) scim_groups: &'a MemoryScimGroupsStore,
    pub(crate) federation_config: &'a MemoryFederationConfigStore,
    pub(crate) federation_attribute_mappings:
        &'a crate::adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore,
    pub(crate) workload_trust: &'a MemoryWorkloadTrustStore,
    pub(crate) admin_auth: &'a MemoryAdminAuthStore,
    pub(crate) federation_flow: &'a MemoryFederationFlowStore,
    pub(crate) codes: &'a MemoryCodeStore,
    pub(crate) sessions: &'a MemorySessionStore,
    pub(crate) refresh: &'a MemoryRefreshStore,
    pub(crate) grace: Option<&'a MemoryGraceStore>,
    pub(crate) passkey_challenges: &'a MemoryPasskeyChallengeStore,
    pub(crate) passkeys: &'a MemoryPasskeyStore,
    pub(crate) jtis: Option<&'a MemoryJtiStore>,
    pub(crate) passwords: &'a MemoryPasswordStore,
    pub(crate) recovery: &'a MemoryRecoveryStore,
    pub(crate) magic_links: &'a MemoryMagicLinkStore,
    pub(crate) invitations: &'a MemoryInvitationStore,
    pub(crate) messages: &'a MemoryOutboxNotifier,
    pub(crate) ciba: &'a MemoryCibaStore,
    pub(crate) device: &'a MemoryDeviceStore,
    pub(crate) par: &'a MemoryParStore,
    pub(crate) replay: Option<&'a MemoryReplayStore>,
    pub(crate) authz_sessions: &'a MemoryAuthzSessionStore,
    pub(crate) grants: &'a MemoryGrantStore,
    pub(crate) domain_map: &'a MemoryDomainMapStore,
    pub(crate) policy_artifacts: &'a MemoryPolicyArtifactStore,
    pub(crate) policy_versions: &'a MemoryPolicyVersionStore,
    pub(crate) rate_limit: Option<&'a MemoryRateLimitStore>,
    pub(crate) ssf: &'a crate::ssf::MemorySsfStore,
}

impl MemoryGovernanceTenantDataPlane<'_> {
    pub(crate) async fn cleanup_stage(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
        stage: crate::governance::TenantCleanupStage,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<u64, StoreError> {
        use crate::governance::TenantCleanupStage;
        use crate::ssf::SsfStore;

        let _guard = self
            .governance
            .acquire_destructive_guard(logical_tenant, fence, now)
            .await?;
        let removed = match stage {
            TenantCleanupStage::Clients => {
                let client_ids = self
                    .clients
                    .map
                    .lock()
                    .await
                    .keys()
                    .filter(|(tenant, _)| tenant == data_tenant)
                    .map(|(_, client_id)| client_id.clone())
                    .collect::<BTreeSet<_>>();
                let mut removed =
                    retain_count(&self.clients.map, |(tenant, _), _| tenant != data_tenant).await;
                removed = removed.saturating_add(
                    retain_count(&self.domain_map.map, |_, binding| {
                        !client_ids.contains(&binding.client_id)
                    })
                    .await,
                );
                removed = removed.saturating_add(
                    retain_count(&self.authz_sessions.map, |(tenant, _), session| {
                        tenant != data_tenant || !client_ids.contains(&session.client_id)
                    })
                    .await,
                );
                if let Some(rate_limit) = self.rate_limit {
                    let mut buckets = rate_limit.buckets.lock().await;
                    let before = buckets.len();
                    let prefix = format!("{data_tenant}{}", crate::tenant::SEP);
                    buckets.retain(|key, _| {
                        if data_tenant.is_empty() {
                            false
                        } else {
                            !key.starts_with(&prefix)
                        }
                    });
                    removed = removed.saturating_add(before.saturating_sub(buckets.len()));
                }
                removed
            }
            TenantCleanupStage::InitialAccessTokens => {
                retain_count(&self.initial_access_tokens.map, |(tenant, _), _| {
                    tenant != data_tenant
                })
                .await
            }
            TenantCleanupStage::DirectoryGroups => {
                let mut removed = retain_count(&self.scim_groups.groups, |(tenant, _), _| {
                    tenant != data_tenant
                })
                .await;
                let mut aliases = self.scim_groups.by_external_id.lock().await;
                let before = aliases.len();
                aliases.retain(|(tenant, _), _| tenant != data_tenant);
                removed = removed.saturating_add(before.saturating_sub(aliases.len()));
                removed
            }
            TenantCleanupStage::Federation => {
                let removed = retain_count(&self.federation_config.map, |(tenant, _), _| {
                    tenant != logical_tenant
                })
                .await;
                removed.saturating_add(
                    self.federation_attribute_mappings
                        .delete_all_by_tenant(logical_tenant)
                        .await?,
                )
            }
            TenantCleanupStage::WorkloadTrust => {
                retain_count(&self.workload_trust.map, |_, binding| {
                    binding.tenant_id != logical_tenant
                })
                .await
            }
            TenantCleanupStage::AdminAuthority => {
                let mut removed = usize::from(
                    self.admin_auth
                        .configs
                        .lock()
                        .await
                        .remove(logical_tenant)
                        .is_some(),
                );
                removed = removed.saturating_add(
                    retain_count(&self.admin_auth.flows, |_, flow| {
                        flow.tenant_id != logical_tenant
                    })
                    .await,
                );
                removed.saturating_add(
                    retain_count(&self.admin_auth.sessions, |_, session| {
                        session.tenant_id != logical_tenant
                    })
                    .await,
                )
            }
            TenantCleanupStage::ProtocolState => {
                self.cleanup_protocol_state(logical_tenant, data_tenant)
                    .await
            }
            TenantCleanupStage::PolicyAndDomains => {
                let mut removed =
                    retain_count(&self.grants.map, |(tenant, _), _| tenant != data_tenant).await;
                removed = removed.saturating_add(
                    retain_count(&self.domain_map.map, |_, binding| {
                        binding.tenant_id != logical_tenant
                    })
                    .await,
                );
                removed = removed.saturating_add(
                    retain_count(&self.policy_artifacts.map, |(tenant, _), _| {
                        tenant != data_tenant
                    })
                    .await,
                );
                removed.saturating_add(usize::from(
                    self.policy_versions
                        .map
                        .lock()
                        .await
                        .remove(data_tenant)
                        .is_some(),
                ))
            }
            TenantCleanupStage::SharedSignals => {
                self.ssf.revoke_all_by_tenant(logical_tenant, now).await?
            }
            TenantCleanupStage::Users
            | TenantCleanupStage::SigningKeysAndSecrets
            | TenantCleanupStage::Complete => {
                return Err(StoreError::Permanent(
                    "tenant cleanup stage is not a memory authority-store stage".into(),
                ))
            }
        };
        u64::try_from(removed)
            .map_err(|_| StoreError::Permanent("tenant cleanup count exceeds u64".into()))
    }

    async fn cleanup_protocol_state(&self, logical_tenant: &str, data_tenant: &str) -> usize {
        let mut removed = retain_count(&self.federation_flow.map, |_, flow| {
            flow.tenant_id != logical_tenant
        })
        .await;
        removed = removed.saturating_add(
            retain_count(&self.codes.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        {
            let mut state = self.sessions.state.lock().await;
            let sessions_before = state.sessions.len();
            state
                .sessions
                .retain(|(tenant, _), _| tenant != data_tenant);
            removed = removed.saturating_add(sessions_before.saturating_sub(state.sessions.len()));
            let generations_before = state.generations.len();
            state
                .generations
                .retain(|(tenant, _), _| tenant != data_tenant);
            removed =
                removed.saturating_add(generations_before.saturating_sub(state.generations.len()));
        }
        let family_ids = {
            let mut refresh = self.refresh.map.lock().await;
            let family_ids = refresh
                .iter()
                .filter(|((tenant, _), _)| tenant == data_tenant)
                .map(|(_, family)| family.family_id.clone())
                .collect::<BTreeSet<_>>();
            refresh.retain(|(tenant, _), _| tenant != data_tenant);
            removed = removed.saturating_add(family_ids.len());
            family_ids
        };
        if let Some(grace) = self.grace {
            let mut map = grace.map.lock().await;
            let before = map.len();
            map.retain(|_, entry| !family_ids.contains(&entry.family_id));
            removed = removed.saturating_add(before.saturating_sub(map.len()));
        }
        removed = removed.saturating_add(
            retain_count(&self.passkey_challenges.map, |_, challenge| {
                challenge.tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.passkeys.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        if let Some(jtis) = self.jtis {
            removed = removed.saturating_add(
                retain_count(&jtis.map, |_, record| record.tenant_id != logical_tenant).await,
            );
        }
        removed = removed.saturating_add(
            retain_count(&self.passwords.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        removed = removed.saturating_add(
            retain_count(&self.recovery.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        removed = removed.saturating_add(
            retain_count(&self.invitations.map, |(tenant, _), _| {
                tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.magic_links.links, |(tenant, _), _| {
                tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.magic_links.cooldown, |(tenant, _), _| {
                tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_vec_count(&self.messages.outbox, |message| {
                message.tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.ciba.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        removed = removed.saturating_add(
            retain_count(&self.ciba.last_authorize, |(tenant, _), _| {
                tenant != data_tenant
            })
            .await,
        );
        removed = removed.saturating_add(
            retain_count(&self.device.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        removed = removed.saturating_add(
            retain_count(&self.par.map, |(tenant, _), _| tenant != data_tenant).await,
        );
        if let Some(replay) = self.replay {
            removed = removed.saturating_add(
                retain_count(&replay.map, |(tenant, _), _| tenant != data_tenant).await,
            );
        }
        removed.saturating_add(
            retain_count(&self.authz_sessions.map, |(tenant, _), _| {
                tenant != data_tenant
            })
            .await,
        )
    }

    pub(crate) async fn inventory_tenant(
        &self,
        logical_tenant: &str,
        data_tenant: &str,
    ) -> Result<BTreeMap<String, u64>, StoreError> {
        use crate::ssf::{SsfDeliveryCursor, SsfDeliveryStatus, SsfStore, SsfStreamStatus};

        let mut inventory = BTreeMap::new();
        let users = self.users.by_id.lock().await;
        inventory_count(
            &mut inventory,
            "identities",
            users
                .keys()
                .filter(|(tenant, _)| tenant == data_tenant)
                .count(),
        )?;
        let embedded_aliases = users
            .iter()
            .filter(|((tenant, _), _)| tenant == data_tenant)
            .map(|(_, record)| {
                usize::from(!record.email.is_empty())
                    + usize::from(record.scim_external_id.is_some())
                    + usize::from(record.scim_user_name.is_some())
            })
            .sum::<usize>();
        drop(users);
        let scim_claims = self
            .users
            .scim_create_claims
            .lock()
            .await
            .keys()
            .filter(|(tenant, _, _)| tenant == data_tenant)
            .count();
        inventory_count(
            &mut inventory,
            "identity_aliases",
            embedded_aliases.saturating_add(scim_claims),
        )?;
        inventory_count(
            &mut inventory,
            "clients",
            count_keyed(&self.clients.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "initial_access_tokens",
            count_keyed(&self.initial_access_tokens.map, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "directory_groups",
            count_keyed(&self.scim_groups.groups, |(tenant, _), entry| {
                tenant == data_tenant && !entry.deleted
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "directory_group_tombstones",
            count_keyed(&self.scim_groups.groups, |(tenant, _), entry| {
                tenant == data_tenant && entry.deleted
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "directory_group_aliases",
            count_keyed(&self.scim_groups.by_external_id, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "federation_configs",
            count_keyed(&self.federation_config.map, |(tenant, _), _| {
                tenant == logical_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "federation_attribute_mapping_rows",
            self.federation_attribute_mappings
                .governance_count_all_by_tenant(logical_tenant)
                .await?,
        )?;
        inventory_count(
            &mut inventory,
            "workload_trust",
            self.workload_trust
                .map
                .lock()
                .await
                .values()
                .filter(|binding| binding.tenant_id == logical_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "admin_configs",
            usize::from(
                self.admin_auth
                    .configs
                    .lock()
                    .await
                    .contains_key(logical_tenant),
            ),
        )?;
        inventory_count(
            &mut inventory,
            "admin_flows",
            self.admin_auth
                .flows
                .lock()
                .await
                .values()
                .filter(|flow| flow.tenant_id == logical_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "admin_sessions",
            self.admin_auth
                .sessions
                .lock()
                .await
                .values()
                .filter(|session| session.tenant_id == logical_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "federation_flows",
            self.federation_flow
                .map
                .lock()
                .await
                .values()
                .filter(|flow| flow.tenant_id == logical_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "codes",
            count_keyed(&self.codes.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        let sessions = self.sessions.state.lock().await;
        inventory_count(
            &mut inventory,
            "sessions",
            sessions
                .sessions
                .keys()
                .filter(|(tenant, _)| tenant == data_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "session_generations",
            sessions
                .generations
                .keys()
                .filter(|(tenant, _)| tenant == data_tenant)
                .count(),
        )?;
        drop(sessions);
        let refresh = self.refresh.map.lock().await;
        let family_ids = refresh
            .iter()
            .filter(|((tenant, _), _)| tenant == data_tenant)
            .map(|(_, family)| family.family_id.as_str())
            .collect::<BTreeSet<_>>();
        inventory_count(&mut inventory, "refresh_families", family_ids.len())?;
        let grace = if let Some(grace) = self.grace {
            grace
                .map
                .lock()
                .await
                .values()
                .filter(|entry| family_ids.contains(entry.family_id.as_str()))
                .count()
        } else {
            0
        };
        inventory_count(&mut inventory, "refresh_grace", grace)?;
        drop(refresh);
        inventory_count(
            &mut inventory,
            "passkey_challenges",
            self.passkey_challenges
                .map
                .lock()
                .await
                .values()
                .filter(|challenge| challenge.tenant == data_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "passkeys",
            count_keyed(&self.passkeys.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        let jtis = if let Some(jtis) = self.jtis {
            jtis.map
                .lock()
                .await
                .values()
                .filter(|record| record.tenant_id == logical_tenant)
                .count()
        } else {
            0
        };
        inventory_count(&mut inventory, "jtis", jtis)?;
        inventory_count(
            &mut inventory,
            "passwords",
            count_keyed(&self.passwords.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "recovery",
            count_keyed(&self.recovery.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "invitations",
            count_keyed(&self.invitations.map, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "magic_links",
            count_keyed(&self.magic_links.links, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "magic_cooldowns",
            count_keyed(&self.magic_links.cooldown, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "messages",
            self.messages
                .outbox
                .lock()
                .await
                .iter()
                .filter(|message| message.tenant == data_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "ciba_requests",
            count_keyed(&self.ciba.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "ciba_throttles",
            count_keyed(&self.ciba.last_authorize, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "device_grants",
            count_keyed(&self.device.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "par",
            count_keyed(&self.par.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        let replay = if let Some(replay) = self.replay {
            count_keyed(&replay.map, |(tenant, _), _| tenant == data_tenant).await
        } else {
            0
        };
        inventory_count(&mut inventory, "replay", replay)?;
        inventory_count(
            &mut inventory,
            "authz_sessions",
            count_keyed(&self.authz_sessions.map, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        let rate_limits = if let Some(rate_limit) = self.rate_limit {
            let prefix = format!("{data_tenant}{}", crate::tenant::SEP);
            rate_limit
                .buckets
                .lock()
                .await
                .keys()
                .filter(|key| data_tenant.is_empty() || key.starts_with(&prefix))
                .count()
        } else {
            0
        };
        inventory_count(&mut inventory, "rate_limits", rate_limits)?;
        inventory_count(
            &mut inventory,
            "grants",
            count_keyed(&self.grants.map, |(tenant, _), _| tenant == data_tenant).await,
        )?;
        inventory_count(
            &mut inventory,
            "domains",
            self.domain_map
                .map
                .lock()
                .await
                .values()
                .filter(|binding| binding.tenant_id == logical_tenant)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "policy_artifacts",
            count_keyed(&self.policy_artifacts.map, |(tenant, _), _| {
                tenant == data_tenant
            })
            .await,
        )?;
        inventory_count(
            &mut inventory,
            "policy_versions",
            usize::from(
                self.policy_versions
                    .map
                    .lock()
                    .await
                    .contains_key(data_tenant),
            ),
        )?;

        let streams = self.ssf.list_streams(logical_tenant).await?;
        inventory_count(
            &mut inventory,
            "ssf_streams_live",
            streams
                .iter()
                .filter(|stream| stream.status != SsfStreamStatus::Revoked)
                .count(),
        )?;
        inventory_count(
            &mut inventory,
            "ssf_stream_tombstones_retained",
            streams
                .iter()
                .filter(|stream| stream.status == SsfStreamStatus::Revoked)
                .count(),
        )?;
        let mut ssf_delivery_live = 0usize;
        let mut ssf_delivery_tombstones = 0usize;
        let mut ssf_delivery_audit = 0usize;
        for stream in streams {
            let mut cursor = None;
            loop {
                let page = self
                    .ssf
                    .list_deliveries(logical_tenant, &stream.stream_id, 100, cursor.as_ref())
                    .await?;
                for delivery in page.deliveries {
                    match delivery.status {
                        SsfDeliveryStatus::Pending | SsfDeliveryStatus::RetryWait => {
                            ssf_delivery_live = ssf_delivery_live.saturating_add(1);
                        }
                        SsfDeliveryStatus::Suppressed => {
                            ssf_delivery_tombstones = ssf_delivery_tombstones.saturating_add(1);
                        }
                        SsfDeliveryStatus::Delivered
                        | SsfDeliveryStatus::Terminal
                        | SsfDeliveryStatus::DeadLettered => {
                            ssf_delivery_audit = ssf_delivery_audit.saturating_add(1);
                        }
                    }
                }
                let Some(encoded) = page.next_cursor else {
                    break;
                };
                cursor = Some(SsfDeliveryCursor::decode_for_stream(
                    &encoded,
                    logical_tenant,
                    &stream.stream_id,
                )?);
            }
        }
        inventory_count(&mut inventory, "ssf_deliveries_live", ssf_delivery_live)?;
        inventory_count(
            &mut inventory,
            "ssf_delivery_tombstones_retained",
            ssf_delivery_tombstones,
        )?;
        inventory_count(
            &mut inventory,
            "ssf_delivery_audit_retained",
            ssf_delivery_audit,
        )?;
        Ok(inventory)
    }
}

async fn retain_count<K, V, F>(map: &Arc<Mutex<HashMap<K, V>>>, mut keep: F) -> usize
where
    K: Eq + std::hash::Hash,
    F: FnMut(&K, &mut V) -> bool,
{
    let mut map = map.lock().await;
    let before = map.len();
    map.retain(|key, value| keep(key, value));
    before.saturating_sub(map.len())
}

async fn count_keyed<K, V, F>(map: &Arc<Mutex<HashMap<K, V>>>, mut include: F) -> usize
where
    K: Eq + std::hash::Hash,
    F: FnMut(&K, &V) -> bool,
{
    map.lock()
        .await
        .iter()
        .filter(|(key, value)| include(key, value))
        .count()
}

async fn retain_vec_count<V, F>(values: &Arc<Mutex<Vec<V>>>, mut keep: F) -> usize
where
    F: FnMut(&V) -> bool,
{
    let mut values = values.lock().await;
    let before = values.len();
    values.retain(|value| keep(value));
    before.saturating_sub(values.len())
}

fn inventory_count(
    inventory: &mut BTreeMap<String, u64>,
    category: &str,
    count: usize,
) -> Result<(), StoreError> {
    inventory.insert(
        category.to_string(),
        u64::try_from(count)
            .map_err(|_| StoreError::Permanent("governance inventory count exceeds u64".into()))?,
    );
    Ok(())
}

#[derive(Default)]
struct MemoryGovernanceState {
    policies: BTreeMap<String, crate::governance::GovernancePolicyRecord>,
    manifests: BTreeMap<(String, String), crate::governance::GovernanceExportManifest>,
    jobs: BTreeMap<(String, String), crate::governance::GovernanceJobRecord>,
    job_leases: BTreeMap<(String, String), crate::governance::GovernanceJobLeaseRecord>,
    mutation_gates: BTreeMap<String, crate::governance::TenantMutationGateRecord>,
    mutation_permits: BTreeMap<(String, String), crate::governance::TenantMutationPermit>,
    continuations: BTreeMap<(String, String), crate::governance::GovernanceContinuationRecord>,
    continuation_jtis: BTreeSet<(String, String, String)>,
    evidence: BTreeMap<(String, String, u64), crate::governance::GovernanceEvidenceRecord>,
    tenant_lifecycles: BTreeMap<String, crate::governance::TenantLifecycleRecord>,
    external_actions:
        BTreeMap<(String, String, String), crate::governance::GovernanceExternalActionRecord>,
    suppressions: BTreeSet<(String, String, String, u64)>,
    #[cfg(test)]
    fail_next_job_update: bool,
}

pub(crate) const MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT: &str =
    "governance destructive fence conflict";

fn prune_expired_mutation_permits(
    state: &mut MemoryGovernanceState,
    tenant_id: &str,
    now: i64,
) -> Result<u64, StoreError> {
    let before = state.mutation_permits.len();
    state
        .mutation_permits
        .retain(|(tenant, _), permit| tenant != tenant_id || permit.deadline > now);
    let removed = before.saturating_sub(state.mutation_permits.len());
    let active = state
        .mutation_permits
        .keys()
        .filter(|(tenant, _)| tenant == tenant_id)
        .count();
    let active = u64::try_from(active)
        .map_err(|_| StoreError::Permanent("tenant mutation permit count exceeds u64".into()))?;
    if let Some(gate) = state.mutation_gates.get_mut(tenant_id) {
        if gate.active_permits != active {
            gate.active_permits = active;
            gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant mutation gate revision exhausted".into())
            })?;
            gate.updated_at = now;
        } else if removed > 0 {
            return Err(StoreError::Permanent(
                "tenant mutation gate count did not include expired permits".into(),
            ));
        }
    } else if active > 0 {
        return Err(StoreError::Permanent(
            "tenant mutation permits exist without their gate".into(),
        ));
    }
    Ok(active)
}

/// Holds the in-memory governance authority lock across one destructive
/// data-plane mutation. Its contents are intentionally not exposed.
pub(crate) struct MemoryGovernanceDestructiveGuard {
    _authority: tokio::sync::OwnedMutexGuard<MemoryGovernanceState>,
}

fn governance_destructive_fence_matches(
    state: &MemoryGovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceDestructiveFence,
    now: i64,
) -> bool {
    use crate::governance::{GovernanceJobState, LegalHoldState, TenantLifecycleState};

    let policy_matches = match state.policies.get(tenant_id) {
        Some(policy) => {
            fence.policy_revision != 0
                && policy.tenant_id == tenant_id
                && policy.revision == fence.policy_revision
                && policy.legal_hold == LegalHoldState::Disabled
        }
        None => fence.policy_revision == 0,
    };
    let job_matches = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()))
        .is_some_and(|job| {
            job.tenant_id == tenant_id
                && job.job_id == fence.job_id
                && job.revision == fence.job_revision
                && job.policy_revision == fence.policy_revision
                && job.tenant_revision == fence.tenant_revision
                && matches!(
                    job.state,
                    GovernanceJobState::Queued
                        | GovernanceJobState::Running
                        | GovernanceJobState::Retryable
                )
                && fence
                    .target_epoch
                    .is_none_or(|target_epoch| target_epoch == job.target_epoch)
        });
    let lease_matches = state
        .job_leases
        .get(&(tenant_id.to_string(), fence.job_id.clone()))
        .is_some_and(|lease| {
            lease.tenant_id == tenant_id
                && lease.job_id == fence.job_id
                && lease.job_revision == fence.job_revision
                && lease.policy_revision == fence.policy_revision
                && lease.tenant_revision == fence.tenant_revision
                && lease.token_digest == fence.lease_token_digest
                && lease.deadline == fence.lease_deadline
                && lease.deadline > now
        });
    let lifecycle_matches = match state.tenant_lifecycles.get(tenant_id) {
        Some(lifecycle) if fence.tenant_revision == 0 => {
            lifecycle.tenant_id == tenant_id && lifecycle.state == TenantLifecycleState::Active
        }
        None if fence.tenant_revision == 0 => true,
        Some(lifecycle) => {
            lifecycle.tenant_id == tenant_id
                && lifecycle.state == TenantLifecycleState::Offboarding
                && lifecycle.revision == fence.tenant_revision
        }
        None => false,
    };

    policy_matches && job_matches && lease_matches && lifecycle_matches
}

fn governance_external_fence_matches(
    state: &MemoryGovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceExternalActionFence,
    now: i64,
) -> bool {
    let policy = state
        .policies
        .get(tenant_id)
        .cloned()
        .unwrap_or_else(|| crate::governance::GovernancePolicyRecord::default_for(tenant_id));
    let job = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lease = state
        .job_leases
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lifecycle = state.tenant_lifecycles.get(tenant_id);
    policy.revision == fence.policy_revision
        && !policy.held()
        && job.is_some_and(|job| {
            job.revision == fence.job_revision
                && job.policy_revision == fence.policy_revision
                && job.tenant_revision == fence.tenant_revision
                && job.kind == crate::governance::GovernanceJobKind::TenantOffboarding
                && matches!(
                    job.state,
                    crate::governance::GovernanceJobState::Running
                        | crate::governance::GovernanceJobState::Retryable
                )
        })
        && lease.is_some_and(|lease| {
            lease.job_revision == fence.job_revision
                && lease.policy_revision == fence.policy_revision
                && lease.tenant_revision == fence.tenant_revision
                && lease.token_digest == fence.lease_token_digest
                && lease.deadline == fence.lease_deadline
                && lease.deadline > now
        })
        && lifecycle.is_some_and(|lifecycle| {
            lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                && lifecycle.revision == fence.tenant_revision
        })
}

fn governance_job_authority_conflict(
    state: &MemoryGovernanceState,
    tenant_id: &str,
    job_id: &str,
    expected_job_revision: u64,
) -> Option<crate::governance::GovernanceJobLeaseConflict> {
    use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobState};

    let Some(job) = state.jobs.get(&(tenant_id.to_string(), job_id.to_string())) else {
        return Some(GovernanceJobLeaseConflict::Job);
    };
    let policy = state
        .policies
        .get(tenant_id)
        .cloned()
        .unwrap_or_else(|| crate::governance::GovernancePolicyRecord::default_for(tenant_id));
    if policy.revision != job.policy_revision || policy.held() {
        return Some(GovernanceJobLeaseConflict::Policy);
    }
    if job.revision != expected_job_revision
        || !matches!(
            job.state,
            GovernanceJobState::Queued
                | GovernanceJobState::Running
                | GovernanceJobState::Retryable
        )
    {
        return Some(GovernanceJobLeaseConflict::Job);
    }
    let lifecycle_conflict = match state.tenant_lifecycles.get(tenant_id) {
        Some(lifecycle) if job.tenant_revision == 0 => {
            lifecycle.state != crate::governance::TenantLifecycleState::Active
        }
        None if job.tenant_revision == 0 => false,
        Some(lifecycle) => {
            lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                || lifecycle.revision != job.tenant_revision
        }
        None => true,
    };
    if lifecycle_conflict {
        return Some(GovernanceJobLeaseConflict::TenantLifecycle);
    }
    None
}

fn governance_external_reconcile_fence_matches(
    state: &MemoryGovernanceState,
    tenant_id: &str,
    fence: &crate::governance::GovernanceExternalActionReconcileFence,
) -> bool {
    let job = state
        .jobs
        .get(&(tenant_id.to_string(), fence.job_id.clone()));
    let lifecycle = state.tenant_lifecycles.get(tenant_id);
    job.is_some_and(|job| {
        job.tenant_revision == fence.tenant_revision
            && job.kind == crate::governance::GovernanceJobKind::TenantOffboarding
    }) && lifecycle.is_some_and(|lifecycle| {
        lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
            && lifecycle.revision == fence.tenant_revision
    })
}

fn same_external_action_identity(
    left: &crate::governance::GovernanceExternalActionRecord,
    right: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    left.action_id == right.action_id
        && left.tenant_id == right.tenant_id
        && left.job_id == right.job_id
        && left.kind == right.kind
        && left.resource_ref == right.resource_ref
        && left.resource_fingerprint == right.resource_fingerprint
        && left.ownership == right.ownership
}

fn valid_external_dispatch_transition(
    current: &crate::governance::GovernanceExternalActionRecord,
    next: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    use crate::governance::{GovernanceExternalActionState, GovernanceResourceOwnership};

    let claimed = matches!(
        (current.state, next.state),
        (
            GovernanceExternalActionState::Prepared
                | GovernanceExternalActionState::ClaimTombstoned,
            GovernanceExternalActionState::Claimed
        )
    ) && next.claim_token_digest.is_some()
        && next.claim_deadline.is_some()
        && next.committed_at.is_none()
        && next.verified_at.is_none()
        && (current.state != GovernanceExternalActionState::ClaimTombstoned
            || current.claim_token_digest != next.claim_token_digest);
    let external_verified = current.ownership == GovernanceResourceOwnership::External
        && current.state == GovernanceExternalActionState::OperatorPending
        && next.state == GovernanceExternalActionState::Verified
        && current.claim_token_digest.is_none()
        && next.claim_token_digest.is_none()
        && next.claim_deadline.is_none()
        && next.committed_at.is_none()
        && next.verified_at.is_some()
        && next.retention_until.is_none();
    claimed || external_verified
}

fn valid_external_reconcile_transition(
    current: &crate::governance::GovernanceExternalActionRecord,
    next: &crate::governance::GovernanceExternalActionRecord,
) -> bool {
    use crate::governance::GovernanceExternalActionState;

    matches!(
        (current.state, next.state),
        (
            GovernanceExternalActionState::Claimed,
            GovernanceExternalActionState::ClaimTombstoned
                | GovernanceExternalActionState::ExternalPreparationDispatched
                | GovernanceExternalActionState::ExternallyCommitted
                | GovernanceExternalActionState::Verified
        ) | (
            GovernanceExternalActionState::ExternalPreparationDispatched,
            GovernanceExternalActionState::ClaimTombstoned
                | GovernanceExternalActionState::ExternallyCommitted
                | GovernanceExternalActionState::Verified
        ) | (
            GovernanceExternalActionState::ExternallyCommitted,
            GovernanceExternalActionState::Verified
        )
    ) && current.claim_token_digest.is_some()
        && current.claim_token_digest == next.claim_token_digest
        && current.claim_deadline == next.claim_deadline
}

/// Deterministic local implementation of the durable governance authority.
#[derive(Clone, Default)]
pub struct MemoryGovernanceStore {
    state: Arc<Mutex<MemoryGovernanceState>>,
}

impl MemoryGovernanceStore {
    pub(crate) async fn acquire_destructive_guard(
        &self,
        tenant_id: &str,
        fence: &crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<MemoryGovernanceDestructiveGuard, StoreError> {
        let authority = self.state.clone().lock_owned().await;
        if !governance_destructive_fence_matches(&authority, tenant_id, fence, now) {
            return Err(StoreError::Transient(
                MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT.into(),
            ));
        }
        Ok(MemoryGovernanceDestructiveGuard {
            _authority: authority,
        })
    }
}

#[cfg(test)]
impl MemoryGovernanceStore {
    pub async fn fail_next_job_update(&self) {
        self.state.lock().await.fail_next_job_update = true;
    }
}

impl GovernanceStore for MemoryGovernanceStore {
    async fn acquire_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<crate::governance::TenantMutationPermitAcquireOutcome, StoreError> {
        use crate::governance::{
            TenantLifecycleState, TenantMutationGateRecord, TenantMutationGateState,
            TenantMutationPermitAcquireOutcome,
        };

        if permit.tenant_id.is_empty()
            || permit.permit_id.is_empty()
            || permit.permit_id.len() > 128
            || permit.deadline <= now
        {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit".into(),
            ));
        }
        let mut state = self.state.lock().await;
        prune_expired_mutation_permits(&mut state, &permit.tenant_id, now)?;
        let lifecycle_revision = state
            .tenant_lifecycles
            .get(&permit.tenant_id)
            .filter(|record| record.state == TenantLifecycleState::Offboarding)
            .map(|record| record.revision);
        if lifecycle_revision.is_some()
            || state
                .mutation_gates
                .get(&permit.tenant_id)
                .is_some_and(|gate| gate.state == TenantMutationGateState::Frozen)
        {
            return Ok(TenantMutationPermitAcquireOutcome::Frozen { lifecycle_revision });
        }
        let key = (permit.tenant_id.clone(), permit.permit_id.clone());
        if state.mutation_permits.contains_key(&key) {
            return Err(StoreError::Transient(
                "tenant mutation permit identifier collided; retry".into(),
            ));
        }
        state.mutation_permits.insert(key, permit.clone());
        let gate = state
            .mutation_gates
            .entry(permit.tenant_id.clone())
            .or_insert(TenantMutationGateRecord {
                tenant_id: permit.tenant_id.clone(),
                state: TenantMutationGateState::Active,
                active_permits: 0,
                revision: 0,
                updated_at: now,
            });
        gate.active_permits = gate.active_permits.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation permit count exhausted".into())
        })?;
        gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation gate revision exhausted".into())
        })?;
        gate.updated_at = now;
        Ok(TenantMutationPermitAcquireOutcome::Acquired(permit))
    }

    async fn renew_tenant_mutation_permit(
        &self,
        permit: &crate::governance::TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> Result<bool, StoreError> {
        if deadline <= now || deadline <= permit.deadline {
            return Err(StoreError::Permanent(
                "invalid tenant mutation permit renewal".into(),
            ));
        }
        let mut state = self.state.lock().await;
        let Some(current) = state
            .mutation_permits
            .get_mut(&(permit.tenant_id.clone(), permit.permit_id.clone()))
        else {
            return Ok(false);
        };
        if current.deadline != permit.deadline || current.deadline <= now {
            return Ok(false);
        }
        current.deadline = deadline;
        Ok(true)
    }

    async fn release_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut state = self.state.lock().await;
        let key = (permit.tenant_id.clone(), permit.permit_id.clone());
        if state
            .mutation_permits
            .get(&key)
            .is_none_or(|current| current.deadline != permit.deadline)
        {
            return Ok(false);
        }
        let gate = state
            .mutation_gates
            .get_mut(&permit.tenant_id)
            .ok_or_else(|| {
                StoreError::Permanent("tenant mutation permit has no aggregate gate".into())
            })?;
        if gate.state != crate::governance::TenantMutationGateState::Active
            || gate.active_permits == 0
        {
            return Err(StoreError::Permanent(
                "tenant mutation gate count is inconsistent".into(),
            ));
        }
        gate.active_permits -= 1;
        gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("tenant mutation gate revision exhausted".into())
        })?;
        gate.updated_at = now;
        state.mutation_permits.remove(&key);
        Ok(true)
    }

    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::GovernancePolicyRecord>, StoreError> {
        Ok(self.state.lock().await.policies.get(tenant_id).cloned())
    }

    async fn put_policy(
        &self,
        mut record: crate::governance::GovernancePolicyRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernancePolicyPutOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let current = state
            .policies
            .get(&record.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&record.tenant_id)
            });
        if current.revision != expected_revision {
            return Ok(crate::governance::GovernancePolicyPutOutcome::Conflict(
                current,
            ));
        }
        record.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance policy revision exhausted".into()))?;
        state
            .policies
            .insert(record.tenant_id.clone(), record.clone());
        Ok(crate::governance::GovernancePolicyPutOutcome::Stored(
            record,
        ))
    }

    async fn put_export_manifest(
        &self,
        manifest: crate::governance::GovernanceExportManifest,
    ) -> Result<bool, StoreError> {
        let key = (manifest.tenant_id.clone(), manifest.export_id.clone());
        let mut state = self.state.lock().await;
        if state.manifests.contains_key(&key) {
            return Ok(false);
        }
        state.manifests.insert(key, manifest);
        Ok(true)
    }

    async fn get_export_manifest(
        &self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> Result<Option<crate::governance::GovernanceExportManifest>, StoreError> {
        let key = (tenant_id.to_string(), export_id.to_string());
        let mut state = self.state.lock().await;
        let manifest = state.manifests.get(&key).cloned();
        if manifest
            .as_ref()
            .is_some_and(|manifest| manifest.expires_at <= now)
        {
            state.manifests.remove(&key);
            return Ok(None);
        }
        Ok(manifest)
    }

    async fn start_or_resume_job(
        &self,
        mut job: crate::governance::GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> Result<crate::governance::GovernanceJobStartOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(crate::governance::GovernanceJobStartOutcome::PolicyConflict(policy));
        }
        let key = (job.tenant_id.clone(), job.job_id.clone());
        if let Some(mut existing) = state.jobs.get(&key).cloned() {
            let lifecycle = state.tenant_lifecycles.get(&job.tenant_id).cloned();
            if job.tenant_revision == 0 {
                if let Some(lifecycle) = lifecycle.filter(|lifecycle| {
                    lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                }) {
                    return Ok(crate::governance::GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            } else {
                if lifecycle.as_ref().is_none_or(|lifecycle| {
                    lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                }) {
                    return Err(StoreError::Permanent(
                        "offboarding child job has no matching tenant lifecycle".into(),
                    ));
                }
                if existing.tenant_revision == 0
                    && !matches!(
                        existing.state,
                        crate::governance::GovernanceJobState::RetentionPending
                            | crate::governance::GovernanceJobState::Completed
                    )
                {
                    if existing.kind != job.kind
                        || existing.target_id != job.target_id
                        || existing.target_epoch != job.target_epoch
                    {
                        return Err(StoreError::Permanent(
                            "offboarding child job identity mismatch".into(),
                        ));
                    }
                    existing.tenant_revision = job.tenant_revision;
                    existing.policy_revision = policy.revision;
                    if existing.state == crate::governance::GovernanceJobState::BlockedLegalHold {
                        existing.state = crate::governance::GovernanceJobState::Queued;
                    }
                    existing.revision = existing.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("governance job revision exhausted".into())
                    })?;
                    existing.updated_at = job.updated_at;
                    state.jobs.insert(key, existing.clone());
                    return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                        existing,
                    ));
                }
                if existing.tenant_revision != 0 && existing.tenant_revision != job.tenant_revision
                {
                    return Err(StoreError::Permanent(
                        "offboarding child job tenant lifecycle mismatch".into(),
                    ));
                }
            }
            if existing.state != crate::governance::GovernanceJobState::BlockedLegalHold
                || policy.held()
            {
                return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                    existing,
                ));
            }
            existing.state = crate::governance::GovernanceJobState::Queued;
            existing.policy_revision = policy.revision;
            existing.revision = existing
                .revision
                .checked_add(1)
                .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
            existing.updated_at = job.updated_at;
            if freeze_tenant {
                let active =
                    prune_expired_mutation_permits(&mut state, &job.tenant_id, job.updated_at)?;
                if active > 0 {
                    return Ok(
                        crate::governance::GovernanceJobStartOutcome::MutationConflict {
                            active_permits: active,
                        },
                    );
                }
                let revision = match state.tenant_lifecycles.get(&job.tenant_id) {
                    Some(record)
                        if record.state == crate::governance::TenantLifecycleState::Offboarding =>
                    {
                        record.revision
                    }
                    Some(record) => record.revision.checked_add(1).ok_or_else(|| {
                        StoreError::Permanent("tenant lifecycle revision exhausted".into())
                    })?,
                    None => 1,
                };
                state.tenant_lifecycles.insert(
                    job.tenant_id.clone(),
                    crate::governance::TenantLifecycleRecord {
                        tenant_id: job.tenant_id.clone(),
                        state: crate::governance::TenantLifecycleState::Offboarding,
                        revision,
                        updated_at: job.updated_at,
                    },
                );
                existing.tenant_revision = revision;
                let continuation =
                    crate::governance::GovernanceContinuationRecord::for_offboarding_job(&existing)
                        .map_err(StoreError::Permanent)?;
                if state.continuations.get(&key).is_some_and(|current| {
                    current.tenant_id != continuation.tenant_id
                        || current.job_id != continuation.job_id
                        || current.tenant_revision != continuation.tenant_revision
                }) {
                    return Err(StoreError::Permanent(
                        "offboarding continuation identity mismatch".into(),
                    ));
                }
                state
                    .continuations
                    .entry(key.clone())
                    .or_insert(continuation);
                let gate = state.mutation_gates.entry(job.tenant_id.clone()).or_insert(
                    crate::governance::TenantMutationGateRecord {
                        tenant_id: job.tenant_id.clone(),
                        state: crate::governance::TenantMutationGateState::Active,
                        active_permits: 0,
                        revision: 0,
                        updated_at: job.updated_at,
                    },
                );
                gate.state = crate::governance::TenantMutationGateState::Frozen;
                gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                    StoreError::Permanent("tenant mutation gate revision exhausted".into())
                })?;
                gate.updated_at = job.updated_at;
            }
            state.jobs.insert(key, existing.clone());
            return Ok(crate::governance::GovernanceJobStartOutcome::Existing(
                existing,
            ));
        }

        if !freeze_tenant {
            if job.tenant_revision == 0 {
                if let Some(lifecycle) =
                    state
                        .tenant_lifecycles
                        .get(&job.tenant_id)
                        .filter(|lifecycle| {
                            lifecycle.state == crate::governance::TenantLifecycleState::Offboarding
                        })
                {
                    return Ok(crate::governance::GovernanceJobStartOutcome::TenantFrozen {
                        lifecycle_revision: lifecycle.revision,
                    });
                }
            } else if state
                .tenant_lifecycles
                .get(&job.tenant_id)
                .is_none_or(|lifecycle| {
                    lifecycle.state != crate::governance::TenantLifecycleState::Offboarding
                        || lifecycle.revision != job.tenant_revision
                })
            {
                return Err(StoreError::Permanent(
                    "offboarding child job has no matching tenant lifecycle".into(),
                ));
            }
        }
        if policy.held() {
            job.state = crate::governance::GovernanceJobState::BlockedLegalHold;
        } else if freeze_tenant {
            let active =
                prune_expired_mutation_permits(&mut state, &job.tenant_id, job.updated_at)?;
            if active > 0 {
                return Ok(
                    crate::governance::GovernanceJobStartOutcome::MutationConflict {
                        active_permits: active,
                    },
                );
            }
            let current_revision = state
                .tenant_lifecycles
                .get(&job.tenant_id)
                .map_or(0, |record| record.revision);
            let revision = current_revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant lifecycle revision exhausted".into())
            })?;
            state.tenant_lifecycles.insert(
                job.tenant_id.clone(),
                crate::governance::TenantLifecycleRecord {
                    tenant_id: job.tenant_id.clone(),
                    state: crate::governance::TenantLifecycleState::Offboarding,
                    revision,
                    updated_at: job.updated_at,
                },
            );
            job.tenant_revision = revision;
            let continuation =
                crate::governance::GovernanceContinuationRecord::for_offboarding_job(&job)
                    .map_err(StoreError::Permanent)?;
            state.continuations.insert(key.clone(), continuation);
            let gate = state.mutation_gates.entry(job.tenant_id.clone()).or_insert(
                crate::governance::TenantMutationGateRecord {
                    tenant_id: job.tenant_id.clone(),
                    state: crate::governance::TenantMutationGateState::Active,
                    active_permits: 0,
                    revision: 0,
                    updated_at: job.updated_at,
                },
            );
            gate.state = crate::governance::TenantMutationGateState::Frozen;
            gate.revision = gate.revision.checked_add(1).ok_or_else(|| {
                StoreError::Permanent("tenant mutation gate revision exhausted".into())
            })?;
            gate.updated_at = job.updated_at;
        }
        job.policy_revision = policy.revision;
        state.jobs.insert(key, job.clone());
        Ok(crate::governance::GovernanceJobStartOutcome::Stored(job))
    }

    async fn get_job(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceJobRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .jobs
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .cloned())
    }

    async fn list_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceJobRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .jobs
            .iter()
            .filter_map(|((tenant, _), record)| (tenant == tenant_id).then_some(record.clone()))
            .collect())
    }

    async fn get_continuation(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceContinuationRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .continuations
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .cloned())
    }

    async fn update_continuation(
        &self,
        mut record: crate::governance::GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> Result<crate::governance::GovernanceContinuationUpdateOutcome, StoreError> {
        use crate::governance::GovernanceContinuationUpdateOutcome;

        let key = (record.tenant_id.clone(), record.job_id.clone());
        let mut state = self.state.lock().await;
        let current =
            state.continuations.get(&key).cloned().ok_or_else(|| {
                StoreError::Permanent("governance continuation disappeared".into())
            })?;
        if current.revision != expected_revision {
            return Ok(GovernanceContinuationUpdateOutcome::Conflict(current));
        }
        if current.tenant_id != record.tenant_id
            || current.job_id != record.job_id
            || current.tenant_revision != record.tenant_revision
            || record.resume_revision < current.resume_revision
            || record.read_revision < current.read_revision
        {
            return Err(StoreError::Permanent(
                "governance continuation identity or revision regressed".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance continuation revision exhausted".into())
        })?;
        state.continuations.insert(key, record.clone());
        Ok(GovernanceContinuationUpdateOutcome::Stored(record))
    }

    async fn consume_continuation_resume(
        &self,
        tenant_id: &str,
        job_id: &str,
        jti_digest: &str,
        expected_resume_revision: u64,
        _expires_at: i64,
    ) -> Result<bool, StoreError> {
        if jti_digest.is_empty() {
            return Err(StoreError::Permanent(
                "governance continuation JTI digest is empty".into(),
            ));
        }
        let mut state = self.state.lock().await;
        let continuation = state
            .continuations
            .get(&(tenant_id.to_string(), job_id.to_string()))
            .ok_or_else(|| StoreError::Permanent("governance continuation disappeared".into()))?;
        if !continuation.resume_enabled || continuation.resume_revision != expected_resume_revision
        {
            return Ok(false);
        }
        Ok(state.continuation_jtis.insert((
            tenant_id.to_string(),
            job_id.to_string(),
            jti_digest.to_string(),
        )))
    }

    async fn update_job(
        &self,
        mut job: crate::governance::GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        use crate::governance::GovernanceJobUpdateOutcome;

        let mut state = self.state.lock().await;
        #[cfg(test)]
        if std::mem::take(&mut state.fail_next_job_update) {
            return Err(StoreError::Transient(
                "injected governance job checkpoint failure".into(),
            ));
        }
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        let key = (job.tenant_id.clone(), job.job_id.clone());
        let current = state.jobs.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance job disappeared during update".into())
        })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        state.jobs.insert(key, job.clone());
        Ok(GovernanceJobUpdateOutcome::Stored(job))
    }

    async fn complete_job_with_evidence(
        &self,
        mut job: crate::governance::GovernanceJobRecord,
        evidence: crate::governance::GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> Result<crate::governance::GovernanceJobUpdateOutcome, StoreError> {
        use crate::governance::GovernanceJobUpdateOutcome;

        if !evidence.verifies_completion_of(&job) || job.revision != expected_revision {
            return Err(StoreError::Permanent(
                "invalid governance job completion evidence".into(),
            ));
        }
        let mut state = self.state.lock().await;
        #[cfg(test)]
        if std::mem::take(&mut state.fail_next_job_update) {
            return Err(StoreError::Transient(
                "injected governance job checkpoint failure".into(),
            ));
        }
        let policy = state
            .policies
            .get(&job.tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                crate::governance::GovernancePolicyRecord::default_for(&job.tenant_id)
            });
        if policy.revision != expected_policy_revision {
            return Ok(GovernanceJobUpdateOutcome::PolicyConflict(policy));
        }
        if evidence.payload.legal_hold != policy.legal_hold {
            return Err(StoreError::Permanent(
                "governance completion evidence policy mismatch".into(),
            ));
        }
        let job_key = (job.tenant_id.clone(), job.job_id.clone());
        let current = state.jobs.get(&job_key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance job disappeared during completion".into())
        })?;
        if current.revision != expected_revision {
            return Ok(GovernanceJobUpdateOutcome::Conflict(current));
        }
        let evidence_key = (
            evidence.payload.tenant_id.clone(),
            evidence.payload.job_id.clone(),
            evidence.payload.evidence_revision,
        );
        if state.evidence.contains_key(&evidence_key) {
            return Err(StoreError::Permanent(
                "governance completion evidence revision already exists".into(),
            ));
        }
        job.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("governance job revision exhausted".into()))?;
        job.policy_revision = policy.revision;
        state.jobs.insert(job_key, job.clone());
        state.evidence.insert(evidence_key, evidence);
        Ok(GovernanceJobUpdateOutcome::Stored(job))
    }

    async fn claim_job_lease(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        token_digest: &str,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        if token_digest.is_empty() || token_digest.len() > 128 || deadline <= now {
            return Err(StoreError::Permanent(
                "invalid governance job lease claim".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if let Some(conflict) =
            governance_job_authority_conflict(&state, tenant_id, job_id, expected_job_revision)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(conflict));
        }
        let key = (tenant_id.to_string(), job_id.to_string());
        if state
            .job_leases
            .get(&key)
            .is_some_and(|lease| lease.deadline > now)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        let job = state
            .jobs
            .get(&key)
            .expect("authority check proved the governance job exists");
        let lease = crate::governance::GovernanceJobLeaseRecord {
            tenant_id: tenant_id.to_string(),
            job_id: job_id.to_string(),
            job_revision: expected_job_revision,
            policy_revision: job.policy_revision,
            tenant_revision: job.tenant_revision,
            token_digest: token_digest.to_string(),
            acquired_at: now,
            deadline,
        };
        state.job_leases.insert(key, lease.clone());
        Ok(GovernanceJobLeaseOutcome::Acquired(lease))
    }

    async fn renew_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        if deadline <= now || deadline <= fence.lease_deadline {
            return Err(StoreError::Permanent(
                "invalid governance job lease renewal".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if let Some(conflict) =
            governance_job_authority_conflict(&state, tenant_id, &fence.job_id, fence.job_revision)
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(conflict));
        }
        let key = (tenant_id.to_string(), fence.job_id.clone());
        let Some(current) = state.job_leases.get(&key) else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        };
        if current.token_digest != fence.lease_token_digest
            || current.deadline != fence.lease_deadline
            || current.deadline <= now
            || current.policy_revision != fence.policy_revision
            || current.tenant_revision != fence.tenant_revision
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        let mut renewed = current.clone();
        renewed.deadline = deadline;
        state.job_leases.insert(key, renewed.clone());
        Ok(GovernanceJobLeaseOutcome::Renewed(renewed))
    }

    async fn release_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
    ) -> Result<crate::governance::GovernanceJobLeaseOutcome, StoreError> {
        use crate::governance::{GovernanceJobLeaseConflict, GovernanceJobLeaseOutcome};

        let mut state = self.state.lock().await;
        let key = (tenant_id.to_string(), fence.job_id);
        let Some(current) = state.job_leases.get(&key) else {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        };
        if current.job_revision != fence.job_revision
            || current.policy_revision != fence.policy_revision
            || current.tenant_revision != fence.tenant_revision
            || current.token_digest != fence.lease_token_digest
            || current.deadline != fence.lease_deadline
        {
            return Ok(GovernanceJobLeaseOutcome::Conflict(
                GovernanceJobLeaseConflict::Lease,
            ));
        }
        state.job_leases.remove(&key);
        Ok(GovernanceJobLeaseOutcome::Released)
    }

    async fn tenant_has_active_job_leases(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let state = self.state.lock().await;
        Ok(state.job_leases.iter().any(|((tenant, _), lease)| {
            tenant == tenant_id && lease.tenant_id == tenant_id && lease.deadline > now
        }))
    }

    async fn get_tenant_lifecycle(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::governance::TenantLifecycleRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .tenant_lifecycles
            .get(tenant_id)
            .cloned())
    }

    async fn prepare_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionPutOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionPutOutcome;

        if record.tenant_id.is_empty()
            || record.job_id != fence.job_id
            || record.action_id.is_empty()
            || record.resource_ref.is_empty()
            || record.resource_fingerprint.is_empty()
            || record.revision != 1
        {
            return Err(StoreError::Permanent(
                "invalid governance external action".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if !governance_external_fence_matches(&state, &record.tenant_id, &fence, record.updated_at)
        {
            return Ok(GovernanceExternalActionPutOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        if let Some(existing) = state.external_actions.get(&key) {
            if !same_external_action_identity(existing, &record) {
                return Err(StoreError::Permanent(
                    "governance external action identity changed".into(),
                ));
            }
            return Ok(GovernanceExternalActionPutOutcome::Existing(
                existing.clone(),
            ));
        }
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionPutOutcome::Stored(record))
    }

    async fn get_external_action(
        &self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> Result<Option<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .external_actions
            .get(&(
                tenant_id.to_string(),
                job_id.to_string(),
                action_id.to_string(),
            ))
            .cloned())
    }

    async fn list_external_actions(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .external_actions
            .iter()
            .filter_map(|((tenant, job, _), record)| {
                (tenant == tenant_id && job == job_id).then_some(record.clone())
            })
            .collect())
    }

    async fn list_tenant_external_actions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .external_actions
            .iter()
            .filter_map(|((tenant, _, _), record)| (tenant == tenant_id).then_some(record.clone()))
            .collect())
    }

    async fn update_external_action(
        &self,
        mut record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionUpdateOutcome;

        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action job mismatch".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if !governance_external_fence_matches(&state, &record.tenant_id, &fence, record.updated_at)
        {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        let current = state.external_actions.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance external action disappeared".into())
        })?;
        if !same_external_action_identity(&current, &record) {
            return Err(StoreError::Permanent(
                "governance external action identity changed".into(),
            ));
        }
        if current.revision != expected_revision {
            return Ok(GovernanceExternalActionUpdateOutcome::Conflict(current));
        }
        if !valid_external_dispatch_transition(&current, &record) {
            return Err(StoreError::Permanent(
                "invalid governance external action dispatch transition".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionUpdateOutcome::Stored(record))
    }

    async fn reconcile_external_action(
        &self,
        mut record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionReconcileFence,
    ) -> Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError> {
        use crate::governance::GovernanceExternalActionUpdateOutcome;

        if record.job_id != fence.job_id {
            return Err(StoreError::Permanent(
                "governance external action reconciliation job mismatch".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if !governance_external_reconcile_fence_matches(&state, &record.tenant_id, &fence) {
            return Ok(GovernanceExternalActionUpdateOutcome::FenceConflict);
        }
        let key = (
            record.tenant_id.clone(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        let current = state.external_actions.get(&key).cloned().ok_or_else(|| {
            StoreError::Permanent("governance external action disappeared".into())
        })?;
        if !same_external_action_identity(&current, &record) {
            return Err(StoreError::Permanent(
                "governance external action identity changed".into(),
            ));
        }
        if current.revision != expected_revision {
            return Ok(GovernanceExternalActionUpdateOutcome::Conflict(current));
        }
        if current.claim_token_digest.as_deref() != Some(fence.claim_token_digest.as_str())
            || !valid_external_reconcile_transition(&current, &record)
        {
            return Err(StoreError::Permanent(
                "invalid governance external action reconciliation transition".into(),
            ));
        }
        record.revision = expected_revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("governance external action revision exhausted".into())
        })?;
        state.external_actions.insert(key, record.clone());
        Ok(GovernanceExternalActionUpdateOutcome::Stored(record))
    }

    async fn put_evidence(
        &self,
        record: crate::governance::GovernanceEvidenceRecord,
    ) -> Result<crate::governance::GovernanceEvidencePutOutcome, StoreError> {
        use crate::governance::GovernanceEvidencePutOutcome;

        if !record.verify_hash()
            || record.payload.tenant_id.is_empty()
            || record.payload.job_id.is_empty()
            || record.payload.evidence_revision == 0
        {
            return Err(StoreError::Permanent("invalid governance evidence".into()));
        }
        let key = (
            record.payload.tenant_id.clone(),
            record.payload.job_id.clone(),
            record.payload.evidence_revision,
        );
        let mut state = self.state.lock().await;
        if let Some(existing) = state.evidence.get(&key) {
            return Ok(GovernanceEvidencePutOutcome::Existing(existing.clone()));
        }
        state.evidence.insert(key, record.clone());
        Ok(GovernanceEvidencePutOutcome::Stored(record))
    }

    async fn latest_evidence(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> Result<Option<crate::governance::GovernanceEvidenceRecord>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .evidence
            .iter()
            .rev()
            .find_map(|((tenant, job, _), record)| {
                (tenant == tenant_id && job == job_id).then_some(record.clone())
            }))
    }

    async fn put_suppression(
        &self,
        record: crate::governance::GovernanceSuppressionRecord,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> Result<bool, StoreError> {
        let expected_epoch = fence.target_epoch.unwrap_or(fence.tenant_revision);
        if expected_epoch == 0 || record.target_epoch != expected_epoch {
            return Err(StoreError::Permanent(
                "suppression record does not match its destructive fence".into(),
            ));
        }
        let mut state = self.state.lock().await;
        if !governance_destructive_fence_matches(&state, &record.tenant_id, &fence, now) {
            return Err(StoreError::Transient(
                MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT.into(),
            ));
        }
        Ok(state.suppressions.insert((
            record.tenant_id,
            record.target_class,
            record.digest,
            record.target_epoch,
        )))
    }

    async fn is_suppressed(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .suppressions
            .iter()
            .any(|(tenant, class, stored_digest, _)| {
                tenant == tenant_id && class == target_class && stored_digest == digest
            }))
    }

    async fn latest_suppression_epoch(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> Result<Option<u64>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .suppressions
            .iter()
            .filter_map(|(tenant, class, stored_digest, epoch)| {
                (tenant == tenant_id && class == target_class && stored_digest == digest)
                    .then_some(*epoch)
            })
            .max())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{CibaAuthRequest, CibaStore, DeviceAuthGrant, DeviceStore};

    #[tokio::test]
    async fn ciba_and_device_poll_claims_are_atomic() {
        let ciba = MemoryCibaStore::default();
        ciba.put(
            "tenant-1",
            CibaAuthRequest {
                auth_req_id: "auth-1".into(),
                tenant: "tenant-1".into(),
                client_id: "client-1".into(),
                user_id: "user-1".into(),
                authz_session_id: None,
                scope: vec!["openid".into()],
                resources: vec![],
                binding_message: None,
                interval: 5,
                last_poll_at: None,
                expires_at: 10_000,
                status: "pending".into(),
                consumed: false,
                delivery_mode: None,
                notification_endpoint: None,
                client_notification_token: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
        let (ciba_first, ciba_second) = tokio::join!(
            ciba.claim_poll("tenant-1", "auth-1", None, 1_000),
            ciba.claim_poll("tenant-1", "auth-1", None, 1_000),
        );
        assert_eq!(
            usize::from(ciba_first.unwrap()) + usize::from(ciba_second.unwrap()),
            1,
            "concurrent CIBA polls must have exactly one interval-slot winner"
        );

        let device = MemoryDeviceStore::default();
        device
            .put(
                "tenant-1",
                DeviceAuthGrant {
                    device_code: "device-1".into(),
                    user_code: "USERCODE".into(),
                    client_id: "client-1".into(),
                    user_id: None,
                    authz_session_id: None,
                    scope: vec!["openid".into()],
                    resources: vec![],
                    interval: 5,
                    last_poll_at: None,
                    expires_at: 10_000,
                    status: "pending".into(),
                    consumed: false,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        let (device_first, device_second) = tokio::join!(
            device.claim_poll("tenant-1", "device-1", None, 1_000),
            device.claim_poll("tenant-1", "device-1", None, 1_000),
        );
        assert_eq!(
            usize::from(device_first.unwrap()) + usize::from(device_second.unwrap()),
            1,
            "concurrent device polls must have exactly one interval-slot winner"
        );
    }

    #[tokio::test]
    async fn shortlived_writes_reject_expired_records() {
        use agent_auth_authn::authz_session::AuthzState;

        let sessions = MemoryAuthzSessionStore::default();
        for session_id in ["expired-transition", "expired-bind"] {
            sessions
                .create(
                    "tenant-1",
                    AuthzSessionRecord {
                        session_id: session_id.into(),
                        client_id: "client-1".into(),
                        user_id: None,
                        state: AuthzState::Created.as_str().into(),
                        session_token_hash: "hash".into(),
                        sequence: 0,
                        last_error: None,
                        expires_at: 1_000,
                    },
                )
                .await
                .unwrap();
        }
        let transition_before = sessions
            .get("tenant-1", "expired-transition")
            .await
            .unwrap()
            .unwrap();
        assert!(sessions
            .transition(
                "tenant-1",
                "expired-transition",
                AuthzState::PendingConsent.as_str(),
                None,
                1_000,
            )
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sessions
                .get("tenant-1", "expired-transition")
                .await
                .unwrap()
                .unwrap(),
            transition_before
        );
        let bind_before = sessions
            .get("tenant-1", "expired-bind")
            .await
            .unwrap()
            .unwrap();
        assert!(sessions
            .bind_user("tenant-1", "expired-bind", "user-1", 1_000)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sessions
                .get("tenant-1", "expired-bind")
                .await
                .unwrap()
                .unwrap(),
            bind_before
        );

        let device = MemoryDeviceStore::default();
        for device_code in [
            "expired-poll",
            "expired-consume",
            "expired-decide",
            "expired-release",
        ] {
            device
                .put(
                    "tenant-1",
                    DeviceAuthGrant {
                        device_code: device_code.into(),
                        user_code: format!("USER-{device_code}"),
                        client_id: "client-1".into(),
                        user_id: None,
                        authz_session_id: None,
                        scope: vec!["openid".into()],
                        resources: vec![],
                        interval: 5,
                        last_poll_at: None,
                        expires_at: 1_000,
                        status: "pending".into(),
                        consumed: device_code == "expired-release",
                        password_credential_version: None,
                    },
                )
                .await
                .unwrap();
        }
        let poll_before = device
            .get("tenant-1", "expired-poll")
            .await
            .unwrap()
            .unwrap();
        assert!(!device
            .claim_poll("tenant-1", "expired-poll", None, 1_000)
            .await
            .unwrap());
        assert_eq!(
            device
                .get("tenant-1", "expired-poll")
                .await
                .unwrap()
                .unwrap(),
            poll_before
        );
        let consume_before = device
            .get("tenant-1", "expired-consume")
            .await
            .unwrap()
            .unwrap();
        assert!(!device
            .consume("tenant-1", "expired-consume", 1_000)
            .await
            .unwrap());
        assert_eq!(
            device
                .get("tenant-1", "expired-consume")
                .await
                .unwrap()
                .unwrap(),
            consume_before
        );
        let decide_before = device
            .get("tenant-1", "expired-decide")
            .await
            .unwrap()
            .unwrap();
        assert!(!device
            .decide("tenant-1", "expired-decide", "user-1", None, true, 1_000,)
            .await
            .unwrap());
        assert_eq!(
            device
                .get("tenant-1", "expired-decide")
                .await
                .unwrap()
                .unwrap(),
            decide_before
        );
        let release_before = device
            .get("tenant-1", "expired-release")
            .await
            .unwrap()
            .unwrap();
        device
            .release_consume("tenant-1", "expired-release", 1_000)
            .await
            .unwrap();
        assert_eq!(
            device
                .get("tenant-1", "expired-release")
                .await
                .unwrap()
                .expect("expired device record remains physically present"),
            release_before,
            "rollback must not change an expired consumed device grant"
        );
    }

    async fn destructive_guard_fixture() -> (
        MemoryGovernanceStore,
        crate::governance::GovernanceDestructiveFence,
    ) {
        use crate::governance::{
            GovernanceJobKind, GovernanceJobLeaseOutcome, GovernanceJobPhase, GovernanceJobRecord,
            GovernanceJobStartOutcome, GovernanceJobState, TenantCleanupStage,
        };
        use crate::ports::GovernanceStore;

        let store = MemoryGovernanceStore::default();
        let job = GovernanceJobRecord {
            job_id: "guard-job".into(),
            tenant_id: "t1".into(),
            kind: GovernanceJobKind::UserErasure,
            target_id: Some("user-1".into()),
            target_aliases: vec![],
            verification_target: None,
            active_child_job_id: None,
            processed_records: 0,
            tenant_cleanup_stage: TenantCleanupStage::Users,
            target_epoch: 7,
            state: GovernanceJobState::Running,
            phase: GovernanceJobPhase::PrimaryCleanup,
            policy_revision: 0,
            tenant_revision: 0,
            revision: 1,
            created_at: 10,
            updated_at: 10,
            primary_erasure_at: None,
            retention_anchor_at: None,
            retention_until: None,
            evidence_revision: 0,
            error_class: None,
        };
        assert!(matches!(
            store.start_or_resume_job(job, 0, false).await.unwrap(),
            GovernanceJobStartOutcome::Stored(_)
        ));
        let lease = match store
            .claim_job_lease("t1", "guard-job", 1, "opaque-token-digest", 100, 200)
            .await
            .unwrap()
        {
            GovernanceJobLeaseOutcome::Acquired(lease) => lease,
            outcome => panic!("unexpected lease outcome: {outcome:?}"),
        };
        (store, lease.destructive_fence(Some(7)))
    }

    #[derive(Clone, Default)]
    struct GovernanceUserDataFixture {
        governance: MemoryGovernanceStore,
        users: MemoryUsersStore,
        codes: MemoryCodeStore,
        sessions: MemorySessionStore,
        refresh: MemoryRefreshStore,
        grace: MemoryGraceStore,
        passkey_challenges: MemoryPasskeyChallengeStore,
        passkeys: MemoryPasskeyStore,
        grants: MemoryGrantStore,
        jtis: MemoryJtiStore,
        ciba: MemoryCibaStore,
        device: MemoryDeviceStore,
        recovery: MemoryRecoveryStore,
        passwords: MemoryPasswordStore,
        magic_links: MemoryMagicLinkStore,
        invitations: MemoryInvitationStore,
        messages: MemoryOutboxNotifier,
        scim_groups: MemoryScimGroupsStore,
        admin_auth: MemoryAdminAuthStore,
        authz_sessions: MemoryAuthzSessionStore,
    }

    impl GovernanceUserDataFixture {
        fn data_plane(&self) -> MemoryGovernanceUserDataPlane<'_> {
            MemoryGovernanceUserDataPlane {
                governance: &self.governance,
                users: &self.users,
                codes: &self.codes,
                sessions: &self.sessions,
                refresh: &self.refresh,
                grace: Some(&self.grace),
                passkey_challenges: &self.passkey_challenges,
                passkeys: &self.passkeys,
                grants: &self.grants,
                jtis: Some(&self.jtis),
                ciba: &self.ciba,
                device: &self.device,
                recovery: &self.recovery,
                passwords: &self.passwords,
                magic_links: &self.magic_links,
                invitations: &self.invitations,
                messages: &self.messages,
                scim_groups: &self.scim_groups,
                admin_auth: &self.admin_auth,
                authz_sessions: &self.authz_sessions,
            }
        }
    }

    #[derive(Clone, Default)]
    struct GovernanceTenantDataFixture {
        governance: MemoryGovernanceStore,
        users: MemoryUsersStore,
        clients: MemoryClientStore,
        initial_access_tokens: MemoryInitialAccessTokenStore,
        scim_groups: MemoryScimGroupsStore,
        federation_config: MemoryFederationConfigStore,
        federation_attribute_mappings:
            crate::adapters::memory_federation_attributes::MemoryFederationAttributeMappingsStore,
        workload_trust: MemoryWorkloadTrustStore,
        admin_auth: MemoryAdminAuthStore,
        federation_flow: MemoryFederationFlowStore,
        codes: MemoryCodeStore,
        sessions: MemorySessionStore,
        refresh: MemoryRefreshStore,
        grace: MemoryGraceStore,
        passkey_challenges: MemoryPasskeyChallengeStore,
        passkeys: MemoryPasskeyStore,
        jtis: MemoryJtiStore,
        passwords: MemoryPasswordStore,
        recovery: MemoryRecoveryStore,
        magic_links: MemoryMagicLinkStore,
        invitations: MemoryInvitationStore,
        messages: MemoryOutboxNotifier,
        ciba: MemoryCibaStore,
        device: MemoryDeviceStore,
        par: MemoryParStore,
        replay: MemoryReplayStore,
        authz_sessions: MemoryAuthzSessionStore,
        grants: MemoryGrantStore,
        domain_map: MemoryDomainMapStore,
        policy_artifacts: MemoryPolicyArtifactStore,
        policy_versions: MemoryPolicyVersionStore,
        rate_limit: MemoryRateLimitStore,
        ssf: crate::ssf::MemorySsfStore,
    }

    impl GovernanceTenantDataFixture {
        fn data_plane(&self) -> MemoryGovernanceTenantDataPlane<'_> {
            MemoryGovernanceTenantDataPlane {
                governance: &self.governance,
                users: &self.users,
                clients: &self.clients,
                initial_access_tokens: &self.initial_access_tokens,
                scim_groups: &self.scim_groups,
                federation_config: &self.federation_config,
                federation_attribute_mappings: &self.federation_attribute_mappings,
                workload_trust: &self.workload_trust,
                admin_auth: &self.admin_auth,
                federation_flow: &self.federation_flow,
                codes: &self.codes,
                sessions: &self.sessions,
                refresh: &self.refresh,
                grace: Some(&self.grace),
                passkey_challenges: &self.passkey_challenges,
                passkeys: &self.passkeys,
                jtis: Some(&self.jtis),
                passwords: &self.passwords,
                recovery: &self.recovery,
                magic_links: &self.magic_links,
                invitations: &self.invitations,
                messages: &self.messages,
                ciba: &self.ciba,
                device: &self.device,
                par: &self.par,
                replay: Some(&self.replay),
                authz_sessions: &self.authz_sessions,
                grants: &self.grants,
                domain_map: &self.domain_map,
                policy_artifacts: &self.policy_artifacts,
                policy_versions: &self.policy_versions,
                rate_limit: Some(&self.rate_limit),
                ssf: &self.ssf,
            }
        }
    }

    fn governance_code(code: &str, user_id: &str) -> CodeRecord {
        CodeRecord {
            code: code.into(),
            client_id: "client".into(),
            cimd_snapshot: None,
            redirect_uri: "https://app.example.com/cb".into(),
            code_challenge: "challenge".into(),
            resources: vec![],
            user_id: user_id.into(),
            scope: vec!["openid".into()],
            expires_at: 9999,
            authz_session_id: None,
            nonce: None,
            auth_time: 100,
            authorization_details: vec![],
            acr: None,
            amr: vec![],
            credential_epoch: Some(0),
            password_credential_version: None,
        }
    }

    fn governance_tombstone(user_id: &str) -> crate::ports::UserRecord {
        crate::ports::UserRecord {
            user_id: user_id.into(),
            email: String::new(),
            created_at: 10,
            updated_at: 100,
            last_login_at: None,
            status: crate::ports::UserStatus::Tombstoned,
            credential_epoch: 7,
            revocation_pending: true,
            scim_external_id: None,
            scim_user_name: None,
            scim_display_name: None,
            attributes_generation: 0,
            attributes: BTreeMap::new(),
        }
    }

    fn assert_destructive_fence_conflict(
        result: Result<MemoryGovernanceDestructiveGuard, StoreError>,
    ) {
        match result {
            Err(StoreError::Transient(message)) => {
                assert_eq!(message, MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT);
                assert!(!message.contains("opaque-token-digest"));
            }
            Err(error) => panic!("expected transient fence conflict, got {error:?}"),
            Ok(_) => panic!("expected destructive fence conflict"),
        }
    }

    #[tokio::test]
    async fn governance_destructive_guard_accepts_current_authority() {
        let (store, fence) = destructive_guard_fixture().await;
        let guard = store
            .acquire_destructive_guard("t1", &fence, 150)
            .await
            .unwrap();
        drop(guard);
    }

    #[tokio::test]
    async fn governance_destructive_guard_rejects_stale_fence_fields() {
        let (store, fence) = destructive_guard_fixture().await;

        let mut stale_token = fence.clone();
        stale_token.lease_token_digest = "stale-token-digest".into();
        assert_destructive_fence_conflict(
            store
                .acquire_destructive_guard("t1", &stale_token, 150)
                .await,
        );

        let mut stale_deadline = fence.clone();
        stale_deadline.lease_deadline += 1;
        assert_destructive_fence_conflict(
            store
                .acquire_destructive_guard("t1", &stale_deadline, 150)
                .await,
        );

        let mut stale_epoch = fence;
        stale_epoch.target_epoch = Some(8);
        assert_destructive_fence_conflict(
            store
                .acquire_destructive_guard("t1", &stale_epoch, 150)
                .await,
        );
    }

    #[tokio::test]
    async fn governance_destructive_guard_rejects_expired_lease() {
        let (store, fence) = destructive_guard_fixture().await;
        assert_destructive_fence_conflict(
            store
                .acquire_destructive_guard("t1", &fence, fence.lease_deadline)
                .await,
        );
    }

    fn suppression_record(digest: &str) -> crate::governance::GovernanceSuppressionRecord {
        crate::governance::GovernanceSuppressionRecord {
            tenant_id: "t1".into(),
            target_class: "user".into(),
            key_version: crate::governance::SUPPRESSION_KEY_VERSION,
            normalization_version: crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
            digest: digest.into(),
            target_epoch: 7,
            created_at: 150,
        }
    }

    #[tokio::test]
    async fn suppression_write_requires_current_unexpired_destructive_fence() {
        use crate::ports::GovernanceStore;

        let (store, fence) = destructive_guard_fixture().await;
        assert!(store
            .put_suppression(suppression_record("current"), fence.clone(), 150)
            .await
            .unwrap());

        let mut stale = fence.clone();
        stale.lease_token_digest = "stale-token".into();
        assert!(matches!(
            store
                .put_suppression(suppression_record("stale"), stale, 150)
                .await,
            Err(StoreError::Transient(message))
                if message == MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT
        ));
        assert!(matches!(
            store
                .put_suppression(
                    suppression_record("expired"),
                    fence.clone(),
                    fence.lease_deadline,
                )
                .await,
            Err(StoreError::Transient(message))
                if message == MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT
        ));
        assert!(!store.is_suppressed("t1", "user", "stale").await.unwrap());
        assert!(!store.is_suppressed("t1", "user", "expired").await.unwrap());
    }

    #[tokio::test]
    async fn suppression_write_is_blocked_after_legal_hold_changes() {
        use crate::governance::{GovernancePolicyRecord, LegalHoldState};
        use crate::ports::GovernanceStore;

        let (store, fence) = destructive_guard_fixture().await;
        let mut policy = GovernancePolicyRecord::default_for("t1");
        policy.legal_hold = LegalHoldState::Enabling;
        policy.legal_hold_reason = Some("case-suppression".into());
        store.put_policy(policy, 0).await.unwrap();

        assert!(matches!(
            store
                .put_suppression(suppression_record("held"), fence, 150)
                .await,
            Err(StoreError::Transient(message))
                if message == MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT
        ));
        assert!(!store.is_suppressed("t1", "user", "held").await.unwrap());
    }

    #[tokio::test]
    async fn governance_destructive_guard_blocks_enabling_hold_until_drop() {
        use crate::governance::{
            GovernancePolicyPutOutcome, GovernancePolicyRecord, LegalHoldState,
        };
        use crate::ports::GovernanceStore;
        use std::time::Duration;
        use tokio::sync::Barrier;
        use tokio::time::timeout;

        let (store, fence) = destructive_guard_fixture().await;
        let guard = store
            .acquire_destructive_guard("t1", &fence, 150)
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let pending_store = store.clone();
        let pending_barrier = barrier.clone();
        let mut enabling_hold = tokio::spawn(async move {
            pending_barrier.wait().await;
            pending_store
                .put_policy(
                    GovernancePolicyRecord {
                        tenant_id: "t1".into(),
                        legal_hold: LegalHoldState::Enabling,
                        legal_hold_reason: Some("case-guard".into()),
                        retention_exception_capability: Default::default(),
                        actor: "owner".into(),
                        updated_at: 151,
                        revision: 0,
                    },
                    0,
                )
                .await
        });
        barrier.wait().await;

        assert!(
            timeout(Duration::from_millis(100), &mut enabling_hold)
                .await
                .is_err(),
            "legal-hold update crossed the destructive authority guard"
        );
        drop(guard);

        let outcome = timeout(Duration::from_secs(1), enabling_hold)
            .await
            .expect("legal-hold update did not converge after guard drop")
            .expect("legal-hold task panicked")
            .expect("legal-hold update failed");
        assert!(matches!(
            outcome,
            GovernancePolicyPutOutcome::Stored(policy)
                if policy.legal_hold == LegalHoldState::Enabling && policy.revision == 1
        ));
    }

    #[tokio::test]
    async fn governance_user_cleanup_holds_barrier_until_physical_mutation_finishes() {
        use crate::governance::{
            GovernancePolicyPutOutcome, GovernancePolicyRecord, LegalHoldState,
        };
        use crate::ports::GovernanceStore;
        use std::time::Duration;
        use tokio::time::timeout;

        let (governance, fence) = destructive_guard_fixture().await;
        let fixture = GovernanceUserDataFixture {
            governance,
            ..Default::default()
        };
        fixture
            .codes
            .put("t1", governance_code("blocked-code", "user-1"))
            .await
            .unwrap();
        fixture.users.by_id.lock().await.insert(
            ("t1".into(), "user-1".into()),
            governance_tombstone("user-1"),
        );

        let code_lock = fixture.codes.map.lock().await;
        let cleanup_fixture = fixture.clone();
        let cleanup_fence = fence.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_fixture
                .data_plane()
                .cleanup_user("t1", "t1", "user-1", &[], &cleanup_fence, 150)
                .await
        });
        timeout(Duration::from_secs(1), async {
            loop {
                if fixture.governance.state.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup did not acquire the destructive authority guard");

        let hold_store = fixture.governance.clone();
        let mut enabling_hold = tokio::spawn(async move {
            hold_store
                .put_policy(
                    GovernancePolicyRecord {
                        tenant_id: "t1".into(),
                        legal_hold: LegalHoldState::Enabling,
                        legal_hold_reason: Some("case-cleanup".into()),
                        retention_exception_capability: Default::default(),
                        actor: "owner".into(),
                        updated_at: 151,
                        revision: 0,
                    },
                    0,
                )
                .await
        });
        assert!(
            timeout(Duration::from_millis(100), &mut enabling_hold)
                .await
                .is_err(),
            "legal hold crossed an in-flight physical cleanup"
        );

        drop(code_lock);
        assert_eq!(
            timeout(Duration::from_secs(1), cleanup)
                .await
                .expect("cleanup did not finish")
                .expect("cleanup task panicked")
                .expect("cleanup failed"),
            1
        );
        let outcome = timeout(Duration::from_secs(1), enabling_hold)
            .await
            .expect("legal hold did not finish")
            .expect("legal-hold task panicked")
            .expect("legal-hold update failed");
        assert!(matches!(
            outcome,
            GovernancePolicyPutOutcome::Stored(policy)
                if policy.legal_hold == LegalHoldState::Enabling
        ));
    }

    #[tokio::test]
    async fn governance_user_cleanup_rejects_stale_fence_without_mutation() {
        let (governance, fence) = destructive_guard_fixture().await;
        let fixture = GovernanceUserDataFixture {
            governance,
            ..Default::default()
        };
        fixture
            .codes
            .put("t1", governance_code("preserved-code", "user-1"))
            .await
            .unwrap();
        fixture.users.by_id.lock().await.insert(
            ("t1".into(), "user-1".into()),
            governance_tombstone("user-1"),
        );
        let mut stale = fence;
        stale.lease_token_digest = "stale-token".into();

        let error = fixture
            .data_plane()
            .cleanup_user("t1", "t1", "user-1", &[], &stale, 150)
            .await
            .expect_err("stale fence must fail");
        assert!(matches!(
            error,
            StoreError::Transient(message)
                if message == MEMORY_GOVERNANCE_DESTRUCTIVE_FENCE_CONFLICT
        ));
        assert_eq!(fixture.codes.map.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn governance_user_cleanup_deletes_owned_authorization_sessions_without_codes() {
        let (governance, fence) = destructive_guard_fixture().await;
        let fixture = GovernanceUserDataFixture {
            governance,
            ..Default::default()
        };
        fixture.users.by_id.lock().await.insert(
            ("t1".into(), "user-1".into()),
            governance_tombstone("user-1"),
        );
        for (session_id, user_id) in [("target-authz", "user-1"), ("other-authz", "user-2")] {
            fixture
                .authz_sessions
                .create(
                    "t1",
                    AuthzSessionRecord {
                        session_id: session_id.into(),
                        client_id: "client".into(),
                        user_id: Some(user_id.into()),
                        state: "code_issued_awaiting_exchange".into(),
                        session_token_hash: format!("hash-{session_id}"),
                        sequence: 1,
                        last_error: None,
                        expires_at: 9999,
                    },
                )
                .await
                .unwrap();
            let mut code = governance_code(&format!("code-{session_id}"), user_id);
            code.authz_session_id = Some(session_id.into());
            fixture.codes.put("t1", code).await.unwrap();
        }
        fixture
            .authz_sessions
            .create(
                "t1",
                AuthzSessionRecord {
                    session_id: "target-without-code".into(),
                    client_id: "client".into(),
                    user_id: Some("user-1".into()),
                    state: "denied".into(),
                    session_token_hash: "hash-target-without-code".into(),
                    sequence: 2,
                    last_error: None,
                    expires_at: 9999,
                },
            )
            .await
            .unwrap();

        let before = fixture
            .data_plane()
            .inventory_user("t1", "t1", "user-1", &[])
            .await
            .unwrap();
        assert_eq!(before.get("authz_sessions"), Some(&2));
        assert_eq!(
            fixture
                .data_plane()
                .cleanup_user("t1", "t1", "user-1", &[], &fence, 150)
                .await
                .unwrap(),
            3
        );
        assert!(fixture
            .authz_sessions
            .get("t1", "target-authz")
            .await
            .unwrap()
            .is_none());
        assert!(fixture
            .authz_sessions
            .get("t1", "target-without-code")
            .await
            .unwrap()
            .is_none());
        assert!(fixture
            .authz_sessions
            .get("t1", "other-authz")
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            fixture
                .data_plane()
                .inventory_user("t1", "t1", "user-1", &[])
                .await
                .unwrap()
                .get("authz_sessions"),
            Some(&0)
        );
    }

    #[tokio::test]
    async fn governance_user_inventory_is_read_only_and_observes_late_residuals() {
        let fixture = GovernanceUserDataFixture::default();
        fixture
            .codes
            .put("t1", governance_code("first-code", "user-1"))
            .await
            .unwrap();

        let first = fixture
            .data_plane()
            .inventory_user("t1", "t1", "user-1", &[])
            .await
            .unwrap();
        assert_eq!(first.get("codes"), Some(&1));
        assert_eq!(fixture.codes.map.lock().await.len(), 1);

        fixture
            .codes
            .put("t1", governance_code("late-code", "user-1"))
            .await
            .unwrap();
        let second = fixture
            .data_plane()
            .inventory_user("t1", "t1", "user-1", &[])
            .await
            .unwrap();
        assert_eq!(second.get("codes"), Some(&2));
        assert_eq!(fixture.codes.map.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn governance_user_cleanup_removes_only_the_targets_admin_sessions() {
        use crate::ports::{AdminAuthStore, AdminSessionRecord, TenantRole};

        let (governance, fence) = destructive_guard_fixture().await;
        let fixture = GovernanceUserDataFixture {
            governance,
            ..Default::default()
        };
        fixture.users.by_id.lock().await.insert(
            ("t1".into(), "user-1".into()),
            governance_tombstone("user-1"),
        );
        for (session_hash, user_id) in [("target-session", "user-1"), ("other-session", "user-2")] {
            fixture
                .admin_auth
                .create_session(AdminSessionRecord {
                    session_hash: session_hash.into(),
                    tenant_id: "t1".into(),
                    user_id: user_id.into(),
                    upstream_subject: format!("upstream-{user_id}"),
                    role: TenantRole::Admin,
                    credential_epoch: 0,
                    config_revision: 1,
                    config_binding_id: "binding-1".into(),
                    acr: None,
                    auth_time: 100,
                    created_at: 100,
                    expires_at: 1_000,
                })
                .await
                .unwrap();
        }

        let before = fixture
            .data_plane()
            .inventory_user("t1", "t1", "user-1", &[])
            .await
            .unwrap();
        assert_eq!(before.get("admin_sessions"), Some(&1));
        assert_eq!(
            fixture
                .data_plane()
                .cleanup_user("t1", "t1", "user-1", &[], &fence, 150)
                .await
                .unwrap(),
            1
        );
        let after = fixture
            .data_plane()
            .inventory_user("t1", "t1", "user-1", &[])
            .await
            .unwrap();
        assert_eq!(after.get("admin_sessions"), Some(&0));
        assert!(fixture
            .admin_auth
            .get_session("other-session", 200)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn governance_tenant_inventory_is_read_only_and_observes_late_residuals() {
        let fixture = GovernanceTenantDataFixture::default();
        fixture
            .codes
            .put("t1", governance_code("first-code", "user-1"))
            .await
            .unwrap();

        let first = fixture
            .data_plane()
            .inventory_tenant("t1", "t1")
            .await
            .unwrap();
        assert_eq!(first.get("codes"), Some(&1));
        assert_eq!(fixture.codes.map.lock().await.len(), 1);

        fixture
            .codes
            .put("t1", governance_code("late-code", "user-1"))
            .await
            .unwrap();
        let second = fixture
            .data_plane()
            .inventory_tenant("t1", "t1")
            .await
            .unwrap();
        assert_eq!(second.get("codes"), Some(&2));
        assert_eq!(fixture.codes.map.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn governance_federation_stage_inventories_and_cleans_mapping_authority() {
        let (governance, fence) = destructive_guard_fixture().await;
        let fixture = GovernanceTenantDataFixture {
            governance,
            ..Default::default()
        };
        let outcome = fixture
            .federation_attribute_mappings
            .change(
                "t1",
                "idp-1",
                "https://idp.example.com",
                crate::federation_attributes::MappingChange::Create {
                    mapping_id: "fm_governance".into(),
                    expected_registry_revision: 0,
                    spec: crate::federation_attributes::MappingSpec {
                        source_claim: "department".into(),
                        target_namespace: "https://resource.example.com".into(),
                        target_key: "department".into(),
                        mode: crate::federation_attributes::MappingMode::CopyString,
                    },
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            crate::federation_attributes::MappingChangeOutcome::Applied(_)
        ));

        let before = fixture
            .data_plane()
            .inventory_tenant("t1", "t1")
            .await
            .unwrap();
        assert_eq!(before.get("federation_attribute_mapping_rows"), Some(&3));
        assert_eq!(
            fixture
                .data_plane()
                .cleanup_stage(
                    "t1",
                    "t1",
                    crate::governance::TenantCleanupStage::Federation,
                    &fence,
                    150,
                )
                .await
                .unwrap(),
            3
        );
        let after = fixture
            .data_plane()
            .inventory_tenant("t1", "t1")
            .await
            .unwrap();
        assert_eq!(after.get("federation_attribute_mapping_rows"), Some(&0));
    }

    async fn active_user(users: &MemoryUsersStore, email: &str, now: i64) -> String {
        let user_id = format!("user:{email}");
        crate::ports::UsersStore::create_or_get_by_email(users, "t1", email, &user_id, now)
            .await
            .unwrap();
        user_id
    }

    fn test_session(session_id: &str, user_id: &str, now: i64) -> SessionRecord {
        SessionRecord {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            credential_epoch: 0,
            auth_time: now,
            created_at: now,
            last_used_at: now,
            device: "Test browser".to_string(),
            expires_at: now + 3_600,
            acr: None,
            amr: vec!["email".to_string()],
        }
    }

    fn test_passkey(
        credential_id: &str,
        user_id: &str,
    ) -> agent_auth_authn::passkey::PasskeyCredential {
        agent_auth_authn::passkey::PasskeyCredential {
            credential_id: credential_id.to_string(),
            user_id: user_id.to_string(),
            rp_id: "t1.saas.example.com".to_string(),
            public_key_sec1: vec![0x04; 65],
            sign_count: 0,
            name: "Passkey".to_string(),
            created_at: 1_000,
        }
    }

    #[tokio::test]
    async fn recovery_success_results_are_partitioned_by_tenant() {
        use crate::ports::RecoveryStore;

        let recovery = MemoryRecoveryStore::default();
        let result = RecoverySuccessResult {
            operation_key: "tenant-bound-operation".to_string(),
            user_lookup: "lookup".to_string(),
            user_id: "user:test@example.com".to_string(),
            presented_hash: "presented-hash".to_string(),
            credential_epoch: 1,
            session_id: "recovered-session".to_string(),
            created_at: 1_000,
            expires_at: 1_060,
        };
        recovery.results.lock().await.insert(
            ("t1".to_string(), result.operation_key.clone()),
            result.clone(),
        );

        assert_eq!(
            recovery
                .get_success_result("t1", &result.operation_key)
                .await
                .unwrap(),
            Some(result.clone())
        );
        assert!(
            recovery
                .get_success_result("t2", &result.operation_key)
                .await
                .unwrap()
                .is_none(),
            "another tenant must not retrieve the operation result"
        );
    }

    #[tokio::test]
    async fn recovery_operation_reconciles_after_a_concurrent_epoch_advance() {
        use crate::ports::{RecoveryCodeEntry, RecoveryStore, UsersStore};
        use base64::Engine as _;

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let sessions = MemorySessionStore::default();
        let recovery = MemoryRecoveryStore::default();
        let user_id = active_user(&users, "concurrent-recovery@example.com", now).await;
        let lookup = "concurrent-recovery-lookup";
        let operation_key = "concurrent-recovery-operation";
        let presented_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]);
        recovery
            .put(
                "t1",
                RecoveryRecord {
                    user_lookup: lookup.to_string(),
                    user_id: user_id.clone(),
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![RecoveryCodeEntry {
                        hash_b64: presented_hash.clone(),
                        consumed: false,
                    }],
                    attempt_count: 0,
                    locked_until: 0,
                },
            )
            .await
            .unwrap();

        let committed_at = now + 1;
        let mut committed_session =
            test_session("concurrent-recovery-session", &user_id, committed_at);
        committed_session.credential_epoch = 1;
        committed_session.amr = vec!["recovery_code".to_string()];
        let committed_result = RecoverySuccessResult {
            operation_key: operation_key.to_string(),
            user_lookup: lookup.to_string(),
            user_id: user_id.clone(),
            presented_hash: presented_hash.clone(),
            credential_epoch: 1,
            session_id: committed_session.session_id.clone(),
            created_at: committed_at,
            expires_at: committed_at + 60,
        };
        assert_eq!(
            recovery
                .verify_and_consume_at_epoch(
                    &users,
                    &passwords,
                    &sessions,
                    RecoveryConsumeRequest {
                        tenant: "t1",
                        user_lookup: lookup,
                        user_id: &user_id,
                        expected_email: "concurrent-recovery@example.com",
                        expected_epoch: 0,
                        presented_hash: &presented_hash,
                        now: committed_at,
                    },
                    committed_session,
                    committed_result.clone(),
                )
                .await
                .unwrap(),
            RecoveryAuthorityConsume::Valid {
                credential_epoch: 1
            }
        );

        let mut stale_request_session = test_session("concurrent-recovery-session", &user_id, now);
        stale_request_session.credential_epoch = 1;
        stale_request_session.amr = vec!["recovery_code".to_string()];
        let stale_request_result = RecoverySuccessResult {
            operation_key: operation_key.to_string(),
            user_lookup: lookup.to_string(),
            user_id: user_id.clone(),
            presented_hash: presented_hash.clone(),
            credential_epoch: 1,
            session_id: stale_request_session.session_id.clone(),
            created_at: now,
            expires_at: now + 60,
        };
        assert_eq!(
            recovery
                .verify_and_consume_at_epoch(
                    &users,
                    &passwords,
                    &sessions,
                    RecoveryConsumeRequest {
                        tenant: "t1",
                        user_lookup: lookup,
                        user_id: &user_id,
                        expected_email: "concurrent-recovery@example.com",
                        expected_epoch: 0,
                        presented_hash: &presented_hash,
                        now,
                    },
                    stale_request_session,
                    stale_request_result,
                )
                .await
                .unwrap(),
            RecoveryAuthorityConsume::Replayed {
                result: committed_result
            }
        );
        assert_eq!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .credential_epoch,
            1
        );
        assert_eq!(
            recovery
                .get("t1", lookup)
                .await
                .unwrap()
                .unwrap()
                .attempt_count,
            0
        );
    }

    #[tokio::test]
    async fn recovery_session_collision_leaves_code_and_authority_unchanged() {
        use crate::ports::{RecoveryCodeEntry, RecoveryStore, SessionStore, UsersStore};
        use base64::Engine as _;

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let sessions = MemorySessionStore::default();
        let recovery = MemoryRecoveryStore::default();
        let user_id = active_user(&users, "recovery@example.com", now).await;
        let lookup = "recovery-lookup";
        let presented_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        recovery
            .put(
                "t1",
                RecoveryRecord {
                    user_lookup: lookup.to_string(),
                    user_id: user_id.clone(),
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![RecoveryCodeEntry {
                        hash_b64: presented_hash.clone(),
                        consumed: false,
                    }],
                    attempt_count: 0,
                    locked_until: 0,
                },
            )
            .await
            .unwrap();
        sessions
            .create("t1", test_session("collision", &user_id, now))
            .await
            .unwrap();
        let mut recovered_session = test_session("collision", &user_id, now);
        recovered_session.credential_epoch = 1;
        recovered_session.amr = vec!["recovery_code".to_string()];
        let recovery_result = RecoverySuccessResult {
            operation_key: "collision-operation".to_string(),
            user_lookup: lookup.to_string(),
            user_id: user_id.clone(),
            presented_hash: presented_hash.clone(),
            credential_epoch: 1,
            session_id: recovered_session.session_id.clone(),
            created_at: now,
            expires_at: now + 60,
        };

        assert!(recovery
            .verify_and_consume_at_epoch(
                &users,
                &passwords,
                &sessions,
                RecoveryConsumeRequest {
                    tenant: "t1",
                    user_lookup: lookup,
                    user_id: &user_id,
                    expected_email: "recovery@example.com",
                    expected_epoch: 0,
                    presented_hash: &presented_hash,
                    now,
                },
                recovered_session,
                recovery_result,
            )
            .await
            .is_err());
        assert_eq!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .credential_epoch,
            0
        );
        assert!(
            !recovery
                .get("t1", lookup)
                .await
                .unwrap()
                .unwrap()
                .code_hashes[0]
                .consumed
        );
        assert!(sessions.get("t1", "collision").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn recovery_contact_change_leaves_material_and_authority_unchanged() {
        use crate::ports::{RecoveryCodeEntry, RecoveryStore, SessionStore, UsersStore};
        use base64::Engine as _;

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let sessions = MemorySessionStore::default();
        let recovery = MemoryRecoveryStore::default();
        let original_email = "recovery@example.com";

        let rotation_user = active_user(&users, "rotation@example.com", now).await;
        assert_eq!(
            users
                .begin_credential_change("t1", &rotation_user, 0, "rotation-owner", now + 1)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        users
            .by_id
            .lock()
            .await
            .get_mut(&("t1".to_string(), rotation_user.clone()))
            .unwrap()
            .email = "rotation-moved@example.com".to_string();
        assert!(!recovery
            .commit_rotation(
                &users,
                "t1",
                RecoveryRecord {
                    user_lookup: "rotation-contact-change".to_string(),
                    user_id: rotation_user,
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![],
                    attempt_count: 0,
                    locked_until: 0,
                },
                "rotation@example.com",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "rotation-owner",
                },
                now + 2,
            )
            .await
            .unwrap());
        assert!(recovery
            .get("t1", "rotation-contact-change")
            .await
            .unwrap()
            .is_none());

        let user_id = active_user(&users, original_email, now).await;
        let lookup = "recovery-contact-change";
        let presented_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8_u8; 32]);
        recovery
            .put(
                "t1",
                RecoveryRecord {
                    user_lookup: lookup.to_string(),
                    user_id: user_id.clone(),
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![RecoveryCodeEntry {
                        hash_b64: presented_hash.clone(),
                        consumed: false,
                    }],
                    attempt_count: 0,
                    locked_until: 0,
                },
            )
            .await
            .unwrap();
        users
            .by_id
            .lock()
            .await
            .get_mut(&("t1".to_string(), user_id.clone()))
            .unwrap()
            .email = "moved@example.com".to_string();
        let mut recovered_session = test_session("contact-change", &user_id, now);
        recovered_session.credential_epoch = 1;
        recovered_session.amr = vec!["recovery_code".to_string()];
        let recovery_result = RecoverySuccessResult {
            operation_key: "contact-change-operation".to_string(),
            user_lookup: lookup.to_string(),
            user_id: user_id.clone(),
            presented_hash: presented_hash.clone(),
            credential_epoch: 1,
            session_id: recovered_session.session_id.clone(),
            created_at: now,
            expires_at: now + 60,
        };

        let outcome = recovery
            .verify_and_consume_at_epoch(
                &users,
                &passwords,
                &sessions,
                RecoveryConsumeRequest {
                    tenant: "t1",
                    user_lookup: lookup,
                    user_id: &user_id,
                    expected_email: original_email,
                    expected_epoch: 0,
                    presented_hash: &presented_hash,
                    now,
                },
                recovered_session,
                recovery_result,
            )
            .await
            .unwrap();
        assert_eq!(outcome, RecoveryAuthorityConsume::AuthorityChanged);
        assert_eq!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .credential_epoch,
            0
        );
        assert!(
            !recovery
                .get("t1", lookup)
                .await
                .unwrap()
                .unwrap()
                .code_hashes[0]
                .consumed
        );
        assert!(sessions
            .get("t1", "contact-change")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn authorized_passkey_registration_rejects_stale_user_and_session_authority() {
        use crate::ports::{PasskeyStore, SessionStore, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let sessions = MemorySessionStore::default();
        let passkeys = MemoryPasskeyStore::default();

        let epoch_user = active_user(&users, "epoch@example.com", now).await;
        let epoch_session = test_session("epoch-session", &epoch_user, now);
        sessions.create("t1", epoch_session.clone()).await.unwrap();
        assert_eq!(
            users
                .begin_credential_change("t1", &epoch_user, 0, "epoch-owner", now + 1)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert_eq!(
            passkeys
                .put_new_authorized(
                    &users,
                    &sessions,
                    "t1",
                    &epoch_session,
                    test_passkey("stale-epoch", &epoch_user),
                    now + 2,
                )
                .await
                .unwrap(),
            PasskeyRegistrationOutcome::AuthorityChanged
        );
        assert!(passkeys.get("t1", "stale-epoch").await.unwrap().is_none());

        let session_user = active_user(&users, "session@example.com", now).await;
        let stale_session = test_session("stale-session", &session_user, now);
        sessions.create("t1", stale_session.clone()).await.unwrap();
        assert!(sessions
            .revoke_all_by_actor("t1", &session_user, &stale_session.session_id)
            .await
            .unwrap());
        assert_eq!(
            passkeys
                .put_new_authorized(
                    &users,
                    &sessions,
                    "t1",
                    &stale_session,
                    test_passkey("stale-session-credential", &session_user),
                    now + 2,
                )
                .await
                .unwrap(),
            PasskeyRegistrationOutcome::AuthorityChanged
        );
        assert!(passkeys
            .get("t1", "stale-session-credential")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn credential_change_operations_are_replayable_owned_and_legacy_safe() {
        use crate::ports::{CredentialChangeStart, UserStatus, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let user_id = active_user(&users, "operation-owner@example.com", now).await;

        assert_eq!(
            users
                .begin_credential_change("t1", &user_id, 0, "operation-a", now + 1)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 }
        );
        assert_eq!(
            users
                .begin_credential_change("t1", &user_id, 0, "operation-a", now + 2)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 },
            "replaying the owner must return the committed epoch"
        );
        assert_eq!(
            users
                .begin_credential_change("t1", &user_id, 0, "operation-b", now + 2)
                .await
                .unwrap(),
            CredentialChangeStart::ConcurrentChange
        );
        assert!(!users
            .complete_credential_change(
                "t1",
                &user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "operation-b",
                },
                now + 3,
            )
            .await
            .unwrap());
        assert!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .revocation_pending
        );
        assert!(users
            .complete_credential_change(
                "t1",
                &user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "operation-a",
                },
                now + 3,
            )
            .await
            .unwrap());

        let tombstoned = active_user(&users, "operation-owner-tombstoned@example.com", now).await;
        assert_eq!(
            users
                .begin_credential_change("t1", &tombstoned, 0, "tombstone-operation", now + 1)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(users
            .set_status("t1", &tombstoned, UserStatus::Tombstoned, now + 2)
            .await
            .unwrap());
        assert_eq!(
            users
                .begin_credential_change("t1", &tombstoned, 0, "tombstone-operation", now + 3)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 },
            "the exact owner must observe its committed begin after a tombstone race"
        );
        assert_eq!(
            users
                .begin_credential_change("t1", &tombstoned, 0, "different-operation", now + 3)
                .await
                .unwrap(),
            CredentialChangeStart::Ineligible,
            "another operation must not claim a tombstoned fence"
        );

        assert_eq!(
            users
                .begin_credential_change("t1", &user_id, 1, "operation-c", now + 4)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 2 }
        );
        assert!(users
            .recover_expired_credential_change("t1", &user_id, 2, now + 4, now + 5)
            .await
            .unwrap());

        users
            .by_id
            .lock()
            .await
            .get_mut(&("t1".to_string(), user_id.clone()))
            .unwrap()
            .revocation_pending = true;
        assert!(!users
            .recover_expired_credential_change("t1", &user_id, 2, now + 100, now + 101)
            .await
            .unwrap());
        assert!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .revocation_pending,
            "legacy pending rows without an operation marker fail closed"
        );
    }

    #[tokio::test]
    async fn expired_admin_credential_fence_can_recover_while_user_is_disabled() {
        use crate::ports::{CredentialChangeStart, UserStatus, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let user_id = active_user(&users, "disabled-admin-fence@example.com", now).await;
        assert!(users
            .set_status("t1", &user_id, UserStatus::Disabled, now + 1)
            .await
            .unwrap());
        assert_eq!(
            users
                .begin_admin_credential_change("t1", &user_id, 0, "admin-reset-operation", now + 2,)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(!users
            .recover_expired_credential_change("t1", &user_id, 1, now + 1, now + 3)
            .await
            .unwrap());
        assert!(users
            .recover_expired_credential_change("t1", &user_id, 1, now + 2, now + 4)
            .await
            .unwrap());

        let recovered = users.get_by_id("t1", &user_id).await.unwrap().unwrap();
        assert_eq!(recovered.status, UserStatus::Disabled);
        assert_eq!(recovered.credential_epoch, 1);
        assert!(!recovered.revocation_pending);
    }

    #[tokio::test]
    async fn admin_reset_stage_complete_and_abort_require_the_exact_owner() {
        use crate::ports::{CredentialChangeStart, PasswordStore, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let user_id = active_user(&users, "admin-reset-owner@example.com", now).await;
        assert_eq!(
            users
                .begin_admin_credential_change("t1", &user_id, 0, "admin-owner", now + 1)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 }
        );
        let mutation = || crate::ports::FencedPasswordMutation {
            tenant: "t1",
            user_id: &user_id,
            password_hash: agent_auth_authn::password::hash_password(
                "Owned temporary password 123!",
            )
            .unwrap(),
            expected_version: None,
            credential_epoch: 1,
            updated_at: now + 2,
        };
        assert_eq!(
            passwords
                .stage_admin_reset(
                    &users,
                    mutation(),
                    crate::ports::CredentialChangeOwner {
                        epoch: 1,
                        operation_id: "other-owner",
                    },
                )
                .await
                .unwrap(),
            None
        );
        assert!(passwords.get("t1", &user_id).await.unwrap().is_none());
        assert_eq!(
            passwords
                .stage_admin_reset(
                    &users,
                    mutation(),
                    crate::ports::CredentialChangeOwner {
                        epoch: 1,
                        operation_id: "admin-owner",
                    },
                )
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            passwords
                .get("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .credential_change_id
                .as_deref(),
            Some("admin-owner")
        );
        assert!(!passwords
            .complete_admin_reset(
                &users,
                "t1",
                &user_id,
                1,
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "other-owner",
                },
                now + 3,
            )
            .await
            .unwrap());
        assert!(!users
            .abort_admin_credential_change(
                "t1",
                &user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "other-owner",
                },
                now + 3,
            )
            .await
            .unwrap());
        assert!(passwords
            .complete_admin_reset(
                &users,
                "t1",
                &user_id,
                1,
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "admin-owner",
                },
                now + 3,
            )
            .await
            .unwrap());
        let completed = passwords.get("t1", &user_id).await.unwrap().unwrap();
        assert!(!completed.revocation_pending);
        assert!(completed.credential_change_id.is_none());

        assert_eq!(
            users
                .begin_credential_change("t1", &user_id, 1, "self-service-owner", now + 4)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 2 }
        );
        assert!(!users
            .abort_admin_credential_change(
                "t1",
                &user_id,
                crate::ports::CredentialChangeOwner {
                    epoch: 2,
                    operation_id: "admin-owner",
                },
                now + 5,
            )
            .await
            .unwrap());
        assert!(
            users
                .get_by_id("t1", &user_id)
                .await
                .unwrap()
                .unwrap()
                .revocation_pending
        );
    }

    #[tokio::test]
    async fn credential_atomic_commits_require_the_fence_owner() {
        use crate::ports::{PasskeyStore, PasswordStore, RecoveryStore, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let recovery = MemoryRecoveryStore::default();
        let passkeys = MemoryPasskeyStore::default();

        let password_user = active_user(&users, "password-owner@example.com", now).await;
        users
            .begin_credential_change("t1", &password_user, 0, "password-owner", now + 1)
            .await
            .unwrap();
        assert!(!passwords
            .commit_credential_change(
                &users,
                crate::ports::FencedPasswordMutation {
                    tenant: "t1",
                    user_id: &password_user,
                    password_hash: agent_auth_authn::password::hash_password("New password 123!")
                        .unwrap(),
                    expected_version: None,
                    credential_epoch: 1,
                    updated_at: now + 2,
                },
                crate::ports::CredentialChangeOwner {
                    epoch: 2,
                    operation_id: "password-owner",
                },
            )
            .await
            .unwrap());
        assert!(!passwords
            .commit_credential_change(
                &users,
                crate::ports::FencedPasswordMutation {
                    tenant: "t1",
                    user_id: &password_user,
                    password_hash: agent_auth_authn::password::hash_password("New password 123!")
                        .unwrap(),
                    expected_version: None,
                    credential_epoch: 1,
                    updated_at: now + 2,
                },
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "different-operation",
                },
            )
            .await
            .unwrap());
        assert!(passwords.get("t1", &password_user).await.unwrap().is_none());

        let recovery_user = active_user(&users, "recovery-owner@example.com", now).await;
        users
            .begin_credential_change("t1", &recovery_user, 0, "recovery-owner", now + 1)
            .await
            .unwrap();
        assert!(!recovery
            .commit_rotation(
                &users,
                "t1",
                RecoveryRecord {
                    user_lookup: "owner-check".to_string(),
                    user_id: recovery_user,
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![],
                    attempt_count: 0,
                    locked_until: 0,
                },
                "recovery-owner@example.com",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "different-operation",
                },
                now + 2,
            )
            .await
            .unwrap());
        assert!(recovery.get("t1", "owner-check").await.unwrap().is_none());

        let passkey_user = active_user(&users, "passkey-owner@example.com", now).await;
        passkeys
            .put_new("t1", test_passkey("owner-check", &passkey_user))
            .await
            .unwrap();
        users
            .begin_credential_change("t1", &passkey_user, 0, "passkey-owner", now + 1)
            .await
            .unwrap();
        assert!(!passkeys
            .delete_owned_and_complete(
                &users,
                "t1",
                &passkey_user,
                "owner-check",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "different-operation",
                },
                now + 2,
            )
            .await
            .unwrap());
        assert!(passkeys.get("t1", "owner-check").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn credential_commits_do_not_cross_tombstones_and_passkey_delete_is_atomic() {
        use crate::ports::{PasskeyStore, PasswordStore, RecoveryStore, UserStatus, UsersStore};

        let now = 1_000;
        let users = MemoryUsersStore::default();
        let passwords = MemoryPasswordStore::default();
        let recovery = MemoryRecoveryStore::default();
        let passkeys = MemoryPasskeyStore::default();

        let tombstoned = active_user(&users, "tombstoned@example.com", now).await;
        assert_eq!(
            users
                .begin_credential_change("t1", &tombstoned, 0, "tombstone-owner", now + 1)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(users
            .set_status("t1", &tombstoned, UserStatus::Tombstoned, now + 2)
            .await
            .unwrap());
        assert!(!passwords
            .commit_credential_change(
                &users,
                crate::ports::FencedPasswordMutation {
                    tenant: "t1",
                    user_id: &tombstoned,
                    password_hash: agent_auth_authn::password::hash_password("New password 123!",)
                        .unwrap(),
                    expected_version: None,
                    credential_epoch: 1,
                    updated_at: now + 3,
                },
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "tombstone-owner",
                },
            )
            .await
            .unwrap());
        assert!(passwords.get("t1", &tombstoned).await.unwrap().is_none());
        let recovery_lookup = "tombstone-lookup";
        assert!(!recovery
            .commit_rotation(
                &users,
                "t1",
                RecoveryRecord {
                    user_lookup: recovery_lookup.to_string(),
                    user_id: tombstoned.clone(),
                    activation_id: "recovery".to_string(),
                    code_hashes: vec![],
                    attempt_count: 0,
                    locked_until: 0,
                },
                "tombstoned@example.com",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "tombstone-owner",
                },
                now + 3,
            )
            .await
            .unwrap());
        assert!(recovery.get("t1", recovery_lookup).await.unwrap().is_none());

        let active = active_user(&users, "delete@example.com", now).await;
        assert!(passkeys
            .put_new("t1", test_passkey("delete-me", &active))
            .await
            .unwrap());
        assert_eq!(
            users
                .begin_credential_change("t1", &active, 0, "delete-owner", now + 1)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(passkeys
            .delete_owned_and_complete(
                &users,
                "t1",
                &active,
                "delete-me",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "delete-owner",
                },
                now + 2,
            )
            .await
            .unwrap());
        assert!(passkeys.get("t1", "delete-me").await.unwrap().is_none());
        let active_after = users.get_by_id("t1", &active).await.unwrap().unwrap();
        assert_eq!(active_after.credential_epoch, 1);
        assert!(!active_after.revocation_pending);

        let deleted_user = active_user(&users, "delete-race@example.com", now).await;
        assert!(passkeys
            .put_new("t1", test_passkey("survives-tombstone", &deleted_user))
            .await
            .unwrap());
        assert_eq!(
            users
                .begin_credential_change("t1", &deleted_user, 0, "deleted-owner", now + 1,)
                .await
                .unwrap(),
            crate::ports::CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(users
            .set_status("t1", &deleted_user, UserStatus::Tombstoned, now + 2,)
            .await
            .unwrap());
        assert!(!passkeys
            .delete_owned_and_complete(
                &users,
                "t1",
                &deleted_user,
                "survives-tombstone",
                crate::ports::CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "deleted-owner",
                },
                now + 3,
            )
            .await
            .unwrap());
        assert!(passkeys
            .get("t1", "survives-tombstone")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn scim_groups_are_idempotent_and_mapping_is_explicit() {
        use crate::ports::{
            ScimGroupChange, ScimGroupCreateInput, ScimGroupCreateOutcome, ScimGroupDeleteOutcome,
            ScimGroupMutation, ScimGroupMutationOutcome, ScimGroupsStore, ScimRoleMappingOutcome,
            TenantRole,
        };

        let store = MemoryScimGroupsStore::default();
        let input = ScimGroupCreateInput {
            group_id: "group-1".into(),
            external_id: "directory-admins".into(),
            display_name: "Directory Admins".into(),
            members: vec!["user-1".into()],
            now: 10,
        };
        let created = match store.create("t1", input.clone()).await.unwrap() {
            ScimGroupCreateOutcome::Created(record) => record,
            other => panic!("unexpected create outcome: {other:?}"),
        };
        assert_eq!(created.version, 1);
        let retried = match store
            .create(
                "t1",
                ScimGroupCreateInput {
                    group_id: "ignored-retry-id".into(),
                    ..input
                },
            )
            .await
            .unwrap()
        {
            ScimGroupCreateOutcome::Existing(record) => record,
            other => panic!("unexpected retry outcome: {other:?}"),
        };
        assert_eq!(retried.group_id, "group-1");

        let unmapped = store.mapped_role_for_member("t1", "user-1").await.unwrap();
        assert_eq!(unmapped.role, None);
        assert!(unmapped.mappings.is_empty());

        assert!(matches!(
            store
                .set_role_mapping("t1", "directory-admins", Some(TenantRole::Admin), 20)
                .await
                .unwrap(),
            ScimRoleMappingOutcome::Updated(_)
        ));
        assert_eq!(
            store.get("t1", "group-1").await.unwrap().unwrap().version,
            2,
            "a mapping change must advance the Group CAS version"
        );
        store
            .set_role_mapping("t1", "directory-admins", Some(TenantRole::Admin), 21)
            .await
            .unwrap();
        assert_eq!(
            store.get("t1", "group-1").await.unwrap().unwrap().version,
            2,
            "an idempotent mapping retry must not advance the Group version"
        );
        assert_eq!(
            store
                .mapped_role_for_member("t1", "user-1")
                .await
                .unwrap()
                .role,
            Some(TenantRole::Admin)
        );
        store
            .create(
                "t1",
                ScimGroupCreateInput {
                    group_id: "group-2".into(),
                    external_id: "directory-owners".into(),
                    display_name: "Directory Owners".into(),
                    members: vec!["user-1".into()],
                    now: 21,
                },
            )
            .await
            .unwrap();
        store
            .set_role_mapping("t1", "directory-owners", Some(TenantRole::Owner), 22)
            .await
            .unwrap();
        assert_eq!(
            store
                .mapped_role_for_member("t1", "user-1")
                .await
                .unwrap()
                .role,
            Some(TenantRole::Owner),
            "multiple mappings must resolve by fixed role priority"
        );
        store
            .set_role_mapping("t1", "directory-owners", None, 23)
            .await
            .unwrap();

        let mutation = ScimGroupMutation::Patch {
            changes: vec![ScimGroupChange::AddMembers(vec!["user-2".into()])],
            now: 30,
        };
        let updated = match store
            .mutate("t1", "group-1", mutation.clone())
            .await
            .unwrap()
        {
            ScimGroupMutationOutcome::Updated(record) => record,
            other => panic!("unexpected mutation outcome: {other:?}"),
        };
        assert_eq!(updated.version, 3);
        let exact_retry = match store.mutate("t1", "group-1", mutation).await.unwrap() {
            ScimGroupMutationOutcome::Updated(record) => record,
            other => panic!("unexpected mutation retry outcome: {other:?}"),
        };
        assert_eq!(exact_retry.version, 3);

        assert_eq!(
            store.delete("t1", "group-1", 40).await.unwrap(),
            ScimGroupDeleteOutcome::Deleted
        );
        assert_eq!(
            store.delete("t1", "group-1", 41).await.unwrap(),
            ScimGroupDeleteOutcome::Deleted
        );
        assert!(store
            .mapped_role_for_member("t1", "user-1")
            .await
            .unwrap()
            .mappings
            .is_empty());
        assert!(matches!(
            store
                .set_role_mapping("t1", "directory-admins", Some(TenantRole::Owner), 50)
                .await
                .unwrap(),
            ScimRoleMappingOutcome::GroupNotFound
        ));
    }

    #[tokio::test]
    async fn scim_group_create_enforces_member_limit_and_never_reuses_tombstoned_id() {
        use crate::ports::{
            ScimGroupCreateInput, ScimGroupDeleteOutcome, ScimGroupsStore, SCIM_GROUP_MAX_MEMBERS,
        };

        let store = MemoryScimGroupsStore::default();
        let oversized = store
            .create(
                "t1",
                ScimGroupCreateInput {
                    group_id: "too-large".into(),
                    external_id: "too-large".into(),
                    display_name: "Too Large".into(),
                    members: (0..=SCIM_GROUP_MAX_MEMBERS)
                        .map(|index| format!("user-{index}"))
                        .collect(),
                    now: 10,
                },
            )
            .await;
        assert!(matches!(oversized, Err(StoreError::Permanent(_))));
        assert!(store.get("t1", "too-large").await.unwrap().is_none());

        let input = ScimGroupCreateInput {
            group_id: "stable-id".into(),
            external_id: "first-external".into(),
            display_name: "First".into(),
            members: Vec::new(),
            now: 20,
        };
        store.create("t1", input).await.unwrap();
        assert_eq!(
            store.delete("t1", "stable-id", 21).await.unwrap(),
            ScimGroupDeleteOutcome::Deleted
        );
        let reuse = store
            .create(
                "t1",
                ScimGroupCreateInput {
                    group_id: "stable-id".into(),
                    external_id: "second-external".into(),
                    display_name: "Second".into(),
                    members: Vec::new(),
                    now: 22,
                },
            )
            .await;
        assert!(matches!(reuse, Err(StoreError::Permanent(_))));
        assert!(store
            .get_by_external_id("t1", "second-external")
            .await
            .unwrap()
            .is_none());
    }

    // spec 005 C10.7:per-key 令牌桶限流——容量内放行、超额拒 + Retry-After;不同 key 独立(非全局)。
    #[tokio::test]
    async fn rate_limit_store_exhausts_and_isolates_per_key() {
        use crate::ports::RateLimitStore;
        let store = MemoryRateLimitStore::default();
        // 容量 5、补充 1/s。同一秒(now 固定)连取:前 5 个放行,第 6 个拒。
        let mut allowed = 0;
        let mut denied_retry = None;
        for _ in 0..8 {
            let d = store
                .try_consume("client-a", 1000, 5.0, 1.0, 1.0)
                .await
                .unwrap();
            if d.allowed {
                allowed += 1;
            } else {
                denied_retry = d.retry_after_secs;
            }
        }
        assert_eq!(allowed, 5, "容量 5 → 恰放行 5 个(同秒不补充)");
        assert!(
            matches!(denied_retry, Some(s) if s >= 1),
            "超额拒应带 Retry-After ≥1s(攒 1 token 需 1s),实得 {denied_retry:?}"
        );

        // 不同 key 独立满桶:client-b 首取放行(不受 client-a 打满影响)。
        let d = store
            .try_consume("client-b", 1000, 5.0, 1.0, 1.0)
            .await
            .unwrap();
        assert!(d.allowed, "不同 key 独立桶,首取应放行(per-key 非全局)");

        // 时间推进补充:client-a 过 3s 后至少补 3 token → 再取放行。
        let d = store
            .try_consume("client-a", 1003, 5.0, 1.0, 1.0)
            .await
            .unwrap();
        assert!(d.allowed, "3s 后补充 ~3 token → 应放行");
    }

    #[tokio::test]
    async fn rate_limit_availability_check_does_not_consume() {
        use crate::ports::RateLimitStore;
        let store = MemoryRateLimitStore::default();

        for _ in 0..6 {
            assert!(
                store
                    .check_available("account", 1000, 5.0, 1.0, 1.0)
                    .await
                    .unwrap()
                    .allowed,
                "availability checks must leave the full bucket unchanged"
            );
        }

        for _ in 0..5 {
            assert!(
                store
                    .try_consume("account", 1000, 5.0, 1.0, 1.0)
                    .await
                    .unwrap()
                    .allowed
            );
        }
        let denied = store
            .check_available("account", 1000, 5.0, 1.0, 1.0)
            .await
            .unwrap();
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after_secs, Some(1));
    }

    // CIBA/device 内存 store:put/get/update + device user_code 反查(spec 013)。
    #[tokio::test]
    async fn ciba_device_store_roundtrip() {
        use crate::ports::{CibaAuthRequest, CibaStore, DeviceAuthGrant, DeviceStore};
        let ciba = MemoryCibaStore::default();
        let r = CibaAuthRequest {
            auth_req_id: "ar1".into(),
            tenant: String::new(),
            client_id: "c1".into(),
            user_id: "user:alice".into(),
            authz_session_id: Some("s1".into()),
            scope: vec!["openid".into()],
            resources: vec![],
            binding_message: Some("Approve login".into()),
            interval: 5,
            last_poll_at: None,
            expires_at: 9_999_999_999,
            status: "pending".into(),
            consumed: false,
            delivery_mode: None,
            notification_endpoint: None,
            client_notification_token: None,
            password_credential_version: None,
        };
        ciba.put("", r.clone()).await.unwrap();
        assert_eq!(
            ciba.get("", "ar1").await.unwrap().unwrap().status,
            "pending"
        );
        // update 迁 approved + last_poll_at。
        let mut r2 = r.clone();
        r2.status = "approved".into();
        r2.last_poll_at = Some(1000);
        ciba.update("", r2).await.unwrap();
        let got = ciba.get("", "ar1").await.unwrap().unwrap();
        assert_eq!(got.status, "approved");
        assert_eq!(got.last_poll_at, Some(1000));

        let dev = MemoryDeviceStore::default();
        let g = DeviceAuthGrant {
            device_code: "dc1".into(),
            user_code: "WDJBMJHT".into(),
            client_id: "c1".into(),
            user_id: None,
            authz_session_id: None,
            scope: vec!["openid".into()],
            resources: vec![],
            interval: 5,
            last_poll_at: None,
            expires_at: 9_999_999_999,
            status: "pending".into(),
            consumed: false,
            password_credential_version: None,
        };
        dev.put("", g).await.unwrap();
        // 按 user_code 反查(验证页用)。
        assert_eq!(
            dev.get_by_user_code("", "WDJBMJHT")
                .await
                .unwrap()
                .unwrap()
                .device_code,
            "dc1"
        );
        assert!(dev.get_by_user_code("", "NOPE").await.unwrap().is_none());
        assert_eq!(
            dev.get("", "dc1").await.unwrap().unwrap().user_code,
            "WDJBMJHT"
        );
    }

    // 宽限窗内存 store:put/get 按 (family,version) 键;delete_family 清全部版本(C3.5)。
    #[tokio::test]
    async fn grace_store_roundtrip_and_delete_family() {
        use crate::ports::{GraceCacheEntry, GraceCachedResponse, GraceStore};
        let g = MemoryGraceStore::default();
        let mk = |fam: &str, ver: u64| GraceCacheEntry {
            family_id: fam.into(),
            version: ver,
            fingerprint: [ver as u8; 32],
            client_id: "c1".into(),
            dpop_jkt: None,
            response: GraceCachedResponse {
                access_token: format!("at-{fam}-{ver}"),
                refresh_token: format!("rt-{fam}-{ver}"),
                id_token: None,
                scope: Some("openid".into()),
                expires_in: 300,
            },
            expires_at: 9_999_999_999,
        };
        g.put(mk("fam1", 0)).await.unwrap();
        g.put(mk("fam1", 1)).await.unwrap();
        g.put(mk("fam2", 0)).await.unwrap();

        // 按 (family,version) 精确取。
        assert_eq!(
            g.get("fam1", 0)
                .await
                .unwrap()
                .unwrap()
                .response
                .access_token,
            "at-fam1-0"
        );
        assert_eq!(
            g.get("fam1", 1)
                .await
                .unwrap()
                .unwrap()
                .response
                .refresh_token,
            "rt-fam1-1"
        );
        assert!(
            g.get("fam1", 2).await.unwrap().is_none(),
            "不存在的版本 → None"
        );

        // delete_family 只清该 family 所有版本,不动其它 family(C3.5)。
        g.delete_family("fam1").await.unwrap();
        assert!(g.get("fam1", 0).await.unwrap().is_none());
        assert!(g.get("fam1", 1).await.unwrap().is_none());
        assert_eq!(
            g.get("fam2", 0)
                .await
                .unwrap()
                .unwrap()
                .response
                .access_token,
            "at-fam2-0",
            "delete_family 不得误删其它 family"
        );
    }

    // MemorySigner 产出的签名能被 p256 验签器验证(sanity;真机验签在 e2e 用 PyJWT)。
    #[tokio::test]
    async fn memory_signer_produces_verifiable_es256() {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let signer = MemorySigner::from_seed([3u8; 32]);
        let input = b"header.payload";
        let sig_bytes = signer.sign_es256(input).await.unwrap();
        assert_eq!(sig_bytes.len(), 64, "JOSE ES256 = 64 字节 r‖s");

        // 用公钥 JWK 的 x/y 重建 verifying key 验签。
        let jwks = signer.public_jwks().await.unwrap();
        let jwk = &jwks[0];
        let x = URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y = URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        assert!(vk.verify(input, &sig).is_ok());
    }

    fn rec(code: &str) -> CodeRecord {
        CodeRecord {
            code: code.into(),
            client_id: "client".into(),
            cimd_snapshot: None,
            redirect_uri: "https://app.example.com/cb".into(),
            code_challenge: "chal".into(),
            resources: vec![],
            user_id: "u1".into(),
            scope: vec!["openid".into()],
            expires_at: 9999,
            authz_session_id: None,
            nonce: None,
            auth_time: 0,
            authorization_details: vec![],
            acr: None,
            amr: vec![],
            credential_epoch: Some(0),
            password_credential_version: None,
        }
    }

    #[tokio::test]
    async fn authorized_code_write_serializes_with_user_tombstone() {
        use crate::ports::{CodeIssueOutcome, UserStatus, UsersStore};

        let users = MemoryUsersStore::default();
        let codes = MemoryCodeStore::default();
        let user_id = active_user(&users, "code-race@example.com", 100).await;

        let mut before_tombstone = rec("before-tombstone");
        before_tombstone.user_id = user_id.clone();
        assert_eq!(
            codes
                .put_authorized(&users, "t1", before_tombstone, 0)
                .await
                .unwrap(),
            CodeIssueOutcome::Stored
        );
        assert!(users
            .set_status("t1", &user_id, UserStatus::Tombstoned, 101)
            .await
            .unwrap());
        assert_eq!(codes.delete_by_user("t1", &user_id).await.unwrap(), 1);
        assert_eq!(
            codes
                .acquire_lease("t1", "before-tombstone", "before-owner", 102, 162)
                .await
                .unwrap(),
            LeaseAcquire::NotFound
        );

        let mut after_tombstone = rec("after-tombstone");
        after_tombstone.user_id = user_id;
        assert_eq!(
            codes
                .put_authorized(&users, "t1", after_tombstone, 0)
                .await
                .unwrap(),
            CodeIssueOutcome::AuthorityChanged
        );
        assert_eq!(
            codes
                .acquire_lease("t1", "after-tombstone", "after-owner", 102, 162)
                .await
                .unwrap(),
            LeaseAcquire::NotFound
        );
    }

    // 两阶段 lease:占 lease → finalize 后重放拒。
    #[tokio::test]
    async fn lease_acquire_then_finalize_one_shot() {
        let store = MemoryCodeStore::default();
        store.put("", rec("c1")).await.unwrap();
        // 第一次占 lease 成功。
        assert!(matches!(
            store
                .acquire_lease("", "c1", "owner-a", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        // 未过期时并发再占 → Locked。
        assert_eq!(
            store
                .acquire_lease("", "c1", "owner-b", 120, 160)
                .await
                .unwrap(),
            LeaseAcquire::Locked
        );
        // finalize 后 → AlreadyConsumed。
        store
            .finalize(
                "",
                "c1",
                "client-a",
                2_000,
                200,
                "owner-a",
                Some("grant-c1"),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "c1", "owner-c", 200, 260)
                .await
                .unwrap(),
            LeaseAcquire::AlreadyConsumed {
                issued_grant_id: Some(grant_id),
                ..
            } if grant_id == "grant-c1"
        ));
        assert!(!store.replay_detected("", "c1").await.unwrap());
        assert!(store.record_replay("", "c1", 201).await.unwrap());
        assert!(store.replay_detected("", "c1").await.unwrap());
    }

    #[tokio::test]
    async fn exchange_failure_rejects_mismatched_session_binding_without_mutation() {
        use agent_auth_authn::authz_session::AuthzState;

        let codes = MemoryCodeStore::default();
        let sessions = MemoryAuthzSessionStore::default();
        let mut code = rec("bound-code");
        code.authz_session_id = Some("bound-session".into());
        codes.put("t1", code).await.unwrap();
        sessions
            .create(
                "t1",
                AuthzSessionRecord {
                    session_id: "bound-session".into(),
                    client_id: "client-1".into(),
                    user_id: Some("user-1".into()),
                    state: AuthzState::CodeIssuedAwaitingExchange.as_str().into(),
                    session_token_hash: "hash".into(),
                    sequence: 7,
                    last_error: None,
                    expires_at: 1_700_001_800,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            codes
                .acquire_lease("t1", "bound-code", "owner-1", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));

        assert!(matches!(
            codes
                .finalize_exchange_failure(
                    &sessions,
                    "t1",
                    "bound-code",
                    "client-a",
                    2_000,
                    100,
                    "owner-1",
                    Some("other-session"),
                    "error".into(),
                )
                .await,
            Err(StoreError::Transient(_))
        ));
        let unchanged = sessions.get("t1", "bound-session").await.unwrap().unwrap();
        assert_eq!(unchanged.sequence, 7);
        assert_eq!(
            unchanged.state,
            AuthzState::CodeIssuedAwaitingExchange.as_str()
        );

        let transitioned = codes
            .finalize_exchange_failure(
                &sessions,
                "t1",
                "bound-code",
                "client-a",
                2_000,
                100,
                "owner-1",
                Some("bound-session"),
                "error".into(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(transitioned.sequence, 8);
        assert_eq!(transitioned.state, AuthzState::ExchangeFailed.as_str());
        assert!(matches!(
            codes
                .acquire_lease("t1", "bound-code", "owner-2", 161, 221)
                .await
                .unwrap(),
            LeaseAcquire::AlreadyConsumed { .. }
        ));
    }

    // C10.1 ①:release_lease 后可重新占用(签名前瞬时失败可重试)。
    #[tokio::test]
    async fn lease_release_allows_retry() {
        let store = MemoryCodeStore::default();
        store.put("", rec("c2")).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "c2", "owner-a", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        store.release_lease("", "c2", "owner-a", 100).await.unwrap(); // 瞬时失败,释放不消费
                                                                      // 立刻可重占(未 finalize)。
        assert!(matches!(
            store
                .acquire_lease("", "c2", "owner-b", 101, 161)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
    }

    // lease TTL 到期后可被重新占用(③ finalize 失败停 signing、TTL 到期重试)。
    #[tokio::test]
    async fn lease_expiry_allows_reacquire() {
        let store = MemoryCodeStore::default();
        store.put("", rec("c3")).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "c3", "owner-a", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        // lease 未到期 → Locked。
        assert_eq!(
            store
                .acquire_lease("", "c3", "owner-b", 150, 160)
                .await
                .unwrap(),
            LeaseAcquire::Locked
        );
        // lease 到期(now >= 160)→ 可重占。
        assert!(matches!(
            store
                .acquire_lease("", "c3", "owner-b", 160, 220)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
    }

    #[tokio::test]
    async fn expired_lease_owner_cannot_finalize_or_release_replacement_lease() {
        let store = MemoryCodeStore::default();
        store.put("", rec("c4")).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "c4", "stale-owner", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        assert!(matches!(
            store
                .acquire_lease("", "c4", "current-owner", 160, 220)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));

        assert!(store
            .finalize(
                "",
                "c4",
                "client-a",
                2_000,
                180,
                "stale-owner",
                Some("stale-grant"),
            )
            .await
            .is_err());
        assert!(store
            .release_lease("", "c4", "stale-owner", 180)
            .await
            .is_err());
        assert_eq!(
            store
                .acquire_lease("", "c4", "third-owner", 180, 240)
                .await
                .unwrap(),
            LeaseAcquire::Locked,
            "a stale owner must not clear the replacement lease"
        );

        store
            .finalize(
                "",
                "c4",
                "client-a",
                2_000,
                200,
                "current-owner",
                Some("current-grant"),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "c4", "third-owner", 221, 281)
                .await
                .unwrap(),
            LeaseAcquire::AlreadyConsumed {
                issued_grant_id: Some(grant_id),
                ..
            } if grant_id == "current-grant"
        ));
    }

    // 不存在的 code → NotFound。
    #[tokio::test]
    async fn lease_notfound() {
        let store = MemoryCodeStore::default();
        assert_eq!(
            store
                .acquire_lease("", "nope", "owner-a", 100, 160)
                .await
                .unwrap(),
            LeaseAcquire::NotFound
        );
    }

    #[tokio::test]
    async fn expired_authorization_codes_never_acquire_or_surface_as_consumed() {
        let store = MemoryCodeStore::default();

        let mut unconsumed = rec("expired-unconsumed");
        unconsumed.expires_at = 1_000;
        store.put("", unconsumed).await.unwrap();
        let unconsumed_before = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-unconsumed".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert_eq!(
            store
                .acquire_lease("", "expired-unconsumed", "owner-a", 1_000, 1_060)
                .await
                .unwrap(),
            LeaseAcquire::NotFound
        );
        let unconsumed_entry = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-unconsumed".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert_eq!(unconsumed_entry, unconsumed_before);

        let mut consumed = rec("expired-consumed");
        consumed.expires_at = 1_000;
        store.put("", consumed).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "expired-consumed", "owner-b", 999, 1_059)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        store
            .finalize(
                "",
                "expired-consumed",
                "client",
                1_000,
                999,
                "owner-b",
                Some("grant-expired"),
            )
            .await
            .unwrap();
        let consumed_before = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-consumed".to_string()))
            .cloned()
            .expect("expired consumed code remains physically present");
        assert_eq!(
            store
                .acquire_lease("", "expired-consumed", "owner-c", 1_000, 1_060)
                .await
                .unwrap(),
            LeaseAcquire::NotFound,
            "an expired consumed code must not enter replay revocation"
        );
        assert!(!store.replay_detected("", "expired-consumed").await.unwrap());
        let consumed_entry = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-consumed".to_string()))
            .cloned()
            .expect("expired consumed code remains physically present");
        assert_eq!(consumed_entry, consumed_before);

        let mut finalize_race = rec("expired-finalize");
        finalize_race.expires_at = 1;
        store.put("", finalize_race).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "expired-finalize", "owner-d", 0, 60)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        let finalize_before = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-finalize".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert!(store
            .finalize(
                "",
                "expired-finalize",
                "client",
                1,
                1,
                "owner-d",
                Some("grant-too-late"),
            )
            .await
            .is_err());
        let finalize_entry = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-finalize".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert_eq!(finalize_entry, finalize_before);

        let release_before = finalize_entry;
        assert!(store
            .release_lease("", "expired-finalize", "owner-d", 1)
            .await
            .is_err());
        let release_entry = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-finalize".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert_eq!(release_entry, release_before);

        let mut replay = rec("expired-replay");
        replay.expires_at = 1;
        store.put("", replay).await.unwrap();
        {
            let mut map = store.map.lock().await;
            map.get_mut(&("".to_string(), "expired-replay".to_string()))
                .expect("seed replay code")
                .consumed = true;
        }
        let replay_before = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-replay".to_string()))
            .cloned()
            .expect("expired replay code remains physically present");
        assert!(!store.record_replay("", "expired-replay", 1).await.unwrap());
        let replay_after = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-replay".to_string()))
            .cloned()
            .expect("expired replay code remains physically present");
        assert_eq!(replay_after, replay_before);

        let sessions = MemoryAuthzSessionStore::default();
        let mut exchange_failure = rec("expired-exchange-failure");
        exchange_failure.expires_at = 1;
        store.put("", exchange_failure).await.unwrap();
        assert!(matches!(
            store
                .acquire_lease("", "expired-exchange-failure", "owner-e", 0, 60)
                .await
                .unwrap(),
            LeaseAcquire::Acquired(_)
        ));
        let exchange_before = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-exchange-failure".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert!(store
            .finalize_exchange_failure(
                &sessions,
                "",
                "expired-exchange-failure",
                "client",
                1,
                1,
                "owner-e",
                None,
                "too late".into(),
            )
            .await
            .is_err());
        let exchange_entry = store
            .map
            .lock()
            .await
            .get(&("".to_string(), "expired-exchange-failure".to_string()))
            .cloned()
            .expect("expired code remains physically present");
        assert_eq!(exchange_entry, exchange_before);
    }

    fn fam(id: &str) -> RefreshFamilyRecord {
        RefreshFamilyRecord {
            family_id: id.into(),
            current_version: 0,
            revoked: false,
            client_id: "c".into(),
            cimd_snapshot: None,
            user_id: "u".into(),
            credential_epoch: 0,
            resources: vec![],
            scope: vec!["openid".into()],
            actor_allowlist: vec![],
            max_act_chain: 1,
            dpop_jkt: None,
            pkce_code_challenge: None,
            auth_time: None,
            acr: None,
            password_credential_version: None,
        }
    }

    #[tokio::test]
    async fn refresh_lease_reclaim_fences_old_owner_and_finalizes_grace_atomically() {
        let store = MemoryRefreshStore::default();
        let grace = MemoryGraceStore::default();
        store.create("tenant-a", fam("fenced")).await.unwrap();

        assert_eq!(
            store
                .acquire_lease("tenant-a", "fenced", 0, "owner-a", 100, 130)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
        assert_eq!(
            store
                .acquire_lease("tenant-a", "fenced", 0, "owner-b", 110, 140)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Locked {
                retry_after_secs: 20
            }
        );
        assert!(!store
            .release_lease("tenant-a", "fenced", 0, "owner-b")
            .await
            .unwrap());

        assert_eq!(
            store
                .acquire_lease("tenant-a", "fenced", 0, "owner-b", 130, 160)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
        assert!(!store
            .finalize_rotation("tenant-a", "fenced", 0, "owner-a", 131)
            .await
            .unwrap());
        assert!(!store
            .release_lease("tenant-a", "fenced", 0, "owner-a")
            .await
            .unwrap());

        let entry = GraceCacheEntry {
            family_id: "fenced".into(),
            version: 0,
            fingerprint: [7; 32],
            client_id: "c".into(),
            dpop_jkt: None,
            response: crate::ports::GraceCachedResponse {
                access_token: "access".into(),
                refresh_token: "fenced.1".into(),
                id_token: None,
                scope: Some("openid".into()),
                expires_in: 300,
            },
            expires_at: 165,
        };
        assert!(store
            .finalize_rotation_with_grace(
                Some(&grace),
                "tenant-a",
                "fenced",
                0,
                "owner-b",
                131,
                Some(entry.clone()),
            )
            .await
            .unwrap());
        assert_eq!(
            store
                .get("tenant-a", "fenced")
                .await
                .unwrap()
                .unwrap()
                .current_version,
            1
        );
        assert_eq!(grace.get("fenced", 0).await.unwrap(), Some(entry));
    }

    // C3.1/C10.1:only an acquired lease can finalize the current version.
    #[tokio::test]
    async fn refresh_finalize_current_ok_old_version_mismatches() {
        let store = MemoryRefreshStore::default();
        store.create("", fam("f1")).await.unwrap();
        assert_eq!(
            store
                .acquire_lease("", "f1", 0, "owner-0", 100, 130)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
        assert!(store
            .finalize_rotation("", "f1", 0, "owner-0", 101)
            .await
            .unwrap());
        assert_eq!(
            store.get("", "f1").await.unwrap().unwrap().current_version,
            1
        );
        assert_eq!(
            store
                .acquire_lease("", "f1", 0, "owner-stale", 102, 132)
                .await
                .unwrap(),
            RefreshLeaseAcquire::VersionMismatch
        );
        assert_eq!(
            store
                .acquire_lease("", "f1", 1, "owner-1", 102, 132)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Acquired
        );
    }

    // C3.1:revoked families cannot acquire a signing lease.
    #[tokio::test]
    async fn refresh_revoked_cannot_acquire_lease() {
        let store = MemoryRefreshStore::default();
        store.create("", fam("f2")).await.unwrap();
        store.revoke("", "f2").await.unwrap();
        assert_eq!(
            store
                .acquire_lease("", "f2", 0, "owner", 100, 130)
                .await
                .unwrap(),
            RefreshLeaseAcquire::Revoked
        );
        assert!(store.get("", "f2").await.unwrap().unwrap().revoked);
    }

    // A missing family cannot acquire a signing lease.
    #[tokio::test]
    async fn refresh_missing_family_lease_not_found() {
        let store = MemoryRefreshStore::default();
        assert_eq!(
            store
                .acquire_lease("", "nope", 0, "owner", 100, 130)
                .await
                .unwrap(),
            RefreshLeaseAcquire::NotFound
        );
    }

    // C9.3:revoke_by_user 吊销某 user 全部 family(账户恢复),不碰其它 user;重试仍返回全部
    // family id,使上层可再次清理 grace。
    #[tokio::test]
    async fn refresh_revoke_by_user_revokes_all_for_user() {
        let store = MemoryRefreshStore::default();
        let mk = |id: &str, u: &str| RefreshFamilyRecord {
            family_id: id.into(),
            current_version: 0,
            revoked: false,
            client_id: "c".into(),
            cimd_snapshot: None,
            user_id: u.into(),
            credential_epoch: 0,
            resources: vec![],
            scope: vec!["openid".into()],
            actor_allowlist: vec![],
            max_act_chain: 1,
            dpop_jkt: None,
            pkce_code_challenge: None,
            auth_time: None,
            acr: None,
            password_credential_version: None,
        };
        store.create("", mk("fa", "alice")).await.unwrap();
        store.create("", mk("fb", "alice")).await.unwrap();
        store.create("", mk("fc", "bob")).await.unwrap();
        // 吊销 alice 的两条,不碰 bob;返回被吊销的 family_id 列表(供删宽限缓存 C3.5)。
        let mut revoked = store.revoke_by_user("", "alice").await.unwrap();
        revoked.sort();
        assert_eq!(revoked, vec!["fa".to_string(), "fb".to_string()]);
        assert!(store.get("", "fa").await.unwrap().unwrap().revoked);
        assert!(store.get("", "fb").await.unwrap().unwrap().revoked);
        assert!(
            !store.get("", "fc").await.unwrap().unwrap().revoked,
            "bob 不受影响"
        );
        // 再次吊销仍返回全部 id,供上层重试清理 grace。
        let mut retried = store.revoke_by_user("", "alice").await.unwrap();
        retried.sort();
        assert_eq!(retried, vec!["fa".to_string(), "fb".to_string()]);
        // 无此 user → 空。
        assert!(store.revoke_by_user("", "nobody").await.unwrap().is_empty());
    }

    // spec 003 §4.1 / C10.19:联邦配置存储的**复合键 tenant 隔离**——
    // t1 与 t2 各配同名 upstream_idp_id="okta",t1 只能取到 t1 的、拿不到 t2 的(key 含 tenant)。
    #[tokio::test]
    async fn federation_config_store_tenant_isolation() {
        use crate::ports::FederationConfigStore;
        use agent_auth_authn::federation::{FederationConfig, UpstreamProtocol};
        let store = MemoryFederationConfigStore::default();
        let mk = |tenant: &str, iss: &str| FederationConfig {
            tenant_id: tenant.into(),
            upstream_idp_id: "okta".into(), // **同名 idp,靠 tenant 隔离**
            protocol: UpstreamProtocol::Oidc,
            upstream_issuer: iss.into(),
            strong_acr_values: vec![],
            oidc: None, // 本测试只验 tenant 隔离/复合键,不涉 OIDC RP 参数
        };
        store
            .put(mk("t1", "https://t1-idp.example.com"))
            .await
            .unwrap();
        store
            .put(mk("t2", "https://t2-idp.example.com"))
            .await
            .unwrap();

        // t1 查 okta → 拿到 t1 的(issuer=t1-idp);绝不串到 t2。
        let g1 = store.get("t1", "okta").await.unwrap().unwrap();
        assert_eq!(g1.upstream_issuer, "https://t1-idp.example.com");
        assert_eq!(g1.tenant_id, "t1");
        // t2 查 okta → 拿到 t2 的。
        let g2 = store.get("t2", "okta").await.unwrap().unwrap();
        assert_eq!(g2.upstream_issuer, "https://t2-idp.example.com");
        // t3(未登记)查 okta → None(不泄露他租户配置)。
        assert!(store.get("t3", "okta").await.unwrap().is_none());
        // list_by_tenant 只返本租户。
        let l1 = store.list_by_tenant("t1").await.unwrap();
        assert_eq!(l1.len(), 1);
        assert_eq!(l1[0].tenant_id, "t1");
        // 复合键删:删 t1 的 okta 不影响 t2。
        store.delete("t1", "okta").await.unwrap();
        assert!(store.get("t1", "okta").await.unwrap().is_none());
        assert!(
            store.get("t2", "okta").await.unwrap().is_some(),
            "删 t1 不碰 t2"
        );
    }

    #[tokio::test]
    async fn password_store_is_tenant_scoped_and_cas_is_one_shot() {
        use crate::ports::{PasswordCredential, PasswordStore};

        let store = MemoryPasswordStore::default();
        let initial = agent_auth_authn::password::hash_password("temporary password").unwrap();
        assert!(store
            .create_if_absent(
                "t1",
                PasswordCredential {
                    user_id: "user:alice@example.com".into(),
                    password_hash: initial.clone(),
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 100,
                },
            )
            .await
            .unwrap());
        assert!(!store
            .create_if_absent(
                "t1",
                PasswordCredential {
                    user_id: "user:alice@example.com".into(),
                    password_hash: initial.clone(),
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 100,
                },
            )
            .await
            .unwrap());
        assert!(
            store
                .get("t2", "user:alice@example.com")
                .await
                .unwrap()
                .is_none(),
            "same user id in another tenant must not resolve"
        );

        let replacement = agent_auth_authn::password::hash_password("permanent password").unwrap();
        assert!(store
            .replace_if_version_and_temporary("t1", "user:alice@example.com", replacement, 1, 200,)
            .await
            .unwrap());
        assert!(!store
            .replace_if_version_and_temporary(
                "t1",
                "user:alice@example.com",
                agent_auth_authn::password::hash_password("other permanent password").unwrap(),
                1,
                201,
            )
            .await
            .unwrap());
        let active = store
            .get("t1", "user:alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!active.must_change);
        assert_eq!(active.version, 2);
        assert_eq!(active.updated_at, 200);
        assert!(
            !store
                .delete_if_version("t1", "user:alice@example.com", 1)
                .await
                .unwrap(),
            "stale provisioning cleanup must not delete a changed credential"
        );

        let orphan_id = "user:orphan@example.com";
        assert!(store
            .create_if_absent(
                "t1",
                PasswordCredential {
                    user_id: orphan_id.into(),
                    password_hash: initial,
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 100,
                },
            )
            .await
            .unwrap());
        assert!(store.delete_if_version("t1", orphan_id, 1).await.unwrap());
        assert!(store.get("t1", orphan_id).await.unwrap().is_none());

        let reset_hash =
            agent_auth_authn::password::hash_password("reset temporary password").unwrap();
        let reset_version = store
            .reset_temporary("t1", "user:alice@example.com", reset_hash, Some(2), 300)
            .await
            .unwrap();
        assert_eq!(reset_version, Some(3));
        let reset = store
            .get("t1", "user:alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(reset.must_change);
        assert!(reset.revocation_pending);
        assert_eq!(reset.version, 3);
        assert_eq!(reset.updated_at, 300);
        let conflicting_hash =
            agent_auth_authn::password::hash_password("conflicting temporary password").unwrap();
        assert_eq!(
            store
                .reset_temporary(
                    "t1",
                    "user:alice@example.com",
                    conflicting_hash,
                    Some(2),
                    301,
                )
                .await
                .unwrap(),
            None,
            "a reset using the stale observed version must not overwrite the winner"
        );
        let after_conflict = store
            .get("t1", "user:alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_conflict.version, 3);
        assert!(agent_auth_authn::password::verify_password(
            "reset temporary password",
            &after_conflict.password_hash
        )
        .unwrap());
        assert!(!store
            .replace_if_version_and_temporary(
                "t1",
                "user:alice@example.com",
                agent_auth_authn::password::hash_password("blocked permanent password").unwrap(),
                3,
                302,
            )
            .await
            .unwrap());
        assert!(store
            .complete_reset_revocation("t1", "user:alice@example.com", 3)
            .await
            .unwrap());
        assert!(
            !store
                .get("t1", "user:alice@example.com")
                .await
                .unwrap()
                .unwrap()
                .revocation_pending
        );

        assert_eq!(
            store
                .reset_temporary(
                    "t2",
                    "user:alice@example.com",
                    agent_auth_authn::password::hash_password("tenant two temporary").unwrap(),
                    None,
                    400,
                )
                .await
                .unwrap(),
            Some(1)
        );
        let tenant_two = store
            .get("t2", "user:alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tenant_two.version, 1);
        assert!(tenant_two.must_change);
        assert!(tenant_two.revocation_pending);

        store.delete("t1", "user:alice@example.com").await.unwrap();
        assert!(store
            .get("t1", "user:alice@example.com")
            .await
            .unwrap()
            .is_none());
    }

    // spec 003 §1.4:UsersStore by-email 幂等 upsert + get_by_id。
    #[tokio::test]
    async fn users_store_create_or_get_by_email_idempotent() {
        use crate::ports::UsersStore;
        let store = MemoryUsersStore::default();
        // 首登:create,user_id = 派生值。
        let u1 = store
            .create_or_get_by_email("", "alice@example.com", "user:alice@example.com", 1000)
            .await
            .unwrap();
        assert_eq!(u1.user_id, "user:alice@example.com");
        assert_eq!(u1.email, "alice@example.com");
        assert_eq!(u1.created_at, 1000);
        assert_eq!(u1.last_login_at, None);
        // 后续登录(同 email,不同 now):**复用同 user_id + 不覆盖 created_at**(幂等)。
        let u2 = store
            .create_or_get_by_email("", "alice@example.com", "user:alice@example.com", 9999)
            .await
            .unwrap();
        assert_eq!(
            u2.user_id, "user:alice@example.com",
            "同 email 复用 user_id"
        );
        assert_eq!(u2.created_at, 1000, "created_at 不被后续登录覆盖");
        // email 归一(大写/空白)命中同一条(GSI key 归一)。
        let u3 = store
            .create_or_get_by_email("", "  ALICE@Example.com ", "user:whatever", 5000)
            .await
            .unwrap();
        assert_eq!(
            u3.user_id, "user:alice@example.com",
            "归一后同 email 复用,不新建"
        );
        // get_by_id 取回。
        let got = store.get_by_id("", "user:alice@example.com").await.unwrap();
        assert_eq!(got.unwrap().email, "alice@example.com");
        // 不同 email → 不同 user。
        let bob = store
            .create_or_get_by_email("", "bob@example.com", "user:bob@example.com", 2000)
            .await
            .unwrap();
        assert_ne!(bob.user_id, u1.user_id);

        // 空 email 不得误命中联邦用户的稀疏 email 字段。
        let federated = store
            .create_or_get_by_id("", "user:fed:abc", 3000)
            .await
            .unwrap();
        let empty_email = store
            .create_or_get_by_email("", "", "user:empty-email", 3001)
            .await
            .unwrap();
        assert_ne!(empty_email.user_id, federated.user_id);
        assert_eq!(empty_email.user_id, "user:empty-email");
    }

    #[tokio::test]
    async fn users_store_identity_creation_serializes_with_suppression_write() {
        use crate::ports::{StoreError, UsersStore};

        let hmac_key = Arc::new(b"governance-test-key".to_vec());
        let governance = MemoryGovernanceStore::default();
        let store = MemoryUsersStore::default()
            .with_governance_suppression(governance.clone(), hmac_key.clone());
        let email = "erased@example.com";
        let digest = crate::governance::suppression_digest(
            &hmac_key,
            "t1",
            "user",
            crate::governance::GovernanceAliasKind::Email.as_str(),
            crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
            email,
        );

        let mut authority = governance.state.lock().await;
        let pending_store = store.clone();
        let create = tokio::spawn(async move {
            pending_store
                .create_or_get_by_email("t1", email, "user:erased@example.com", 1_000)
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !create.is_finished(),
            "identity creation must wait for the suppression authority lock"
        );

        authority
            .suppressions
            .insert(("t1".into(), "user".into(), digest, 1));
        drop(authority);

        assert!(matches!(
            create.await.unwrap(),
            Err(StoreError::Permanent(message))
                if message == "identity alias is permanently suppressed"
        ));
        assert!(store
            .get_by_id("t1", "user:erased@example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn users_store_scim_creation_checks_email_suppression_atomically() {
        use crate::ports::{ScimUserInput, StoreError, UsersStore};

        let hmac_key = Arc::new(b"governance-test-key".to_vec());
        let governance = MemoryGovernanceStore::default();
        let store = MemoryUsersStore::default()
            .with_governance_suppression(governance.clone(), hmac_key.clone());
        let email = "erased@example.com";
        let digest = crate::governance::suppression_digest(
            &hmac_key,
            "t1",
            "user",
            crate::governance::GovernanceAliasKind::Email.as_str(),
            crate::governance::SUPPRESSION_NORMALIZATION_VERSION,
            email,
        );
        governance
            .state
            .lock()
            .await
            .suppressions
            .insert(("t1".into(), "user".into(), digest, 1));

        assert!(matches!(
            store
                .create_scim(
                    "t1",
                    ScimUserInput {
                        user_id: "user:new-scim".into(),
                        external_id: "external-new".into(),
                        user_name: email.into(),
                        display_name: None,
                        active: true,
                        now: 1_001,
                    },
                )
                .await,
            Err(StoreError::Permanent(message))
                if message == "identity alias is permanently suppressed"
        ));
        assert!(store
            .get_by_id("t1", "user:new-scim")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn users_store_erasure_preserves_other_tenant_scim_create_claim() {
        use crate::ports::{ScimCreateOutcome, ScimUserInput, UsersStore};

        let store = MemoryUsersStore::default();
        let shared_user_id = "shared-user-id";
        let input = |tenant: &str| ScimUserInput {
            user_id: shared_user_id.to_string(),
            external_id: format!("{tenant}-external"),
            user_name: format!("{tenant}@example.com"),
            display_name: None,
            active: false,
            now: 1_000,
        };

        for tenant in ["t1", "t2"] {
            assert!(matches!(
                store.create_scim(tenant, input(tenant)).await.unwrap(),
                ScimCreateOutcome::Created(_)
            ));
        }

        store
            .fence_for_erasure("t1", shared_user_id, 2, 1_001)
            .await
            .unwrap();
        assert!(store
            .delete_erased_identity("t1", shared_user_id, 2)
            .await
            .unwrap());

        assert!(matches!(
            store.create_scim("t2", input("t2")).await.unwrap(),
            ScimCreateOutcome::Existing {
                pending_initial_epoch: Some(0),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn users_store_touch_last_login_is_monotonic_and_active_only() {
        use crate::ports::{UserStatus, UsersStore};
        let store = MemoryUsersStore::default();
        let user_id = "user:activity@example.com";
        store
            .create_or_get_by_email("t1", "activity@example.com", user_id, 100)
            .await
            .unwrap();
        store
            .create_or_get_by_email("t2", "activity-t2@example.com", user_id, 100)
            .await
            .unwrap();

        store.touch_last_login("t1", user_id, 200).await.unwrap();
        store.touch_last_login("t1", user_id, 150).await.unwrap();
        assert_eq!(
            store
                .get_by_id("t1", user_id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at,
            Some(200),
            "较旧的并发观测不得覆盖较新登录"
        );

        store
            .set_status("t1", user_id, UserStatus::Disabled, 210)
            .await
            .unwrap();
        store.touch_last_login("t1", user_id, 300).await.unwrap();
        assert_eq!(
            store
                .get_by_id("t1", user_id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at,
            Some(200),
            "Disabled 用户不得推进最后登录时间"
        );

        store.touch_last_login("t2", user_id, 400).await.unwrap();
        assert_eq!(
            store
                .get_by_id("t2", user_id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at,
            Some(400),
            "同一逻辑 user_id 的 t2 观测必须只推进 t2"
        );
        assert_eq!(
            store
                .get_by_id("t1", user_id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at,
            Some(200),
            "t2 观测不得修改同一逻辑 user_id 的 t1 记录"
        );
        store
            .touch_last_login("t2", "user:missing@example.com", 500)
            .await
            .unwrap();
        assert!(store
            .get_by_id("t2", "user:missing@example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn users_store_searches_full_tenant_result_set_before_pagination() {
        use crate::ports::UsersStore;
        let store = MemoryUsersStore::default();
        for (email, user_id) in [
            ("alice@example.com", "user:alice@example.com"),
            ("bob@example.com", "user:bob@example.com"),
            ("carol@other.test", "user:carol@other.test"),
        ] {
            store
                .create_or_get_by_email("t1", email, user_id, 1)
                .await
                .unwrap();
        }
        store
            .create_or_get_by_email("t2", "hidden@example.com", "user:hidden@example.com", 1)
            .await
            .unwrap();

        let (first, cursor) = store
            .list(
                "t1",
                1,
                None,
                Some("EXAMPLE"),
                crate::ports::UserListStatusFilter::All,
            )
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        let (second, next) = store
            .list(
                "t1",
                1,
                cursor.as_deref(),
                Some("example"),
                crate::ports::UserListStatusFilter::All,
            )
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert!(next.is_none());
        assert_ne!(first[0].user_id, second[0].user_id);

        let (by_id, _) = store
            .list(
                "t1",
                10,
                None,
                Some("CAROL@OTHER"),
                crate::ports::UserListStatusFilter::All,
            )
            .await
            .unwrap();
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].user_id, "user:carol@other.test");
    }

    // spec 013 §2b.5:get_by_email 只读——命中返记录 / 未注册 None(**绝不 create**)+ 归一。
    #[tokio::test]
    async fn users_store_get_by_email_readonly() {
        use crate::ports::UsersStore;
        let store = MemoryUsersStore::default();
        // 未注册 → None,且**不 create**(后续再查仍 None)。
        assert!(store
            .get_by_email("", "ghost@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(
            store
                .get_by_email("", "ghost@example.com")
                .await
                .unwrap()
                .is_none(),
            "get_by_email 只读,不得自动 onboard"
        );
        // 注册后 → 命中。
        store
            .create_or_get_by_email("", "alice@example.com", "user:alice@example.com", 1000)
            .await
            .unwrap();
        let hit = store.get_by_email("", "alice@example.com").await.unwrap();
        assert_eq!(hit.unwrap().user_id, "user:alice@example.com");
        // 归一(大写/空白)命中同一条(与 GSI email-index key 口径一致)。
        let hit2 = store
            .get_by_email("", "  ALICE@Example.com ")
            .await
            .unwrap();
        assert_eq!(
            hit2.unwrap().user_id,
            "user:alice@example.com",
            "归一后命中同一注册记录"
        );
    }

    // spec 007 §6.1:put_attributes 乐观锁全量替换 + 幂等 + 冲突 + 清空 + 体积 + Tombstone/GDPR。
    #[tokio::test]
    async fn users_store_put_attributes_lifecycle() {
        use crate::ports::{PutAttrOutcome, UserStatus, UsersStore};
        use std::collections::BTreeMap;
        let store = MemoryUsersStore::default();
        store
            .create_or_get_by_email("", "a@ex.com", "user:a@ex.com", 1)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_by_id("", "user:a@ex.com")
                .await
                .unwrap()
                .unwrap()
                .attributes_generation,
            0
        );
        let ns = "https://mcp.ek.example.com/";
        let kv = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };

        // 首写(expected_revision=0)→ Ok{revision:1}。
        let r = store
            .put_attributes(
                "",
                "user:a@ex.com",
                ns,
                kv(&[("role", "admin"), ("team", "x")]),
                0,
            )
            .await
            .unwrap();
        assert_eq!(r, PutAttrOutcome::Ok { revision: 1 });
        // 读回:属性正确 + revision=1。
        let rec = store.get_by_id("", "user:a@ex.com").await.unwrap().unwrap();
        assert_eq!(rec.attributes_generation, 1);
        let n = rec.attributes.get(ns).unwrap();
        assert_eq!(n.revision, 1);
        assert_eq!(n.kv.get("role").unwrap(), "admin");

        // Lost-response retry: same prior revision and same complete body is idempotent.
        let retry = store
            .put_attributes(
                "",
                "user:a@ex.com",
                ns,
                kv(&[("role", "admin"), ("team", "x")]),
                0,
            )
            .await
            .unwrap();
        assert_eq!(retry, PutAttrOutcome::Ok { revision: 1 });
        assert_eq!(
            store
                .get_by_id("", "user:a@ex.com")
                .await
                .unwrap()
                .unwrap()
                .attributes_generation,
            1,
            "idempotent retry must not advance generation"
        );

        // stale If-Match(用旧 revision 0)→ 冲突,current=1。
        let conflict = store
            .put_attributes("", "user:a@ex.com", ns, kv(&[("role", "editor")]), 0)
            .await
            .unwrap();
        assert_eq!(conflict, PutAttrOutcome::RevisionConflict { current: 1 });
        assert_eq!(
            store
                .get_by_id("", "user:a@ex.com")
                .await
                .unwrap()
                .unwrap()
                .attributes_generation,
            1,
            "revision conflict must not advance the cross-namespace generation"
        );

        // 正确 If-Match(revision=1)全量替换 → team 被替换掉,revision→2。
        let r2 = store
            .put_attributes("", "user:a@ex.com", ns, kv(&[("role", "editor")]), 1)
            .await
            .unwrap();
        assert_eq!(r2, PutAttrOutcome::Ok { revision: 2 });
        let rec = store.get_by_id("", "user:a@ex.com").await.unwrap().unwrap();
        assert_eq!(rec.attributes_generation, 2);
        let n = rec.attributes.get(ns).unwrap();
        assert_eq!(n.kv.len(), 1, "全量替换:team 被移除");
        assert_eq!(n.kv.get("role").unwrap(), "editor");

        // 空 kv = 清空该 namespace，同时保留递增 revision 墓碑防 ABA。
        let cleared = store
            .put_attributes("", "user:a@ex.com", ns, BTreeMap::new(), 2)
            .await
            .unwrap();
        assert_eq!(cleared, PutAttrOutcome::Ok { revision: 3 });
        let rec = store.get_by_id("", "user:a@ex.com").await.unwrap().unwrap();
        assert_eq!(rec.attributes_generation, 3);
        assert_eq!(rec.attributes[ns].revision, 3);
        assert!(rec.attributes[ns].kv.is_empty());

        let clear_retry = store
            .put_attributes("", "user:a@ex.com", ns, BTreeMap::new(), 2)
            .await
            .unwrap();
        assert_eq!(clear_retry, PutAttrOutcome::Ok { revision: 3 });
        assert_eq!(
            store
                .get_by_id("", "user:a@ex.com")
                .await
                .unwrap()
                .unwrap()
                .attributes_generation,
            3,
            "idempotent clear retry must not advance generation"
        );
        assert_eq!(
            store
                .put_attributes("", "user:a@ex.com", ns, kv(&[("role", "stale")]), 0)
                .await
                .unwrap(),
            PutAttrOutcome::RevisionConflict { current: 3 },
            "clearing must not recreate the absent-revision ABA state"
        );

        // 不存在的 user → NotFound。
        assert_eq!(
            store
                .put_attributes("", "user:ghost", ns, kv(&[("k", "v")]), 0)
                .await
                .unwrap(),
            PutAttrOutcome::NotFound
        );

        // Tombstone 后写 → Tombstoned;且 tombstone 级联清空已有属性(GDPR)。
        store
            .put_attributes("", "user:a@ex.com", ns, kv(&[("role", "admin")]), 3)
            .await
            .unwrap();
        store
            .set_status("", "user:a@ex.com", UserStatus::Tombstoned, 5)
            .await
            .unwrap();
        let rec = store.get_by_id("", "user:a@ex.com").await.unwrap().unwrap();
        assert!(rec.attributes.is_empty(), "tombstone 级联清空属性(GDPR)");
        assert_eq!(
            store
                .put_attributes("", "user:a@ex.com", ns, kv(&[("k", "v")]), 0)
                .await
                .unwrap(),
            PutAttrOutcome::Tombstoned,
            "Tombstoned 用户拒写(不复活)"
        );
    }

    #[tokio::test]
    async fn users_store_attributes_are_tenant_scoped() {
        use crate::ports::{PutAttrOutcome, UsersStore};
        use std::collections::BTreeMap;

        let store = MemoryUsersStore::default();
        let user_id = "user:shared";
        let namespace = "https://resource.example.com/";
        store
            .create_or_get_by_id("tenant-a", user_id, 1)
            .await
            .unwrap();
        store
            .create_or_get_by_id("tenant-b", user_id, 1)
            .await
            .unwrap();

        assert_eq!(
            store
                .put_attributes(
                    "tenant-a",
                    user_id,
                    namespace,
                    BTreeMap::from([("role".to_string(), "admin".to_string())]),
                    0,
                )
                .await
                .unwrap(),
            PutAttrOutcome::Ok { revision: 1 }
        );
        assert_eq!(
            store
                .put_attributes(
                    "tenant-b",
                    user_id,
                    namespace,
                    BTreeMap::from([("role".to_string(), "viewer".to_string())]),
                    0,
                )
                .await
                .unwrap(),
            PutAttrOutcome::Ok { revision: 1 }
        );

        let tenant_a = store.get_by_id("tenant-a", user_id).await.unwrap().unwrap();
        let tenant_b = store.get_by_id("tenant-b", user_id).await.unwrap().unwrap();
        assert_eq!(tenant_a.attributes[namespace].kv["role"], "admin");
        assert_eq!(tenant_b.attributes[namespace].kv["role"], "viewer");
    }

    #[tokio::test]
    async fn admin_attribute_write_preserves_federation_owned_keys() {
        use crate::ports::{FederatedAttributeOwner, NamespaceAttrs, PutAttrOutcome, UsersStore};
        use std::collections::BTreeMap;

        let store = MemoryUsersStore::default();
        let user_id = "user:federated";
        let namespace = "https://resource.example.com";
        store.create_or_get_by_id("", user_id, 1).await.unwrap();
        {
            let mut users = store.by_id.lock().await;
            let user = users
                .get_mut(&(String::new(), user_id.to_string()))
                .unwrap();
            user.attributes.insert(
                namespace.to_string(),
                NamespaceAttrs {
                    revision: 1,
                    kv: BTreeMap::from([
                        ("note".to_string(), "local".to_string()),
                        ("role".to_string(), "admin".to_string()),
                    ]),
                    federation_owners: BTreeMap::from([(
                        "role".to_string(),
                        FederatedAttributeOwner {
                            upstream_idp_id: "corp".to_string(),
                            upstream_issuer: "https://idp.example.com".to_string(),
                            mapping_id: "fm_role".to_string(),
                            mapping_revision: 4,
                        },
                    )]),
                },
            );
            user.attributes_generation = 1;
        }

        let changed_owned = store
            .put_attributes(
                "",
                user_id,
                namespace,
                BTreeMap::from([
                    ("note".to_string(), "local".to_string()),
                    ("role".to_string(), "viewer".to_string()),
                ]),
                1,
            )
            .await
            .unwrap();
        assert_eq!(changed_owned, PutAttrOutcome::OwnershipConflict);

        let deleted_owned = store
            .put_attributes(
                "",
                user_id,
                namespace,
                BTreeMap::from([("note".to_string(), "local".to_string())]),
                1,
            )
            .await
            .unwrap();
        assert_eq!(deleted_owned, PutAttrOutcome::OwnershipConflict);

        let updated_admin = store
            .put_attributes(
                "",
                user_id,
                namespace,
                BTreeMap::from([
                    ("note".to_string(), "updated".to_string()),
                    ("role".to_string(), "admin".to_string()),
                ]),
                1,
            )
            .await
            .unwrap();
        assert_eq!(updated_admin, PutAttrOutcome::Ok { revision: 2 });

        let user = store.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(user.attributes_generation, 2);
        assert_eq!(user.attributes[namespace].kv["note"], "updated");
        assert_eq!(
            user.attributes[namespace].federation_owners["role"].mapping_revision,
            4
        );
    }

    // spec 007 §6.1:单用户全部 namespace 序列化 > 4096B → TooLarge(不部分写)。
    #[tokio::test]
    async fn users_store_put_attributes_too_large() {
        use crate::ports::{PutAttrOutcome, UsersStore};
        use std::collections::BTreeMap;
        let store = MemoryUsersStore::default();
        store
            .create_or_get_by_email("", "b@ex.com", "user:b@ex.com", 1)
            .await
            .unwrap();
        // 一个 5KB 的 value → 超 4096B 上限。
        let big: BTreeMap<String, String> = [("blob".to_string(), "x".repeat(5000))]
            .into_iter()
            .collect();
        let r = store
            .put_attributes("", "user:b@ex.com", "https://rs.example.com/", big, 0)
            .await
            .unwrap();
        assert_eq!(r, PutAttrOutcome::TooLarge);
        // 未部分写:属性仍空。
        let rec = store.get_by_id("", "user:b@ex.com").await.unwrap().unwrap();
        assert_eq!(
            rec.attributes_generation, 0,
            "oversized rejection must not advance the cross-namespace generation"
        );
        assert!(rec.attributes.is_empty(), "超限拒后不留部分写");
    }

    #[tokio::test]
    async fn users_store_migrates_attribute_namespaces_atomically() {
        use crate::ports::{AttributeMigrationOutcome, UsersStore};
        use std::collections::{BTreeMap, BTreeSet};

        let store = MemoryUsersStore::default();
        let user_id = "user:migrate@example.com";
        let canonical = "https://resources.example.com/finance";
        let alias = "https://finance.example.com";
        let other_alias = "https://finance-dr.example.com";
        let values = BTreeMap::from([("role".to_string(), "admin".to_string())]);
        store
            .create_or_get_by_email("", "migrate@example.com", user_id, 1)
            .await
            .unwrap();
        store
            .put_attributes("", user_id, alias, values.clone(), 0)
            .await
            .unwrap();
        store
            .put_attributes("", user_id, other_alias, values.clone(), 0)
            .await
            .unwrap();

        let migrated = store
            .migrate_attributes(
                "",
                user_id,
                canonical,
                &BTreeSet::from([alias.to_string(), other_alias.to_string()]),
            )
            .await
            .unwrap();
        assert_eq!(
            migrated,
            AttributeMigrationOutcome::Migrated { generation: 3 }
        );
        let record = store.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(record.attributes_generation, 3);
        assert_eq!(record.attributes.len(), 1);
        assert_eq!(record.attributes[canonical].kv, values);

        let conflicting_alias = "https://finance-legacy.example.com";
        store
            .put_attributes(
                "",
                user_id,
                conflicting_alias,
                BTreeMap::from([("role".to_string(), "viewer".to_string())]),
                0,
            )
            .await
            .unwrap();
        let before = store.get_by_id("", user_id).await.unwrap().unwrap();
        let conflict = store
            .migrate_attributes(
                "",
                user_id,
                canonical,
                &BTreeSet::from([conflicting_alias.to_string()]),
            )
            .await
            .unwrap();
        assert!(matches!(
            conflict,
            AttributeMigrationOutcome::Conflict { .. }
        ));
        assert_eq!(
            store.get_by_id("", user_id).await.unwrap().unwrap(),
            before,
            "conflict must not mutate attributes or generation"
        );
    }

    // spec 003 §4 Task 4.6:secret 解析器——命中预置引用名返明文;未知引用名 → None(误配拒,非 panic)。
    #[tokio::test]
    async fn secret_resolver_hit_and_miss() {
        use crate::ports::SecretResolver;
        let r = MemorySecretResolver::default();
        r.seed("secretsmanager:fed/okta", "PLACEHOLDER-resolved-secret")
            .await;
        assert_eq!(
            r.resolve("secretsmanager:fed/okta").await.unwrap(),
            Some("PLACEHOLDER-resolved-secret".to_string())
        );
        assert_eq!(
            r.resolve("secretsmanager:does-not-exist").await.unwrap(),
            None,
            "未知引用名 → None(误配拒,不 panic/不返空串)"
        );
    }

    // spec 003 §4 Task 4.6:上游 token 交换器——命中预置 code 返 token set;未知 code → None(模拟上游拒)。
    #[tokio::test]
    async fn upstream_token_exchanger_hit_and_miss() {
        use crate::ports::{
            UpstreamTokenExchangeRequest, UpstreamTokenExchanger, UpstreamTokenSet,
        };
        let x = MemoryUpstreamTokenExchanger::default();
        x.seed(
            "auth-code-abc",
            UpstreamTokenSet {
                id_token: "eyJ...upstream-id-token".to_string(),
                access_token: None,
            },
        )
        .await;
        let req = |code: &'static str| UpstreamTokenExchangeRequest {
            token_endpoint: "https://idp.example.com/token",
            client_id: "as-rp",
            client_secret: "resolved-secret",
            code,
            code_verifier: "verifier",
            redirect_uri: "https://as.example.com/federation/callback",
        };
        let hit = x.exchange_code(&req("auth-code-abc")).await.unwrap();
        assert_eq!(hit.unwrap().id_token, "eyJ...upstream-id-token");
        assert_eq!(
            x.exchange_code(&req("unknown-code")).await.unwrap(),
            None,
            "未知 code → None(模拟上游 4xx 拒,登录失败非重试)"
        );
        for index in 0..65 {
            let code = format!("bounded-code-{index}");
            x.exchange_code(&UpstreamTokenExchangeRequest {
                token_endpoint: "https://idp.example.com/token",
                client_id: "as-rp",
                client_secret: "resolved-secret",
                code: &code,
                code_verifier: "verifier",
                redirect_uri: "https://as.example.com/federation/callback",
            })
            .await
            .unwrap();
        }
        let requests = x.requests().await;
        assert_eq!(
            requests.len(),
            MemoryUpstreamTokenExchanger::MAX_RECORDED_REQUESTS
        );
        assert_eq!(
            requests.first().unwrap().code_sha256,
            agent_auth_client::s256_challenge("bounded-code-1")
        );
        assert_eq!(
            requests.last().unwrap().code_sha256,
            agent_auth_client::s256_challenge("bounded-code-64")
        );
        assert_eq!(
            requests.last().unwrap().code_challenge,
            agent_auth_client::s256_challenge("verifier")
        );
        let observation = format!("{requests:?}");
        for secret in ["bounded-code-64", "verifier", "resolved-secret"] {
            assert!(!observation.contains(secret));
        }
    }

    // spec 003 §4 Task 4.7:flow 状态一次性消费——put→consume 返状态(含下游续跑上下文);
    // 二次 consume → None(防 state 重放);过期 → None(fail-closed)。
    #[tokio::test]
    async fn federation_flow_store_consume_is_one_shot_and_expiry() {
        use crate::ports::{FederationFlowState, FederationFlowStore};
        let store = MemoryFederationFlowStore::default();
        let now = crate::token::current_unix_secs_pub();
        let mk = |state: &str, exp: i64| FederationFlowState {
            state: state.into(),
            nonce: "n-xyz".into(),
            code_verifier: "cv".into(),
            tenant_id: "t1".into(),
            upstream_idp_id: "okta".into(),
            original_authz_request: "client_id=app&redirect_uri=https://app/cb&state=dstate".into(),
            required_max_age_secs: None,
            expires_at: exp,
        };
        store.put(mk("st-1", now + 600)).await.unwrap();

        // 首次 consume:命中 + 带下游续跑上下文(F1)。
        let got = store.consume("st-1").await.unwrap().expect("命中");
        assert_eq!(got.nonce, "n-xyz");
        assert!(
            got.original_authz_request.contains("client_id=app"),
            "MUST 带原下游 authorize 上下文(F1 续跑)"
        );
        // 二次 consume:已删 → None(一次性,防 state 重放)。
        assert_eq!(
            store.consume("st-1").await.unwrap(),
            None,
            "二次消费 → None(state 一次性,防重放)"
        );

        // 过期项:consume → None(fail-closed)。
        store.put(mk("st-exp", now - 1)).await.unwrap();
        assert_eq!(
            store.consume("st-exp").await.unwrap(),
            None,
            "过期 flow → None(fail-closed)"
        );
    }

    // spec 003 §3 Task 3.7:passkey challenge 一次性消费 + 过期 fail-closed。
    #[tokio::test]
    async fn passkey_challenge_consume_one_shot_and_expiry() {
        use crate::ports::{PasskeyCeremony, PasskeyChallenge, PasskeyChallengeStore};
        let store = MemoryPasskeyChallengeStore::default();
        let now = crate::token::current_unix_secs_pub();
        store
            .put(PasskeyChallenge {
                challenge_b64url: "ch1".into(),
                tenant: "t1".into(),
                user_id: Some("u1".into()),
                ceremony: PasskeyCeremony::Registration,
                rp_id: "t1.example.com".into(),
                origin: "https://t1.example.com".into(),
                expires_at: now + 300,
            })
            .await
            .unwrap();
        // 首次 consume 命中 + 带 user_id 绑定(注册档)。
        assert_eq!(store.consume("t2", "ch1").await.unwrap(), None);
        let got = store.consume("t1", "ch1").await.unwrap().expect("命中");
        assert_eq!(got.tenant, "t1");
        assert_eq!(got.user_id.as_deref(), Some("u1"));
        assert_eq!(got.ceremony, PasskeyCeremony::Registration);
        assert_eq!(got.rp_id, "t1.example.com");
        assert_eq!(got.origin, "https://t1.example.com");
        // 二次 consume → None(一次性,防重放)。
        assert_eq!(store.consume("t1", "ch1").await.unwrap(), None);
        // 过期 → None(fail-closed)。
        store
            .put(PasskeyChallenge {
                challenge_b64url: "ch-exp".into(),
                tenant: "t1".into(),
                user_id: None,
                ceremony: PasskeyCeremony::Authentication,
                rp_id: "t1.example.com".into(),
                origin: "https://t1.example.com".into(),
                expires_at: now - 1,
            })
            .await
            .unwrap();
        assert_eq!(store.consume("t1", "ch-exp").await.unwrap(), None);

        for tenant in ["t1", "t2"] {
            store
                .put(PasskeyChallenge {
                    challenge_b64url: format!("{tenant}-governance"),
                    tenant: tenant.into(),
                    user_id: Some("shared-user-id".into()),
                    ceremony: PasskeyCeremony::Registration,
                    rp_id: format!("{tenant}.example.com"),
                    origin: format!("https://{tenant}.example.com"),
                    expires_at: now + 300,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            store.delete_by_user("t1", "shared-user-id").await.unwrap(),
            1
        );
        assert!(store
            .consume("t2", "t2-governance")
            .await
            .unwrap()
            .is_some());
    }

    // spec 003 §3 Task 3.7:凭证 credentialId 唯一(put_new 拒覆盖)+ signCount CAS(防克隆)。
    #[tokio::test]
    async fn passkey_store_unique_and_signcount_cas() {
        use crate::ports::PasskeyStore;
        let store = MemoryPasskeyStore::default();
        let cred = |id: &str, uid: &str, count: u32| agent_auth_authn::passkey::PasskeyCredential {
            credential_id: id.into(),
            user_id: uid.into(),
            rp_id: "t1.saas.example.com".into(),
            public_key_sec1: vec![0x04; 65],
            sign_count: count,
            name: "Passkey".into(),
            created_at: 0,
        };
        // 首次写成功。
        assert!(store.put_new("", cred("c1", "u1", 0)).await.unwrap());
        // 同 credentialId 再写 → false(拒覆盖,防伪造/碰撞,评审 Kiro)。
        assert!(!store.put_new("", cred("c1", "attacker", 0)).await.unwrap());
        // 原记录未被覆盖(user 仍 u1)。
        assert_eq!(store.get("", "c1").await.unwrap().unwrap().user_id, "u1");
        // list_by_user。
        store.put_new("", cred("c2", "u1", 0)).await.unwrap();
        assert_eq!(store.list_by_user("", "u1").await.unwrap().len(), 2);
        assert_eq!(store.list_by_user("", "other").await.unwrap().len(), 0);
        // signCount CAS:expected_prev 匹配 → 写成功。
        assert!(store.update_sign_count("", "c1", 5, 0).await.unwrap());
        assert_eq!(store.get("", "c1").await.unwrap().unwrap().sign_count, 5);
        // expected_prev 不匹配(仍传 0,但已是 5)→ false(竞态/回退拒,防克隆)。
        assert!(!store.update_sign_count("", "c1", 9, 0).await.unwrap());
        assert_eq!(
            store.get("", "c1").await.unwrap().unwrap().sign_count,
            5,
            "CAS 失败不改"
        );

        let (renamed, counted) = tokio::join!(
            store.rename_owned("", "u1", "c2", "Security key"),
            store.update_sign_count("", "c2", 7, 0),
        );
        assert!(renamed.unwrap());
        assert!(counted.unwrap());
        let concurrent = store.get("", "c2").await.unwrap().unwrap();
        assert_eq!(concurrent.name, "Security key");
        assert_eq!(concurrent.sign_count, 7);
    }

    // spec 005 §9.2:touch_last_used 天级条件写——同日仅写一次、跨日推进。
    #[tokio::test]
    async fn client_touch_last_used_daily_conditional() {
        let store = MemoryClientStore::default();
        let mut c = ClientRecord {
            client_id: "cid".into(),
            ..Default::default()
        };
        c.created_at = 100;
        store.put("t1", c.clone()).await.unwrap();
        store.put("t2", c).await.unwrap();
        // 首次 touch(day=20000)→ 写。
        store.touch_last_used("t1", "cid", 20000).await.unwrap();
        assert_eq!(
            store.get("t1", "cid").await.unwrap().unwrap().last_used_day,
            Some(20000)
        );
        assert_eq!(
            store.get("t2", "cid").await.unwrap().unwrap().last_used_day,
            None,
            "同 client_id 的活动更新必须 tenant-scoped"
        );
        // 同日再 touch → 不变(条件 last_used_day < today 不满足)。
        store.touch_last_used("t1", "cid", 20000).await.unwrap();
        assert_eq!(
            store.get("t1", "cid").await.unwrap().unwrap().last_used_day,
            Some(20000)
        );
        // 次日 touch → 推进。
        store.touch_last_used("t1", "cid", 20001).await.unwrap();
        assert_eq!(
            store.get("t1", "cid").await.unwrap().unwrap().last_used_day,
            Some(20001)
        );
        // 不存在的 client → no-op(不 panic、不建)。
        store.touch_last_used("t1", "ghost", 20001).await.unwrap();
        assert!(store.get("t1", "ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replacing_one_credential_kind_preserves_the_other_legacy_fallback() {
        let store = MemoryClientStore::default();
        store
            .put(
                "t1",
                ClientRecord {
                    client_id: "cid".into(),
                    client_secret: Some("legacy-secret".into()),
                    reg_token_hash: Some("legacy-registration-hash".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(store
            .replace_credential_set(
                "t1",
                "cid",
                crate::credential::CredentialKind::ClientSecret,
                0,
                crate::credential::CredentialSet {
                    version: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap());
        let after_secret = store.get("t1", "cid").await.unwrap().unwrap();
        assert!(after_secret.client_secret.is_none());
        assert_eq!(
            after_secret.reg_token_hash.as_deref(),
            Some("legacy-registration-hash")
        );

        assert!(store
            .replace_credential_set(
                "t1",
                "cid",
                crate::credential::CredentialKind::RegistrationAccessToken,
                0,
                crate::credential::CredentialSet {
                    version: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap());
        let after_registration = store.get("t1", "cid").await.unwrap().unwrap();
        assert!(after_registration.reg_token_hash.is_none());
        assert_eq!(after_registration.client_secret_credentials.version, 1);
    }

    #[tokio::test]
    async fn client_metadata_writes_cannot_replace_a_tombstone() {
        let store = MemoryClientStore::default();
        let client = ClientRecord {
            client_id: "cid".into(),
            tombstoned_at: Some(5_000),
            ..Default::default()
        };
        store.put("t1", client.clone()).await.unwrap();

        assert!(!store
            .put_if_credential_versions(
                "t1",
                ClientRecord {
                    tombstoned_at: None,
                    ..client
                },
                0,
                0
            )
            .await
            .unwrap());
        assert!(!store
            .replace_credential_set(
                "t1",
                "cid",
                crate::credential::CredentialKind::ClientSecret,
                0,
                crate::credential::CredentialSet {
                    version: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap());
        assert_eq!(
            store.get("t1", "cid").await.unwrap().unwrap().tombstoned_at,
            Some(5_000)
        );

        let active = ClientRecord {
            client_id: "active".into(),
            authority_revision: 1,
            ..Default::default()
        };
        store.put("t1", active.clone()).await.unwrap();
        assert!(!store
            .put_if_credential_versions(
                "t1",
                ClientRecord {
                    authority_revision: 0,
                    ..active
                },
                0,
                0,
            )
            .await
            .unwrap());
        assert_eq!(
            store
                .get("t1", "active")
                .await
                .unwrap()
                .unwrap()
                .authority_revision,
            1
        );
    }

    #[tokio::test]
    async fn grant_creation_cannot_cross_a_client_tombstone() {
        let clients = MemoryClientStore::default();
        clients
            .put(
                "t1",
                ClientRecord {
                    client_id: "cid".into(),
                    tombstoned_at: Some(5_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let grants = MemoryGrantStore::default();
        let stored = grants
            .put_for_active_client(
                &clients,
                "t1",
                agent_auth_grant::Grant {
                    grant_id: "g1".into(),
                    user_id: "u1".into(),
                    client_id: "cid".into(),
                    per_resource: vec![],
                    effective_per_resource: vec![],
                    effective_pv: 0,
                    allowed_ip_cidrs: vec![],
                    allowed_vpce: vec![],
                    credential_epoch: 0,
                    revision: 0,
                    constraints: agent_auth_grant::GrantConstraints {
                        max_act_chain: 1,
                        actor_allowlist: vec![],
                        expires_at: 9_999_999_999,
                    },
                    status: agent_auth_grant::GrantStatus::Active,
                },
            )
            .await
            .unwrap();
        assert!(!stored);
        assert!(crate::ports::GrantStore::get(&grants, "t1", "g1")
            .await
            .unwrap()
            .is_none());
    }

    // spec 005 §9.5:convert_to_tombstone 并发守卫——快照后被并发 touch 推进则跳过(fail-safe 不误回收)。
    #[tokio::test]
    async fn client_convert_to_tombstone_concurrency_guard() {
        let store = MemoryClientStore::default();
        let c = ClientRecord {
            client_id: "cid".into(),
            last_used_day: Some(19000), // 扫描读到的快照日
            ..Default::default()
        };
        store.put("", c).await.unwrap();
        // 快照日 = 19000,期间无并发使用 → tombstone 成功。
        assert!(store
            .convert_to_tombstone("", "cid", 5000, Some(19000), 0)
            .await
            .unwrap());
        assert_eq!(
            store.get("", "cid").await.unwrap().unwrap().tombstoned_at,
            Some(5000)
        );
        // 已 tombstone → 再转跳过(幂等,不重复)。
        assert!(!store
            .convert_to_tombstone("", "cid", 6000, Some(19000), 0)
            .await
            .unwrap());
        assert_eq!(
            store.get("", "cid").await.unwrap().unwrap().tombstoned_at,
            Some(5000)
        );

        // 竞态:另一 client 快照日 19000,但期间被 touch 推进到 19001 → 条件失败跳过。
        let c2 = ClientRecord {
            client_id: "cid2".into(),
            last_used_day: Some(19001), // 已被并发 touch 推进(> 快照)
            ..Default::default()
        };
        store.put("", c2).await.unwrap();
        assert!(
            !store
                .convert_to_tombstone("", "cid2", 5000, Some(19000), 0)
                .await
                .unwrap(),
            "last_used_day 已越快照 → 跳过(方向安全,不误回收刚用过的 client)"
        );
        assert!(store
            .get("", "cid2")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none());

        // 同日 authority 创建不会推进 last_used_day，但会递增 revision；旧快照必须失败。
        let c3 = ClientRecord {
            client_id: "cid3".into(),
            last_used_day: Some(19000),
            authority_revision: 1,
            ..Default::default()
        };
        store.put("", c3).await.unwrap();
        assert!(!store
            .convert_to_tombstone("", "cid3", 5000, Some(19000), 0)
            .await
            .unwrap());
    }

    // spec 005 §9.4:回收信号只读端口——refresh 未吊销 family / 未过期 code 命中(不 mutate)。
    #[tokio::test]
    async fn reclaim_signal_readonly_ports() {
        use crate::ports::{CodeStore, RefreshStore};
        // refresh:未吊销 family → true;吊销后 → false;只读不改状态。
        let rs = MemoryRefreshStore::default();
        rs.create(
            "",
            RefreshFamilyRecord {
                family_id: "f1".into(),
                current_version: 0,
                revoked: false,
                client_id: "cid".into(),
                cimd_snapshot: None,
                user_id: "u1".into(),
                credential_epoch: 0,
                resources: vec![],
                scope: vec![],
                actor_allowlist: vec![],
                max_act_chain: 1,
                dpop_jkt: None,
                pkce_code_challenge: None,
                auth_time: None,
                acr: None,
                password_credential_version: None,
            },
        )
        .await
        .unwrap();
        assert!(rs.has_active_family_by_client("", "cid").await.unwrap());
        assert!(!rs.has_active_family_by_client("", "other").await.unwrap());
        // 只读:调用后 family 仍未吊销(区别于 revoke_by_client)。
        assert!(
            !rs.get("", "f1").await.unwrap().unwrap().revoked,
            "signal 只读,不 mutate"
        );
        rs.revoke("", "f1").await.unwrap();
        assert!(
            !rs.has_active_family_by_client("", "cid").await.unwrap(),
            "吊销后无 active family"
        );

        // code:未过期未消费 → true;过期 → false。
        let cs = MemoryCodeStore::default();
        let mk = |code: &str, exp: i64| CodeRecord {
            code: code.into(),
            client_id: "cid".into(),
            cimd_snapshot: None,
            redirect_uri: "https://x".into(),
            code_challenge: "c".into(),
            resources: vec![],
            user_id: "u1".into(),
            scope: vec![],
            expires_at: exp,
            authz_session_id: None,
            nonce: None,
            auth_time: 0,
            authorization_details: vec![],
            acr: None,
            amr: vec![],
            credential_epoch: Some(0),
            password_credential_version: None,
        };
        cs.put("", mk("code-valid", 2000)).await.unwrap();
        assert!(
            cs.has_unexpired_by_client("", "cid", 1000).await.unwrap(),
            "未过期 code → true"
        );
        assert!(
            !cs.has_unexpired_by_client("", "cid", 3000).await.unwrap(),
            "now 越 expires → false"
        );
        assert!(!cs.has_unexpired_by_client("", "other", 1000).await.unwrap());
    }
}
