//! 六边形架构**端口**(trait):handler 依赖抽象、不直接依赖 AWS SDK。
//!
//! - 本地/测试 → 内存适配器(`adapters::memory`,同步、可确定性单测、无 AWS)。
//! - 真机 → AWS 适配器(`adapters::aws`,KMS 签名 + DynamoDB 状态,`aws` feature 门控)。
//!
//! 协议决策不在此;端口只定义"签名/存储需要什么能力"。签发热路径的两阶段 lease、复用检测等
//! 语义仍由纯逻辑 crate(infra-core/token)承载,适配器只负责 IO(KMS Sign / DynamoDB 条件写)。

use agent_auth_infra_core::EcJwk;
use serde::{Deserialize, Serialize};
use std::future::Future;
use utoipa::ToSchema;

/// 客户端形态枚举(spec 012;从 workload crate 再导出,供 handler/测试用)。
pub use agent_auth_workload::ClientType;

/// 签名端口:ES256 签名(access token)+ 发布公钥 JWK(`/jwks.json`)。
/// 真机 = KMS Sign(DER)+ der_to_jose;本地 = 进程内 P-256 key。
pub trait Signer: Send + Sync {
    /// 对 JWS signing input(`header.payload`)签名,返回 **JOSE 裸 r‖s**(已 DER→JOSE)。
    fn sign_es256(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, SignerError>> + Send;

    /// 当前发布的 EC 公钥集合(双活重叠期可含多把),供 access token 验签 + `/jwks.json`。
    fn public_jwks(&self) -> impl Future<Output = Result<Vec<EcJwk>, SignerError>> + Send;

    /// 当前 EC 签名 key 的 `kid`(= 其 JWK thumbprint),写进 access token JWT header。
    fn active_kid(&self) -> impl Future<Output = Result<String, SignerError>> + Send;

    /// RS256 签名(id_token,spec 001 C2.7 默认 alg)。返回 (kid, 裸 RSA 签名字节)——
    /// RSA 的 KMS 签名 blob 即 JWS 所需签名(不做 EC 的 DER→JOSE 转换,codex 评审确认)。
    /// 返回 `Permanent` 表示本部署未配 RSA 签名 key(降级:无法签 RS256 id_token)。
    fn sign_rs256(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<(String, Vec<u8>), SignerError>> + Send;

    /// 当前发布的 RSA 公钥集合(供 id_token 验签 + `/jwks.json`;无 RSA key 时空;轮换重叠期可多把)。
    fn public_rsa_jwks(
        &self,
    ) -> impl Future<Output = Result<Vec<agent_auth_infra_core::RsaJwk>, SignerError>> + Send;

    /// 当前**活跃** RSA 签名 key 的 `kid`(= 其 JWK thumbprint),写进 id_token JWT header。
    /// **MUST 与 `sign_rs256` 实际用的 key 一致**(轮换重叠期 published 多把时,绝不能用 `public_rsa_jwks().first()`
    /// ——那可能是 retiring 旧 key 或 publish-ahead 新 key,与活跃签名 key 不符 → header.kid 与签名 key 错配、
    /// id_token 验签失败,spec 005 §8 评审 Blocker)。返回 `Permanent` 表示本部署未配 RSA 签名 key。
    fn active_rsa_kid(&self) -> impl Future<Output = Result<String, SignerError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// 瞬时失败(KMS throttle / server_error)——上层按 C10.2 返 503、释放 lease。
    Transient(String),
    /// 永久失败(key 不存在 / 配置错)。
    Permanent(String),
}

/// `/authorize` 阶段落地的授权码记录(`/token` 兑换时读取并消费)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRecord {
    pub code: String,
    pub client_id: String,
    /// CIMD clients bind their verified metadata into the code. Registered
    /// clients leave this empty and continue to resolve through ClientStore.
    pub cimd_snapshot: Option<crate::cimd::CimdClientSnapshot>,
    pub redirect_uri: String,
    /// PKCE:S256 challenge(兑换时用 code_verifier 校验)。
    pub code_challenge: String,
    /// `/authorize` 绑定的 resource 集合(token 收窄边界,C2.8/authorize↔token 绑定)。
    pub resources: Vec<String>,
    /// 授权主体(pairwise sub 派生前的内部 user_id)。
    pub user_id: String,
    pub scope: Vec<String>,
    /// 过期时刻(Unix 秒;短命项 fail-closed 校验,C10.4)。
    pub expires_at: i64,
    /// 关联的授权会话 id(spec 004):token 兑换成功/失败时据此迁移会话状态。可空(未接会话时)。
    pub authz_session_id: Option<String>,
    /// OIDC `nonce`(spec 001 C2.9):authorize 请求带则原样透传,签 id_token 时 echo。可空。
    pub nonce: Option<String>,
    /// 用户登录时刻(Unix 秒;spec 001 C2.7 id_token `auth_time`)。占位登录用受理时刻。
    pub auth_time: i64,
    /// RFC 9396 `authorization_details`(RAR;spec 010 §4 发行)。authorize 收 → 准入校验 → 存此
    /// → 建 Grant 时按 locations 归 per_resource → 签入 token。空 = 无 RAR(P0/P1 或未请求)。
    pub authorization_details: Vec<serde_json::Value>,
    /// Canonical authentication assurance `acr`; consent copies it from the session.
    pub acr: Option<String>,
    /// 认证方法 `amr`(C9.5b:联邦透传;consent 取自会话)。空 = 无。
    pub amr: Vec<String>,
    /// User authentication authority captured when the code was issued.
    /// Legacy records without a snapshot fail closed at exchange.
    pub credential_epoch: Option<u64>,
    /// 本地密码 authority 快照。`Some(0)` 表示发码时尚无密码凭证,
    /// `Some(n)` 表示凭证版本 n；`None` 表示非本地用户或旧记录。
    pub password_credential_version: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeIssueOutcome {
    Stored,
    AuthorityChanged,
    CodeExists,
}

/// 授权码存储端口。真机 = DynamoDB(条件写保证一次性消费);本地 = 内存。
/// PAR 推送授权请求记录(spec 006 §7.3,RFC 9126;pk=request_uri)。存**已剔除认证参数**的授权参数串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParRecord {
    /// `urn:ietf:params:oauth:request_uri:<opaque>`(opaque=CSPRNG ≥128bit)。
    pub request_uri: String,
    /// 提交该 PAR 的 client_id(authorize 引用时权威源;绑定,忽略请求里的 client_id)。
    pub client_id: String,
    /// 授权参数串(form-encoded,**已剔除 client_secret/client_assertion* 认证参数**,H3 防明文落库)。
    pub raw_params: String,
    /// 过期时刻(Unix 秒;短命 ≤90s;consume MUST fail-closed 校 `expires_at > now`,C10.4)。
    pub expires_at: i64,
}

/// PAR 存储端口(spec 006 §7.3)。真机 = DynamoDB(pk=request_uri,TTL 只做 GC,一次性走条件删);本地 = 内存。
pub trait ParStore: Send + Sync {
    /// 落地一条 PAR 记录(POST /par)。
    fn put(
        &self,
        tenant: &str,
        record: ParRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **一次性 consume**(authorize 引用 request_uri 时):取出即删(防重放);**fail-closed 校 expires_at**
    /// (过期返 None,不靠 TTL 惰性删,C10.4/H4)。不存在/已用/过期 → None。
    fn consume(
        &self,
        tenant: &str,
        request_uri: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<ParRecord>, StoreError>> + Send;

    /// Governance-only physical cleanup of pending pushed requests.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键前缀 + by-client 隔离,codex B1)。
pub trait CodeStore: Send + Sync {
    /// 落地一条授权码(authorize 阶段)。
    fn put(
        &self,
        tenant: &str,
        record: CodeRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **两阶段 lease 的第①步**(C10.1):原子占 `signing` lease 并取出记录。
    /// 并发只有一个能占到 lease(条件写),其余得 `Locked`(处理中,非消费);
    /// 已 finalize → `AlreadyConsumed`(重放拒);不存在 → `NotFound`。
    /// 占到 lease 后**尚未消费 code**——校验 + KMS 签名后再 `finalize`;签名前失败则 `release`。
    /// `lease_owner` 是本次请求的高熵 fencing token；到期重占后旧 owner 不得 finalize/释放新 lease。
    /// `lease_expires_at` 是该 lease 的到期时刻(到期后可被重新占用重试)。
    fn acquire_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> impl Future<Output = Result<LeaseAcquire, StoreError>> + Send;

    /// **第③步**:标记 code 已消费(finalize),并在成功签发路径绑定本次创建的 Grant/family id。
    /// 此后 `acquire_lease` 返回 `AlreadyConsumed` 及该绑定,供已认证的重放请求吊销首次签发结果。
    /// 仅当前 lease owner 可 finalize；语义失败在 Grant 创建前消费 code 时传 `None`。
    fn finalize(
        &self,
        tenant: &str,
        code: &str,
        client_id: &str,
        expires_at: i64,
        now: i64,
        lease_owner: &str,
        issued_grant_id: Option<&str>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 释放自己的 lease(签名前瞬时失败时,C10.1 ①):清 lease、**不消费**,允许安全重试同一 code。
    fn release_lease(
        &self,
        tenant: &str,
        code: &str,
        lease_owner: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 已认证的重复兑换请求持久标记 replay。必须与 `consumed` 及 `expires_at > now`
    /// 绑定,不得让未认证或已过期请求触发撤销。返回 false 表示记录已不再具备标记资格。
    fn record_replay(
        &self,
        tenant: &str,
        code: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 强一致读取 code 是否在 finalize 后被再次呈现。首次签发路径在返回 token 前检查此标记,
    /// 闭合 replay 与 Grant/family 创建并发时的撤销竞态。
    fn replay_detected(
        &self,
        tenant: &str,
        code: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// **只读**:该 client 是否有**任一未过期**(`expires_at > now`)授权码(spec 005 §9.4,C10.5 回收信号)。
    /// 真机 MUST 查询与 source 生命周期原子维护、可强一致读取的 client-reference 基表。
    /// coverage 未完成或读取失败必须返回 transient；最终一致 GSI 未命中不能证明不存在。
    /// tenant 从被回收记录派生(D3b)。
    fn has_unexpired_by_client(
        &self,
        tenant: &str,
        client_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Governance-only physical cleanup of every code still referencing one
    /// canonical user. TTL remains defense in depth, not completion evidence.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only fallback for codes whose canonical user is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// `acquire_lease` 的结果(两阶段 lease 第①步)。
// Acquired 变体携带完整 CodeRecord 是签发热路径的常态(占 lease 即拿记录去签),不 box——
// box 会在热路径多一次堆分配;其余变体是终态信号,大小差异可接受。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAcquire {
    /// 占到 lease,返回记录(可继续校验 + 签名)。
    Acquired(CodeRecord),
    /// 有未过期的 signing lease(别人正在签)→ 处理中,不重复签、不消费。
    Locked,
    /// code 不存在。
    NotFound,
    /// 已 finalize(消费过)→ 重放。回带原始 code 记录供 token 端点完成 client 绑定与认证；
    /// 认证成功后调用 `record_replay` 再吊销,防未认证请求利用 code 做撤销 DoS。
    AlreadyConsumed {
        record: CodeRecord,
        issued_grant_id: Option<String>,
    },
}

/// DCR 客户端记录(P0 子集:audience 相关 + 认证方式 + redirect)。
///
/// `Default` 派生:新增可选字段(如回收元数据 created_at/last_used_day/tombstoned_at,spec 005 §9)
/// 时,测试/构造点可 `..Default::default()` 收尾,减少 16 处构造的机械改动。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisteredClientJwk {
    /// RFC 7517 key identifier. Optional for general JWK metadata, but required
    /// and unique when the set authenticates `private_key_jwt`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisteredClientJwks {
    pub keys: Vec<RegisteredClientJwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientRecord {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    /// OIDC application type: `native` or `web`. Missing legacy values default
    /// to `web`; new DCR and management writes persist an explicit value.
    pub application_type: Option<String>,
    /// none(public+PKCE)/ client_secret_basic / client_secret_post / private_key_jwt(C4.2)。
    pub token_endpoint_auth_method: String,
    /// 仅用于读取并迁移历史明文记录。新写入 MUST 为 None；认证使用
    /// `client_secret_credentials` 中的带 pepper verifier。
    pub client_secret: Option<String>,
    /// Client secret current/next verifier 与生命周期元数据。
    pub client_secret_credentials: crate::credential::CredentialSet,
    /// RFC 7591 inline public JWKS。与 `jwks_uri` 互斥；用于 `private_key_jwt`
    /// 时两者须恰有一个，且 inline key 的 `kid` 须唯一非空。
    pub jwks: Option<RegisteredClientJwks>,
    /// RFC 7591 受保护远程 JWKS URI。与 `jwks` 互斥。
    pub jwks_uri: Option<String>,
    /// RFC 7591 每 client assertion 签名算法 pin；仅用于 `private_key_jwt`，
    /// 且仅接受 RS256/ES256。
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// 省略 resource 时的默认绑定(C2.8)。
    pub default_resource: Option<String>,
    /// **MCP RS 注册记录**(spec 010 C8.6):该 client 是否具 `/introspect` 权限。
    /// 普通机密 client 默认 false——不因复用 client-secret 认证就获得 introspect 权限。
    pub introspect_enabled: bool,
    /// 该 introspection client 绑定的 RS 资源标识集合(1 client ↔ N resource_id)。
    /// `/introspect` 的 aud 隔离:被查 token 的 `aud`(单元素)MUST ∈ 此集合(C8.6)。
    pub resource_ids: Vec<String>,
    /// RP-initiated logout 的 `post_logout_redirect_uri` 允许集合(spec 003 C9.6):
    /// `/end-session` 的回跳 MUST 按此**精确匹配**,未注册拒。**独立于 `redirect_uris`**。
    pub post_logout_redirect_uris: Vec<String>,
    /// 仅用于读取并迁移历史 registration token verifier。新写入 MUST 为 None。
    pub reg_token_hash: Option<String>,
    /// Registration access token current/next verifier 与生命周期元数据。
    pub registration_token_credentials: crate::credential::CredentialSet,
    /// 客户端形态(spec 012 H1):public/confidential/workload。**workload 仅管理面显式设**
    /// (不靠 auth_method 隐式判定);缺省(旧记录/DCR)按 auth_method 推 public/confidential。
    /// 存储时可缺(向后兼容):`client_type()` 缺省时按 auth_method 推,绝不推出 workload。
    pub client_type: Option<String>,
    /// id_token 签名算法(spec 001 C2.7;OIDC DCR `id_token_signed_response_alg`)。
    /// None = 默认 **RS256**(OIDC 动态注册未声明时的默认);仅接受 `RS256`/`ES256`(discovery 宣告集)。
    pub id_token_signed_response_alg: Option<String>,
    /// OIDC sector identifier(spec 001 C2.11 / §2.8):pairwise 下 id_token/userinfo 的 sector 键。
    /// 注册时从全部 redirect_uris 计算并持久化(全同 host→该 host;多 host 须 sector_identifier_uri)。
    /// None = 未算(public 形态不需要;pairwise 下注册时若算不出会拒注册)。
    pub oidc_sector_identifier: Option<String>,
    /// 2LO(client_credentials)可请求的 resource 白名单(spec 012 H2/C7.5:机器身份自主行动的边界
    /// 由 client 注册策略约束,**非 Grant**)。空 = 该 client 不能 2LO 换任何 resource(fail-closed)。
    /// 单值时可作省略 resource 的缺省。受信 operator 登记 workload 或 service 时设；
    /// 公开 DCR 与当前 Admin client 表单均保持为空。
    pub allowed_resources: Vec<String>,
    /// 2LO 可请求的 scope 白名单(spec 012 C7.5)。请求 scope MUST 是其子集；
    /// 空集 = 不授予任何 scope(fail-closed)。
    pub allowed_scopes: Vec<String>,
    /// redirect 匹配模式(spec 002 §5 / C4.4b/C4.6)。None/`"exact"` = 精确(默认,P0);`"loopback"` = RFC 8252
    /// IP 字面量;`"prefix"` = 受控前缀通配(**仅 confidential**,C4.6:public 配 prefix 在 authorize 拒)。
    /// 缺省(旧记录/未设)= exact(最严,fail-safe)。
    pub redirect_mode: Option<String>,
    // ── client 回收元数据(spec 005 §9,C10.5;均可缺=向后兼容旧记录)──
    /// 注册时刻(Unix 秒)。回收审计留存 + never-used 残渣边界判定用。0 = 旧记录未记(不参与判定)。
    pub created_at: i64,
    /// 最后使用日(`floor(now/86400)`,天级桶,spec 005 §9.2)。签发成功路径条件写(同日仅一次,防热路径写放大)。
    /// None = 从未使用(注册残渣;`decide_reclaim` 保守不由本流程回收)。
    pub last_used_day: Option<i64>,
    /// 注册 client 的活跃 Code/Refresh 创建版本。每次 authority 创建事务原子递增；
    /// reclaim 在强一致空读后用该快照做 tombstone CAS，阻止同日新 authority 被日粒度
    /// `last_used_day` 掩盖。旧记录缺失按 0。
    pub authority_revision: u64,
    /// tombstone 时刻(Unix 秒,spec 005 §9)。Some = 已转 tombstone(签发路径 fail-closed 拒 `invalid_client`;
    /// 硬删须延到 `now - tombstoned_at >= max_access_ttl`)。None = Normal。
    pub tombstoned_at: Option<i64>,
    // ── CIBA ping/push 投递模式(spec 013 §4,C7b.5,P3;均可缺=向后兼容旧记录/poll)──
    /// CIBA token 投递模式(OIDC CIBA Core §10.2 `backchannel_token_delivery_mode`):
    /// None/`"poll"` = poll(缺省,后向兼容);`"ping"`/`"push"` = 回调投递(**MUST confidential**,注册时校验)。
    pub backchannel_token_delivery_mode: Option<String>,
    /// CIBA ping/push 的回调通知端点(OIDC CIBA Core §10.2 `backchannel_client_notification_endpoint`)。
    /// ping/push 时 MUST 提供且过 SSRF 结构校验(https/端口/非字面私网,见 agent_auth_ciba::validate_endpoint_url);
    /// 投递前 MUST 再 DNS 复校 + 连接固定到已校验 IP(防 rebinding)。None = poll(无回调)。
    pub backchannel_client_notification_endpoint: Option<String>,
    /// **require DPoP**(spec 010 §5.2/C8.7b,RFC 9449;可缺=false 后向兼容)。true = `/token` MUST 带
    /// 合法 DPoP proof,缺 proof 拒 `invalid_dpop_proof`(防中间件丢头/漏配把期望 sender-constrained 的
    /// client 静默签成 bearer)。缺省 false(opt-in:有 proof 才绑,无 proof 仍发 bearer)。降级 true→false
    /// 算安全姿态弱化,走 C4.7 降级确认。
    pub require_dpop: bool,
    /// **BYOD 已登记域名**(spec 010 §5.4 / C8.1b;可缺=空=后向兼容旧记录)。仅供 admin 展示 +
    /// **删 client 时级联清 domain map 行**(否则悬空行会为已删 RS 继续返 PRM / 阻塞他人抢注)。
    /// ⚠️ **lookup 权威走 domain map 行,不走此 list**(评审 B1/B2:DynamoDB 不能索引 List 成员,
    /// GSI-on-list 不可行;此 list 只是 owner→domains 的反查便利,权威绑定恒在全局 domain map 表)。
    pub prm_domains: Vec<String>,
}

impl ClientRecord {
    /// Effective OIDC application type. Unknown persisted values fail closed
    /// to the stricter web redirect policy.
    pub fn application_type(&self) -> &str {
        match self.application_type.as_deref() {
            Some("native") => "native",
            _ => "web",
        }
    }

    /// 解析该 client 的形态(spec 012):显式 `client_type` 优先;缺省按 auth_method 推
    /// (public/confidential),**绝不隐式推出 workload**。未知 auth_method 缺省当 confidential(fail-safe:
    /// 至少要认证;识别 workload 只认显式标记)。
    pub fn client_type(&self) -> agent_auth_workload::ClientType {
        use agent_auth_workload::ClientType;
        if let Some(t) = self.client_type.as_deref().and_then(ClientType::parse) {
            return t;
        }
        ClientType::default_from_auth_method(&self.token_endpoint_auth_method)
            .unwrap_or(ClientType::Confidential)
    }

    /// 是否 workload(识别一律走此)。
    pub fn is_workload(&self) -> bool {
        self.client_type().is_workload()
    }

    /// Whether this record can participate in a flow that requires authenticated confidential
    /// client semantics. Persisted type and authentication method must agree; malformed legacy
    /// records such as `client_type=confidential` plus `token_endpoint_auth_method=none` fail closed.
    pub fn is_confidential_auth_client(&self) -> bool {
        self.client_type() == agent_auth_workload::ClientType::Confidential
            && self.token_endpoint_auth_method != "none"
    }

    /// 是否已转 tombstone(回收中,spec 005 §9.3 / C10.5)。签发/建授权路径 fail-closed 据此拒
    /// `invalid_client`——不签新 token / 不建新 code/session(离线已签发 token 仍可验,硬删延后)。
    pub fn is_tombstoned(&self) -> bool {
        self.tombstoned_at.is_some()
    }

    /// id_token 签名 alg(spec 001 C2.7):显式声明优先;缺省 **RS256**(OIDC DCR 默认)。
    pub fn id_token_alg(&self) -> &str {
        self.id_token_signed_response_alg
            .as_deref()
            .unwrap_or("RS256")
    }

    /// OIDC sector 键(spec 001 C2.11):持久化值优先;缺省从 redirect_uris 归一(全同 host→该 host)。
    /// 返回 None 表示多 host 且无 sector_identifier_uri(pairwise 下不可确定 sub → 上层拒)。
    pub fn oidc_sector(&self) -> Option<String> {
        if let Some(s) = &self.oidc_sector_identifier {
            return Some(s.clone());
        }
        agent_auth_token::oidc_sector_from_redirect_hosts(&self.redirect_uris)
    }
}

/// 客户端存储端口。真机 = DynamoDB;本地 = 内存。
///
/// **tenant 分区(spec 020 §2.3,C10.19)**:每个方法首参 `tenant`——物理分区键前缀,
/// 跨租户物理隔离。空 tenant(flag 关)= 透传无前缀 = 分区前字节等价。**GSI 键(client_id-index /
/// last_used_day-index)亦按 tenant 隔离**(评审:不止主 pk,二级路径同样会跨租户泄露)。
pub trait ClientStore: Send + Sync {
    fn get(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<ClientRecord>, StoreError>> + Send;

    fn put(
        &self,
        tenant: &str,
        record: ClientRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 整记录更新的凭据双版本 CAS。Admin/RFC 7592 元数据更新从读取快照构造新记录，
    /// 必须同时确认两类凭据均未被并发 rotate/cutover/revoke，避免陈旧记录覆盖 verifier。
    fn put_if_credential_versions(
        &self,
        tenant: &str,
        record: ClientRecord,
        expected_client_secret_version: u64,
        expected_registration_token_version: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 仅替换一种凭据集合，并以集合 version 做 CAS。避免并发轮换/cutover 覆盖 client
    /// 其它元数据或另一类凭据。条件不满足返回 Ok(false)。
    fn replace_credential_set(
        &self,
        tenant: &str,
        client_id: &str,
        kind: crate::credential::CredentialKind,
        expected_version: u64,
        credentials: crate::credential::CredentialSet,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 列出**某租户**所有 client(spec 025 admin 列表)。P1 全量、按 client_id 字典序稳定;
    /// 量大改分页/GSI(见 spec 020)。内存遍历 / DynamoDB 分页 Scan(按 tenant 前缀过滤)。
    fn list(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Vec<ClientRecord>, StoreError>> + Send;

    /// 删除 client(spec 025 DELETE)。不存在也返 Ok(幂等;上层据先前 get 判 404)。
    fn delete(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 记该 client 的最后使用日(spec 005 §9.2,C10.5;天级桶 `floor(now/86400)`)。
    /// **条件写**:仅当 `last_used_day` 缺失或 `< today` 才写(同日仅一次,防签发热路径写放大)。
    /// 调用方在**签发成功后**尽力而为调用;**瞬时失败可吞**(不拒签),但调用方 MUST 记失败指标
    /// (评审:陈旧 last_used → 更早误回收,方向不安全,须可告警)。已是今天 → Ok(无写)。
    fn touch_last_used(
        &self,
        tenant: &str,
        client_id: &str,
        today: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 转 tombstone(spec 005 §9.5,C10.5):**并发守卫条件写**——仅当未 tombstone 且
    /// `last_used_day <= snapshot_day` 且 `authority_revision == snapshot_authority_revision`
    /// (扫描读快照后无并发使用/authority 创建)才写 `tombstoned_at`。
    /// 条件不满足(已 tombstone / 已被并发 touch)→ Ok(false)(跳过,方向安全);写成功 → Ok(true)。
    fn convert_to_tombstone(
        &self,
        tenant: &str,
        client_id: &str,
        tombstoned_at: i64,
        snapshot_day: Option<i64>,
        snapshot_authority_revision: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 列出回收候选(spec 005 §9.5,C10.5):`last_used_day <= older_than_day` 的 client(含已 tombstone,
    /// 供判猶予期硬删)。真机走 GSI `last_used_day-index`(pk=tenant + sk=last_used_day,Query 范围;
    /// spec 020 §2.3 D4:tenant 前缀数值 pk 会破 `<=` 范围,故用 tenant 作 GSI pk、day 作 sk)。
    /// **空 tenant(flag 关 / D3b reclaim 全局维护作业)**= **跨租户全量**(GSI Scan);**非空** = 仅该租户(Query)。
    /// **返回 `(tenant, record)` 对**(评审 codex B2):reclaim 无请求 Host,后续 `convert_to_tombstone`/
    /// `hard_delete_with_audit` 须用**记录自身所属 tenant** 构造正确物理键(全局扫后不能用空 tenant 回写)。
    /// **不含从未使用(last_used_day=None)的 client**——注册残渣清理走 TTL 例外,非本扫描(DESIGN §8)。
    fn list_reclaim_candidates(
        &self,
        tenant: &str,
        older_than_day: i64,
    ) -> impl Future<Output = Result<Vec<(String, ClientRecord)>, StoreError>> + Send;

    /// 硬删 client + 独立留存审计元数据(spec 005 §9.5,C10.5)。**原子**(真机 TransactWriteItems:
    /// DeleteItem client + PutItem 审计);审计写失败则**不删**(返 Err,留 tombstone 下轮重试)。
    /// 仅应对已过猶予期的 tombstone client 调用(调用方据 `decide_reclaim`==HardDelete 判定)。
    /// tenant 从被回收记录派生(D3b:reclaim 无请求 Host,tenant 来自记录本身)。
    fn hard_delete_with_audit(
        &self,
        tenant: &str,
        record: &ClientRecord,
        hard_deleted_at: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Initial access token 独立存储端口。票据格式携带高熵 token_id，认证路径先按 id
/// 定位记录，再校验不可逆 verifier；表中从不保存可直接使用的 token。
pub trait InitialAccessTokenStore: Send + Sync {
    fn get(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> impl Future<Output = Result<Option<crate::credential::InitialAccessTokenRecord>, StoreError>>
           + Send;

    fn put_new(
        &self,
        tenant: &str,
        record: crate::credential::InitialAccessTokenRecord,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn list(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Vec<crate::credential::InitialAccessTokenRecord>, StoreError>> + Send;

    /// 显式吊销，按 version CAS；已吊销视为幂等成功。
    fn revoke(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        revoked_at: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 一次性票据在注册前原子标记 consumed；并发仅一个请求成功。
    fn consume_once(
        &self,
        tenant: &str,
        token_id: &str,
        expected_version: u64,
        used_at: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Governance-only physical deletion after tenant authority is frozen.
    fn delete(
        &self,
        tenant: &str,
        token_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// workload 信任绑定存储端口(spec 012 C5.5;管理面登记,MUST NOT 走 DCR)。
/// 真机 = DynamoDB;本地 = 内存。记录 = `agent_auth_workload::TrustBinding`(纯逻辑结构)。
///
/// **tenant 分区(spec 020 §2.3,评审 codex Low)**:`binding_id` 是 SPIFFE 派生哈希(trust_domain+
/// workload_id),**不是随机高熵**——不同租户可能登记同一 SPIFFE 身份 → 同 binding_id。故 put/delete
/// MUST 按 tenant tpk 键,否则租户 A 能覆盖/删除租户 B 的同 binding_id 绑定。空 tenant 透传单租户。
/// list_by_tenant 已按 `tenant_id` 属性过滤(认证路径本就 tenant-safe),此处补齐写路径隔离。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadTrustEntry {
    pub binding_id: String,
    pub binding: agent_auth_workload::TrustBinding,
}

pub trait WorkloadTrustStore: Send + Sync {
    /// 登记一条信任绑定(管理面 POST;`binding_id` = 幂等键;按 `tenant` tpk 隔离)。
    fn put(
        &self,
        tenant: &str,
        binding_id: String,
        binding: agent_auth_workload::TrustBinding,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 列出某租户名下所有信任绑定(认证时按 tenant 过滤匹配;管理面列表)。
    fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<WorkloadTrustEntry>, StoreError>> + Send;

    /// 删除一条信任绑定(管理面 DELETE;不存在也 Ok 幂等;按 `tenant` tpk 隔离)。
    fn delete(
        &self,
        tenant: &str,
        binding_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only physical cleanup of the tenant partition.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// BYOD 域名 → RS 绑定(spec 010 §5.4 / C8.1b)。RS 自带域名 CNAME 到本系统 CloudFront 托管其 PRM 数据面。
///
/// **全局键、非 tenant 分区(评审 B2 铁律)**:pk = 归一小写 domain(标量)——BYOD host 解不出 tenant
/// (`derive_issuer` 返 `NotATenantSubdomain`),查之前不知 tenant 就没法拼 tenant 前缀键;且 tenant 分区会
/// 让 t1/t2 各在自己分区登记同一域名 = 无冲突 = 可劫持。故全局键 + **注册时 conditional put
/// `attribute_not_exists`** 保 fleet 全局域名唯一(= 真正的反劫持:先到先得,不能抢他人已登记域名)。
///
/// **PRM 是 RFC 9728 公开元数据**——本绑定防的是**跨租户 issuer 误导**(登记不拥有的域名把其 PRM 的
/// authorization_servers 指向攻击者 issuer),非机密性。issuer 由查询方从存下的 `tenant_id` + 形态重建
/// (`issuer_for_tenant`),绝不从请求 Host 派生。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainBinding {
    /// 归一小写 BYOD 域名(pk)。
    pub domain: String,
    /// 该域名 PRM 的 `resource` 字段(RS 资源标识,完整 URL)。
    pub resource_id: String,
    /// 归属租户(登记时由 `tenant_id_from` 算出;PRM issuer 从它 + form 重建,不用请求 Host)。
    pub tenant_id: String,
    /// 拥有该绑定的 RS client_id(删 client 时级联清本行;de-register CAS on owner 防悬空)。
    pub client_id: String,
}

pub trait DomainMapStore: Send + Sync {
    /// 按 domain 点查绑定(数据面 well-known 用;O(1) GetItem,无 Scan)。None = 未登记。
    fn get(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Option<DomainBinding>, StoreError>> + Send;

    /// 登记一条域名绑定;**conditional put `attribute_not_exists(domain)`** 保全局唯一。
    /// 返回 `Ok(true)` = 登记成功;`Ok(false)` = 该域名已被(他人)登记(唯一冲突,拒);`Err` = store 瞬时/永久错。
    fn put_if_absent(
        &self,
        binding: DomainBinding,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 删除域名绑定,**仅当 owner 匹配**(CAS on client_id;de-register 防删他人 + 换租户防悬空返错 issuer)。
    /// 返回 `Ok(true)` = 删成功;`Ok(false)` = 不存在或 owner 不符(不删他人)。
    ///
    /// ⚠️ **依赖 client_id 全局唯一**(评审 L2):domain map 是全局键(非 tenant 分区),owner CAS 用**裸**
    /// client_id 比对。当前 admin 建的 client_id = `c_` + 16 随机字节(碰撞可忽略),故安全;若将来引入
    /// 低熵/可选 client_id 路径,须在此叠加 tenant 维度(否则两租户同 client_id 会跨租户误删绑定)。
    fn delete_if_owner(
        &self,
        domain: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 按 owner client_id 反查其**所有**已登记域名(删 client 级联的**权威源**,评审 M1/L3)。
    /// 走 `client_id-index` GSI(标量键,DynamoDB 可索引——区别于不可索引的 List 成员,B1)。
    /// 不依赖 ClientRecord.prm_domains(那是可漂移的展示副本),从而级联不漏悬空行。
    fn list_by_client(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<Vec<DomainBinding>, StoreError>> + Send;

    /// Governance-only fallback for dangling bindings whose client is absent.
    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// 上游 IdP 联邦配置存储(spec 003 §4.1 / C9.5b + C10.19,SaaS 逐租户隔离)。
///
/// ⚠️ **隔离铁律(codex+Kiro 双评审)**:读/删 MUST 用**复合键 `(tenant_id, upstream_idp_id)`**——
/// `upstream_idp_id`(如 `"okta"`/`"entra"`)多租户下极可能撞名,单键查询会跨租户命中。
/// **本端口 MUST NOT 提供无 `tenant_id` 的查询方法**(如 `get_by_idp`)——从 API 表面即断绝跨租户查
/// (编译期可审计的隔离)。真机 adapter 用 `tenant_id` 作分区键(C10.19 tenant_id 贯穿分区键),
/// A 租户上下文物理取不到 B 分区。tenant 一致性 + issuer 匹配的 fail-closed 断言在
/// `agent_auth_authn::federation::resolve_upstream_context`(纯逻辑,不依赖 adapter 自觉)。
pub trait FederationConfigStore: Send + Sync {
    /// 按**复合键**取联邦配置(联邦回调时查;None = 未登记该上游 → 回调拒)。绝无无 tenant 的全局查。
    fn get(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> impl Future<
        Output = Result<Option<agent_auth_authn::federation::FederationConfig>, StoreError>,
    > + Send;

    /// 列出某租户名下所有联邦配置(管理面列表 / `/authorize` 选上游 IdP;按 tenant 分区,绝不跨租户列)。
    fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<agent_auth_authn::federation::FederationConfig>, StoreError>>
           + Send;

    /// 登记联邦配置(管理面 PUT;幂等键 = `(config.tenant_id, config.upstream_idp_id)`)。
    fn put(
        &self,
        config: agent_auth_authn::federation::FederationConfig,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 删除(管理面 DELETE;复合键防跨租户删;不存在也 Ok 幂等)。
    fn delete(
        &self,
        tenant_id: &str,
        upstream_idp_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only physical cleanup of every tenant configuration.
    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// 瞬时失败(DynamoDB throttle / 事务冲突)——按 C10.1 ③ 处理。
    Transient(String),
    /// 永久失败。
    Permanent(String),
}

/// refresh token family 记录(C3:rotation + 复用检测的载体;P0/P1 = refresh-family,P2 起 = Grant)。
/// refresh token 不透明(查库随机串);family 绑定 authorize 的整个 resource 集合(C3.6 rotation 保集合)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamilyRecord {
    pub family_id: String,
    /// 当前有效版本;呈现非当前版本 = 复用 → 全链吊销(C3.1)。
    pub current_version: u64,
    pub revoked: bool,
    pub client_id: String,
    /// CIMD metadata inherited from the authorization code. Refresh never
    /// re-fetches a mutable remote document or requires a ClientStore row.
    pub cimd_snapshot: Option<crate::cimd::CimdClientSnapshot>,
    pub user_id: String,
    /// User lifecycle generation captured when this family was created.
    pub credential_epoch: u64,
    /// authorize 绑定的整个 resource 集合(下采样换发的边界;rotation 保集合不保单值 C3.6)。
    pub resources: Vec<String>,
    pub scope: Vec<String>,
    /// token-exchange 委托身份闸(spec 011 C7.2,Grant 前身):**允许作 actor 的 workload client_id 集合**。
    /// 空 = 不允许任何委托(P1 默认:普通 3LO 无委托授权源)。P2 迁移 Grant 时转 constraints.actor_allowlist。
    /// ⚠️ 3LO 的 `client_id` 是发起 authorize 的 OAuth 客户端,**不一定**是发起委托的 workload agent,
    /// 故委托授权 MUST 靠此显式集合、不能默认取 client_id(评审 codex/Kiro:否则要么挡真 actor、要么误授)。
    pub actor_allowlist: Vec<String>,
    /// 委托链深度上限(spec 011 C7.2;Grant 前身默认 1)。
    pub max_act_chain: u32,
    /// DPoP sender-constraint 绑定(spec 010 §5.2/C8.7b,RFC 9449 §5;可缺=向后兼容 bearer family)。
    /// Some(jkt) = 该 family 由 DPoP-bound 首签建立 → refresh 换发 MUST 出示匹配 jkt 的 proof,缺/不匹配拒
    /// **不降级 bearer**(否则 DPoP refresh 可换无约束 bearer = 降级洞,评审 B1)。None = 非 DPoP-bound
    /// (bearer family),refresh 不要求 proof(后向兼容)。
    pub dpop_jkt: Option<String>,
    /// Originating PKCE S256 challenge. Legacy and non-PKCE families omit it.
    /// C3.2 binds this immutable authorization origin into every grace fingerprint.
    pub pkce_code_challenge: Option<String>,
    /// Original user authentication event. Missing on legacy families and non-user grants.
    pub auth_time: Option<i64>,
    /// Canonical Agent Auth assurance class from the original authentication event.
    pub acr: Option<String>,
    /// 建 family 的授权工件所绑定的本地密码版本；编码同 [`CodeRecord::password_credential_version`]。
    pub password_credential_version: Option<u64>,
}

/// Refresh rotation lease acquisition result (C10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshLeaseAcquire {
    /// This owner acquired the signing lease for the presented family version.
    Acquired,
    /// Another owner still holds an unexpired signing lease.
    Locked { retry_after_secs: u64 },
    /// The presented version is no longer current.
    VersionMismatch,
    /// The family is revoked.
    Revoked,
    /// The family does not exist.
    NotFound,
}

/// refresh token family 存储端口。真机 = DynamoDB(条件写做原子 rotation);本地 = 内存。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键前缀 + by-user/by-client 二级路径隔离;
/// 评审 codex B1:`user:{email}` 跨租户碰撞,by-user/by-client 若不 tenant-scope 会泄露)。
pub trait RefreshStore: Send + Sync {
    /// 新建 family(code flow 首次签发 refresh 时);返回初始版本(0)。
    fn create(
        &self,
        tenant: &str,
        record: RefreshFamilyRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 取 family(按 family_id)。
    fn get(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> impl Future<Output = Result<Option<RefreshFamilyRecord>, StoreError>> + Send;

    /// Acquire the signing lease for one exact family version. An expired
    /// lease may be replaced, but the new owner fences every old finalize or
    /// release attempt.
    fn acquire_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> impl Future<Output = Result<RefreshLeaseAcquire, StoreError>> + Send;

    /// Finalize a signed refresh response by advancing the exact version and
    /// clearing only this owner's still-current lease.
    fn finalize_rotation(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Release this owner's lease after a pre-finalize failure. A stale owner
    /// must not clear a replacement lease.
    fn release_lease(
        &self,
        tenant: &str,
        family_id: &str,
        expected_version: u64,
        lease_owner: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// 全链吊销 family(复用检测触发,C3.1);同时上层须条件删宽限缓存(C3.5,spec 001)。
    fn revoke(
        &self,
        tenant: &str,
        family_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 吊销某 user 名下**所有** refresh family(账户恢复用,C9.3):恢复既要吊销浏览器会话,
    /// 也要吊销既存 refresh token,否则攻击者手里的旧 refresh 仍能持续换新 access(评审 codex#1)。
    /// 返回该 user 的**全部 family_id 列表**(包括此前已吊销的 family),供上层可重试地逐
    /// family 条件删宽限缓存(C3.5;评审 codex/Kiro F3)。
    /// **tenant-scope**(codex B1):仅吊销本租户 user 的 family,不误伤他租户同名 user。
    fn revoke_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    /// Revoke only families captured before one user lifecycle generation.
    /// Conditional writes fence a delayed disable worker from touching families
    /// created after the same generation was re-enabled.
    fn revoke_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    /// 吊销某 client 名下**所有** refresh family(spec 025 DELETE client 级联):删 client 后
    /// 旧 refresh token MUST 不能再 rotate 换 access(否则 ClientStore 删了但 token 仍有效)。
    /// 返回**被吊销的 family_id 列表**(供上层删宽限缓存,C3.5)。**tenant-scope**(codex B1)。
    fn revoke_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    /// **只读**:该 client 是否有**任一未吊销** refresh family(spec 005 §9.4,C10.5 回收信号)。
    /// 与 `revoke_by_client` 分离(那个是 MUTATING,绝不可当信号读);真机 MUST 查询与 source
    /// 生命周期原子维护、可强一致读取的 client-reference 基表。coverage 未完成或读取失败必须
    /// 返回 transient；最终一致 GSI 未命中不能证明不存在。
    /// tenant 从被回收记录派生(D3b;reclaim 无请求 Host)。
    fn has_active_family_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Governance-only physical cleanup. Returns all removed family ids so
    /// callers can delete associated grace responses.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    /// Governance-only fallback for families whose canonical user is absent.
    /// Returns every removed family id so callers can purge grace responses.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;
}

/// 宽限窗缓存的**已签发结果**(C3.2:命中时原样重放"已生成的同一组结果",非再签一组)。
/// ⚠️ 含可直接使用的 access+refresh(+id)token **明文**;落 DynamoDB MUST item-level 信封加密(C3.4)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceCachedResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: Option<String>,
    pub scope: Option<String>,
    pub expires_in: i64,
}

/// 宽限窗缓存项(C3.2/C3.4):键 = (family_id, version)。`version` = **本次被消费的那个版本**——
/// 该版本在宽限窗内被再次呈现且 client_id + DPoP jkt + 请求指纹全一致时,返回 `response`(不再签)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceCacheEntry {
    pub family_id: String,
    pub version: u64,
    /// 请求指纹(C3.2,fingerprint crate 计算的 32 字节 HMAC)。
    pub fingerprint: [u8; 32],
    /// 独立比较维度:client_id。
    pub client_id: String,
    /// 独立比较维度:DPoP key thumbprint(无 DPoP 为 None)。
    pub dpop_jkt: Option<String>,
    /// 命中时重放的已签发结果。
    pub response: GraceCachedResponse,
    /// 宽限窗结束(unix 秒);超过即视为未命中(过期项由 TTL 清)。
    pub expires_at: i64,
}

/// 宽限窗缓存存储端口(C3.2/C3.4/C3.5)。真机 = DynamoDB + item-level 信封加密(只授 token 端点
/// KMS Decrypt);本地/测试 = 内存明文。**None**(AppState.grace 未装配)= 宽限窗关闭 → 每次非当前
/// 版本一律按复用处理(更严的 fail-closed;真机在信封加密适配器落地前维持此姿态)。
pub trait GraceStore: Send + Sync {
    /// 写入宽限缓存项(rotation 成功后)。
    fn put(&self, entry: GraceCacheEntry) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 取宽限缓存项(呈现非当前版本时,判是否为窗内合法重试)。
    fn get(
        &self,
        family_id: &str,
        version: u64,
    ) -> impl Future<Output = Result<Option<GraceCacheEntry>, StoreError>> + Send;

    /// **条件删除**该 family 的所有宽限缓存项(C3.5:family revoke / 复用检测触发全链吊销时,
    /// MUST 同时删缓存,否则吊销后窗内仍命中旧 token)。
    fn delete_family(&self, family_id: &str)
        -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// 平台 JWKS 的一把公钥(spec 012 workload_oidc_jwt / spiffe_jwt_svid 本地验签用;字段为 base64url)。
/// **RSA**(kty=RSA/None):用 `n`/`e`;**EC P-256**(kty=EC,SPIFFE JWT-SVID / SPIRE 默认 ES256):用 `crv`/`x`/`y`
/// (spec 012 §1.4 实现前置 1.4-pre.1)。**非持久化类型**(不 derive Serde;由 JwksFetcher 从 `jwks_uri` 现取、
/// 内存缓存),故新增 EC 字段无落库反序列化兼容问题;`#[derive(Default)]` 使构造点可 `..Default::default()`
/// 只填相关字段(RSA 记录 crv/x/y=None、EC 记录 n/e 空)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformJwk {
    pub kid: Option<String>,
    /// 密钥类型:`RSA`(默认/None 按 RSA)或 `EC`。verify 侧据此 + alg 选验签器,pin 防 alg 混淆。
    pub kty: Option<String>,
    /// RSA modulus(base64url);EC key 为空。
    pub n: String,
    /// RSA exponent(base64url);EC key 为空。
    pub e: String,
    /// EC 曲线(仅 `P-256`;RSA key 为 None)。
    pub crv: Option<String>,
    /// EC 公钥 x 坐标(base64url,32B;RSA key 为 None)。
    pub x: Option<String>,
    /// EC 公钥 y 坐标(base64url,32B;RSA key 为 None)。
    pub y: Option<String>,
    /// alg(如宣告);为空时按 kty 推(RSA→RS256、EC→ES256)。
    pub alg: Option<String>,
}

/// 平台 JWKS 取用端口(spec 012 C5.1:workload_oidc_jwt 用平台 JWKS **本地验签**)。
/// 真机 = HTTP GET `jwks_uri` + 缓存 TTL + 负缓存 + 限速(评审 M3);dev/测试 = 内存预置。
/// ⚠️ `jwks_uri` **MUST** 来自管理面登记的 TrustBinding,**绝不**取自 JWT header 的 `jku`/`x5u`
/// (评审:防 key confusion)。
pub trait JwksFetcher: Send + Sync {
    /// 取该 `jwks_uri` 的 RSA 公钥集(命中缓存直接返)。瞬时失败(网络/超时)→ Transient(上层可 503)。
    fn fetch(
        &self,
        jwks_uri: &str,
    ) -> impl Future<Output = Result<Vec<PlatformJwk>, StoreError>> + Send;

    /// **强制刷新**(绕过缓存)取一次(评审:平台 key 轮换后 kid 未命中时,单次 force-refresh 拿新 key,
    /// 免等缓存 TTL)。上层只在缓存结果里选不到 kid 时调用一次(限一次,防重取风暴)。
    fn fetch_fresh(
        &self,
        jwks_uri: &str,
    ) -> impl Future<Output = Result<Vec<PlatformJwk>, StoreError>> + Send;
}

/// STS `GetCallerIdentity` 转发端口(spec 012 C5.2/C5.3:SigV4/STS 兜底路径)。
/// 真机 = reqwest POST 到**已校验的固定 STS host**(前校 `validate_sigv4_pre_sts` 通过后才调),
/// 带超时(2s);dev/测试 = 内存预置(assertion signature → 身份)。
/// ⚠️ 调用方 MUST 先过前校组合门(audience 被签名/TTL/host allowlist)再转发——本端口只负责"把已校验的
/// 预签名请求发给 STS、拿回它验证过的 caller 身份",不重做前校。瞬时失败(超时/5xx)→ Transient(上层
/// 熔断 + 503);签名无效(STS 4xx)→ Permanent-ish 的 Ok(None)(拒认证,非重试)。
pub trait StsCaller: Send + Sync {
    /// 转发 `assertion`(预签名 GetCallerIdentity)给 STS,返回解析出的 caller 身份。
    /// - `Ok(Some(id))`:STS 200 + 成功解析(签名有效,身份可信);
    /// - `Ok(None)`:STS 拒(4xx / 签名无效 / 响应无法解析)→ 认证失败(非瞬时,不重试);
    /// - `Err(Transient)`:STS 超时/5xx/网络 → 上层熔断计数 + 503。
    fn get_caller_identity(
        &self,
        assertion: &agent_auth_workload::SigV4Assertion,
    ) -> impl Future<Output = Result<Option<agent_auth_workload::StsCallerIdentity>, StoreError>> + Send;
}

/// **secret 引用名 → 明文**解析端口(spec 003 §4 Task 4.6,评审 Kiro F4)。联邦 config 只存 secret 的
/// **引用名**(`secretsmanager:...` / `ssm:...`),绝不落库明文(守"secret 不进 repo/不落库"红线);
/// 换 code 前经本端口解析成明文。真机 = Secrets Manager/SSM GetSecretValue;dev/测试 = 内存预置映射。
/// ⚠️ 引用名解析 MUST 在**调用边界内**完成(用完即弃),解析结果绝不写回 config、不进日志。
/// 瞬时失败(网络/超时/限流)→ `Err(Transient)`(上层可 503,不误当"secret 不存在")。
pub trait SecretResolver: Send + Sync {
    /// 把引用名解析成明文 secret。`Ok(Some(s))`=解析到;`Ok(None)`=引用名不存在(误配→拒,非重试);
    /// `Err(Transient)`=后端瞬时不可用(上层 503)。
    fn resolve(
        &self,
        secret_ref: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;
}

/// 上游 IdP **token 端点** code→token 交换端口(spec 003 §4 Task 4.6,联邦 OIDC RP 往返)。
/// 真机 = reqwest POST 到 **config 登记的 `token_endpoint`**(超时 + 按 `(tenant,idp)` 熔断,复用 circuit.rs
/// 纯状态机);dev/测试 = 内存预置(code → UpstreamTokenSet)。
/// ⚠️ `token_endpoint` **MUST** 来自登记 config(SSRF 防线,`FederationConfig::validate` 已强制 https 绝对 URL),
/// **绝不**取自请求参数。`client_secret` 由调用方经 `SecretResolver` 解析后传入(明文只在调用栈内存活)。
/// 瞬时失败(超时/5xx/网络)→ `Err(Transient)`(上层熔断 + 503);上游拒(4xx)→ `Ok(None)`(登录失败,非重试)。
pub trait UpstreamTokenExchanger: Send + Sync {
    /// 用 authorization code 向上游换 token。`Ok(Some(set))`=换到(含 id_token);`Ok(None)`=上游拒(4xx);
    /// `Err(Transient)`=瞬时不可用。**不验签 id_token**(验签在 callback 用 JwksFetcher,信任锚绑 config)。
    fn exchange_code(
        &self,
        req: &UpstreamTokenExchangeRequest<'_>,
    ) -> impl Future<Output = Result<Option<UpstreamTokenSet>, StoreError>> + Send;
}

/// code→token 交换的入参(借用,避免克隆;`client_secret` 是**解析后明文**,只在调用栈内存活)。
pub struct UpstreamTokenExchangeRequest<'a> {
    /// 登记 config 的 token_endpoint(已 validate 为 https 绝对 URL)。
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    /// 经 SecretResolver 解析后的明文(调用方负责用完即弃,不落库/不日志)。
    pub client_secret: &'a str,
    pub code: &'a str,
    /// PKCE code_verifier(RP 侧 PKCE)。
    pub code_verifier: &'a str,
    /// 本 AS 的 callback redirect_uri(固定,与发起授权时一致)。
    pub redirect_uri: &'a str,
}

/// 上游 token 端点返回的 token 集(只取 callback 需要的字段)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTokenSet {
    /// 上游 id_token(compact JWT;callback 用 config.jwks_uri 验签后提取 acr/amr/sub)。
    pub id_token: String,
    /// 上游 access_token(可选;P1 透传不用,预留)。
    pub access_token: Option<String>,
}

/// 联邦往返的短命 flow 状态(spec 003 §4 Task 4.7,评审 Kiro F1)。承载**两类状态**:
/// ①**上游腿**(RP CSRF/重放绑定):`state`(CSRF)、`nonce`(绑上游 id_token)、`code_verifier`(RP PKCE)、
///   `upstream_idp_id`(callback 据此取回哪条 config)、`tenant_id`(隔离,callback 校 Host 派生一致);
/// ②**下游续跑**(F1:AS 作 RP 的唯一目的是替某下游 client 完成登录):`original_authz_request` —— 用户最初
///   那笔下游 `/authorize` 的参数原样保存,callback 成功后据此续跑、向**原 client** 发本 AS code。
/// 缺 ② = "登录成功却回不到调用方"的死流(F1 Blocker)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationFlowState {
    /// flow key = `state`(不可预测;callback 精确等 + 一次性消费 → 防 CSRF/固定/重放)。
    pub state: String,
    /// OIDC `nonce`(callback 校 == 上游 id_token.nonce,防 id_token 重放)。
    pub nonce: String,
    /// RP 侧 PKCE code_verifier(换 token 时带)。
    pub code_verifier: String,
    /// callback 据此取回上游 config(复合键 (tenant_id, upstream_idp_id))。
    pub tenant_id: String,
    pub upstream_idp_id: String,
    /// **下游续跑上下文**(F1):原下游 authorize 请求的原始 query(client_id/redirect_uri/PKCE
    /// code_challenge/state/scope/resource 等),callback 成功后据此续跑发码回原 client。
    pub original_authz_request: String,
    /// 上游认证必须满足的新鲜度。独立于下游续跑 query 保存，使 `max_age=0`
    /// 可在 callback 校验后从续跑请求移除，避免再次触发认证循环。
    pub required_max_age_secs: Option<i64>,
    /// 短命过期时刻(Unix 秒;≤10min,fail-closed 校验)。
    pub expires_at: i64,
}

/// 联邦 flow 状态存储(spec 003 §4 Task 4.7)。`/authorize?idp_hint` 分支重定向上游前 `put`,
/// callback 用 `state` 作 key `consume`(**一次性**:取出即删,防 state 重放)。真机 = DynamoDB
/// 条件删(一次性 + TTL);dev/测试 = 内存。
pub trait FederationFlowStore: Send + Sync {
    /// 存一条 flow 状态(key = `state.state`)。
    fn put(
        &self,
        state: FederationFlowState,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **一次性消费**:按 `state` 取出并删除。`Ok(Some)`=命中且未过期(已删,不可再用);
    /// `Ok(None)`=不存在/已消费/已过期(callback fail-closed 拒)。防 state 重放。
    fn consume(
        &self,
        state: &str,
    ) -> impl Future<Output = Result<Option<FederationFlowState>, StoreError>> + Send;

    /// Governance-only physical cleanup of every pending flow for one tenant.
    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// WebAuthn ceremony bound to a short-lived challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCeremony {
    Registration,
    Authentication,
}

impl PasskeyCeremony {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "registration" => Some(Self::Registration),
            "authentication" => Some(Self::Authentication),
            _ => None,
        }
    }
}

/// passkey 仪式短命 challenge(spec 003 §3;评审 Kiro:注册绑 user_id、认证绑 challenge 值)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyChallenge {
    /// challenge 值(base64url;既作存储 key 又是 clientDataJSON.challenge 比对目标)。
    pub challenge_b64url: String,
    /// Logical tenant that issued the challenge. Required even though the
    /// random challenge remains the physical key, so consume and governance
    /// cleanup cannot cross tenant boundaries.
    pub tenant: String,
    /// 用途:注册须绑发起的登录会话 user_id(防 A 会话 challenge 铸凭证到 B);认证 pre-login 为 None。
    pub user_id: Option<String>,
    /// Ceremony type. Registration challenges cannot be replayed as authentication challenges.
    pub ceremony: PasskeyCeremony,
    /// Exact RP ID admitted when the challenge was issued.
    pub rp_id: String,
    /// Exact browser origin admitted when the challenge was issued.
    pub origin: String,
    /// 短命过期(Unix 秒;≤5min,fail-closed)。
    pub expires_at: i64,
}

/// passkey challenge 存储(spec 003 §3 Task 3.7)。begin 存、finish 一次性 consume(防重放)。
/// 真机 = DynamoDB 条件删 + TTL;dev/测试 = 内存。
pub trait PasskeyChallengeStore: Send + Sync {
    fn put(&self, ch: PasskeyChallenge) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// 一次性:按 challenge 值取出并删。`Ok(Some)`=命中未过期(已删);`Ok(None)`=无/已用/过期(拒)。
    fn consume(
        &self,
        tenant: &str,
        challenge_b64url: &str,
    ) -> impl Future<Output = Result<Option<PasskeyChallenge>, StoreError>> + Send;

    /// Remove registration challenges bound to the erased canonical user.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only physical cleanup of every pending challenge in a tenant.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyRegistrationOutcome {
    Created,
    CredentialExists,
    AuthorityChanged,
}

/// passkey 凭证存储(spec 003 §3 Task 3.7)。真机 = DynamoDB(pk=credential_id + GSI user_id-index);
/// dev/测试 = 内存。credentialId **MUST 全局唯一**(评审 Kiro:put 条件写,防伪造/碰撞覆盖他人)。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键 + user_id-index by-user 隔离,codex B1:
/// `user:{email}` 跨租户碰撞 → list_by_user/delete_by_user 不 tenant-scope 会返他租户凭证)。
pub trait PasskeyStore: Send + Sync {
    /// 存新凭证。**MUST 条件写(credential_id 不存在才写)**:已存在 → `Ok(false)`(拒,防覆盖);新写 → `Ok(true)`。
    fn put_new(
        &self,
        tenant: &str,
        cred: agent_auth_authn::passkey::PasskeyCredential,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// 按 credentialId 取(认证时)。
    fn get(
        &self,
        tenant: &str,
        credential_id: &str,
    ) -> impl Future<Output = Result<Option<agent_auth_authn::passkey::PasskeyCredential>, StoreError>>
           + Send;
    /// 列某 user 的凭证(register/begin excludeCredentials + authenticate/begin allowCredentials 用)。
    fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Vec<agent_auth_authn::passkey::PasskeyCredential>, StoreError>> + Send;
    /// signCount CAS 回写(评审 Kiro:防克隆须原子)。`expected_prev`=读到的旧值;仅当当前仍==expected_prev
    /// 才写 `new_count` → `Ok(true)`;竞态/回退 → `Ok(false)`(调用方拒认证)。
    fn update_sign_count(
        &self,
        tenant: &str,
        credential_id: &str,
        new_count: u32,
        expected_prev: u32,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// Rename only when the credential still belongs to the authenticated user.
    fn rename_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
        name: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// Delete one credential only when it belongs to the authenticated user.
    fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        credential_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **删某 user 全部凭证**(admin disable/delete 级联,§1.4)。返回删除数。真机走 list_by_user(GSI)
    /// 再逐个 DeleteItem;内存遍历删。
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only fallback for credentials whose canonical user is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// **一次性 replay 缓存**(spec 012 C5.3②:SigV4 预签名请求防重放;dpop_jti 同类短命项)。
/// key = `HMAC-SHA256(server_secret, Authorization 的 Signature= 段)`(只哈希签名段,评审 M1)。
/// 真机 = DynamoDB 条件写(pk 不存在才写,TTL=expires_at);dev/测试 = 内存。
pub trait ReplayStore: Send + Sync {
    /// 原子 **check-and-set**:key 首次出现 → 记录并返 `true`(接受);已存在(窗内重放)→ `false`(拒)。
    /// `expires_at` = 该 key 的短命 TTL(Unix 秒;= 预签名 TTL 窗上限)。
    fn check_and_set(
        &self,
        tenant: &str,
        key: &str,
        expires_at: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// **Grant 授权记录存储**(spec 011 §5.1;P2 权威源)。真机 = DynamoDB(pk=grant_id + GSI user_id);
/// dev/测试 = 内存。Grant 模型 + 校验纯逻辑见 `agent_auth_grant`;本端口只做 IO(存/取/列/吊销)。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键 + user_id GSI by-user 隔离,codex B1:
/// `user:{email}` 跨租户碰撞 → list_by_user 不 tenant-scope 会返他租户 Grant = 直接泄露)。
pub trait GrantStore: Send + Sync {
    /// 落地/更新一条 Grant(pk=grant_id)。
    fn put(
        &self,
        tenant: &str,
        grant: agent_auth_grant::Grant,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// 按 grant_id 取(token-exchange 据 grant_id claim 反查;`/grants/{id}`)。
    fn get(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> impl Future<Output = Result<Option<agent_auth_grant::Grant>, StoreError>> + Send;
    /// 列某 user 的全部 Grant(用户自助查询页,FAPI Grant Management;按 user_id GSI)。
    fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Vec<agent_auth_grant::Grant>, StoreError>> + Send;
    /// 吊销一条 Grant(status→Revoked)。**IDOR-safe**:调用方须先校 grant.user_id == 当前用户
    /// (端口只做状态写;归属校验在 handler)。返回 false = grant_id 不存在。
    fn revoke(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Revoke only when the stored Grant belongs to a generation before
    /// `epoch`. The check and status update must be atomic.
    fn revoke_if_epoch_before(
        &self,
        tenant: &str,
        grant_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Revoke only when the stored Grant still has `expected_revision`.
    /// Policy recompute uses this CAS to avoid revoking a Grant that was
    /// concurrently replaced by newer consent or policy state.
    fn revoke_if_revision(
        &self,
        tenant: &str,
        grant_id: &str,
        expected_revision: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// **条件写(CAS,spec 005 §7 补强 ⑫)**:仅当当前 `revision == expected_revision` **且未 Revoked**
    /// 才写(内部把 `grant.revision` 置为 `expected_revision + 1` 落库)。用于后台重算避免覆盖并发吊销 /
    /// consent 更新 / 更新的重算。返回 `Ok(true)`=写成功;`Ok(false)`=冲突(revision 不符 / 已 Revoked /
    /// 不存在)——调用方应跳过(下轮重算再处理)。
    fn put_conditional(
        &self,
        tenant: &str,
        grant: agent_auth_grant::Grant,
        expected_revision: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// **列 stale Grant**(spec 005 §7 补强 ⑩,C10.17):`effective_pv < current_pv` 的 Grant(后台重算候选)。
    /// 真机走 GSI(pk=tenant, sk=effective_pv)`Query effective_pv < current`(分页,非全表 Scan)。
    /// **返回 `(tenant, Grant)`**(重算无请求 Host,后续 put_conditional 用记录自身 tenant)。空 tenant = 全量维护扫描。
    fn list_stale(
        &self,
        tenant: &str,
        current_pv: u64,
    ) -> impl Future<Output = Result<Vec<(String, agent_auth_grant::Grant)>, StoreError>> + Send;

    /// Governance-only physical deletion of every Grant for one user.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Client lifecycle physical cascade. The caller MUST first establish the registered-client
    /// tombstone barrier, so no new Grant can appear after this bounded strong scan.
    /// Implementations must scope by both tenant and the client_id in authoritative Grant JSON.
    fn delete_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only fallback for Grants whose canonical user is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// **逐租户 policy_version 存储**(spec 005 §7 补强 ②/③;C10.17)。策略变更 bump → 触发重算;
/// **MUST 逐租户分区**(全局单值会在租户 B bump 时误 stale 租户 A 的 Grant)。自部署 = 空 tenant 退化。
pub trait PolicyVersionStore: Send + Sync {
    /// 取本租户当前 policy_version(无记录 → 0)。
    fn get(&self, tenant: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// 原子 +1 并返回**新版本**(单调递增;策略激活时调)。
    fn bump(&self, tenant: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// Governance-only physical cleanup of the tenant's activation pointer.
    fn delete(&self, tenant: &str) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// **不可变策略工件存储**(spec 005 §7 补强 ⑨)。按 `(tenant, version)` 存已校验的 Cedar 策略文本 + digest;
/// **先写工件 + 校验 → 后 bump 激活**(避免 version=N 已激活但 worker 仍读旧工件)。工件不可变(同 version 不改写)。
pub trait PolicyArtifactStore: Send + Sync {
    /// 写一份工件(激活前);`digest` = 文本 sha256(可审计防篡改)。
    fn put(
        &self,
        tenant: &str,
        version: u64,
        text: String,
        digest: String,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// 取某 (tenant, version) 的工件文本 + digest(None = 未登记该版本)。
    fn get(
        &self,
        tenant: &str,
        version: u64,
    ) -> impl Future<Output = Result<Option<(String, String)>, StoreError>> + Send;
    /// Governance-only physical cleanup of every immutable tenant artifact.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// jti → 授权主体映射(spec 011 C7.8:token-exchange 用入站 subject_token 的 `jti` 反查内部 `user_id`,
/// **绝不解 pairwise `sub`**,HMAC 单向)。`family_id` 是 Grant 前身指针(解 M3 同-RS-多-Grant 消歧);
/// family 创建失败的极少数 token 无 family_id(消歧退化到按目标 resource 唯一命中)。
/// ⚠️ **按 tenant 分区**(评审:SaaS 跨租户主体泄露闸,对齐 C10.19);短命 TTL ≥ token TTL。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JtiRecord {
    pub jti: String,
    pub tenant_id: String,
    pub user_id: String,
    /// Grant 前身指针(refresh-family id);None = 无 family(直发 access,消歧退化)。
    pub family_id: Option<String>,
    /// **Grant 正式化指针**(spec 011 §5.1,P2):指向 Grant 权威记录。token-exchange 对 access/ID
    /// token 均要求 Some 并按 Grant 校验；None 只表示该签发路径未建立可委托 Grant。
    #[allow(clippy::doc_lazy_continuation)]
    pub grant_id: Option<String>,
    /// 过期(unix 秒;TTL GC,判定走应用层)。
    pub expires_at: i64,
}

/// jti 映射存储端口(spec 011 C7.8;token-exchange subject 解析用)。真机 = DynamoDB(短命 TTL);dev = 内存。
pub trait JtiStore: Send + Sync {
    /// 签发 3LO token 时落映射(access + id_token;2LO 无 user_id 不落)。
    fn put(&self, record: JtiRecord) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 按 (tenant, jti) 反查(token-exchange 定位 user_id/family_id)。跨租户 MUST 查不到(隔离闸)。
    fn get(
        &self,
        tenant_id: &str,
        jti: &str,
    ) -> impl Future<Output = Result<Option<JtiRecord>, StoreError>> + Send;

    /// Governance-only physical deletion of subject-linked JTI mappings.
    fn delete_by_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only physical cleanup of every mapping for one logical tenant.
    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

// ============ 用户目录(spec 003 §1.4 / C9;docs §8 "user by email" access-pattern)============

/// 用户持久身份记录(spec 003 §1.4)。**持久身份 MUST NOT 挂裸 TTL**(C10.5,users 表不设 TTL)。
/// 既有本地用户保留 legacy `user:{归一 email}` id；新 SCIM 用户使用随机、稳定的 canonical id。
/// SCIM 可原子收编既有本地用户并移动 email/userName alias，但不重写既有 `user_id`，因此关联的
/// sessions、Grants 与 passkeys 继续引用同一主体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// 内部稳定 canonical user id；可能是 legacy email-derived id 或随机 SCIM id。
    pub user_id: String,
    /// 归一后的 email(小写 + trim;GSI email-index 键,唯一)。
    pub email: String,
    /// 创建时刻(Unix 秒;首次 magic-link 登录时落)。
    pub created_at: i64,
    /// Last persistent identity or lifecycle update (Unix seconds).
    pub updated_at: i64,
    /// AS 最后一次成功建立该用户认证会话的观测时刻(Unix 秒)。
    /// None = 尚未成功登录;旧记录缺字段时同样按 None 兼容。
    pub last_login_at: Option<i64>,
    /// 账户状态(spec 003 §1.4 admin user 管理面,C9):`Active` 正常;`Disabled` admin 禁用(挡登录,
    /// 可 enable 恢复);`Tombstoned` admin 删除(永久墓碑,同 email 后续 JIT/login 一律拒、不复活)。
    /// **兼容**:UserRecord 不走 serde,Dynamo 侧 `to_record()` 缺 `status` attr → 默认 `Active`
    /// (既有记录无痛);`create_or_get_by_email` 首建写 Active。
    pub status: UserStatus,
    /// Monotonic authentication generation captured by login sessions, refresh
    /// families, and Grants. Account lifecycle and credential changes advance it.
    pub credential_epoch: u64,
    /// True while an account lifecycle or credential-change generation still
    /// needs authentication-state cleanup.
    pub revocation_pending: bool,
    /// Tenant-scoped SCIM aliases and optional presentation data.
    pub scim_external_id: Option<String>,
    pub scim_user_name: Option<String>,
    pub scim_display_name: Option<String>,
    /// Internal cross-namespace CAS generation for the complete attributes map.
    /// Missing legacy values read as zero; every successful attribute mutation increments it.
    pub attributes_generation: u64,
    /// **RS 命名空间用户属性**(spec 007,§6.1):
    /// `attributes[<canonical namespace RFC8707 URI>] = {revision, kv}`。
    /// RS 把自身授权语义(如 EK 的 `role=admin`)托管到 AS;AS **语义无知**只做隔离存储。
    /// **不挂 TTL**(持久身份,C10.5);缺 attr → 空 map(向后兼容,同 `status` 缺省)。删用户级联清(GDPR)。
    /// 单用户全部 namespace 序列化后 ≤ 4096B(防拖垮身份读路径,非 DynamoDB item 上限)。
    pub attributes: std::collections::BTreeMap<String, NamespaceAttrs>,
}

/// 单个 RS 命名空间下的属性 + 乐观锁版本(spec 007,§6.1)。
/// `revision` 每次全量替换递增,RMW 写用 `If-Match` 防丢更新(仿 Grant `put_conditional`)。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FederatedAttributeOwner {
    pub upstream_idp_id: String,
    pub upstream_issuer: String,
    pub mapping_id: String,
    pub mapping_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NamespaceAttrs {
    /// 乐观锁版本(读回带作 ETag;写带 If-Match 比对,不符 409)。首次写从 0→1。
    pub revision: u64,
    /// 该 namespace 下的 key→value(value 字符串,AS 不解释语义)。
    pub kv: std::collections::BTreeMap<String, String>,
    /// Federation-owned keys and their exact mapping authority. Missing legacy metadata means
    /// admin-owned. These values are internal and are never returned by Admin or RS APIs.
    pub federation_owners: std::collections::BTreeMap<String, FederatedAttributeOwner>,
}

/// `put_attributes` 结果(spec 007):区分各失败态供 handler 精确映射状态码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutAttrOutcome {
    /// 写成功,返回新 revision。
    Ok { revision: u64 },
    /// user_id 不存在 → handler 404。
    NotFound,
    /// If-Match 版本不符(并发丢更新)→ handler 409。
    RevisionConflict { current: u64 },
    /// 目标用户 Tombstoned → handler 409(不复活)。
    Tombstoned,
    /// Namespace authority changed, is pending, or is retired → handler 409.
    NamespaceBlocked,
    /// A full-replacement Admin write attempted to modify or remove a federation-owned key.
    OwnershipConflict,
    /// 合并后全部 namespace 序列化 > 4096B → handler 413。
    TooLarge,
}

/// Canonical namespace migration result. Adapters plan from their latest atomic user snapshot
/// and never expose an internal attributes-generation conflict to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeMigrationOutcome {
    Noop,
    Migrated { generation: u64 },
    Conflict { namespaces: Vec<String> },
    NotFound,
    Tombstoned,
    TooLarge,
    RevisionExhausted,
}

/// 单用户全部 namespace attributes 序列化后的硬上限(spec 007,§6.1;防拖垮身份读路径)。
pub const ATTRIBUTES_MAX_BYTES: usize = 4096;

/// 用户账户状态(spec 003 §1.4)。fail-closed:非 Active 一律不放行登录(require_active_user)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// 正常,可登录。
    Active,
    /// admin 禁用:挡所有登录入口 + 级联吊销活跃凭证;可 enable 恢复。
    Disabled,
    /// admin 删除(墓碑):永久,同 email 后续登录/JIT 一律拒、不复活;admin create 遇此返 409。
    Tombstoned,
}

/// Lifecycle filter for paginated canonical-user scans.
///
/// Admin list requests select one of these explicitly; governance, export, and namespace
/// migration callers use `All` so tombstones remain available to those internal workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserListStatusFilter {
    NonDeleted,
    Active,
    Disabled,
    Tombstoned,
    All,
}

impl UserListStatusFilter {
    pub fn matches(self, status: UserStatus) -> bool {
        match self {
            Self::NonDeleted => status != UserStatus::Tombstoned,
            Self::Active => status == UserStatus::Active,
            Self::Disabled => status == UserStatus::Disabled,
            Self::Tombstoned => status == UserStatus::Tombstoned,
            Self::All => true,
        }
    }
}

pub(crate) fn next_disable_epoch(
    status: UserStatus,
    credential_epoch: u64,
) -> Result<u64, StoreError> {
    if status == UserStatus::Active || credential_epoch == 0 {
        credential_epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Permanent("user credential_epoch exhausted".into()))
    } else {
        Ok(credential_epoch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimUserInput {
    pub user_id: String,
    pub external_id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub active: bool,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimReplaceInput {
    pub external_id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub active: bool,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimCreateOutcome {
    Created(UserRecord),
    Existing {
        record: UserRecord,
        pending_initial_epoch: Option<u64>,
    },
    Conflict,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimCreateLifecycleStart {
    Ready { record: UserRecord, epoch: u64 },
    Complete,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimReplaceOutcome {
    Updated(UserRecord),
    NotFound,
    Conflict,
    Tombstoned,
}

/// SCIM Group membership is separate from tenant management roles and
/// resource-server attributes. A role exists only through an explicit
/// tenant-admin mapping for one active Group externalId.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    Member,
    Auditor,
    Admin,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimGroupRecord {
    pub group_id: String,
    pub external_id: String,
    pub display_name: String,
    pub members: Vec<String>,
    pub version: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimGroupCreateInput {
    pub group_id: String,
    pub external_id: String,
    pub display_name: String,
    pub members: Vec<String>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimGroupChange {
    SetDisplayName(String),
    AddMembers(Vec<String>),
    RemoveMembers(Vec<String>),
    ReplaceMembers(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimGroupMutation {
    Replace {
        display_name: String,
        members: Vec<String>,
        now: i64,
    },
    Patch {
        changes: Vec<ScimGroupChange>,
        now: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimGroupCreateOutcome {
    Created(ScimGroupRecord),
    Existing(ScimGroupRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimGroupMutationOutcome {
    Updated(ScimGroupRecord),
    NotFound,
    TooManyMembers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimGroupDeleteOutcome {
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupRoleMapping {
    pub group_id: String,
    pub external_id: String,
    pub role: TenantRole,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimRoleMappingOutcome {
    Updated(ScimGroupRoleMapping),
    Removed,
    GroupNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedTenantRole {
    pub role: Option<TenantRole>,
    pub mappings: Vec<ScimGroupRoleMapping>,
}

/// DynamoDB transactions are capped at 100 items. A Group mutation changes one
/// canonical row plus at most 40 old and 40 new membership index rows.
pub const SCIM_GROUP_MAX_MEMBERS: usize = 40;

pub(crate) fn canonical_scim_group_members(mut members: Vec<String>) -> Vec<String> {
    members.sort();
    members.dedup();
    members
}

pub(crate) fn apply_scim_group_mutation(
    record: &ScimGroupRecord,
    mutation: ScimGroupMutation,
) -> (ScimGroupRecord, i64) {
    let mut next = record.clone();
    let now = match mutation {
        ScimGroupMutation::Replace {
            display_name,
            members,
            now,
        } => {
            next.display_name = display_name;
            next.members = canonical_scim_group_members(members);
            now
        }
        ScimGroupMutation::Patch { changes, now } => {
            for change in changes {
                match change {
                    ScimGroupChange::SetDisplayName(display_name) => {
                        next.display_name = display_name;
                    }
                    ScimGroupChange::AddMembers(members) => {
                        next.members.extend(members);
                        next.members = canonical_scim_group_members(next.members);
                    }
                    ScimGroupChange::RemoveMembers(members) => {
                        next.members.retain(|member| !members.contains(member));
                    }
                    ScimGroupChange::ReplaceMembers(members) => {
                        next.members = canonical_scim_group_members(members);
                    }
                }
            }
            now
        }
    };
    (next, now)
}

/// Tenant-scoped SCIM Groups and explicit platform-role mappings (C12.3).
///
/// Adapters atomically maintain the externalId claim, canonical Group,
/// membership index, and mapping lifecycle. `mapped_role_for_member` resolves
/// membership only; callers must separately require an active canonical User.
pub trait ScimGroupsStore: Send + Sync {
    fn create(
        &self,
        tenant: &str,
        input: ScimGroupCreateInput,
    ) -> impl Future<Output = Result<ScimGroupCreateOutcome, StoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        group_id: &str,
    ) -> impl Future<Output = Result<Option<ScimGroupRecord>, StoreError>> + Send;

    fn get_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> impl Future<Output = Result<Option<ScimGroupRecord>, StoreError>> + Send;

    fn list(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<(Vec<ScimGroupRecord>, usize), StoreError>> + Send;

    fn mutate(
        &self,
        tenant: &str,
        group_id: &str,
        mutation: ScimGroupMutation,
    ) -> impl Future<Output = Result<ScimGroupMutationOutcome, StoreError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        group_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<ScimGroupDeleteOutcome, StoreError>> + Send;

    fn set_role_mapping(
        &self,
        tenant: &str,
        external_id: &str,
        role: Option<TenantRole>,
        now: i64,
    ) -> impl Future<Output = Result<ScimRoleMappingOutcome, StoreError>> + Send;

    fn list_role_mappings(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Vec<ScimGroupRoleMapping>, StoreError>> + Send;

    fn mapped_role_for_member(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<MappedTenantRole, StoreError>> + Send;

    /// Remove one canonical user from every Group and membership index.
    fn remove_member_from_all(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only physical removal of canonical Groups, alias claims,
    /// membership indexes, and role mappings for one frozen tenant.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// The upstream identity claim is resolved only against an existing tenant-local
/// SCIM user. No Admin SSO path creates or links users implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminIdentityField {
    UserId,
    UserName,
}

/// Tenant-owned OIDC RP configuration for the Admin control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminOidcConfig {
    pub tenant_id: String,
    /// Unpredictable binding regenerated on every successful configuration
    /// write. It prevents deleted configuration revision numbers from making
    /// old flows or sessions valid again after recreation.
    pub binding_id: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ref: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// Upstream ACR values explicitly trusted to satisfy the internal
    /// `strong` assurance class. Unknown ACRs and AMR values never elevate.
    #[serde(default)]
    pub strong_acr_values: Vec<String>,
    pub identity_claim: String,
    pub identity_field: AdminIdentityField,
    pub revision: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminOidcConfigPutOutcome {
    Stored(AdminOidcConfig),
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminOidcConfigDeleteOutcome {
    Deleted,
    Conflict,
}

/// One-time OIDC authorization flow. `state_hash` is a domain-separated HMAC
/// of the browser-visible state and a host-only browser cookie, so the flow
/// cannot be moved to another browser and neither opaque value is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminOidcFlow {
    pub state_hash: String,
    pub nonce: String,
    pub code_verifier: String,
    pub tenant_id: String,
    pub config_revision: u64,
    pub config_binding_id: String,
    /// Canonical internal ACR required by the request that started this flow.
    #[serde(default)]
    pub required_acr: Option<String>,
    /// Maximum age accepted for the upstream active authentication event.
    #[serde(default)]
    pub required_max_age_secs: Option<i64>,
    pub expires_at: i64,
}

/// Short-lived Admin session. `session_hash` is the only persisted lookup key;
/// the opaque cookie value is returned to the browser once and never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSessionRecord {
    pub session_hash: String,
    pub tenant_id: String,
    pub user_id: String,
    pub upstream_subject: String,
    pub role: TenantRole,
    pub credential_epoch: u64,
    pub config_revision: u64,
    pub config_binding_id: String,
    /// Canonical internal assurance class mapped from verified upstream evidence.
    #[serde(default)]
    pub acr: Option<String>,
    /// Upstream active authentication event time, or callback time when no
    /// freshness requirement was requested.
    #[serde(default)]
    pub auth_time: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Admin OIDC configuration, one-time flows, and management sessions share one
/// logical port. Production keeps durable configuration and Region-local
/// flow/session rows in separate DynamoDB tables.
pub trait AdminAuthStore: Send + Sync {
    fn get_config(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Option<AdminOidcConfig>, StoreError>> + Send;

    /// Compare-and-swap the tenant configuration. `expected_revision=0` creates
    /// only when absent; updates require an exact current revision.
    fn put_config(
        &self,
        config: AdminOidcConfig,
        expected_revision: u64,
    ) -> impl Future<Output = Result<AdminOidcConfigPutOutcome, StoreError>> + Send;

    /// Delete only the exact configuration revision. Removing the config
    /// immediately invalidates every flow and session that references it.
    fn delete_config(
        &self,
        tenant_id: &str,
        expected_revision: u64,
    ) -> impl Future<Output = Result<AdminOidcConfigDeleteOutcome, StoreError>> + Send;

    fn put_flow(&self, flow: AdminOidcFlow) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Atomically consume a flow and reject expired or malformed rows.
    fn consume_flow(
        &self,
        state_hash: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<AdminOidcFlow>, StoreError>> + Send;

    fn create_session(
        &self,
        session: AdminSessionRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn get_session(
        &self,
        session_hash: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<AdminSessionRecord>, StoreError>> + Send;

    /// Delete the session only when it belongs to the request's logical tenant.
    /// A missing or cross-tenant row is an idempotent no-op.
    fn delete_session(
        &self,
        tenant_id: &str,
        session_hash: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only physical cleanup of config, one-time flows, and Admin
    /// sessions. The tenant mutation fence must already be durable.
    fn delete_all_by_tenant(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// Durable data-governance control plane. Production keeps policy, manifests,
/// jobs, and suppression records in retained tables; physical data operations
/// are performed by a separate purpose-built governance backend.
pub trait GovernanceStore: Send + Sync {
    /// Acquire a leased ordinary-mutation permit. The permit and aggregate
    /// active count must become visible atomically, and acquisition must fail
    /// once tenant offboarding freezes the gate.
    fn acquire_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> impl Future<
        Output = Result<crate::governance::TenantMutationPermitAcquireOutcome, StoreError>,
    > + Send;

    /// Extend an unexpired permit. A false result means that the request no
    /// longer owns mutation authority and must stop before another write.
    fn renew_tenant_mutation_permit(
        &self,
        permit: &crate::governance::TenantMutationPermit,
        now: i64,
        deadline: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Release the exact permit and decrement the aggregate count atomically.
    fn release_tenant_mutation_permit(
        &self,
        permit: crate::governance::TenantMutationPermit,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn get_policy(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Option<crate::governance::GovernancePolicyRecord>, StoreError>> + Send;

    fn put_policy(
        &self,
        record: crate::governance::GovernancePolicyRecord,
        expected_revision: u64,
    ) -> impl Future<Output = Result<crate::governance::GovernancePolicyPutOutcome, StoreError>> + Send;

    fn put_export_manifest(
        &self,
        manifest: crate::governance::GovernanceExportManifest,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn get_export_manifest(
        &self,
        tenant_id: &str,
        export_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<crate::governance::GovernanceExportManifest>, StoreError>>
           + Send;

    /// Atomically checks the policy revision and records or resumes one
    /// deterministic job. Tenant offboarding also advances the durable tenant
    /// lifecycle fence in the same store operation.
    fn start_or_resume_job(
        &self,
        job: crate::governance::GovernanceJobRecord,
        expected_policy_revision: u64,
        freeze_tenant: bool,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobStartOutcome, StoreError>> + Send;

    fn get_job(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> impl Future<Output = Result<Option<crate::governance::GovernanceJobRecord>, StoreError>> + Send;

    fn list_jobs(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Vec<crate::governance::GovernanceJobRecord>, StoreError>> + Send;

    fn get_continuation(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> impl Future<
        Output = Result<Option<crate::governance::GovernanceContinuationRecord>, StoreError>,
    > + Send;

    fn update_continuation(
        &self,
        record: crate::governance::GovernanceContinuationRecord,
        expected_revision: u64,
    ) -> impl Future<
        Output = Result<crate::governance::GovernanceContinuationUpdateOutcome, StoreError>,
    > + Send;

    /// Atomically verifies the current resume revision and consumes one token
    /// digest. Plaintext continuation tokens and JTIs are never persisted.
    fn consume_continuation_resume(
        &self,
        tenant_id: &str,
        job_id: &str,
        jti_digest: &str,
        expected_resume_revision: u64,
        expires_at: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Advance one durable checkpoint only when both the job and policy
    /// revisions still match. The store assigns the next job revision.
    fn update_job(
        &self,
        job: crate::governance::GovernanceJobRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobUpdateOutcome, StoreError>> + Send;

    /// Atomically advances one exact job/policy revision to completion and
    /// appends its immutable completion evidence. A conflict must expose
    /// neither half of the operation.
    fn complete_job_with_evidence(
        &self,
        job: crate::governance::GovernanceJobRecord,
        evidence: crate::governance::GovernanceEvidenceRecord,
        expected_revision: u64,
        expected_policy_revision: u64,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobUpdateOutcome, StoreError>> + Send;

    /// Atomically acquires the one destructive lease for this exact job
    /// revision while the no-hold policy and tenant lifecycle fence are current.
    /// Only the token digest is persisted.
    fn claim_job_lease(
        &self,
        tenant_id: &str,
        job_id: &str,
        expected_job_revision: u64,
        token_digest: &str,
        now: i64,
        deadline: i64,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobLeaseOutcome, StoreError>> + Send;

    /// Extends an unexpired lease only for its exact token and authority fence.
    fn renew_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
        deadline: i64,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobLeaseOutcome, StoreError>> + Send;

    /// Clears a lease only for its exact token, job revision, and deadline.
    fn release_job_lease(
        &self,
        tenant_id: &str,
        fence: crate::governance::GovernanceDestructiveFence,
    ) -> impl Future<Output = Result<crate::governance::GovernanceJobLeaseOutcome, StoreError>> + Send;

    /// Strongly reports whether this tenant still has any unexpired destructive
    /// lease. Legal-hold enabling uses this to establish its quiescence point.
    fn tenant_has_active_job_leases(
        &self,
        tenant_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn get_tenant_lifecycle(
        &self,
        tenant_id: &str,
    ) -> impl Future<Output = Result<Option<crate::governance::TenantLifecycleRecord>, StoreError>> + Send;

    /// Create one deterministic external action only while the exact
    /// no-hold job/tenant fence remains current.
    fn prepare_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> impl Future<
        Output = Result<crate::governance::GovernanceExternalActionPutOutcome, StoreError>,
    > + Send;

    fn get_external_action(
        &self,
        tenant_id: &str,
        job_id: &str,
        action_id: &str,
    ) -> impl Future<
        Output = Result<Option<crate::governance::GovernanceExternalActionRecord>, StoreError>,
    > + Send;

    fn list_external_actions(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> impl Future<
        Output = Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError>,
    > + Send;

    /// Strongly list every external action in one tenant. Legal-hold enabling
    /// uses this only after its CAS has blocked issuance of new claims.
    fn list_tenant_external_actions(
        &self,
        tenant_id: &str,
    ) -> impl Future<
        Output = Result<Vec<crate::governance::GovernanceExternalActionRecord>, StoreError>,
    > + Send;

    /// CAS one action transition under the same current destructive fence.
    fn update_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionFence,
    ) -> impl Future<
        Output = Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError>,
    > + Send;

    /// Record the outcome of an already-issued claim. Unlike dispatch
    /// authorization, reconciliation remains legal after a hold starts, but it
    /// must retain the exact claim token and tenant lifecycle identity.
    fn reconcile_external_action(
        &self,
        record: crate::governance::GovernanceExternalActionRecord,
        expected_revision: u64,
        fence: crate::governance::GovernanceExternalActionReconcileFence,
    ) -> impl Future<
        Output = Result<crate::governance::GovernanceExternalActionUpdateOutcome, StoreError>,
    > + Send;

    /// Append one immutable, hash-verified completion evidence revision.
    fn put_evidence(
        &self,
        record: crate::governance::GovernanceEvidenceRecord,
    ) -> impl Future<Output = Result<crate::governance::GovernanceEvidencePutOutcome, StoreError>> + Send;

    fn latest_evidence(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> impl Future<Output = Result<Option<crate::governance::GovernanceEvidenceRecord>, StoreError>>
           + Send;

    /// Append-only suppression write. A duplicate exact epoch is idempotent;
    /// no implementation may expose update or delete through this port. The
    /// permanent write must be atomic with the current destructive-job fence.
    fn put_suppression(
        &self,
        record: crate::governance::GovernanceSuppressionRecord,
        fence: crate::governance::GovernanceDestructiveFence,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn is_suppressed(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Return the newest non-rollback epoch for one canonical or alias digest.
    /// This lets a retry recover its deterministic job after the identity row
    /// has already been physically deleted.
    fn latest_suppression_epoch(
        &self,
        tenant_id: &str,
        target_class: &str,
        digest: &str,
    ) -> impl Future<Output = Result<Option<u64>, StoreError>> + Send;
}

/// Durable wake-up channel for governance jobs. The job row remains the
/// authority; queue messages carry only the revision that should be advanced.
pub trait GovernanceJobQueue: Send + Sync {
    fn enqueue(
        &self,
        command: crate::governance::GovernanceJobCommand,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableStart {
    Ready { record: UserRecord, epoch: u64 },
    NotFound,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableOutcome {
    Enabled(UserRecord),
    NotFound,
    RevocationPending,
    Tombstoned,
    ConcurrentChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChangeStart {
    Started { epoch: u64 },
    NotFound,
    Ineligible,
    ConcurrentChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialChangeOwner<'a> {
    pub epoch: u64,
    pub operation_id: &'a str,
}

/// 用户目录存储(spec 003 §1.4:magic-link 登录 by email 定位 user)。
/// 真机 = DynamoDB(pk=user_id + GSI email-index);本地 = 内存。持久身份,不挂 TTL(C10.5)。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键 pk + GSI email-index by-email 隔离,
/// codex B1:同一 email 跨租户是**不同用户** → email-index 不 tenant-scope 会串租户)。
pub trait UsersStore: Send + Sync {
    /// **幂等 upsert-by-email**:email 已存在 → 返回其 `user_id`(复用,不覆盖 created_at);
    /// 不存在 → 用给定 `user_id` create 一条(首次 magic-link 登录)并返回。**首登建、后续复用**。
    /// `now` 由调用方注入(首次 create 的 created_at)。
    fn create_or_get_by_email(
        &self,
        tenant: &str,
        email: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<UserRecord, StoreError>> + Send;

    /// **幂等 upsert-by-user_id**(canonical-user,SaaS 审计 K):按 `user_id` **主键**建/取,`email` 留空。
    /// 供**联邦登录**(`user:fed:*`,无 email 语义,F2:email 不参与身份)落 UserRecord——使联邦用户
    /// 进入 `/admin/users` 管理面 + `require_active_user` gate(可 disable/delete),与本地 email 用户对等。
    /// 已存在 → 复用(不覆盖 created_at/status/attributes);不存在 → create Active。**不写 email GSI**。
    fn create_or_get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<UserRecord, StoreError>> + Send;

    /// 按 user_id 取记录(不存在 → None)。gate(require_active_user)数据源,真机强一致读。
    fn get_by_id(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// **只读 by-email 查(不 upsert)**:命中 → Some(记录),未注册 → None。email 归一(trim+lowercase)
    /// 由调用方负责(与 GSI email-index key 口径一致)。消费方 = CIBA `/bc-authorize` login_hint 存在性
    /// 校验(spec 013 §2b.5:login_hint=email → 解析为已注册 user_id;未注册拒 invalid_request)。
    /// 与 `create_or_get_by_email` 的区别:**绝不 create**(未注册就是未注册,不自动 onboard)。
    fn get_by_email(
        &self,
        tenant: &str,
        email: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Atomically claim tenant-scoped SCIM externalId/userName aliases and create or
    /// bind one canonical user. Exact retries return Existing.
    fn create_scim(
        &self,
        tenant: &str,
        input: ScimUserInput,
    ) -> impl Future<Output = Result<ScimCreateOutcome, StoreError>> + Send;

    /// Atomically start or resume the inactive lifecycle attached to one POST
    /// claim. If a newer SCIM operation already completed the claim, return
    /// `Complete` without changing the canonical user.
    fn begin_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<ScimCreateLifecycleStart, StoreError>> + Send;

    /// Mark the initial inactive-user lifecycle attached to a POST tuple complete.
    /// Idempotent retries then return current canonical state without replaying old intent.
    fn complete_scim_create_lifecycle(
        &self,
        tenant: &str,
        external_id: &str,
        user_name: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn get_scim_by_external_id(
        &self,
        tenant: &str,
        external_id: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    fn get_scim_by_user_name(
        &self,
        tenant: &str,
        user_name: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Return one stable, zero-based SCIM page and the exact number of visible
    /// SCIM users in the tenant.
    fn list_scim(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<(Vec<UserRecord>, usize), StoreError>> + Send;

    /// Atomically move supported SCIM aliases while preserving canonical user id.
    fn replace_scim(
        &self,
        tenant: &str,
        user_id: &str,
        input: ScimReplaceInput,
    ) -> impl Future<Output = Result<ScimReplaceOutcome, StoreError>> + Send;

    /// **分页列出用户**(admin 管理面,§1.4)。`status` 在分页前应用；`cursor` = 不透明续页
    /// token(Dynamo LastEvaluatedKey 编码;Memory 用偏移),`limit` 上限由调用方裁。
    /// 返回 `(records, next_cursor)`,next=None 表已到末页。
    /// 非法/篡改 cursor → `StoreError::Permanent`(调用方映射 **400** 非 500;cursor 是客户端输入)。
    /// **tenant-scope**:仅列本租户用户(空 tenant = 现网单租户全量)。
    fn list(
        &self,
        tenant: &str,
        limit: usize,
        cursor: Option<&str>,
        query: Option<&str>,
        status: UserListStatusFilter,
    ) -> impl Future<Output = Result<(Vec<UserRecord>, Option<String>), StoreError>> + Send;

    /// 尽力而为记录成功登录时刻。仅 Active 用户可推进,且时间戳单调递增;不存在、已禁用、
    /// 已 tombstone 或已有更新时刻的记录均为幂等 no-op。
    fn touch_last_login(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **置 status**(admin disable/enable/delete[tombstone],§1.4)。user_id 不存在 → `Ok(false)`
    /// (调用方按需 404/幂等);成功 → `Ok(true)`。Dynamo = UpdateItem(条件 attribute_exists)。
    /// **tombstone 终态(评审 codex Blocker)**:已 `Tombstoned` 的记录,置任何**非** Tombstoned 状态
    /// MUST 返回 `Ok(false)`(不改)——存储层堵死 delete→disable→enable 竞态复活;幂等再置 Tombstoned 允许。
    fn set_status(
        &self,
        tenant: &str,
        user_id: &str,
        status: UserStatus,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Start a self-service credential change only from the exact active user
    /// generation authenticated by the actor session. The write atomically
    /// advances `credential_epoch` and sets `revocation_pending`, making prior
    /// authentication artifacts non-authoritative before a credential changes.
    /// The HTTP operation generates `operation_id`; replaying that ID returns
    /// the already-started epoch, while another ID cannot own the pending fence.
    fn begin_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        operation_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<CredentialChangeStart, StoreError>> + Send;

    /// Clear a completed credential-change fence only when the active user is
    /// still at the exact pending generation owned by this operation.
    fn complete_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        owner: CredentialChangeOwner<'_>,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Recover an abandoned self-service or Admin credential fence after its
    /// lease. Tombstoned users and legacy pending rows without an operation
    /// marker fail closed. The epoch remains advanced, so stale authentication
    /// artifacts stay invalid.
    fn recover_expired_credential_change(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        started_before: i64,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Start or resume an idempotent disable generation.
    fn begin_disable(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<DisableStart, StoreError>> + Send;

    /// Clear pending only if the same generation is still disabled.
    fn complete_disable(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Atomically move a legacy Disabled user whose missing lifecycle generation
    /// reads as zero into generation one with cleanup pending. `None` means the
    /// record no longer matches that legacy state.
    fn begin_legacy_disable_cleanup(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Enable only after revocation completion and only if the Disabled epoch
    /// still matches the caller's strong-read snapshot. Never changes the
    /// epoch.
    fn enable_completed(
        &self,
        tenant: &str,
        user_id: &str,
        expected_epoch: u64,
        now: i64,
    ) -> impl Future<Output = Result<EnableOutcome, StoreError>> + Send;

    /// **全量替换某 namespace 的属性**(spec 007 §6.1,C8.12):乐观锁——`expected_revision` 与当前 namespace
    /// revision 不符 → `RevisionConflict`(handler 409,防两 admin 并发丢更新);`expected_revision=0` 视为
    /// "该 namespace 尚不存在"(首次写)。`kv` 为该 namespace 的完整新内容(空 map = 清空该 namespace)。
    /// **原子内校验**:合并后全部 namespace 序列化 > `ATTRIBUTES_MAX_BYTES` → `TooLarge`(413,不部分写);
    /// user 不存在 → `NotFound`(404);Tombstoned → `Tombstoned`(409,不复活)。成功返回新 revision。
    /// **tenant-scope**(codex B1);真机 DynamoDB 条件写(status≠tombstoned + revision CAS +
    /// attributes generation CAS),内存等价。
    fn put_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        namespace: &str,
        kv: std::collections::BTreeMap<String, String>,
        expected_revision: u64,
    ) -> impl Future<Output = Result<PutAttrOutcome, StoreError>> + Send;

    /// Atomically move or deduplicate exact-audience attribute keys into one canonical namespace.
    /// The adapter plans against its latest user snapshot and installs the complete map with an
    /// attributes-generation CAS. Different values return `Conflict` without mutation.
    fn migrate_attributes(
        &self,
        tenant: &str,
        user_id: &str,
        canonical_namespace: &str,
        source_namespaces: &std::collections::BTreeSet<String>,
    ) -> impl Future<Output = Result<AttributeMigrationOutcome, StoreError>> + Send;

    /// Atomically publish the irreversible user fence. Exact retries return
    /// the same tombstoned record; a different epoch fails closed.
    fn fence_for_erasure(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
        now: i64,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Physically remove a fenced canonical identity and its SCIM alias claims.
    /// Absence is an idempotent success; a non-fenced row fails closed.
    fn delete_erased_identity(
        &self,
        tenant: &str,
        user_id: &str,
        target_epoch: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

// ============ 本地密码凭证(spec 003 C9.8-C9.10)============

/// Password credential kept outside `UserRecord`. The hash wrapper has no
/// `Debug`/`Serialize`, preventing accidental API, log, or audit exposure.
#[derive(Clone)]
pub struct PasswordCredential {
    pub user_id: String,
    pub password_hash: agent_auth_authn::password::EncodedPasswordHash,
    pub must_change: bool,
    /// Initial provisioning or Admin reset has written the temporary
    /// credential but has not yet durably completed its authority checks and
    /// authentication-state cleanup.
    pub revocation_pending: bool,
    /// Owner of a staged Admin reset. Legacy and initial-provisioning rows have
    /// no owner and cannot resume an operation-owned user fence.
    pub credential_change_id: Option<String>,
    pub version: u64,
    pub updated_at: i64,
}

pub(crate) struct FencedPasswordMutation<'a> {
    pub(crate) tenant: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) password_hash: agent_auth_authn::password::EncodedPasswordHash,
    pub(crate) expected_version: Option<u64>,
    pub(crate) credential_epoch: u64,
    pub(crate) updated_at: i64,
}

/// Tenant-scoped persistent password credential store. Credentials have no TTL.
pub trait PasswordStore: Send + Sync {
    /// Strongly consistent read in the Dynamo adapter.
    fn get(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<Option<PasswordCredential>, StoreError>> + Send;

    /// Create the initial temporary credential without replacing an existing one.
    fn create_if_absent(
        &self,
        tenant: &str,
        credential: PasswordCredential,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Delete only the exact credential version created by an initial
    /// provisioning attempt. A concurrent reset or password change wins.
    fn delete_if_version(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// First-login password change CAS. It succeeds only when both the version
    /// matches and the current credential remains temporary.
    fn replace_if_version_and_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: u64,
        updated_at: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Admin reset: atomically upsert a temporary credential. Existing
    /// credentials keep a monotonically increasing version; missing
    /// credentials start at version 1.
    fn reset_temporary(
        &self,
        tenant: &str,
        user_id: &str,
        new_hash: agent_auth_authn::password::EncodedPasswordHash,
        expected_version: Option<u64>,
        updated_at: i64,
    ) -> impl Future<Output = Result<Option<u64>, StoreError>> + Send;

    /// Clear the durable pending marker only for the temporary credential
    /// version that completed all required authority checks and
    /// authentication-state cleanup.
    fn complete_reset_revocation(
        &self,
        tenant: &str,
        user_id: &str,
        expected_version: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Delete credential during user tombstoning. Missing is idempotent.
    fn delete(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only fallback for credentials whose canonical user is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

// ============ Admin-issued one-time invitations(issue #34)============

/// Persistent invitation verifier. The bearer secret is deliberately absent:
/// only its SHA-256 verifier is allowed to cross the storage boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRecord {
    /// Opaque HMAC locator derived from tenant + canonical user id.
    pub locator: String,
    /// Region activation that owns this one-time invitation.
    pub activation_id: String,
    pub user_id: String,
    pub email: String,
    pub verifier_hash: String,
    /// User lifecycle authority captured at issuance.
    pub credential_epoch: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationIssueOutcome {
    Issued,
    /// User is missing, non-local, non-active, or its authority snapshot moved.
    Ineligible,
    /// Invitation bootstrap is available only while no password exists.
    PasswordConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationAcceptRequest {
    pub locator: String,
    pub activation_id: String,
    pub verifier_hash: String,
    pub session_id: String,
    pub device: String,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationAcceptOutcome {
    Accepted { user_id: String, session_id: String },
    Invalid,
    Expired { user_id: String },
    Ineligible { user_id: String },
}

/// Dedicated invitation store. Implementations atomically bind issuance to an
/// active local user without a password, and atomically consume the verifier
/// with login-session creation. It is intentionally unrelated to
/// `MagicLinkStore`, its nonce, cooldown, callback, and notifier.
pub trait InvitationStore: Send + Sync {
    /// Overwrite the tenant/user's single locator row. A successful write
    /// immediately supersedes every previously returned bearer secret.
    fn issue(
        &self,
        tenant: &str,
        record: InvitationRecord,
    ) -> impl Future<Output = Result<InvitationIssueOutcome, StoreError>> + Send;

    /// Consume once and create `amr=["invite"]` session in the same atomic
    /// operation after rechecking user, password, epoch, and expiry.
    fn accept(
        &self,
        tenant: &str,
        request: InvitationAcceptRequest,
    ) -> impl Future<Output = Result<InvitationAcceptOutcome, StoreError>> + Send;

    /// Lifecycle invalidation. Missing rows are an idempotent success.
    fn invalidate(
        &self,
        tenant: &str,
        locator: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

// ============ P0.5 登录/consent(§7 / C9)============

/// AS 已认证会话(magic-link 登录后建立;consent 与 authorize 据此判"已登录")。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// 会话 id(写入 `__Host-` cookie 的不透明值)。
    pub session_id: String,
    /// 已认证用户的内部 user_id(pairwise sub 派生前的稳定标识)。
    pub user_id: String,
    /// User lifecycle generation captured when this session was created.
    pub credential_epoch: u64,
    /// auth_time(Unix 秒;OIDC max_age/prompt 用,C9.5)。
    pub auth_time: i64,
    /// Session creation time. Kept separate from upstream `auth_time`.
    pub created_at: i64,
    /// Last successful request authenticated by this session.
    pub last_used_at: i64,
    /// Normalized browser/platform label. Raw user-agent values are not persisted.
    pub device: String,
    /// 过期时刻(Unix 秒;短命项读写校 expires_at,C10.4)。
    pub expires_at: i64,
    /// Canonical assurance `acr` mapped from the verified login event.
    pub acr: Option<String>,
    /// 上游 `amr`(联邦登录透传;本地登录空)。签 token 时透传进 claim(C9.5b)。
    pub amr: Vec<String>,
}

/// 会话存储端口。真机 = DynamoDB;本地 = 内存。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键 + by-user 隔离,codex B1)。
pub trait SessionStore: Send + Sync {
    fn create(
        &self,
        tenant: &str,
        s: SessionRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send;
    /// 失效会话(logout / end-session,C9.6)。
    fn delete(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// List this user's unexpired login sessions. Never crosses tenant partitions.
    fn list_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<SessionRecord>, StoreError>> + Send;
    /// Delete one owned session only while the authenticated actor session is
    /// still authoritative for the user's current session generation.
    fn delete_owned(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
        target_session_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// Delete every session for this user except the retained current session.
    /// `Some(n)` is an exact logical count; `None` means the authority fence
    /// succeeded but an eventually consistent backend cannot know the count.
    fn delete_others_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        retained_session_id: &str,
    ) -> impl Future<Output = Result<Option<usize>, StoreError>> + Send;
    /// Atomically consume one authoritative actor session and advance the
    /// user's session generation. Exactly one concurrent credential mutation
    /// can win; every prior session becomes non-authoritative immediately.
    fn revoke_all_by_actor(
        &self,
        tenant: &str,
        user_id: &str,
        actor_session_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// Best-effort observation update. A missing/revoked session is never recreated.
    fn touch_last_used(
        &self,
        tenant: &str,
        session_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **吊销某 user 的所有会话**(账户恢复后 user-wide 吊销,防旧攻击者会话续用,codex 评审)。
    /// 返回吊销数。真机 DynamoDB 需 GSI(user_id)扫描删;内存遍历。**tenant-scope**(codex B1)。
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
    /// Delete only sessions captured before one user lifecycle generation.
    /// The epoch predicate must be part of each delete.
    fn delete_by_user_before_epoch(
        &self,
        tenant: &str,
        user_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
    /// **只读**:某 user 未过期会话数(admin get 全貌用,§1.4;不 mutating)。`now` 过期判定基准。
    fn count_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only physical cleanup of sessions and generation markers.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// 一组已下发恢复码的存储记录。**存储键 = `user_lookup`**(码带的非秘密前缀,让 `/recover` 无
/// 有效码时也能按 user 定位限流,codex 评审);`user_id` = 恢复成功后要登入的真实用户标识。
/// 码只存 HMAC(不存明文),含已消费标记 + 失败计数/锁定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecord {
    /// 存储主键:user_lookup(user_id 的非秘密短哈希)。
    pub user_lookup: String,
    /// 恢复成功后登入的真实 user_id。
    pub user_id: String,
    /// Region activation that owns this replay-sensitive recovery-code set.
    pub activation_id: String,
    /// 各码的 HMAC 哈希 + 是否已消费(一次性)。
    pub code_hashes: Vec<RecoveryCodeEntry>,
    /// 验码累计失败次数(达阈值锁定;成功/解锁才清)。
    pub attempt_count: u32,
    /// 锁定截止 Unix 秒(0 = 未锁)。
    pub locked_until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeEntry {
    /// HMAC-SHA256(server_secret, "recovery:"‖code) 的 base64url。
    pub hash_b64: String,
    pub consumed: bool,
}

/// Short-lived authoritative result for one recovery HTTP operation.
///
/// `operation_key` is a server-secret HMAC of the client operation ID. Neither
/// the plaintext recovery code nor the raw operation ID is persisted.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySuccessResult {
    pub(crate) operation_key: String,
    pub(crate) user_lookup: String,
    pub(crate) user_id: String,
    pub(crate) presented_hash: String,
    pub(crate) credential_epoch: u64,
    pub(crate) session_id: String,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}

impl std::fmt::Debug for RecoverySuccessResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoverySuccessResult")
            .field("operation_key", &"[REDACTED]")
            .field("user_lookup", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("presented_hash", &"[REDACTED]")
            .field("credential_epoch", &self.credential_epoch)
            .field("session_id", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// 一次验码消费的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryConsume {
    /// 命中某未消费码 → 已原子标记消费,返回 user_id。
    Valid,
    /// 码不匹配任何未消费码(失败,上层累加失败计数)。
    Invalid,
    /// 该 user 处于锁定窗口(失败过多)。
    Locked { retry_after_secs: i64 },
    /// user 无恢复码记录。
    NotFound,
    /// The user's authoritative credential generation changed before the
    /// recovery-code write could commit. The code was not consumed.
    AuthorityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryAuthorityConsume {
    /// The code and the prior authentication authority were consumed together.
    Valid {
        credential_epoch: u64,
    },
    /// A concurrent request already committed this exact operation.
    Replayed {
        result: RecoverySuccessResult,
    },
    Invalid,
    Locked {
        retry_after_secs: i64,
    },
    NotFound,
    PasswordChangeRequired,
    AuthorityChanged,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RecoveryConsumeRequest<'a> {
    pub(crate) tenant: &'a str,
    pub(crate) user_lookup: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) expected_email: &'a str,
    pub(crate) expected_epoch: u64,
    pub(crate) presented_hash: &'a str,
    pub(crate) now: i64,
}

/// 恢复码存储端口(**键 = user_lookup**)。真机 = DynamoDB(条件写做原子消费 + 失败计数);本地 = 内存。
///
/// **tenant 分区(spec 020 §2.3)**:方法首参 `tenant`(物理键前缀 `{tenant}\x1f{user_lookup}`)。
pub trait RecoveryStore: Send + Sync {
    /// 下发一组恢复码(覆盖旧集 = regenerate 使旧码失效)。键 = record.user_lookup。
    fn put(
        &self,
        tenant: &str,
        record: RecoveryRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 按 user_lookup 取恢复码记录。Dynamo adapter uses a strongly consistent
    /// primary-key read so lockout checks cannot observe a pre-consumption image.
    fn get(
        &self,
        tenant: &str,
        user_lookup: &str,
    ) -> impl Future<Output = Result<Option<RecoveryRecord>, StoreError>> + Send;

    /// Strongly read a short-lived success result by its server-derived
    /// operation key. Callers still validate expiry and current authority.
    fn get_success_result(
        &self,
        tenant: &str,
        operation_key: &str,
    ) -> impl Future<Output = Result<Option<RecoverySuccessResult>, StoreError>> + Send;

    /// **原子验码 + 消费**(键 = user_lookup):锁定则拒;否则比对 `presented_hash` 对未消费码,命中即
    /// 原子标记消费并清失败计数(返回 Valid);未命中累加失败计数(达阈值置锁定)返回 Invalid/Locked。
    /// `now` 由上层注入(锁定判定/设定)。
    fn verify_and_consume(
        &self,
        tenant: &str,
        user_lookup: &str,
        presented_hash: &str,
        now: i64,
    ) -> impl Future<Output = Result<RecoveryConsume, StoreError>> + Send;

    /// **删某 user 的恢复码记录**(admin disable/delete 级联,§1.4)。键 = user_lookup(调用方按同一
    /// `user_lookup` 派生口径算出传入)。不存在 → 幂等 `Ok(())`。真机 DeleteItem;内存 remove。
    fn delete_by_lookup(
        &self,
        tenant: &str,
        user_lookup: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only fallback for recovery sets whose identity row is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// magic-link 待兑现记录(link_id → canonical user + email + session nonce 绑定 + 一次性状态)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLinkRecord {
    pub link_id: String,
    /// Canonical identity selected when the link was issued. Email is mutable
    /// and must not be re-resolved to a different user at redemption.
    pub user_id: String,
    pub email: String,
    /// 发起浏览器会话 nonce(login-CSRF 绑定,C9.2)。
    pub session_nonce: String,
    /// authorize 上下文(登录成功后据此续 OAuth 流)。
    pub authorize_query: String,
    /// 登录后 `next` 回跳(AS 前端同源相对路径,兑现时再 sanitize;spec 003 P0.5)。空 = 无。
    pub next: String,
    pub expires_at: i64,
}

/// magic-link 存储端口:落地待兑现 link + per-email 冷却时间戳(C9.1)+ 一次性消费。
///
/// **tenant 分区(spec 020 §2.3,评审 codex High)**:link_id 主键 + `cool#{email}` 冷却键都按
/// tenant 物理隔离——否则(a)冷却键 `cool#{email}` 全局共享 → 租户 A 请求会占掉租户 B 同 email 的
/// 冷却槽(跨租户可用性耦合 + 存在性枚举 oracle);(b)link 记录不带 tenant → 租户 A 的 link 可能被
/// 租户 B 上下文消费。空 tenant(flag 关)→ tpk 透传 = 现网单租户字节等价。
pub trait MagicLinkStore: Send + Sync {
    fn put(
        &self,
        tenant: &str,
        link: MagicLinkRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Non-consuming lookup used to validate the complete signed link before
    /// the one-time consume. Production implementations must read strongly.
    fn get(
        &self,
        tenant: &str,
        link_id: &str,
    ) -> impl Future<Output = Result<Option<MagicLinkRecord>, StoreError>> + Send;

    /// **绑定浏览器会话的原子消费**(C9.1/C9.2):仅当记录中的 session nonce
    /// 与发起浏览器 cookie 相等时取出并删除;错浏览器、已用或不存在返回 None。
    fn consume_bound(
        &self,
        tenant: &str,
        link_id: &str,
        expected_session_nonce: &str,
    ) -> impl Future<Output = Result<Option<MagicLinkRecord>, StoreError>> + Send;

    /// 取某 email 上次发信时刻(per-email 固定窗口冷却判定用,C9.1);无则 None。
    fn last_sent_at(
        &self,
        tenant: &str,
        email: &str,
    ) -> impl Future<Output = Result<Option<i64>, StoreError>> + Send;

    /// 记录某 email 本次发信时刻(冷却窗口起点)。
    fn mark_sent(
        &self,
        tenant: &str,
        email: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Delete subject-linked links and deterministic plaintext cooldown keys.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
        aliases: &[String],
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only cleanup of pending links and plaintext cooldown aliases.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// 发送抽象(Notifier)——**发送渠道可换**:dev 打日志/返回链接;真机 = SES(邮件,magic-link
/// 的正解:事务性/任意收件人/HTML)/ 或 SNS(SMS/恢复通知,C9.3「恢复即通知」)。handler 零改。
/// magic-link 登录邮件用 SES(见 DESIGN §7/C9.1;SNS 只发已订阅地址、不适合登录邮件)。
pub trait Notifier: Send + Sync {
    /// 发送 magic-link 登录链接到 email。dev 实现打日志/回显、不真发。
    /// **tenant 分区(spec 020 §2.3 / C10.19)**:落 outbox 时按 tenant 前缀,防 `/admin/messages`
    /// 跨租户读到他人 magic-link 登录 URL(可重放凭证)+ email PII。
    fn send_magic_link(
        &self,
        tenant: &str,
        email: &str,
        link_url: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **恢复即通知**(C9.3):账户经恢复码恢复后通知旧联系邮箱(留审计痕迹、防静默接管)。
    /// `recipient_email` MUST 是可投递邮箱,不得传内部 canonical user id。dev 打日志;真机
    /// SES/SNS。`notification_id` 是服务端派生的非明文幂等键；同一恢复操作的重复调用
    /// MUST NOT 产生多封通知。`client_ip` 可选(记录来源)。tenant 分区同上。
    fn notify_recovery(
        &self,
        tenant: &str,
        notification_id: &str,
        recipient_email: &str,
        recovered_at: i64,
        client_ip: Option<&str>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// 一条已"发出"的消息(SES 未接前的 DynamoDB outbox 模拟,spec 003 §1.5 延后项)。
/// 真机 = 把 magic-link / recovery 通知落表(TTL=1 天自动 GC),便于观测"发了什么"而不真发邮件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// 消息 id(高熵;表主键)。
    pub message_id: String,
    /// **所属租户**(spec 020 §2.3):list_recent 按此过滤,防跨租户泄露。空 = 现网单租户。
    pub tenant: String,
    /// 渠道类型:`"magic_link"` / `"recovery"`。
    pub kind: String,
    /// 可投递邮箱地址。
    pub recipient: String,
    /// 正文/链接(magic_link=link_url;recovery=可读摘要)。
    pub body: String,
    /// 发出时刻(Unix 秒)。
    pub created_at: i64,
    /// TTL 过期时刻(Unix 秒;= created_at + 1 天,DynamoDB 自动 GC)。
    pub ttl: i64,
}

/// 消息 outbox 读端口(SES 模拟表的查询面;admin/e2e 观测"发了什么")。
/// 写路径由 Notifier 的 DynamoDB 实现负责;这里只读。内存实现供 UT。
pub trait MessageOutbox: Send + Sync {
    /// 取**本租户**最近 `limit` 条消息(按 created_at 倒序;量小全表 Scan,量大另建 GSI,见 spec 020)。
    /// **tenant-scope(C10.19)**:MUST 只返回 `tenant` 分区内的消息——`/admin/messages` 绝不跨租户
    /// 泄露他人 magic-link URL(可重放)/ email PII。空 tenant(flag 关)= 现网单租户全量(字节等价)。
    fn list_recent(
        &self,
        tenant: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SentMessage>, StoreError>> + Send;

    /// Remove notification bodies addressed to aliases of one erased user.
    fn delete_by_recipients(
        &self,
        tenant: &str,
        recipients: &[String],
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only cleanup of the tenant's short-lived notification outbox.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

// ============ spec 005 应用层限流(C10.7)============

/// per-key(client_id)令牌桶限流存储(spec 005 §3.1 / C10.7)。令牌桶**算法**在
/// `agent_auth_infra_core::ratelimit`(纯逻辑,已测);本 port 提供不写状态的可用性检查与
/// 原子读-改-写消费。
///
/// `check_available`:读取当前桶状态并计算是否可取 `cost`,但不写回、不消费。
/// `try_consume`:读当前桶状态 → `ratelimit::try_acquire`(补 token + 取 cost)→ **条件写回**新状态
/// (乐观并发:写条件 = 桶未被并发改动)。返回是否放行 + Retry-After 秒(拒时)。
/// 存储瞬时错误统一返回 `Err`,由调用方选择策略:CIBA 等普通 anti-abuse gate fail-open(C7b.6);
/// 密码认证 gate 按 C9.10 fail-closed。
pub trait RateLimitStore: Send + Sync {
    /// Check whether `cost` tokens are currently available without consuming
    /// them. Callers that only want to charge a failed operation use this
    /// before the operation, then call `try_consume` on failure.
    fn check_available(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> impl Future<Output = Result<RateLimitDecision, StoreError>> + Send;

    /// 对 `key`(如 `client_id`)取 `cost` 个 token。`capacity`/`refill_per_sec` 为该桶配置。
    /// 返回 `RateLimitDecision`。存储错误 → `Err`(由调用方决定 fail-open/fail-closed)。
    fn try_consume(
        &self,
        key: &str,
        now: i64,
        capacity: f64,
        refill_per_sec: f64,
        cost: f64,
    ) -> impl Future<Output = Result<RateLimitDecision, StoreError>> + Send;

    /// Governance cleanup for the tenant's globally unique client key.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// 限流判定结果(C10.7)。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitDecision {
    /// 放行?
    pub allowed: bool,
    /// 拒时的 Retry-After 秒(向上取整;None=无法估算,用兜底)。
    pub retry_after_secs: Option<i64>,
}

// ============ spec 004 授权会话状态机(C6)============

/// 授权会话记录(spec 004)。**与 magic-link 登录 `SessionRecord` 是两个独立概念**:
/// 本记录追踪一次 authorize 流从发起到 complete 的生命周期。存独立表/PK 前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzSessionRecord {
    /// 授权会话 id(查询用;高熵不透明串)。
    pub session_id: String,
    /// owner client_id(confidential 归属校验 + GSI 列表)。
    pub client_id: String,
    /// Authenticated user once the flow reaches a user-bound step.
    pub user_id: Option<String>,
    /// 当前状态(authz_session::AuthzState 的字符串,docs §4)。
    pub state: String,
    /// session_token 的 HMAC 哈希(存哈希不存明文;public 客户端鉴权用,常量时间比对 C6.2)。
    pub session_token_hash: String,
    /// 每会话单调递增序号(C6.5 事件投影去重排序)。
    pub sequence: u64,
    /// 结构化 last_error(exchange_failed 时;schema 见 spec 004)。None = 无。
    pub last_error: Option<String>,
    /// 过期时刻(Unix 秒;fail-closed 校验 C10.4;= 发起 + 30min)。
    pub expires_at: i64,
}

/// 授权会话存储端口。真机 = DynamoDB(独立表 + GSI client_id);本地 = 内存。
/// **tenant 分区(spec 020 §2.3,评审 codex Blocker)**:授权会话是**每客户端的授权流状态**——
/// `list_by_client`(C6.1 confidential 发现)若不 tenant-scope,tenant B 用同 client_id 可读 tenant A
/// 的授权会话状态(跨租户泄露)。方法首参 `tenant`(物理 pk + GSI client_id 值 tenant 化)。
pub trait AuthzSessionStore: Send + Sync {
    /// 创建授权会话(authorize 受理时)。
    fn create(
        &self,
        tenant: &str,
        record: AuthzSessionRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 按 session_id 取(未命中 None)。
    fn get(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<Option<AuthzSessionRecord>, StoreError>> + Send;

    /// 迁移到新状态(条件:非终态才可迁;合法性由上层纯逻辑判)。同时 sequence++、
    /// 可选写 last_error。返回迁移后记录;未命中/已终态/非法迁移返回 None(上层据此拒)。
    fn transition(
        &self,
        tenant: &str,
        session_id: &str,
        new_state: &str,
        last_error: Option<String>,
        now: i64,
    ) -> impl Future<Output = Result<Option<AuthzSessionRecord>, StoreError>> + Send;

    /// Bind an authenticated user without allowing a later user substitution.
    fn bind_user(
        &self,
        tenant: &str,
        session_id: &str,
        user_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<AuthzSessionRecord>, StoreError>> + Send;

    /// Remove one authorization session after a failed user-ownership fence.
    fn delete(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// 列出某 client 名下会话 id(GSI client_id;C6.1 confidential 发现路径)。**tenant-scope**(codex Blocker)。
    fn list_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    /// 统计**活跃**授权会话数(非终态 + 未过期,以 `now` 判过期;admin overview 用,spec 025)。
    /// 内存 = 遍历;DynamoDB = 分页 Scan + filter(量大另建投影,见 spec 020)。**tenant-scope**
    /// (空 tenant = 全局,现网单租户 / 控制面 overview)。
    fn count_active(
        &self,
        tenant: &str,
        now: i64,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only physical cleanup before the owning client is removed.
    fn delete_by_client(
        &self,
        tenant: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only fallback for orphan sessions whose client is absent.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// 授权会话状态迁移的**事件投影端口**(C6.5)。dev = log/内存 sink;真机 = EventBridge(P2)。
/// 权威源永远是 DynamoDB 会话记录;本端口只把带序号的投影发出去,at-least-once、无序。
pub trait AuthzEventSink: Send + Sync {
    fn emit(
        &self,
        session_id: &str,
        sequence: u64,
        state: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

// ============ spec 013 CIBA / device flow(C7b)============

/// CIBA 授权请求记录(spec 013;pk=auth_req_id)。轮询判定的权威源。
/// `status` 存 `agent_auth_ciba::PollStatus` 的字符串(pending/approved/denied)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaAuthRequest {
    pub auth_req_id: String,
    /// 所属租户,spec 020 §2.3 隔离。
    pub tenant: String,
    pub client_id: String,
    /// 经 login_hint 归一解析出的内部 user_id(推送目标 + 批准归属)。
    pub user_id: String,
    /// 关联的授权会话(004 状态机;可观测旁路)。
    pub authz_session_id: Option<String>,
    pub scope: Vec<String>,
    pub resources: Vec<String>,
    /// 可选 binding_message(≤200 字符;批准页展示)。
    pub binding_message: Option<String>,
    /// 下发的轮询间隔(秒)。
    pub interval: i64,
    /// 上次轮询时刻(判 slow_down;None=未轮询过)。
    pub last_poll_at: Option<i64>,
    /// 过期时刻(Unix 秒;fail-closed 校验)。
    pub expires_at: i64,
    /// pending / approved / denied(批准动作驱动)。
    pub status: String,
    /// 已取过 token(一次性;重放拒)。
    pub consumed: bool,
    // ── ping/push 投递(spec 013 §4,C7b.5;快照进记录,投递按快照不读当前 ClientRecord,防发起↔批准间 PATCH 篡改)──
    /// 快照的投递模式(发起 /bc-authorize 时从 client 记录取:None/poll/ping/push)。None=poll。
    pub delivery_mode: Option<String>,
    /// 快照的回调通知端点(ping/push;发起时从 client 记录取)。None=poll。
    pub notification_endpoint: Option<String>,
    /// per-request `client_notification_token`(OIDC CIBA Core §7.1:client 每次请求提供,≥128-bit,≤1024;
    /// 回调放 `Authorization: Bearer` 供 client 验回调来源)。**port 层持明文**(同 grace 响应/client_secret
    /// 范式);**真机 DynamoStore MUST envelope-encrypt(复用 grace KMS 信封);dev Memory 存明文**。禁日志。
    /// None=poll(无回调)。
    pub client_notification_token: Option<String>,
    /// 用户批准时捕获的本地密码 authority 版本；编码同 [`CodeRecord::password_credential_version`]。
    pub password_credential_version: Option<u64>,
}

/// device 授权记录(spec 013;pk=device_code)。`user_code` 另有独立查找。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthGrant {
    pub device_code: String,
    /// 用户在另一设备输入的短码(规范化大写,防混淆字符集)。
    pub user_code: String,
    pub client_id: String,
    /// 批准后填(经批准页的登录用户)。
    pub user_id: Option<String>,
    pub authz_session_id: Option<String>,
    pub scope: Vec<String>,
    pub resources: Vec<String>,
    pub interval: i64,
    pub last_poll_at: Option<i64>,
    pub expires_at: i64,
    pub status: String,
    pub consumed: bool,
    /// 用户批准时捕获的本地密码 authority 版本；编码同 [`CodeRecord::password_credential_version`]。
    pub password_credential_version: Option<u64>,
}

/// CIBA 授权请求存储端口(spec 013)。真机 = DynamoDB;本地 = 内存。
///
/// 并发/一次性语义与 [`DeviceStore`] 同源(evaluated 教训:device flow 评审 F1/F2 揭示"整对象读-改-写"
/// 会重开已消费码/踩并发批准)。故轮询/批准/消费一律走**字段级/条件 CAS**,`update` 只用于非并发路径。
///
/// **tenant 分区(spec 020 §2.3)**:全 8 方法首参 `tenant`(物理键 `tpk(tenant, auth_req_id)` +
/// throttle 键 tenant-scope)——否则 SaaS 下 CIBA 请求可被他租户审批/签发(跨租户隔离漏洞)。
/// 空 tenant(flag 关)→ tpk 透传 = 分区前字节等价。照 DeviceStore 同一范式。
pub trait CibaStore: Send + Sync {
    fn put(
        &self,
        tenant: &str,
        r: CibaAuthRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn get(
        &self,
        tenant: &str,
        auth_req_id: &str,
    ) -> impl Future<Output = Result<Option<CibaAuthRequest>, StoreError>> + Send;
    /// 覆盖写(仅非并发路径,如受理时初次落库)。状态迁移/消费/节流请用下列原子原语。
    fn update(
        &self,
        tenant: &str,
        r: CibaAuthRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// **原子消费**(一次性;同 DeviceStore::consume):CAS `consumed:false→true`,仅赢家 true。
    /// 签发**前**调用,false=已消费(重放/并发落败,拒)。
    fn consume(
        &self,
        tenant: &str,
        auth_req_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **原子占用轮询槽位**(同 DeviceStore::claim_poll):仅当当前 `last_poll_at` 仍等于调用方
    /// 读到的 `observed_last_poll_at` 时 SET 新值。返回 false=记录已不存在或并发 poll 已抢先更新。
    fn claim_poll(
        &self,
        tenant: &str,
        auth_req_id: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **原子批准/拒绝**(同 DeviceStore::decide):CAS `status:pending→(approved|denied)`,
    /// 绝不触碰 consumed/last_poll_at。返回 true=赢得转移;false=已被决定/不存在。
    fn decide(
        &self,
        tenant: &str,
        auth_req_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **释放消费标记**(签名 503 回滚;同 DeviceStore::release_consume):字段级 SET consumed=false。
    fn release_consume(
        &self,
        tenant: &str,
        auth_req_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// **原子占用**某 `login_hint`(归一后 user_id)的 `/bc-authorize` 冷却窗(防批准疲劳,C7b.6;
    /// 与 magic-link per-email 冷却 C9.1 对称)。**check+mark 合一**(评审 codex MEDIUM:分离的
    /// 读-判-写在并发突发下可被绕过——多个请求同读旧值、全过闸)。语义:
    /// - 当前无记录 **或** 上次受理时刻 ≤ `now - window_secs`(窗外)→ **占用成功**,写入 `now`,返回 `true`(放行);
    /// - 否则(窗内)→ 返回 `false`(拒,调用方返 429),**不覆盖**已有时刻(窗口不因被拒请求延长)。
    ///
    /// Dynamo 走条件写(CAS),内存走临界区,保证同一 user_id 并发只一个 `true`。
    /// throttle 键亦按 `tenant` tpk 隔离(spec 020 §2.3:防跨租户冷却串扰)。
    fn try_arm_throttle(
        &self,
        tenant: &str,
        user_id: &str,
        now: i64,
        window_secs: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Governance-only physical deletion of CIBA requests and throttle state.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only cleanup including pending requests and throttle rows.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

/// CIBA ping/push 回调投递请求(spec 013 §4,C7b.5)。承载一次向 client notification endpoint 的 POST。
#[derive(Debug, Clone)]
pub struct CibaCallbackRequest {
    /// 快照的通知端点(已过注册 SSRF 结构校验;adapter 投递前 MUST 再 DNS 复校 + 连接固定到已校验 IP)。
    pub notification_endpoint: String,
    /// per-request client_notification_token(明文;放 `Authorization: Bearer`;禁日志)。
    pub client_notification_token: String,
    /// POST body 的 JSON(ping = `{"auth_req_id":...}`;push = 完整 token 响应 + auth_req_id)。
    pub body: serde_json::Value,
}

/// 回调投递结果(spec 013 §4:签发前失败 vs 签发后失败的处置在 handler 决定,adapter 只报投递结果)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaDeliveryOutcome {
    /// client 返回 2xx——投递成功。
    Delivered,
    /// 投递前 SSRF 复校拒(DNS rebind 到私网/端点已不可解析)——**未发出任何请求**,token 安全未泄露。
    /// handler 据此可安全退化 poll(push token 尚未签发/未发出)。
    BlockedBySsrf,
    /// 已发出请求但失败(网络/超时/非 2xx)——**模糊态**:无法区分 client 是否已收到 body。
    /// handler 对 push MUST 视为已消费终态(不重签、不退化);对 ping 无副作用(token 未随回调消费)。
    Failed,
}

/// CIBA ping/push 回调投递端口(spec 013 §4)。真机 = reqwest(SSRF 复校 + 连接固定 + redirect 禁 + 熔断);
/// dev/测试 = 内存 mock(记录投了什么,供 e2e 断言;可注入"下一次投递结果"模拟失败/SSRF)。
/// **投递前 SSRF 复校 + 连接固定到已校验 IP** 是真机 adapter 的 MUST(纯逻辑判定复用
/// `agent_auth_ciba::resolved_ips_allowed`);此端口只约定"投递一次并返回结果"的契约。
pub trait CibaCallbackDelivery: Send + Sync {
    fn deliver(&self, req: CibaCallbackRequest)
        -> impl Future<Output = CibaDeliveryOutcome> + Send;
}

/// device 授权存储端口(spec 013)。`get_by_user_code` 供验证页按短码定位。
///
/// **tenant 分区(spec 020 §2.3,评审 codex Medium)**:device_code(128-bit 高熵)本身跨租户碰撞可忽略,
/// 但 `user_code` 仅 8 位大写字母(~2^37),跨租户会碰撞 → 租户 B 用户可能批准租户 A 的 device 请求。
/// 故 device_code 主键 + user_code GSI 均按 tenant tpk 隔离,全 8 方法接 tenant。空 tenant(flag 关)透传单租户。
pub trait DeviceStore: Send + Sync {
    fn put(
        &self,
        tenant: &str,
        r: DeviceAuthGrant,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn get(
        &self,
        tenant: &str,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceAuthGrant>, StoreError>> + Send;
    fn get_by_user_code(
        &self,
        tenant: &str,
        user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceAuthGrant>, StoreError>> + Send;
    fn update(
        &self,
        tenant: &str,
        r: DeviceAuthGrant,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// **原子消费**(spec 013 一次性;评审 codex/Kiro HIGH):条件写 `consumed: false→true`,
    /// 仅当当前 `consumed==false` 时成功(返回 true)。并发/重放只有一个 true → 恰好签发一次 token。
    /// 返回 false = 已被消费(重放,拒);签发**前**调用,失败(false)即不签。
    fn consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **原子占用轮询槽位**:只在当前 `last_poll_at` 仍等于调用方读到的观察值时
    /// `SET last_poll_at`,不碰 status/user_id。返回 false=记录已不存在或并发 poll 已抢先更新。
    fn claim_poll(
        &self,
        tenant: &str,
        device_code: &str,
        observed_last_poll_at: Option<i64>,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **原子批准/拒绝**(评审 codex F1 二轮:`approve_by_user_code` 若整对象覆盖写,会把轮询开始时
    /// 读到的旧快照 `consumed=false` 写回、重开已消费的 device_code → 再签第二个 token)。
    /// CAS `status: "pending"→(approved|denied)` + `SET user_id`,条件仅当当前 `status=="pending"`;
    /// **绝不触碰 `consumed`/`last_poll_at`**。返回 true=本次赢得批准转移;false=已被决定/不存在。
    fn decide(
        &self,
        tenant: &str,
        device_code: &str,
        user_id: &str,
        password_credential_version: Option<u64>,
        approve: bool,
        now: i64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// **释放消费标记**(签名瞬时失败回滚,评审 codex F1 二轮):字段级 `SET consumed=false`,
    /// 仅当 device_code 仍存在且 `expires_at > now`;best-effort。不整对象写(避免踩
    /// last_poll_at/status 旧快照),也不得重开已过期 grant。
    fn release_consume(
        &self,
        tenant: &str,
        device_code: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Governance-only physical deletion of approved/denied user requests.
    fn delete_by_user(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;

    /// Governance-only cleanup including unapproved requests with no user id.
    fn delete_all_by_tenant(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}
