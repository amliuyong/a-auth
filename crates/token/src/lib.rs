//! Agent Auth spec 001 — Token 设计与生命周期(纯逻辑,零 AWS 依赖)。
//!
//! - `claims`:C2.1/2.2a/2.3/2.4/2.5a/2.6 — token claim 形状、命名空间对象、`aud` 编码、`act` 链。
//! - `fingerprint`:C3.2 — 宽限窗请求指纹(HMAC-SHA256,构成钉死)+ 全维度判定。
//! - `refresh`:C3.1/C3.5 — refresh family 状态机,rotation + 复用检测 → 全链吊销。
//! - `subject`:C2.11 — pairwise/sector `sub` 派生(§2.8 唯一权威的**实现**;公式不外泄到别处)。
//!
//! 签名(KMS)、DynamoDB 存储、信封加密属 spec 005/§8,不在本 crate。
//! `sub` 的 pairwise/sector 派生**在本 crate 的 `subject` 模块实现**(§2.8 唯一权威源落于此),
//! 其它能力域只调用 `derive_user_sub`、不复写公式。
//!
//! 决策真相源:docs/DESIGN §2·§2.1·§2.8、docs/CONFORMANCE C2·C3。

pub mod claims;
pub mod fingerprint;
pub mod refresh;
pub mod subject;

pub use claims::{
    act_chain_depth, build_act_chain, check_jwt_size, encode_aud, namespace_object, validate_shape,
    SizeBudget, SubType, JWT_HARD_LIMIT_BYTES, JWT_SOFT_TARGET_BYTES, NAMESPACE, NAMESPACE_KEYS,
    RESERVED_CLAIMS,
};
pub use fingerprint::{decide, fingerprint, GraceDecision, GraceIdentity, GraceRequest};
pub use refresh::{ConsumeOutcome, RefreshFamily};
pub use subject::{derive_user_sub, oidc_sector_from_redirect_hosts, pairwise_sub, SubjectMode};
