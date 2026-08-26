//! Agent Auth spec 005 [a] — 架构面纯逻辑(零 AWS 依赖)。
//!
//! 本 crate 只承载 spec 005 CONFORMANCE C10 里**可脱离 AWS 单测的算法/状态机**([a] 类);
//! CDK-TS 基础设施编排([b])与真机 e2e([c],含 P-1 spike KMS Sign)不在此(见 spec 005 实现边界)。
//!
//! 模块:
//! - `signature`:C10.3 — KMS ECDSA DER ↔ JOSE(裸 `r‖s`)签名格式转换。
//! - `jwks`:C10.11a — `kid` = JWK thumbprint(RFC 7638)+ 双活选键。
//! - `alg`:C10.15a — access token 恒 ES256 不变量守卫。
//! - `lifecycle`:C10.4/C10.6 — 短命项 `expires_at` 读写校验 + 全局时钟偏移余量。
//! - `ratelimit`:C10.7/C10.8 — 应用层令牌桶(per-client / per-IP 兜底)。
//! - `lease`:C10.1 — 两阶段 lease 三失败分治状态机。
//! - `websec`:C10.9/C10.9b/C10.10 — CSRF token、clickjacking 头、CORS 按端点分类。
//!
//! 所有涉及时间/随机的函数均由上层注入 `now`/nonce(不读墙上时钟、不自取随机),便于确定性单测。
//! 决策真相源:docs/DESIGN §8·§2.1·§2;docs/CONFORMANCE C10.*。

pub mod alg;
pub mod client_reclaim;
pub mod jwks;
pub mod lease;
pub mod lifecycle;
pub mod ratelimit;
pub mod signature;
pub mod tenant_keys;
pub mod websec;

pub use alg::{assert_access_es256, check_alg, AlgError, TokenKind};
pub use jwks::{
    ec_jwk_from_spki_der, ec_kid, ec_thumbprint, p256_xy_from_spki_der, rsa_jwk_from_ne, rsa_kid,
    rsa_thumbprint, select_verifying_key, EcJwk, JwkEntry, PubKeyError, RsaJwk,
};
pub use lease::{
    handle_request, lease_expired, resolve, try_acquire_lease, ClientSignal, GrantCredential,
    LeaseResolution, LeaseState, SignOutcome,
};
pub use lifecycle::{
    check_time_claims, key_retire_earliest, shortlived_is_expired, shortlived_is_valid,
    TimeClaimError, DEFAULT_CLOCK_SKEW_SECS,
};
pub use ratelimit::{retry_after_secs, try_acquire, BucketConfig, BucketState, Decision};
pub use signature::{
    der_to_jose, jose_to_der, DerError, JoseError, ES256_JOSE_SIG_LEN, P256_COORD_LEN,
};
pub use tenant_keys::{
    AlgorithmSnapshot, CandidateGeneration, CandidateKey, EcPublicJwk, KeyMaterial, RsaPublicJwk,
    TenantKeyAlgorithm, TenantKeyCompletionOutcome, TenantKeyFailure, TenantKeyLifecycle,
    TenantKeyOperation, TenantKeyOperationKind, TenantKeyRecord, TenantKeySnapshot,
    TenantKeyStateError,
};
pub use websec::{
    cors_decision, csrf_token, csrf_verify, interactive_page_security_headers, CorsClass,
    CorsDecision,
};
