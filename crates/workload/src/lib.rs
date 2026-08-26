//! Agent Auth spec 012 —— workload 机器身份认证**纯逻辑**(零 IO、零 AWS)。
//!
//! 覆盖(不依赖真实 STS/JWKS 的纯逻辑部分):
//! - `client_type`:client 形态枚举(public/confidential/workload),workload 仅管理面显式设(H1)。
//! - `trust`:workload 信任绑定数据模型 + 匹配语义(精确 / glob 前缀单段)+ 认证成功输出
//!   `WorkloadIdentity`(供 2LO 签发 + spec 011 身份闸,H2/M5)。
//! - `sigv4`:SigV4 `client_assertion` 封装 + `SignedHeaders=` 解析 + audience 头**被签名覆盖**核对
//!   (C5.2:未签名的伪造 audience 头拒;不真调 STS,只做纯解析,H3)。
//!
//! 决策真相源:docs/DESIGN §3.1;CONFORMANCE C5.1–C5.6。真实 STS 转发/OIDC JWKS 验签/熔断属 IO 层
//! (http 适配器),不在此;本 crate 只做"匹配 / 解析 / 判定"的确定性契约。

pub mod circuit;
pub mod client_type;
pub mod jwt_es256;
pub mod jwt_rs256;
pub mod oidc;
pub mod replay;
pub mod sigv4;
pub mod spiffe;
pub mod trust;
pub mod x509;

pub use circuit::{CircuitBreaker, CircuitState, Decision, FAILURE_THRESHOLD, OPEN_COOLDOWN_SECS};
pub use client_type::{ClientType, ClientTypeError};
pub use jwt_es256::{verify_es256, Es256Error};
pub use jwt_rs256::{verify_rs256, Rs256Error, VerifiedJwt};
pub use oidc::{authorize_oidc, OidcAuthError};
pub use replay::{
    extract_signature, parse_amz_date, sts_host_allowed, within_ttl, SIGV4_MAX_AGE_SECS,
};
pub use sigv4::{
    audience_signed, parse_get_caller_identity, parse_signed_headers, validate_sigv4_pre_sts,
    SigV4Assertion, SigV4RejectReason, SigV4Validated, StsCallerIdentity,
};
pub use spiffe::{authorize_spiffe_jwt, SpiffeAuthError};
pub use trust::{
    match_oidc, match_sigv4, match_spiffe, match_spiffe_x509, pattern_match, spiffe_id_matches,
    spiffe_trust_domain, MatchError, PrincipalKind, TrustBinding, TrustMechanism, WorkloadIdentity,
};
pub use x509::{spiffe_id_from_leaf_pem, X509Error, X509SvidSubject};
