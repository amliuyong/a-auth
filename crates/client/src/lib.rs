//! Agent Auth spec 002 — 客户端准入面(纯逻辑,零 AWS 依赖)。
//!
//! - `redirect`:C4.4a/C4.5 — redirect_uri canonicalize + exact/loopback 匹配(安全关键)。
//! - `pkce`:C4.1 — PKCE S256 授权校验 + 兑换阶段 verifier↔challenge 绑定。
//! - `downgrade`:C4.7 — 安全降级字段级单调性判定 + 未知字段 fail-safe。
//!
//! DCR 端点/registration_access_token 存储与鉴权、consent UI、PATCH/PUT 落库属签发端(HTTP + DynamoDB),
//! 随 spec 005/006 与 HTTP 层落地;本 crate 只做可脱离 AWS 单测的纯判定逻辑。
//! canonicalize 规则权威在 docs/DESIGN §3.3;prefix/通配匹配属 P1,不在本 crate。
//!
//! 决策真相源:docs/DESIGN §3.1·§3.2·§3.3、docs/CONFORMANCE C4。

pub mod auth_method;
pub mod downgrade;
pub mod pkce;
pub mod redirect;

pub use auth_method::{
    enabled_private_key_jwt_signing_alg_names, enabled_registered_client_auth_method_names,
    executable_private_key_jwt_signing_alg_names, executable_registered_client_auth_method_names,
    RegisteredClientAuthMethod, EXECUTABLE_REGISTERED_CLIENT_AUTH_METHODS,
};
pub use downgrade::{classify, evaluate, ChangeVerdict, DowngradeReport, FieldChange};
pub use pkce::{
    check_authorize, s256_challenge, valid_verifier_format, verify_exchange, PkceCheck,
};
pub use redirect::{match_redirect, MatchResult, RedirectMode};
