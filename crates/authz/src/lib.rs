//! Cedar 授权判定纯逻辑(C10.17)——**cedar 依赖隔离于此 crate,零 AWS**。
//!
//! 决策/契约权威:`docs/DESIGN.md` 与 `docs/CONFORMANCE.md`。本 crate 只做**纯判定**:
//! - [`PolicyArtifact`]:不可变策略工件(parse + validate + digest);
//! - [`evaluate`]:`授权 ∩ 策略 → effective`(对每 (resource, scope) 用 Cedar 判 permit,收窄;恒 ⊆ 授权);
//! - [`ip_in_cidrs`]:§7.2 请求上下文 CIDR 匹配(空 = 不限;坏 CIDR/IP → fail-closed Err);
//! - [`intersect_rar`]:声明式 RAR(C8.5a 词汇表内)按 `type` 过滤,未知 type 剔除(fail-closed)。
//!
//! **绝不**在此做 IO / 网络 / AWS 调用。签发热路径也**绝不**调本 crate 的 `evaluate`(只在创建/重算时调)。

mod context;
mod evaluate;
mod policy;

pub use context::{intersect_rar, ip_in_cidrs};
pub use evaluate::{evaluate, Effective, GrantInput};
pub use policy::PolicyArtifact;

/// 判定错误。**`PolicyParse` 与"策略 deny"严格可辨**(fail-closed 前提:运维要能区分"策略坏了"vs"策略正常拒")。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// 策略文本 parse/validate 失败(工件坏,非 deny)。
    PolicyParse(String),
    /// 存储的 CIDR 非法(§7.2 fail-closed:坏 allowlist 不放行)。
    BadCidr(String),
    /// 请求来源 IP 非法(§7.2 fail-closed)。
    BadIp(String),
    /// Cedar 求值/实体构造错误。
    Eval(String),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzError::PolicyParse(s) => write!(f, "policy parse: {s}"),
            AuthzError::BadCidr(s) => write!(f, "bad cidr: {s}"),
            AuthzError::BadIp(s) => write!(f, "bad ip: {s}"),
            AuthzError::Eval(s) => write!(f, "eval: {s}"),
        }
    }
}

impl std::error::Error for AuthzError {}
