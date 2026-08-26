//! Agent Auth spec 003 [a] — 用户认证层纯逻辑(零 AWS 依赖)。
//!
//! 本 crate 承载 spec 003 CONFORMANCE C9 的 **P0 纯逻辑**([a] 类;SES 发信、DynamoDB 状态、
//! magic-link 端到端 e2e 属 [c] 真机,不在此)。认证层是"用户身份层",独立于 `infra-core` 的
//! 基础设施通用原语(rate-limit/lifecycle/websec),故单列一个 crate;需要时**复用** `infra-core`。
//!
//! 模块:
//! - `cooldown`:C9.1 — per-email **固定窗口冷却**(发后即冷却,**非令牌桶**)。
//! - `magic_link`:C9.2 login-CSRF(link↔session nonce 绑定)+ C9.1 短命一次性(≤10min,fail-closed)。
//!
//! **C9.1 全局发信配额**那一半(跨邮箱洪水的速率限流)= 令牌桶,直接复用
//! `infra_core::ratelimit`(见 `global_email_quota` re-export),不在本 crate 另造。
//!
//! 所有涉及时间/随机/持久状态的入参(now、nonce、last_sent_at、already_used)均由上层注入
//! (不读墙上时钟、不自取随机、不落库),便于确定性单测。
//! 决策真相源:docs/DESIGN §7·§8·§2.1;docs/CONFORMANCE C9.1·C9.2。

pub mod assurance;
pub mod authz_session;
pub mod cooldown;
pub mod federation;
pub mod magic_link;
pub mod passkey;
pub mod password;
pub mod recovery;

pub use cooldown::{
    check as check_cooldown, is_allowed as cooldown_allowed, CooldownConfig, CooldownDecision,
};
pub use magic_link::{
    compute_tag, open as open_magic_link, validate_ttl, MagicLink, OpenError,
    MAX_MAGIC_LINK_TTL_SECS,
};

/// C9.1 全局发信配额 = 令牌桶,复用 `infra_core::ratelimit`。
/// 用法:对"全局发信"这一个逻辑桶按速率取 token(跨所有邮箱共享),token 不足即拒新发信,
/// 防跨大量邮箱的发信洪水拖垮 SES 信誉。per-email 冷却(见 `cooldown`)是另一半、语义不同。
pub mod global_email_quota {
    pub use agent_auth_infra_core::ratelimit::{
        retry_after_secs, try_acquire, BucketConfig, BucketState, Decision,
    };
}
