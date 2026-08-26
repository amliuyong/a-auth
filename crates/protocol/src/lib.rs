//! Agent Auth spec 006 — 协议面结构契约(纯逻辑,零 AWS 依赖)。
//!
//! - `resource`:C2.5a/2.5b/2.8 — resource 绑定、`/token` audience 选择顺序、MCP RS 判定、
//!   authorize↔token 绑定、P0 多 resource authorize 阶段拒、`/userinfo` 隔离。
//! - `endpoints`:DESIGN §1 — 端点清单 / grant 矩阵 × 阶段归属(复用 discovery::Phase)。
//!
//! audience 优先级/pairwise 派生的唯一权威在 docs §2.8(本 crate 只落端点侧选择顺序 + 绑定判定,
//! 不重写派生规则)。HTTP 端点接入、会话记录落库(spec 004)、PRM/RS SDK(spec 010)不在本 crate。
//!
//! 决策真相源:docs/DESIGN §1·§2.8、docs/CONFORMANCE C2.5a·C2.5b·C2.8·C2.11。

pub mod endpoints;
pub mod resource;

pub use endpoints::{endpoint_available, endpoints, grant_accepted, grants, Endpoint};
pub use resource::{
    classify_target, select_audience, userinfo_allowed, AudienceSelection, AuthorizeError,
    AuthorizePhase, AuthorizedResources, ClientRegistration, RequestTarget, TokenError,
};
