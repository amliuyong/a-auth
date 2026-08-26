//! Agent Auth spec 013 —— CIBA / device flow 异步授权**纯逻辑**(零 IO、零 AWS)。
//!
//! 覆盖(不依赖存储/网络的决策核心):
//! - `poll`:轮询决策——slow_down(瞬时频率信号)+ 状态→标准错误码矩阵(C7b.2/C7b.4)。
//! - `hint`:login_hint 三型的**归一意图**分类(实际验签/定位属 IO 层,此处只定形状 + 键推导)。
//! - `state`:CIBA/device 态 ↔ 004 AuthzState 的映射(C6.4)。
//! - `user_code`:device user_code 生成字符集/格式 + 规范化(防混淆字符,RFC 8628 §6.1)。
//!
//! 决策真相源:docs/DESIGN §5.2 / §2.1;CONFORMANCE C7b。存储记录(CibaAuthRequest/DeviceAuthGrant)、
//! 推送、验签、批准端点属 IO 层(http),不在此。

pub mod callback_ssrf;
pub mod hint;
pub mod poll;
pub mod state;
pub mod user_code;

pub use callback_ssrf::{
    ip_is_blocked, resolved_ips_allowed, validate_endpoint_url, EndpointUrlError,
};
pub use hint::{normalize_key, HintKind};
pub use poll::{poll_decision, PollOutcome, PollStatus};
pub use state::{ciba_state_seq, ciba_state_str, CibaState};
pub use user_code::{canonicalize_user_code, is_valid_user_code_charset};
