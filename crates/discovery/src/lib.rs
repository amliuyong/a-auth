//! Agent Auth spec 000 — discovery / metadata 发现面。
//!
//! 纯逻辑、零 AWS 依赖:issuer 派生(C1.6a)/ 两份 metadata 生成(C1.1/1.3/1.4/1.5/1.6)/
//! 分阶段过滤 + 永久非目标(C1.2/C1.2b)/ subject_types 宣告(C1.1b)/ state 回填(C1.7)。
//!
//! 决策真相源:docs/DESIGN §0·§1·§2.8、docs/DEPLOYMENT §0、docs/CONFORMANCE C1。
//! 本 crate 不做签名/流程/AWS 调用 —— 只保证"发现面如实"这一契约,便于脱离 AWS 单测。

pub mod issuer;
pub mod key_group;
pub mod metadata;
pub mod phase;
pub mod prm;
pub mod state_echo;

pub use issuer::{
    assert_iss_belongs_to_tenant, derive as derive_issuer, issuer_for_tenant, tenant_id_from, Form,
    Issuer, IssuerError,
};
pub use metadata::{
    oauth_authorization_server, openid_configuration, Metadata, MetadataConfig, SubjectType,
    OIDC_ONLY_FIELDS, OIDC_REQUIRED_FIELDS, SHARED_FIELDS,
};
pub use phase::Phase;
pub use prm::{build as build_prm, Prm, PrmConfig};
pub use state_echo::echo_state;
