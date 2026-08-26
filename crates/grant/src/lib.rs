//! Agent Auth spec 011 §5.1 — **Grant 授权记录对象** + 委托约束校验(纯逻辑,零 IO/AWS)。
//!
//! Grant 是用户授权的**权威记录**(P2 起正式化;P0/P1 由 refresh-family 前身兜底,见 011 Task 1.2)。
//! 按 resource 结构化(`per_resource[]`),不用扁平数组——否则"哪个 scope/RAR 属哪个 RS"只能靠命名规约
//! 隐式担保(docs §5.1)。本 crate 只做**数据模型 + 校验判定**(确定性可测);存储/迁移/`/grants` API 属 IO
//! 层(http)。
//!
//! 校验核心(token-exchange / refresh 下采样消费,C7.3/C7.4):
//! - `status == Active`(吊销/过期即拒);
//! - 目标 `resource ∈ per_resource`(超出即 invalid_target);
//! - 请求 `scope ⊆ 该 resource 的 scopes`(超出即 invalid_scope);
//! - 委托:actor ∈ `constraints.actor_allowlist`(身份闸)、链深 + 本跳 ≤ `max_act_chain`(深度闸)。
//!
//! 决策真相源:docs/DESIGN §5.1(Grant 结构)、§5.2(委托双闸);CONFORMANCE C7。

pub mod rar;

use serde::{Deserialize, Serialize};

/// Grant 状态(docs §5.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    /// 活跃:可换发/下采样。
    Active,
    /// 已吊销(用户/管理面吊销;终态)。
    Revoked,
    /// 已过期(`constraints.expires_at` 到期;终态)。
    Expired,
}

/// 单个 resource 的授权(scopes + RAR),docs §5.1 `per_resource[]`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGrant {
    /// 目标 RS 标识(RFC 8707 resource)。
    pub resource: String,
    /// 该 RS 授予的 scope 集合(换发/下采样时请求 scope MUST ⊆ 此集;空集 = 该 RS 默认/最小权限)。
    pub scopes: Vec<String>,
    /// RFC 9396 RAR(可选;精细化授权约束,由 RS SDK 执行,C8.5a)。存原始 JSON 数组元素。
    #[serde(default)]
    pub authorization_details: Vec<serde_json::Value>,
}

/// 委托约束(docs §5.1 `constraints`)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantConstraints {
    /// 深度闸(C7.2):委托链最大嵌套层数。默认 1(只允许一级委托)。
    pub max_act_chain: u32,
    /// 身份闸(C7.2/§5.2):可作 actor 的 workload 准入集合(精确 client_id 或 SPIFFE 前缀通配)。
    /// **空集 = 不允许任何委托**(fail-closed;绝不默认取 owning agent)。
    pub actor_allowlist: Vec<String>,
    /// Grant 过期时刻(Unix 秒;fail-closed 读路径校)。
    pub expires_at: i64,
}

/// Grant 授权记录(docs §5.1;P2 权威源)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// 高熵不透明 id(3LO token 的 `grant_id` claim 指回它)。
    pub grant_id: String,
    /// 授权主体(内部 user_id;绝不是 pairwise sub)。
    pub user_id: String,
    /// 授权发起的 3LO OAuth 客户端(≠ 委托 actor;actor 由 actor_allowlist 约束)。
    pub client_id: String,
    /// **用户授权(consent)权威记录 = 换发/重算的输入天花板**(spec 005 §7 补强 ⑧)。按 resource 结构化
    /// (scopes + RAR)。**只随用户 re-consent 变;Cedar 策略预判绝不覆写它**(否则策略放宽后无法还原授权意图、
    /// `/grants` 自助页 + 审计失真)。签发**不直接读它**——读 `effective_view()`(下)。
    pub per_resource: Vec<ResourceGrant>,
    /// **生效预判 = 授权 ∩ 策略**(spec 005 §7,C10.17)。Cedar 在 Grant 创建 + 每次重算时算、写此字段;
    /// 签发热路径实际用它(经 `effective_view()`)。恒 ⊆ `per_resource`(绝不越 consent)。
    /// **是否已评估看 `effective_pv`(0=未评估),不看本字段是否空**(补强 ⑯:已评估结果也可能空——无可评估单元;
    /// resource-ful 被全 deny 的 (pv≥1, 空) 状态由创建 fail-closed / 重算吊销拦下,绝不持久化)。
    #[serde(default)]
    pub effective_per_resource: Vec<ResourceGrant>,
    /// 生效字段所依据的**策略版本快照**(逐租户 policy_version)。`< current_pv` = stale(热路径 fail-safe 拒)。
    #[serde(default)]
    pub effective_pv: u64,
    /// §7.2 请求上下文:允许来源 IP CIDR(空 = 不限)。Cedar 预判写;热路径内联比对(非 Cedar)。
    #[serde(default)]
    pub allowed_ip_cidrs: Vec<String>,
    /// §7.2:允许 VPC endpoint id(空 = 不限)。
    #[serde(default)]
    pub allowed_vpce: Vec<String>,
    /// User lifecycle generation captured when this Grant was created.
    #[serde(default)]
    pub credential_epoch: u64,
    /// 乐观并发版本(spec 005 §7 补强 ⑫):重算条件写(CAS on revision)防覆盖并发吊销/consent 更新。
    #[serde(default)]
    pub revision: u64,
    pub constraints: GrantConstraints,
    pub status: GrantStatus,
}

/// Grant 校验的拒绝原因(token-exchange / 下采样消费;映射到 OAuth 错误码由 IO 层做)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// 非 Active(吊销/过期)→ invalid_grant。
    NotActive,
    /// Grant 已过期(constraints.expires_at ≤ now)→ invalid_grant。
    Expired,
    /// 目标 resource 不在 Grant 的 per_resource → invalid_target。
    ResourceNotGranted,
    /// 请求 scope 超出该 resource 的授权集 → invalid_scope。
    ScopeExceedsGrant,
    /// 委托链深度(入站 + 本跳)超 max_act_chain → invalid_grant(深度闸)。
    ActChainTooDeep,
    /// 发起 actor 不在 actor_allowlist → access_denied(身份闸)。
    ActorNotAllowed,
}

impl Grant {
    /// Grant 是否活跃可用(status==Active 且未过期)。`now` 由调用方传入(零时钟)。
    pub fn is_usable(&self, now: i64) -> Result<(), GrantError> {
        if self.status != GrantStatus::Active {
            return Err(GrantError::NotActive);
        }
        if self.constraints.expires_at <= now {
            return Err(GrantError::Expired);
        }
        Ok(())
    }

    /// **生效视图**(spec 005 §7 补强 ⑧/⑯):判据 = **`effective_pv == 0`**(是否**已评估**),**不是** `effective_per_resource`
    /// 是否为空(评审 Blocker:后者把三态混一——①未评估 ②已评估无可评估单元[空]③已评估被全 deny[空]——
    /// 会把"已评估被全 deny 的 resource-ful Grant"误当未评估、回退 `per_resource` 全集 = 热路径签出被拒授权)。
    /// - `effective_pv == 0`(未评估:flag 关 / 未 bump 过策略 / 旧记录)→ 回退 `per_resource`(=授权,字节等价现网)。
    /// - `effective_pv >= 1`(已评估)→ 用 `effective_per_resource`,**哪怕空**(空 = 无可评估单元;resource-ful 被全 deny
    ///   的 Grant 由创建 fail-closed / 重算吊销拦下,绝不以 (pv≥1, 空) 状态持久化——见补强 ⑯不变量)。
    ///
    /// 签发一律经此,不直读 `per_resource`。
    pub fn effective_view(&self) -> &[ResourceGrant] {
        if self.effective_pv == 0 {
            &self.per_resource
        } else {
            &self.effective_per_resource
        }
    }

    /// 取某 resource 的**生效**授权(None = 未授权/未生效该 RS)。读 `effective_view()`。
    pub fn resource_grant(&self, resource: &str) -> Option<&ResourceGrant> {
        self.effective_view()
            .iter()
            .find(|r| r.resource == resource)
    }

    /// 取某 resource 的**授权(consent 层)**条目(None = 用户从未授权该 RS)。读 `per_resource`(**不经**
    /// `effective_view`)。用于消歧 `resource_grant`(effective)返 None(spec 006 §3.4,评审 Blocker):
    /// `evaluate` 丢弃空 scope+无 RAR 的 resource,故 effective 返 None **不等于**被策略 deny——须回查此 consent 层:
    /// 命中且空 scope+无 RAR = RS 默认权限(签空 scope 不拒);命中有 scope/RAR 但 effective 无 = 真 deny;未命中 = 未授权。
    pub fn consent_grant(&self, resource: &str) -> Option<&ResourceGrant> {
        self.per_resource.iter().find(|r| r.resource == resource)
    }

    /// **换发/下采样校验**(C7.3/C7.4):目标 resource ∈ Grant + 请求 scope ⊆ 该 resource 授权集。
    /// `requested_scopes` 为空 = 继承该 resource 全部授权 scopes(返回它们);非空则须逐个 ⊆。
    /// 返回**授予的 scope 集**(继承或请求的交集验证后原样返回)。**先校 usable**。
    pub fn authorize_target(
        &self,
        resource: &str,
        requested_scopes: &[String],
        now: i64,
    ) -> Result<Vec<String>, GrantError> {
        self.is_usable(now)?;
        let rg = self
            .resource_grant(resource)
            .ok_or(GrantError::ResourceNotGranted)?;
        if requested_scopes.is_empty() {
            // 省略 scope → 继承该 resource 全部授权 scopes(docs §6)。
            return Ok(rg.scopes.clone());
        }
        // 请求 scope MUST 逐个 ∈ 该 resource 授权集(超出即拒,不内联补授权,C7.3)。
        let granted: std::collections::HashSet<&str> =
            rg.scopes.iter().map(String::as_str).collect();
        if requested_scopes
            .iter()
            .any(|s| !granted.contains(s.as_str()))
        {
            return Err(GrantError::ScopeExceedsGrant);
        }
        Ok(requested_scopes.to_vec())
    }

    /// **委托双闸校验**(C7.2/§5.2):身份闸(actor ∈ allowlist)+ 深度闸(入站链深 + 本跳 ≤ max)。
    /// `inbound_act_depth` = subject_token 已含 act 的嵌套层数(0=未委托);本跳 +1。
    /// `actor_id` = 已认证发起 actor 的 client_id(SPIFFE 前缀通配由 `actor_matches` 判)。
    pub fn authorize_delegation(
        &self,
        actor_id: &str,
        inbound_act_depth: u32,
    ) -> Result<(), GrantError> {
        // 身份闸:actor ∈ allowlist(空集 = 不许委托;绝不默认放行)。
        if !self
            .constraints
            .actor_allowlist
            .iter()
            .any(|pat| actor_matches(pat, actor_id))
        {
            return Err(GrantError::ActorNotAllowed);
        }
        // 深度闸:入站链深 + 本跳 ≤ max_act_chain(saturating 防溢出)。
        if inbound_act_depth.saturating_add(1) > self.constraints.max_act_chain {
            return Err(GrantError::ActChainTooDeep);
        }
        Ok(())
    }
}

/// actor_allowlist 匹配(§5.2):精确 client_id,或 SPIFFE ID 末尾 `/*` 前缀通配(单段,fail-closed)。
/// 纯 `*` / 空 pattern MUST NOT 匹配一切(防信任边界绕过)。
pub fn actor_matches(pattern: &str, actor_id: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return false; // 空/纯通配绝不放行
    }
    if let Some(prefix_slash) = pattern.strip_suffix('*') {
        // SPIFFE 前缀通配 `.../*`:actor 须以 `prefix_slash`(含末尾 `/`)开头**且其后至少一段**
        // (`*` 代表一个或多个字符;`.../agent/` 空段不匹配)。prefix_slash 须以 `/` 结尾防裸 `*`。
        prefix_slash.ends_with('/')
            && prefix_slash.len() > 1
            && actor_id.starts_with(prefix_slash)
            && actor_id.len() > prefix_slash.len()
    } else {
        pattern == actor_id
    }
}

/// refresh-family 前身 → Grant 迁移的约束默认(011 Task 1.4 / 评审 Kiro M5):前身载体无 actor_allowlist/
/// max_act_chain 源,故迁移生成的 Grant `max_act_chain=1`、`actor_allowlist` **仅含 owning agent(绝不通配)**、
/// `expires_at` 继承 family。此助手集中该口径,避免各处各写。
pub fn migration_constraints(owning_agent_id: &str, family_expires_at: i64) -> GrantConstraints {
    GrantConstraints {
        max_act_chain: 1,
        actor_allowlist: vec![owning_agent_id.to_string()],
        expires_at: family_expires_at,
    }
}

/// **扁平授权集的 scope 下采样/交集**(RFC 6749 §6 / DESIGN §1:156)。`Grant::authorize_target` 的
/// **无-resource-结构版**:当授权载体是扁平集(refresh-family 记录 `scope`,或 aud=`/userinfo` 等
/// 不在 `per_resource` 的目标)时用它,与 `authorize_target` **同语义**(空请求→继承全集;请求 scope
/// 逐个 MUST ∈ 授权集,超出→`ScopeExceedsGrant`,**不静默丢弃**,RFC 6749 §6;子集→原样返回)。
///
/// 收敛评审(2026-07-12):此前 token_exchange 无-Grant 回退分支内联抄了一份同逻辑;抽此共享自由函数,
/// refresh 下采样 + token_exchange 扁平回退共用,错误码统一走 `ScopeExceedsGrant`(→ `invalid_scope`)。
pub fn narrow_flat_scope(
    authorized: &[String],
    requested: &[String],
) -> Result<Vec<String>, GrantError> {
    if requested.is_empty() {
        return Ok(authorized.to_vec()); // 省略 → 继承全集(§6 / authorize_target 同口径)
    }
    let granted: std::collections::HashSet<&str> = authorized.iter().map(String::as_str).collect();
    if requested.iter().any(|s| !granted.contains(s.as_str())) {
        return Err(GrantError::ScopeExceedsGrant); // 含未授权 scope → 拒(不内联补授权)
    }
    Ok(requested.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> Grant {
        Grant {
            grant_id: "gnt_1".into(),
            user_id: "alice".into(),
            client_id: "app-3lo".into(),
            per_resource: vec![
                ResourceGrant {
                    resource: "https://mcp.kb.example.com".into(),
                    scopes: vec!["kb:read".into(), "kb:search".into()],
                    authorization_details: vec![],
                },
                ResourceGrant {
                    resource: "https://mcp.mail.example.com".into(),
                    scopes: vec!["mail:read".into()],
                    authorization_details: vec![],
                },
            ],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec!["wl-actor".into(), "spiffe://acme/agent/*".into()],
                expires_at: 2_000_000_000,
            },
            status: GrantStatus::Active,
        }
    }

    #[test]
    fn usable_active_not_expired() {
        assert!(grant().is_usable(1_000_000_000).is_ok());
    }

    #[test]
    fn not_usable_when_revoked_or_expired() {
        let mut g = grant();
        g.status = GrantStatus::Revoked;
        assert_eq!(g.is_usable(1_000_000_000), Err(GrantError::NotActive));
        let mut g2 = grant();
        assert_eq!(g2.is_usable(2_000_000_001), Err(GrantError::Expired));
        g2.status = GrantStatus::Expired;
        assert_eq!(g2.is_usable(1), Err(GrantError::NotActive));
    }

    #[test]
    fn authorize_target_scope_subset() {
        let g = grant();
        let now = 1_000_000_000;
        // 请求子集 → 返回请求集。
        assert_eq!(
            g.authorize_target("https://mcp.kb.example.com", &["kb:read".into()], now),
            Ok(vec!["kb:read".into()])
        );
        // 省略 scope → 继承全部。
        assert_eq!(
            g.authorize_target("https://mcp.kb.example.com", &[], now),
            Ok(vec!["kb:read".into(), "kb:search".into()])
        );
        // 超出授权集 → 拒。
        assert_eq!(
            g.authorize_target("https://mcp.kb.example.com", &["kb:write".into()], now),
            Err(GrantError::ScopeExceedsGrant)
        );
        // 未授权的 resource → 拒。
        assert_eq!(
            g.authorize_target("https://other.rs", &[], now),
            Err(GrantError::ResourceNotGranted)
        );
    }

    // RFC 6749 §6 / DESIGN §1:156:扁平 scope 下采样(refresh + token_exchange 扁平回退共用)。
    #[test]
    fn narrow_flat_scope_semantics() {
        let auth: Vec<String> = vec!["kb:read".into(), "kb:search".into()];
        // 省略请求 → 继承全集。
        assert_eq!(narrow_flat_scope(&auth, &[]), Ok(auth.clone()));
        // 子集 → 原样返回(下采样成功)。
        assert_eq!(
            narrow_flat_scope(&auth, &["kb:read".into()]),
            Ok(vec!["kb:read".into()])
        );
        // 全集(顺序不同)→ 通过(集合语义,顺序无关)。
        assert_eq!(
            narrow_flat_scope(&auth, &["kb:search".into(), "kb:read".into()]),
            Ok(vec!["kb:search".into(), "kb:read".into()])
        );
        // 含未授权 scope → 拒(RFC 6749 §6:MUST NOT include not-granted,不静默丢弃)。
        assert_eq!(
            narrow_flat_scope(&auth, &["kb:read".into(), "kb:write".into()]),
            Err(GrantError::ScopeExceedsGrant)
        );
        // 与 authorize_target 同语义:空授权集 + 空请求 → 空(继承空)。
        assert_eq!(narrow_flat_scope(&[], &[]), Ok(vec![]));
        // 空授权集 + 非空请求 → 拒(任何 scope 都超)。
        assert_eq!(
            narrow_flat_scope(&[], &["x".into()]),
            Err(GrantError::ScopeExceedsGrant)
        );
    }

    #[test]
    fn authorize_target_rejects_when_not_usable() {
        let mut g = grant();
        g.status = GrantStatus::Revoked;
        assert_eq!(
            g.authorize_target("https://mcp.kb.example.com", &[], 1_000_000_000),
            Err(GrantError::NotActive)
        );
    }

    #[test]
    fn delegation_identity_and_depth_gates() {
        let g = grant();
        // actor 精确命中 + 入站深度 0(本跳=1 ≤ max 1)→ 通过。
        assert!(g.authorize_delegation("wl-actor", 0).is_ok());
        // actor SPIFFE 前缀命中。
        assert!(g
            .authorize_delegation("spiffe://acme/agent/kb-1", 0)
            .is_ok());
        // actor 不在 allowlist → 拒。
        assert_eq!(
            g.authorize_delegation("evil-agent", 0),
            Err(GrantError::ActorNotAllowed)
        );
        // 入站已 1 层(本跳=2 > max 1)→ 深度超限。
        assert_eq!(
            g.authorize_delegation("wl-actor", 1),
            Err(GrantError::ActChainTooDeep)
        );
    }

    #[test]
    fn delegation_deeper_chain_when_max_raised() {
        let mut g = grant();
        g.constraints.max_act_chain = 3;
        assert!(g.authorize_delegation("wl-actor", 2).is_ok()); // 2+1=3 ≤ 3
        assert_eq!(
            g.authorize_delegation("wl-actor", 3),
            Err(GrantError::ActChainTooDeep)
        ); // 3+1=4 > 3
    }

    #[test]
    fn empty_allowlist_denies_all_delegation() {
        let mut g = grant();
        g.constraints.actor_allowlist = vec![];
        assert_eq!(
            g.authorize_delegation("wl-actor", 0),
            Err(GrantError::ActorNotAllowed)
        );
    }

    #[test]
    fn actor_matches_exact_and_spiffe_prefix() {
        assert!(actor_matches("wl-actor", "wl-actor"));
        assert!(!actor_matches("wl-actor", "wl-actor2"));
        assert!(actor_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/agent/kb"
        ));
        assert!(!actor_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/other/x"
        ));
        // 前缀本身不匹配(须有子段)。
        assert!(!actor_matches(
            "spiffe://acme/agent/*",
            "spiffe://acme/agent/"
        ));
        // 纯通配/空 fail-closed。
        assert!(!actor_matches("*", "anything"));
        assert!(!actor_matches("", "anything"));
    }

    #[test]
    fn migration_constraints_fail_closed_defaults() {
        let c = migration_constraints("agt-owner", 1_700_000_000);
        assert_eq!(c.max_act_chain, 1);
        assert_eq!(c.actor_allowlist, vec!["agt-owner".to_string()]);
        assert_eq!(c.expires_at, 1_700_000_000);
        // 迁移默认下,只有 owning agent 可委托,别人拒。
        let g = Grant {
            grant_id: "g".into(),
            user_id: "u".into(),
            client_id: "c".into(),
            per_resource: vec![],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: c,
            status: GrantStatus::Active,
        };
        assert!(g.authorize_delegation("agt-owner", 0).is_ok());
        assert_eq!(
            g.authorize_delegation("other", 0),
            Err(GrantError::ActorNotAllowed)
        );
    }

    #[test]
    fn grant_serde_roundtrip() {
        let g = grant();
        let json = serde_json::to_string(&g).unwrap();
        let back: Grant = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    // spec 005 §7 补强 ⑧:effective 非空 → authorize_target 读 effective(策略预判);空 → 回退授权(现网/flag 关)。
    #[test]
    fn authorize_target_reads_effective_falls_back_to_authorized() {
        let mut g = grant(); // per_resource: kb -> {kb:read, kb:search}
        let kb = "https://mcp.kb.example.com";
        // effective 空 → 回退授权:可换 kb:search(授权内)。
        assert!(g
            .authorize_target(kb, &["kb:search".into()], 1_000_000_000)
            .is_ok());
        // 设 effective 收窄成 {kb:read} + **打 pv 戳(已评估)** → 换 kb:search 被拒(生效以 effective 为准,恒 ⊆ 授权)。
        // 补强 ⑯:effective_view 判据 = effective_pv==0?未评估:已评估;故须 pv≥1 才走 effective(否则回退 per_resource)。
        g.effective_pv = 1;
        g.effective_per_resource = vec![ResourceGrant {
            resource: kb.into(),
            scopes: vec!["kb:read".into()],
            authorization_details: vec![],
        }];
        assert_eq!(
            g.authorize_target(kb, &["kb:search".into()], 1_000_000_000),
            Err(GrantError::ScopeExceedsGrant)
        );
        assert!(g
            .authorize_target(kb, &["kb:read".into()], 1_000_000_000)
            .is_ok());
    }

    // 补强 ⑯ Blocker 1:effective_view 判据 = effective_pv==0(是否已评估),非 is_empty()。
    #[test]
    fn effective_view_gates_on_pv_not_emptiness() {
        let mut g = grant(); // per_resource: kb + mail(2 项)
        let pr_len = g.per_resource.len();
        // ① 未评估(pv==0)+ effective 空 → 回退 per_resource(字节等价现网)。
        assert_eq!(g.effective_pv, 0);
        assert_eq!(
            g.effective_view().len(),
            pr_len,
            "pv==0 未评估 → 回退 per_resource 全集"
        );
        // ② 已评估(pv≥1)+ effective 空 → 用 effective(空),**不回退**(修复:已评估被全 deny 的 resource-ful
        //    Grant 不再 fail-open 签出 per_resource 全集)。
        g.effective_pv = 1;
        g.effective_per_resource = vec![];
        assert_eq!(
            g.effective_view().len(),
            0,
            "pv>=1 已评估 + effective 空 → 用空 effective,MUST NOT 回退 per_resource(热路径 fail-open 修复)"
        );
    }

    // 补强 ⑯ / spec 006 §3.4:consent_grant 读 per_resource(consent 层),消歧 resource_grant(effective) 返 None。
    #[test]
    fn consent_grant_reads_consent_layer_disambiguates_effective_none() {
        let mut g = grant(); // per_resource: kb {read,search} + mail {read}
        let kb = "https://mcp.kb.example.com";
        let mail = "https://mcp.mail.example.com";
        // 已评估(pv≥1):effective 只保留 kb(收窄成 {read}),mail 被策略全 deny(丢弃)。
        g.effective_pv = 1;
        g.effective_per_resource = vec![ResourceGrant {
            resource: kb.into(),
            scopes: vec!["kb:read".into()],
            authorization_details: vec![],
        }];
        // effective 命中 kb;mail 在 effective 无(resource_grant 返 None)。
        assert_eq!(
            g.resource_grant(kb).unwrap().scopes,
            vec!["kb:read".to_string()]
        );
        assert!(
            g.resource_grant(mail).is_none(),
            "mail 被策略全 deny → effective 无"
        );
        // consent 层两者都在:mail 有 scope(→ 真 deny 消歧);未授权的 rs 则 consent 也无(→ invalid_target)。
        assert_eq!(
            g.consent_grant(mail).unwrap().scopes,
            vec!["mail:read".to_string()]
        );
        assert!(
            g.consent_grant("https://unknown.example.com").is_none(),
            "未授权 rs → consent 无"
        );
    }

    // consent 空 scope+无 RAR(RS 默认权限):effective 丢弃 → resource_grant None,但 consent_grant 命中且空。
    #[test]
    fn consent_grant_empty_scope_default_permission() {
        let rs = "https://mcp.default.example.com";
        let g = Grant {
            grant_id: "g".into(),
            user_id: "u".into(),
            client_id: "c".into(),
            per_resource: vec![ResourceGrant {
                resource: rs.into(),
                scopes: vec![], // RS 默认/最小权限(合法形态)
                authorization_details: vec![],
            }],
            effective_per_resource: vec![], // evaluate 丢弃空 scope+无 RAR 项
            effective_pv: 1,                // 已评估(preserve)
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch: 0,
            revision: 0,
            constraints: GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec![],
                expires_at: i64::MAX,
            },
            status: GrantStatus::Active,
        };
        assert!(
            g.resource_grant(rs).is_none(),
            "effective 丢弃空 scope 项 → None"
        );
        let cg = g.consent_grant(rs).expect("consent 层仍有该条目");
        assert!(
            cg.scopes.is_empty() && cg.authorization_details.is_empty(),
            "consent 空 scope+无 RAR = RS 默认权限(refresh 据此签空 scope 不拒)"
        );
    }

    // serde 向后兼容:旧 Grant JSON(无新字段)→ 反序列化到 default(effective 空 / pv 0 / revision 0)。
    #[test]
    fn serde_backward_compat_old_grant_missing_new_fields() {
        let old = r#"{"grant_id":"g1","user_id":"u","client_id":"c","per_resource":[],"constraints":{"max_act_chain":1,"actor_allowlist":[],"expires_at":9999999999},"status":"active"}"#;
        let g: Grant = serde_json::from_str(old).unwrap();
        assert_eq!(g.effective_pv, 0);
        assert!(g.effective_per_resource.is_empty());
        assert!(g.allowed_ip_cidrs.is_empty());
        assert!(g.allowed_vpce.is_empty());
        assert_eq!(g.revision, 0);
        // effective 空 → effective_view 回退 per_resource(字节等价现网)。
        assert_eq!(g.effective_view().len(), 0);
    }
}
