//! C2.5a / C2.5b / C2.8 — resource 绑定 / audience 选择 / MCP RS 判定 / authorize↔token 绑定。
//!
//! 结构契约(纯逻辑,不签名、不落库):
//! - "面向 MCP RS" 判定三分支(带 resource / 有 default_resource / 纯 OIDC)。
//! - `/token` audience 选择顺序:显式 resource > 继承 code-bound 单值 > 省略优先级(default/userinfo)。
//! - authorize↔token 绑定:token 选定的 resource MUST ∈ authorize 声明集合。
//! - P0 多 resource:authorize 阶段即拒(集合恒单值)。
//!
//! audience 优先级/pairwise 派生的**唯一权威在 docs §2.8**;本模块只落"端点侧选择顺序 + 绑定判定"。
//! 决策真相源:docs/DESIGN §1、§2.8;docs/CONFORMANCE C2.5a/C2.5b/C2.8。

/// `/authorize` 声明并绑定的 resource 集合(写入会话记录,见 spec 004)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedResources(Vec<String>);

/// authorize 阶段的多 resource 门控(**二分**:P0 拒多值 / P1+ 允许集合)。
///
/// ⚠️ 独立于 `agent_auth_discovery::Phase`(P0/P0.5/P1/P2/P3 **五段**,用于端点/grant 阶段归属,
/// 见本 crate `endpoints` 模块)——本枚举只关心"是否允许多 resource",故只需二分;
/// 命名为 `AuthorizePhase` 以区分,避免与五段 Phase 混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizePhase {
    P0,
    /// P1+ 允许多 resource 集合。
    P1Plus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeError {
    /// P0 阶段带多个 resource(C2.5a:每 RS 单独授权)。
    MultiResourceRejectedP0,
}

impl AuthorizedResources {
    /// 从 `/authorize` 请求的 resource 列表构造授权集合。
    /// - P0:0 或 1 个 resource(多个直接拒,C2.5a)。
    /// - P1+:允许多个。
    pub fn from_authorize(
        resources: &[String],
        phase: AuthorizePhase,
    ) -> Result<Self, AuthorizeError> {
        if phase == AuthorizePhase::P0 && resources.len() > 1 {
            return Err(AuthorizeError::MultiResourceRejectedP0);
        }
        Ok(AuthorizedResources(resources.to_vec()))
    }

    /// authorize 是否绑定了恰好一个单值 resource(用于 token 继承判定)。
    pub fn single_bound(&self) -> Option<&str> {
        if self.0.len() == 1 {
            Some(&self.0[0])
        } else {
            None
        }
    }

    /// 是否为空(authorize 未绑定任何 resource → 走省略优先级)。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 某 resource 是否 ∈ 授权集合(authorize↔token 绑定校验)。
    pub fn contains(&self, resource: &str) -> bool {
        self.0.iter().any(|r| r == resource)
    }
}

/// 客户端注册的 audience 相关配置。
#[derive(Debug, Clone, Default)]
pub struct ClientRegistration {
    /// 注册的 default_resource(省略 resource 时的默认绑定);None = 未注册。
    pub default_resource: Option<String>,
}

/// `/token` 选定 audience 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceSelection {
    /// 选定绑定到某具体 resource(MCP RS 或显式 /userinfo)。
    Resource(String),
    /// 纯 OIDC 回落到 `<issuer>/userinfo`(绝对 URI 由上层按 issuer 拼)。
    UserinfoFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// token 显式带的 resource 不属 authorize 授权集合(authorize↔token 绑定)。
    ResourceNotInAuthorizedSet(String),
    /// token 一次带了多个 resource(违反单值:一个 access token 只绑一个 RS)。
    /// 例:`/token` 同时传 `resource=RS1&resource=RS2`。
    MultiResourceAtToken,
    /// authorize 绑定了多值集合(P1+),但 token 省略、未从集合中选定一个(须显式收窄)。
    /// 例:`/authorize` 绑定 {RS1, RS2},`/token` 不带 resource → 须显式选一个。
    /// (P0 不会出现:P0 已在 authorize 阶段拒多值。)
    MustSelectFromAuthorizedSet,
}

/// `/token` audience 选择(C2.8 选择顺序,与 §1/§2.8 一致)。
///
/// 本函数即 §2.8"省略 resource 优先级"在**端点侧**的落地(只做选择顺序 + 绑定判定,
/// 不重写 §2.8 的派生/pairwise 规则):
/// 1. token 显式带 resource → 须 ∈ 授权集合 → 选它;
/// 2. token 省略 + authorize 绑定单值 → 继承该 code-bound 单值(§1"单一 resource 时可继承");
/// 3. token 省略 + authorize 未绑定 → 省略优先级(default_resource → 该 RS;否则 → /userinfo)。
///
/// - `token_resources`:`/token` 请求带的 resource(可空)。
/// - `authorized`:authorize 绑定集合。
/// - `reg`:客户端注册(含 default_resource)。
pub fn select_audience(
    token_resources: &[String],
    authorized: &AuthorizedResources,
    reg: &ClientRegistration,
) -> Result<AudienceSelection, TokenError> {
    match token_resources.len() {
        // 1. token 显式带一个 resource → 须 ∈ 授权集合。
        1 => {
            let r = &token_resources[0];
            // 授权集合为空视为纯 OIDC(authorize 未绑定):此时 token 却带了 resource,
            // 仍须校验它是否被授权——空集合不含任何 resource,故拒(须先在 authorize 绑定)。
            if authorized.contains(r) {
                Ok(AudienceSelection::Resource(r.clone()))
            } else {
                Err(TokenError::ResourceNotInAuthorizedSet(r.clone()))
            }
        }
        // token 带多个:违反单值(P0 已在 authorize 拒;此处兜底拒 token 侧多值)。
        n if n > 1 => Err(TokenError::MultiResourceAtToken),
        // 0 = token 省略。
        _ => {
            if let Some(single) = authorized.single_bound() {
                // 2. 继承 authorize 绑定的 code-bound 单值(含显式绑定的 /userinfo)。
                Ok(AudienceSelection::Resource(single.to_string()))
            } else if authorized.is_empty() {
                // 3. authorize 未绑定 → 省略优先级(§2.8)。
                match &reg.default_resource {
                    Some(dr) => Ok(AudienceSelection::Resource(dr.clone())),
                    // 回落 /userinfo(绝对 URI 由上层按 issuer 拼)。
                    None => Ok(AudienceSelection::UserinfoFallback),
                }
            } else {
                // authorized 多值(P1+)但 token 省略未选 → 须从集合显式收窄一个。
                Err(TokenError::MustSelectFromAuthorizedSet)
            }
        }
    }
}

/// "面向 MCP RS" 判定(三分支,C2.8 判定边界钉死):
/// 只看 (token/authorize 是否带 resource) 与 (是否注册 default_resource),不看 scope/client 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTarget {
    /// 面向 MCP RS(带 resource 或有 default_resource)。
    McpResourceServer,
    /// 纯 OIDC(无 resource 且无 default_resource)。
    PureOidc,
}

/// 判定请求是否"面向 MCP RS"(用于是否强制 resource)。
pub fn classify_target(has_resource: bool, reg: &ClientRegistration) -> RequestTarget {
    if has_resource || reg.default_resource.is_some() {
        RequestTarget::McpResourceServer
    } else {
        RequestTarget::PureOidc
    }
}

/// C2.11 — `/userinfo` audience 隔离:仅 `aud == <issuer>/userinfo` 的 token 可调 `/userinfo`。
/// `token_aud`:token 的单值 audience;`userinfo_resource`:`<issuer>/userinfo`。
pub fn userinfo_allowed(token_aud: &str, userinfo_resource: &str) -> bool {
    token_aud == userinfo_resource
}

#[cfg(test)]
mod tests {
    use super::*;

    const UI: &str = "https://t1.aws.example.com/userinfo";
    const RS1: &str = "https://mcp.rs1.example.com";
    const RS2: &str = "https://mcp.rs2.example.com";

    fn reg_none() -> ClientRegistration {
        ClientRegistration::default()
    }
    fn reg_default(r: &str) -> ClientRegistration {
        ClientRegistration {
            default_resource: Some(r.into()),
        }
    }
    fn authz(rs: &[&str], phase: AuthorizePhase) -> AuthorizedResources {
        AuthorizedResources::from_authorize(
            &rs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            phase,
        )
        .unwrap()
    }

    // C2.5a:P0 authorize 多 resource 直接拒。
    #[test]
    fn p0_multi_resource_authorize_rejected() {
        let r = AuthorizedResources::from_authorize(&[RS1.into(), RS2.into()], AuthorizePhase::P0);
        assert_eq!(r, Err(AuthorizeError::MultiResourceRejectedP0));
    }

    // P1+ 允许多 resource 集合。
    #[test]
    fn p1_multi_resource_allowed() {
        assert!(AuthorizedResources::from_authorize(
            &[RS1.into(), RS2.into()],
            AuthorizePhase::P1Plus
        )
        .is_ok());
    }

    // C2.8 顺序①:token 显式 resource ∈ 集合 → 选它。
    #[test]
    fn explicit_resource_in_set_selected() {
        let a = authz(&[RS1], AuthorizePhase::P0);
        assert_eq!(
            select_audience(&[RS1.into()], &a, &reg_none()),
            Ok(AudienceSelection::Resource(RS1.into()))
        );
    }

    // authorize↔token 绑定:token 带的 resource ∉ 集合 → 拒。
    #[test]
    fn explicit_resource_not_in_set_rejected() {
        let a = authz(&[RS1], AuthorizePhase::P0);
        assert_eq!(
            select_audience(&[RS2.into()], &a, &reg_none()),
            Err(TokenError::ResourceNotInAuthorizedSet(RS2.into()))
        );
    }

    // authorize 未绑定(空集)但 token 却带 resource → 拒(须先在 authorize 绑定,不能只在 token 带)。
    #[test]
    fn explicit_resource_with_empty_authz_rejected() {
        let a = authz(&[], AuthorizePhase::P0);
        assert_eq!(
            select_audience(&[RS1.into()], &a, &reg_default(RS1)),
            Err(TokenError::ResourceNotInAuthorizedSet(RS1.into())),
            "authorize 未绑定任何 resource 时,仅在 token 带 resource MUST 拒(两跳须一致)"
        );
    }

    // C2.8 顺序②:token 省略 + authorize 绑定单值 → 继承(含 /userinfo)。
    #[test]
    fn omitted_inherits_code_bound_single() {
        let a = authz(&[UI], AuthorizePhase::P0); // authorize 绑定 /userinfo
        assert_eq!(
            select_audience(&[], &a, &reg_default(RS1)),
            Ok(AudienceSelection::Resource(UI.into())),
            "authorize 绑定 /userinfo 时,token 省略应继承 /userinfo、不回落 default_resource"
        );
    }

    // C2.8 顺序②优先于③:authorize 绑定单值 RS2 时,即使注册了 default=RS1,省略也继承 RS2(不回落 default)。
    #[test]
    fn omitted_inherits_code_bound_overrides_default() {
        let a = authz(&[RS2], AuthorizePhase::P0); // authorize 绑定 RS2
        assert_eq!(
            select_audience(&[], &a, &reg_default(RS1)),
            Ok(AudienceSelection::Resource(RS2.into())),
            "继承 code-bound 单值优先于 default_resource(default 仅在 authorize 未绑定时才生效)"
        );
    }

    // C2.8 顺序③:token 省略 + authorize 未绑定 + 有 default → default RS。
    #[test]
    fn omitted_no_authz_with_default() {
        let a = authz(&[], AuthorizePhase::P0);
        assert_eq!(
            select_audience(&[], &a, &reg_default(RS1)),
            Ok(AudienceSelection::Resource(RS1.into()))
        );
    }

    // C2.8 顺序③:token 省略 + authorize 未绑定 + 无 default → /userinfo 回落。
    #[test]
    fn omitted_no_authz_no_default_userinfo_fallback() {
        let a = authz(&[], AuthorizePhase::P0);
        assert_eq!(
            select_audience(&[], &a, &reg_none()),
            Ok(AudienceSelection::UserinfoFallback)
        );
    }

    // MCP RS 判定三分支。
    #[test]
    fn classify_target_three_branches() {
        assert_eq!(
            classify_target(true, &reg_none()),
            RequestTarget::McpResourceServer
        ); // ①带 resource
        assert_eq!(
            classify_target(false, &reg_default(RS1)),
            RequestTarget::McpResourceServer
        ); // ②有 default
        assert_eq!(classify_target(false, &reg_none()), RequestTarget::PureOidc);
        // ③纯 OIDC
    }

    // C2.11:/userinfo 隔离。
    #[test]
    fn userinfo_isolation() {
        assert!(userinfo_allowed(UI, UI));
        assert!(
            !userinfo_allowed(RS1, UI),
            "aud=MCP RS 的 token 不可调 /userinfo"
        );
    }

    // 顺序优先:token 显式带,即使 authorize 绑定了别的单值,也以 token 显式为准(须 ∈ 集合)。
    #[test]
    fn explicit_token_resource_takes_precedence_but_must_be_authorized() {
        // authorize 绑定 {RS1, RS2}(P1+),token 显式选 RS2。
        let a = authz(&[RS1, RS2], AuthorizePhase::P1Plus);
        assert_eq!(
            select_audience(&[RS2.into()], &a, &reg_none()),
            Ok(AudienceSelection::Resource(RS2.into()))
        );
    }

    // P1+ 多 resource 集合但 token 省略未选一个 → 拒(须从集合显式收窄)。
    #[test]
    fn multi_authz_token_must_select() {
        let a = authz(&[RS1, RS2], AuthorizePhase::P1Plus);
        assert_eq!(
            select_audience(&[], &a, &reg_none()),
            Err(TokenError::MustSelectFromAuthorizedSet)
        );
    }

    // token 一次带多个 resource → 拒(违反单值,区别于"省略未选")。
    #[test]
    fn token_multi_resource_rejected() {
        let a = authz(&[RS1, RS2], AuthorizePhase::P1Plus);
        assert_eq!(
            select_audience(&[RS1.into(), RS2.into()], &a, &reg_none()),
            Err(TokenError::MultiResourceAtToken)
        );
    }
}
