//! `evaluate`:`授权 ∩ 策略 → effective`(spec 005 §7 补强 ⑧)。
//!
//! 对每个 (resource, scope) 用 Cedar 判 `permit`,只保留策略允许的 → effective **恒 ⊆ 授权**(输入天花板)。
//! **绝不越 consent**:输入 `per_resource` = 用户授权(consent 上限),evaluate 只收窄不扩展。
//!
//! RAR(`authorization_details`):**C8.5a 简单声明式 RAR 在 P2 原样透传**(其执行在 RS SDK 侧,见 spec 010);
//! **策略引擎驱动的复杂 RAR 收窄 = C8.5b,P3 延后**——本 evaluate 不对 RAR 做 Cedar 收窄(词汇表内 RAR
//! 交集原语 [`crate::intersect_rar`] 已备,供策略显式声明 RAR 允许类型时用,非本 P2 默认路径)。

use crate::{policy::PolicyArtifact, AuthzError};
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request};

/// evaluate 的输入 = **用户授权**(consent 上限)。每项 = (resource, 授权 scopes, 授权 RAR)。
pub struct GrantInput {
    pub user_id: String,
    pub client_id: String,
    pub per_resource: Vec<(String, Vec<String>, Vec<serde_json::Value>)>,
}

/// evaluate 的输出 = **生效预判**(授权 ∩ 策略)。签发热路径读它;恒 ⊆ 授权。
pub struct Effective {
    pub per_resource: Vec<(String, Vec<String>, Vec<serde_json::Value>)>,
    pub allowed_ip_cidrs: Vec<String>,
    pub allowed_vpce: Vec<String>,
    /// **有无可评估单元**(spec 005 §7 补强 ⑯):∃ resource 有 ≥1 scope 或 ≥1 RAR entry(Cedar 有东西可判)。
    /// 消歧"空 effective":`has_evaluable_units && per_resource 空` = 策略全 deny(应吊销/拒建);
    /// `!has_evaluable_units` = 无从表态(resource-less / 空 scope+无 RAR)→ 保留,MUST NOT 因策略吊销。
    /// 调用方(重算吊销判据 / 创建 fail-closed)据此决策,**绝不**只看 `per_resource.is_empty()`。
    pub has_evaluable_units: bool,
}

fn uid(s: &str) -> Result<EntityUid, AuthzError> {
    s.parse()
        .map_err(|e| AuthzError::Eval(format!("uid {s}: {e}")))
}

/// Cedar 转义:实体 id 的字符串字面量里的 `"` / `\` 必须转义,否则会破坏 `Type::"id"` 语法或被注入。
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `授权 ∩ 策略 → effective`。对每 (resource, scope) 判 Cedar permit,收窄;恒 ⊆ 输入授权。
/// principal=`User::"<user_id>"`,action=`Action::"<scope>"`,resource=`Resource::"<resource>"`。
pub fn evaluate(art: &PolicyArtifact, input: &GrantInput) -> Result<Effective, AuthzError> {
    let authz = Authorizer::new();
    let principal = uid(&format!(r#"User::"{}""#, esc(&input.user_id)))?;
    let mut out = Vec::new();
    // 有无可评估单元(补强 ⑯):∃ resource 有 ≥1 scope 或 ≥1 RAR。Cedar 是资源级授权,只有当某 resource
    // 携带可判的 (scope) 或 RAR 时它才"有东西可判";全空则无从表态(resource-less / 空 scope+无 RAR)。
    let mut has_evaluable_units = false;
    for (resource, scopes, rar) in &input.per_resource {
        if !scopes.is_empty() || !rar.is_empty() {
            has_evaluable_units = true; // 该 resource 是一个可评估单元
        }
        let res_uid = uid(&format!(r#"Resource::"{}""#, esc(resource)))?;
        let mut granted = Vec::new();
        for scope in scopes {
            let act_uid = uid(&format!(r#"Action::"{}""#, esc(scope)))?;
            let req = Request::new(
                principal.clone(),
                act_uid,
                res_uid.clone(),
                Context::empty(),
                None,
            )
            .map_err(|e| AuthzError::Eval(format!("request: {e}")))?;
            let ans = authz.is_authorized(&req, art.policies(), &Entities::empty());
            if matches!(ans.decision(), Decision::Allow) {
                granted.push(scope.clone()); // 授权 ∩ 策略:仅策略 permit 的 scope 保留
            }
        }
        // RAR:C8.5a P2 原样透传(复杂 RAR 收窄 = C8.5b P3);保留有 scope 或有 RAR 的 resource。
        if !granted.is_empty() || !rar.is_empty() {
            out.push((resource.clone(), granted, rar.clone()));
        }
    }
    Ok(Effective {
        per_resource: out,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        has_evaluable_units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(src: &str) -> PolicyArtifact {
        PolicyArtifact::parse(src, 5).unwrap()
    }

    #[test]
    fn evaluate_narrows_to_policy_never_exceeds_authorized() {
        // 策略只 permit read(不 permit write)。
        let a = art(r#"permit(principal, action == Action::"read", resource);"#);
        let input = GrantInput {
            user_id: "user:alice".into(),
            client_id: "app1".into(),
            per_resource: vec![("rs1".into(), vec!["read".into(), "write".into()], vec![])],
        };
        let eff = evaluate(&a, &input).unwrap();
        assert_eq!(eff.per_resource.len(), 1);
        assert_eq!(eff.per_resource[0].0, "rs1");
        assert_eq!(
            eff.per_resource[0].1,
            vec!["read".to_string()],
            "授权{{read,write}}∩策略{{read}}={{read}}"
        );
    }

    #[test]
    fn evaluate_deny_all_yields_empty() {
        // 空策略 = 默认全 deny → effective 无 scope。
        let a = art(r#"permit(principal, action == Action::"nothing", resource);"#);
        let input = GrantInput {
            user_id: "u".into(),
            client_id: "c".into(),
            per_resource: vec![("rs1".into(), vec!["read".into()], vec![])],
        };
        let eff = evaluate(&a, &input).unwrap();
        assert!(
            eff.per_resource.is_empty(),
            "策略不 permit 任何请求 scope → 该 resource 无 effective"
        );
    }

    #[test]
    fn evaluate_never_exceeds_authorized_even_if_policy_wider() {
        // 策略 permit read+write+delete,但授权只有 read → effective 仍只 read(不越 consent)。
        let a = art(r#"permit(principal, action, resource);"#); // permit 一切
        let input = GrantInput {
            user_id: "u".into(),
            client_id: "c".into(),
            per_resource: vec![("rs1".into(), vec!["read".into()], vec![])],
        };
        let eff = evaluate(&a, &input).unwrap();
        assert_eq!(
            eff.per_resource[0].1,
            vec!["read".to_string()],
            "effective 恒 ⊆ 授权,绝不因策略宽而超 consent"
        );
    }

    // 补强 ⑯:has_evaluable_units 消歧"空 effective"。
    #[test]
    fn evaluate_no_evaluable_units_when_resource_less() {
        let a = art(r#"permit(principal, action, resource);"#);
        // resource-less:per_resource 空。
        let eff = evaluate(
            &a,
            &GrantInput {
                user_id: "u".into(),
                client_id: "c".into(),
                per_resource: vec![],
            },
        )
        .unwrap();
        assert!(eff.per_resource.is_empty());
        assert!(
            !eff.has_evaluable_units,
            "无 resource → 无可评估单元(Cedar 无从表态,应保留)"
        );
    }

    #[test]
    fn evaluate_no_evaluable_units_when_empty_scopes_no_rar() {
        let a = art(r#"permit(principal, action, resource);"#);
        // resource 有但 scopes 空 + 无 RAR("RS 默认/最小权限"合法形态)。
        let eff = evaluate(
            &a,
            &GrantInput {
                user_id: "u".into(),
                client_id: "c".into(),
                per_resource: vec![("rs1".into(), vec![], vec![])],
            },
        )
        .unwrap();
        assert!(eff.per_resource.is_empty());
        assert!(
            !eff.has_evaluable_units,
            "resource 有但 scopes 空+无 RAR → 无可评估单元(Cedar 无从表态,应保留,不吊销)"
        );
    }

    #[test]
    fn evaluate_has_evaluable_units_when_all_denied() {
        // resource 有 scope 但策略全 deny → effective 空,但**有**可评估单元(该吊销,不该保留)。
        let a = art(r#"permit(principal, action == Action::"nothing", resource);"#);
        let eff = evaluate(
            &a,
            &GrantInput {
                user_id: "u".into(),
                client_id: "c".into(),
                per_resource: vec![("rs1".into(), vec!["read".into()], vec![])],
            },
        )
        .unwrap();
        assert!(eff.per_resource.is_empty(), "全 deny → effective 空");
        assert!(
            eff.has_evaluable_units,
            "有 scope 可判(虽被 deny)→ 有可评估单元(吊销判据成立)"
        );
    }

    #[test]
    fn evaluate_passes_rar_through_p2() {
        let a = art(r#"permit(principal, action == Action::"read", resource);"#);
        let rar = vec![serde_json::json!({"type":"doc_read"})];
        let input = GrantInput {
            user_id: "u".into(),
            client_id: "c".into(),
            per_resource: vec![("rs1".into(), vec!["read".into()], rar.clone())],
        };
        let eff = evaluate(&a, &input).unwrap();
        assert_eq!(eff.per_resource[0].2, rar, "C8.5a RAR P2 原样透传");
    }
}
