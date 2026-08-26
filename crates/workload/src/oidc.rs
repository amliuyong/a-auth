//! workload_oidc_jwt 路径的**claims 级决策核心**(spec 012 C5.1)——纯逻辑,零 IO。
//!
//! 关注点:对**已验签**的平台 OIDC token claims(JSON),做 aud 硬校验 + exp + iss/sub→信任绑定
//! 匹配,产出 `WorkloadIdentity`。**签名验证(RS256/ES256)+ JWKS 取用属 IO 层**(http 适配器,
//! 用平台 `jwks_uri` 本地验签),不在此——与 `federation.rs`"从已验证断言提取"同套边界。
//!
//! **aud 绝不放宽**(C5.1):aud≠本 AS issuer 一律拒(confused-deputy/token 转用入口);aud 固定
//! 指向平台/`sts.amazonaws.com` 的平台只能改走 SigV4/STS 兜底,不在此放行。

use crate::trust::{match_oidc, MatchError, TrustBinding, WorkloadIdentity};
use serde_json::Value;

/// claims 级校验失败原因(fail-closed,可测)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcAuthError {
    /// 缺必需 claim(iss/sub/aud/exp 任一缺)。
    MissingClaim(&'static str),
    /// aud 不等于本 AS issuer(**绝不放宽**)。
    AudNotThisAs,
    /// 已过期(exp ≤ now,含 skew 由调用方并入 now)。
    Expired,
    /// iss+sub 未命中任何信任绑定。
    NoTrustBinding,
}

/// 取 claim 的字符串值。
fn claim_str<'a>(claims: &'a Value, key: &str) -> Option<&'a str> {
    claims.get(key).and_then(|v| v.as_str())
}

/// `aud` 是否**包含** `expected`(aud 可为字符串或字符串数组,RFC 7519)。
fn aud_contains(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// 对已验签的平台 OIDC token claims 做决策(C5.1)。`now` 已并入时钟 skew 余量。
///
/// 顺序(fail-closed):必需 claim → aud 硬校验(=本 AS issuer)→ exp → iss+sub 匹配信任绑定。
/// 全过返回 `WorkloadIdentity`(principal = 实际 sub)。
pub fn authorize_oidc(
    claims: &Value,
    as_issuer: &str,
    now: i64,
    bindings: &[TrustBinding],
    tenant_id: &str,
) -> Result<WorkloadIdentity, OidcAuthError> {
    // 必需 claim。
    let iss = claim_str(claims, "iss").ok_or(OidcAuthError::MissingClaim("iss"))?;
    let sub = claim_str(claims, "sub").ok_or(OidcAuthError::MissingClaim("sub"))?;
    if claims.get("aud").is_none() {
        return Err(OidcAuthError::MissingClaim("aud"));
    }
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(OidcAuthError::MissingClaim("exp"))?;

    // aud 硬校验:MUST = 本 AS issuer,**绝不放宽**(C5.1)。
    if !aud_contains(claims, as_issuer) {
        return Err(OidcAuthError::AudNotThisAs);
    }
    // exp:fail-closed(exp ≤ now 即过期)。
    if exp <= now {
        return Err(OidcAuthError::Expired);
    }
    // iss+sub → 信任绑定(按 tenant 隔离)。
    match match_oidc(bindings, tenant_id, iss, sub) {
        Ok(id) => Ok(id),
        Err(MatchError::NoBinding) => Err(OidcAuthError::NoTrustBinding),
        Err(MatchError::AmbiguousBinding) => Err(OidcAuthError::NoTrustBinding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{PrincipalKind, TrustMechanism};
    use serde_json::json;

    const AS_ISS: &str = "https://auth.example.com";
    const PLAT: &str = "https://token.actions.githubusercontent.com";

    fn bindings() -> Vec<TrustBinding> {
        vec![TrustBinding {
            tenant_id: "t1".into(),
            mechanism: TrustMechanism::Oidc {
                platform_issuer: PLAT.into(),
                jwks_uri: format!("{PLAT}/.well-known/jwks"),
                subject_pattern: "repo:acme/agent:*".into(),
            },
            mapped_client_id: "wl-gha".into(),
        }]
    }

    fn claims(aud: Value, sub: &str, exp: i64) -> Value {
        json!({ "iss": PLAT, "sub": sub, "aud": aud, "exp": exp })
    }

    #[test]
    fn happy_path_aud_string() {
        let c = claims(
            json!(AS_ISS),
            "repo:acme/agent:ref:refs/heads/main",
            9_999_999_999,
        );
        let id = authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1").unwrap();
        assert_eq!(id.client_id, "wl-gha");
        assert_eq!(id.principal_kind, PrincipalKind::OidcSubject);
        assert_eq!(id.principal, "repo:acme/agent:ref:refs/heads/main");
    }

    #[test]
    fn happy_path_aud_array() {
        // aud 为数组且含本 AS issuer → 放行。
        let c = claims(json!([AS_ISS, "other"]), "repo:acme/agent:x", 9_999_999_999);
        assert!(authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1").is_ok());
    }

    #[test]
    fn aud_not_this_as_rejected_never_relaxed() {
        // aud 指向 sts.amazonaws.com → 绝不放宽,拒。
        let c = claims(
            json!("sts.amazonaws.com"),
            "repo:acme/agent:x",
            9_999_999_999,
        );
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::AudNotThisAs)
        );
        // aud 指向平台自身 → 拒。
        let c = claims(json!(PLAT), "repo:acme/agent:x", 9_999_999_999);
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::AudNotThisAs)
        );
    }

    #[test]
    fn expired_rejected() {
        let c = claims(json!(AS_ISS), "repo:acme/agent:x", 500);
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::Expired)
        );
    }

    #[test]
    fn sub_not_in_pattern_no_binding() {
        let c = claims(json!(AS_ISS), "repo:evil/x:y", 9_999_999_999);
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::NoTrustBinding)
        );
    }

    #[test]
    fn wrong_tenant_no_binding() {
        let c = claims(json!(AS_ISS), "repo:acme/agent:x", 9_999_999_999);
        // t2 查不到 t1 的绑定(SaaS 隔离)。
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t2"),
            Err(OidcAuthError::NoTrustBinding)
        );
    }

    #[test]
    fn missing_claims_rejected() {
        // 缺 aud。
        let c = json!({ "iss": PLAT, "sub": "repo:acme/agent:x", "exp": 9_999_999_999i64 });
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::MissingClaim("aud"))
        );
        // 缺 exp。
        let c = json!({ "iss": PLAT, "sub": "repo:acme/agent:x", "aud": AS_ISS });
        assert_eq!(
            authorize_oidc(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(OidcAuthError::MissingClaim("exp"))
        );
    }
}
