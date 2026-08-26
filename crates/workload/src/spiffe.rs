//! SPIFFE JWT-SVID 路径的**claims 级决策核心**(spec 012 §1.4,C5.7)——纯逻辑,零 IO。
//!
//! 对**已验签**的 JWT-SVID claims(JSON)做 aud 硬校验 + exp + `sub`(SPIFFE ID)→ 从 sub 解 trust domain
//! → 信任绑定匹配,产出 `WorkloadIdentity`。**签名验证(ES256/RS256)+ trust bundle JWKS 取用属 IO 层**
//! (http 适配器,用绑定 `jwks_uri` 本地验签),不在此——与 `oidc.rs`/`federation.rs`"从已验证断言提取"同套边界。
//!
//! **信任锚 = 从 `sub` 解出的 trust domain(评审 High,MUST NOT 用 `iss`)**:SPIFFE JWT-SVID 不约束 `iss`,
//! SPIRE 常用 server URL 作 `iss`(≠trust domain);按 iss 硬匹配会误拒真实 SVID。锚唯一来自 sub-trust-domain。
//! **aud 绝不放宽**(C5.1/C5.7):aud≠本 AS issuer 一律拒(confused-deputy/token 转用入口),与 OIDC 同口径。

use crate::trust::{match_spiffe, MatchError, TrustBinding, WorkloadIdentity};
use serde_json::Value;

/// claims 级校验失败原因(fail-closed,可测)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeAuthError {
    /// 缺必需 claim(sub/aud/exp 任一缺)。
    MissingClaim(&'static str),
    /// `sub` 非合法 SPIFFE ID(无 `spiffe://` scheme / 空 trust domain)。
    NotSpiffeId,
    /// aud 不等于本 AS issuer(**绝不放宽**)。
    AudNotThisAs,
    /// 已过期(exp ≤ now,含 skew 由调用方并入 now)。
    Expired,
    /// sub(SPIFFE ID)未命中任何信任绑定(trust domain / pattern / tenant)。
    NoTrustBinding,
    /// 多条 SPIFFE 信任绑定同时命中,必须 fail-closed 拒绝非确定映射。
    AmbiguousTrustBinding,
}

fn claim_str<'a>(claims: &'a Value, key: &str) -> Option<&'a str> {
    claims.get(key).and_then(|v| v.as_str())
}

/// `aud` 是否**包含** `expected`(aud 可为字符串或字符串数组,RFC 7519;复用 OIDC 同语义)。
fn aud_contains(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// 对已验签的 JWT-SVID claims 做决策(C5.7)。`now` 已并入时钟 skew 余量。
///
/// 顺序(fail-closed):必需 claim → sub 为合法 SPIFFE ID → aud 硬校验(=本 AS issuer)→ exp →
/// 从 sub 解 trust domain + 完整 SPIFFE ID 匹配信任绑定。全过返回 `WorkloadIdentity`(principal = SPIFFE ID)。
pub fn authorize_spiffe_jwt(
    claims: &Value,
    as_issuer: &str,
    now: i64,
    bindings: &[TrustBinding],
    tenant_id: &str,
) -> Result<WorkloadIdentity, SpiffeAuthError> {
    // 必需 claim。
    let sub = claim_str(claims, "sub").ok_or(SpiffeAuthError::MissingClaim("sub"))?;
    if claims.get("aud").is_none() {
        return Err(SpiffeAuthError::MissingClaim("aud"));
    }
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(SpiffeAuthError::MissingClaim("exp"))?;

    // sub MUST 为合法 SPIFFE ID(spiffe:// + 非空 trust domain);否则无信任锚(防本 AS 2LO token 的
    // sub=client_id 混入,评审 typ/iss 混淆场景)。
    if crate::trust::spiffe_trust_domain(sub).is_none() {
        return Err(SpiffeAuthError::NotSpiffeId);
    }

    // aud 硬校验:MUST = 本 AS issuer,**绝不放宽**(C5.1/C5.7,与 OIDC 同口径)。
    if !aud_contains(claims, as_issuer) {
        return Err(SpiffeAuthError::AudNotThisAs);
    }
    // exp:fail-closed(exp ≤ now 即过期)。
    if exp <= now {
        return Err(SpiffeAuthError::Expired);
    }
    // sub(SPIFFE ID)→ 信任绑定(trust domain 从 sub 解 + 完整 SPIFFE ID pattern,tenant 隔离)。
    match match_spiffe(bindings, tenant_id, sub) {
        Ok(id) => Ok(id),
        Err(MatchError::NoBinding) => Err(SpiffeAuthError::NoTrustBinding),
        Err(MatchError::AmbiguousBinding) => Err(SpiffeAuthError::AmbiguousTrustBinding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{PrincipalKind, TrustMechanism};
    use serde_json::json;

    const AS_ISS: &str = "https://auth.example.com";
    const TD: &str = "acme.example";

    fn bindings() -> Vec<TrustBinding> {
        vec![TrustBinding {
            tenant_id: "t1".into(),
            mechanism: TrustMechanism::SpiffeJwt {
                trust_domain: TD.into(),
                jwks_uri: "https://spire.acme.example/bundle".into(),
                spiffe_id_pattern: "spiffe://acme.example/agent/*".into(),
            },
            mapped_client_id: "wl-spiffe".into(),
        }]
    }

    fn claims(aud: Value, sub: &str, exp: i64) -> Value {
        // iss 故意设成 SPIRE server URL(≠trust domain),验证不以 iss 作锚也能命中。
        json!({ "iss": "https://spire.acme.example", "sub": sub, "aud": aud, "exp": exp })
    }

    #[test]
    fn happy_path_aud_string() {
        let c = claims(
            json!(AS_ISS),
            "spiffe://acme.example/agent/kb",
            9_999_999_999,
        );
        let id = authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1").unwrap();
        assert_eq!(id.client_id, "wl-spiffe");
        assert_eq!(id.principal_kind, PrincipalKind::SpiffeId);
        assert_eq!(id.principal, "spiffe://acme.example/agent/kb");
    }

    #[test]
    fn happy_path_aud_array() {
        let c = claims(
            json!([AS_ISS, "other"]),
            "spiffe://acme.example/agent/x",
            9_999_999_999,
        );
        assert!(authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1").is_ok());
    }

    #[test]
    fn aud_not_this_as_rejected_never_relaxed() {
        let c = claims(
            json!("https://other.example"),
            "spiffe://acme.example/agent/x",
            9_999_999_999,
        );
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::AudNotThisAs)
        );
    }

    #[test]
    fn expired_rejected() {
        let c = claims(json!(AS_ISS), "spiffe://acme.example/agent/x", 500);
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::Expired)
        );
    }

    #[test]
    fn non_spiffe_sub_rejected() {
        // sub=client_id 形态(本 AS 2LO token)→ NotSpiffeId(防混淆)。
        let c = claims(json!(AS_ISS), "wl-some-client", 9_999_999_999);
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::NotSpiffeId)
        );
        // 空 trust domain。
        let c = claims(json!(AS_ISS), "spiffe:///agent/kb", 9_999_999_999);
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::NotSpiffeId)
        );
    }

    #[test]
    fn cross_trust_domain_no_binding() {
        let c = claims(
            json!(AS_ISS),
            "spiffe://evil.example/agent/x",
            9_999_999_999,
        );
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::NoTrustBinding)
        );
    }

    #[test]
    fn pattern_miss_no_binding() {
        let c = claims(json!(AS_ISS), "spiffe://acme.example/svc/db", 9_999_999_999);
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::NoTrustBinding)
        );
    }

    #[test]
    fn wrong_tenant_no_binding() {
        let c = claims(
            json!(AS_ISS),
            "spiffe://acme.example/agent/x",
            9_999_999_999,
        );
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t2"),
            Err(SpiffeAuthError::NoTrustBinding)
        );
    }

    #[test]
    fn missing_claims_rejected() {
        let c = json!({ "sub": "spiffe://acme.example/agent/x", "exp": 9_999_999_999i64 });
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::MissingClaim("aud"))
        );
        let c = json!({ "sub": "spiffe://acme.example/agent/x", "aud": AS_ISS });
        assert_eq!(
            authorize_spiffe_jwt(&c, AS_ISS, 1000, &bindings(), "t1"),
            Err(SpiffeAuthError::MissingClaim("exp"))
        );
    }
}
