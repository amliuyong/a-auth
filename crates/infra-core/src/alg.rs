//! C10.15a — access token 签名算法恒 ES256 不变量守卫。
//!
//! P0–P2(及未启用分流的 P3)access token 的 `alg` MUST 恒为 **ES256**,MUST NOT 出现 RS256——
//! 保护"硬编码 alg 的第三方 RS 不被间歇拒签"的承诺(见 DESIGN §2/§8 access 算法契约)。
//! ⚠️ 该不变量**只针对 access token**;ID token 的 per-client `id_token_signed_response_alg`
//! (默认 RS256)不受此约束——两者不可混用同一守卫。
//!
//! 本模块纯枚举检查、零 AWS 依赖:签发路径在拿到 header.alg 后过此守卫,防 RS256 泄漏到 access。
//! 决策真相源:docs/DESIGN §2·§8;docs/CONFORMANCE C10.15a。

/// token 用途——决定套用哪条算法不变量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// access token:恒 ES256(本不变量的保护对象)。
    Access,
    /// ID token:per-client alg(默认 RS256),不受 access 不变量约束。
    Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgError {
    /// access token 出现了非 ES256 的 alg(RS256 泄漏等)。
    AccessNotEs256(String),
    /// 出现明确禁止的算法(none / 对称 HS*)——任何 token 都不接受。
    ForbiddenAlg(String),
}

/// 永久禁止的签名算法(无论 access/ID):`none`(未签名)、HS*(对称,泄漏即伪造)。
fn is_forbidden(alg: &str) -> bool {
    alg.eq_ignore_ascii_case("none") || alg.starts_with("HS") || alg.starts_with("hs")
}

/// 校验一枚将签发 token 的 `alg` 是否满足其用途的算法不变量(C10.15a)。
/// - 任何 token:禁 `none` / HS*。
/// - Access:必须恰为 `ES256`(未启用分流的缺省语义)。
/// - Id:允许 per-client alg(此处只挡 forbidden,不强制某具体值)。
pub fn check_alg(kind: TokenKind, alg: &str) -> Result<(), AlgError> {
    if is_forbidden(alg) {
        return Err(AlgError::ForbiddenAlg(alg.to_string()));
    }
    match kind {
        TokenKind::Access => {
            if alg == "ES256" {
                Ok(())
            } else {
                Err(AlgError::AccessNotEs256(alg.to_string()))
            }
        }
        TokenKind::Id => Ok(()),
    }
}

/// 便捷断言:access token 的 alg 恒 ES256(签发热路径的最后一道守卫)。
pub fn assert_access_es256(alg: &str) -> Result<(), AlgError> {
    check_alg(TokenKind::Access, alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // C10.15a:access = ES256 通过。
    #[test]
    fn access_es256_ok() {
        assert!(assert_access_es256("ES256").is_ok());
    }

    // C10.15a:access = RS256 泄漏 → 拒。
    #[test]
    fn access_rs256_rejected() {
        assert_eq!(
            assert_access_es256("RS256"),
            Err(AlgError::AccessNotEs256("RS256".into()))
        );
    }

    // 反复签发都恒 ES256(不变量)。
    #[test]
    fn access_invariant_holds_repeatedly() {
        for _ in 0..1000 {
            assert!(check_alg(TokenKind::Access, "ES256").is_ok());
        }
        for bad in ["RS256", "ES384", "PS256", "EdDSA"] {
            assert!(
                check_alg(TokenKind::Access, bad).is_err(),
                "{bad} 不该被 access 接受"
            );
        }
    }

    // ID token 允许 RS256(per-client,不受 access 不变量约束)。
    #[test]
    fn id_token_rs256_allowed() {
        assert!(check_alg(TokenKind::Id, "RS256").is_ok());
        assert!(check_alg(TokenKind::Id, "ES256").is_ok());
    }

    // none / HS* 任何 token 都禁。
    #[test]
    fn forbidden_algs_rejected_for_all() {
        for kind in [TokenKind::Access, TokenKind::Id] {
            assert!(matches!(
                check_alg(kind, "none"),
                Err(AlgError::ForbiddenAlg(_))
            ));
            assert!(matches!(
                check_alg(kind, "NONE"),
                Err(AlgError::ForbiddenAlg(_))
            ));
            assert!(matches!(
                check_alg(kind, "HS256"),
                Err(AlgError::ForbiddenAlg(_))
            ));
        }
    }
}
