//! C4.1 — PKCE S256 parameter validation and verifier binding.
//!
//! 使用 PKCE 的授权请求 MUST 有非空 `code_challenge` 且 method = `S256`(拒 plain/缺失)。
//! 兑换阶段:`BASE64URL(SHA256(code_verifier)) == code_challenge` 才放行(RFC 7636)。
//! 哪些 client 可完全省略 PKCE 由 HTTP 层结合 client authority 与运行时认证能力决定。
//!
//! 决策真相源:docs/DESIGN §3.1、docs/CONFORMANCE C4.1;S256 计算由 RFC 7636 钉死。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

/// 授权请求的 PKCE 参数校验(C4.1):method 必须 S256、challenge 必须非空。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkceCheck {
    Ok,
    /// 缺 code_challenge。
    MissingChallenge,
    /// method 非 S256(如 plain / 缺省)。
    NotS256,
}

/// 校验授权阶段 PKCE tuple；调用方另行决定完整缺省 tuple 是否可接受。
/// - `code_challenge`:授权请求里的 challenge(None = 未带)。
/// - `method`:`code_challenge_method`(None = 未带)。
pub fn check_authorize(code_challenge: Option<&str>, method: Option<&str>) -> PkceCheck {
    match code_challenge {
        None | Some("") => PkceCheck::MissingChallenge,
        Some(_) => {
            // OAuth 2.1:未带 method 默认 plain,而本系统只接受 S256 → 必须显式 S256。
            match method {
                Some("S256") => PkceCheck::Ok,
                _ => PkceCheck::NotS256,
            }
        }
    }
}

/// 计算 S256 challenge = BASE64URL-NOPAD(SHA256(verifier))(RFC 7636)。
pub fn s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// 校验 `code_verifier` 格式(RFC 7636 §4.1:43–128 字符,unreserved 集 `[A-Za-z0-9-._~]`)。
pub fn valid_verifier_format(code_verifier: &str) -> bool {
    let len = code_verifier.len();
    (43..=128).contains(&len)
        && code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// 兑换阶段:verifier 是否与 stored challenge 匹配(C4.1 绑定校验)。
/// 先校验 verifier 格式(RFC 7636 §4.1),再比对 S256——格式非法直接拒。
pub fn verify_exchange(code_verifier: &str, stored_challenge: &str) -> bool {
    if !valid_verifier_format(code_verifier) {
        return false;
    }
    // 常量时间比较此处非必需(challenge 是公开值、非秘密);直接相等即可。
    s256_challenge(code_verifier) == stored_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    // C4.1:缺 challenge 拒。
    #[test]
    fn missing_challenge() {
        assert_eq!(
            check_authorize(None, Some("S256")),
            PkceCheck::MissingChallenge
        );
        assert_eq!(
            check_authorize(Some(""), Some("S256")),
            PkceCheck::MissingChallenge
        );
    }

    // C4.1:非 S256 拒(plain / 缺省)。
    #[test]
    fn non_s256_rejected() {
        assert_eq!(
            check_authorize(Some("abc"), Some("plain")),
            PkceCheck::NotS256
        );
        assert_eq!(check_authorize(Some("abc"), None), PkceCheck::NotS256);
    }

    // C4.1:S256 + challenge 通过。
    #[test]
    fn s256_ok() {
        assert_eq!(check_authorize(Some("abc"), Some("S256")), PkceCheck::Ok);
    }

    // RFC 7636 附录 B 官方测试向量。
    #[test]
    fn rfc7636_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), expected);
    }

    // C4.1 兑换:正确 verifier 通过(43 字符,RFC 7636 合法)。
    #[test]
    fn verify_correct_verifier() {
        let verifier = "the-secret-verifier-value-1234567890-abcdef"; // 43 chars, unreserved
        assert_eq!(verifier.len(), 43);
        let challenge = s256_challenge(verifier);
        assert!(verify_exchange(verifier, &challenge));
    }

    // C4.1 兑换:错误 verifier 拒。
    #[test]
    fn verify_wrong_verifier_rejected() {
        let correct = "correct-verifier-1234567890-abcdefghijklmno"; // 43 chars
        let wrong = "wrong-verifier-0987654321-zyxwvutsrqponmlkj"; // 43 chars
        let challenge = s256_challenge(correct);
        assert!(!verify_exchange(wrong, &challenge));
    }

    // RFC 7636 §4.1:verifier 长度/字符集校验。
    #[test]
    fn verifier_format_validation() {
        assert!(valid_verifier_format(&"a".repeat(43)));
        assert!(valid_verifier_format(&"a".repeat(128)));
        assert!(!valid_verifier_format(&"a".repeat(42))); // 太短
        assert!(!valid_verifier_format(&"a".repeat(129))); // 太长
        assert!(!valid_verifier_format(&"a".repeat(50).replace('a', "!"))); // 非 unreserved
        assert!(valid_verifier_format(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )); // RFC 向量
    }

    // 格式非法的 verifier 兑换直接拒(即便 challenge 算得出)。
    #[test]
    fn malformed_verifier_rejected_at_exchange() {
        let short = "too-short"; // < 43
        let challenge = s256_challenge(short);
        assert!(
            !verify_exchange(short, &challenge),
            "格式非法 verifier 兑换必拒"
        );
    }
}
