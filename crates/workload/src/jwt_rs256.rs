//! RS256 JWT 本地验签(spec 012 C5.1 平台 OIDC token 验签核心)——纯逻辑,**无网络**。
//!
//! 给定平台 JWKS 的 `n`/`e`(base64url,由 IO 层从 `jwks_uri` 抓来),对 compact JWT 验签 +
//! 校 `alg=RS256`。**不抓 JWKS、不解 aud/exp/绑定**(那分别是 IO 层 + `oidc::authorize_oidc`)。
//! 平台 token 多为 RS256(GitHub Actions / K8s projected SA / Cognito)。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rs256Error {
    /// JWT 结构非法(非三段 / base64 解码失败)。
    Malformed,
    /// header.alg 不是 RS256(不接受其它 alg,防降级/none)。
    NotRs256,
    /// header 缺 kid,或与期望 kid 不符。
    KidMismatch,
    /// JWKS n/e 非法(base64 解码失败 / 非有效公钥)。
    BadKey,
    /// 签名验证失败。
    BadSignature,
}

/// 一枚已验签的平台 JWT 的解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwt {
    pub kid: Option<String>,
    /// payload claims(JSON;交给 `oidc::authorize_oidc` 做 aud/exp/绑定判定)。
    pub claims: serde_json::Value,
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// 验 RS256 compact JWT。`expected_kid` = 从 JWKS 依 header.kid 选中的那把 key 的 kid
/// (调用方按 header.kid 选 key 后传入;传 None 则不校 kid,仅验签)。
///
/// `n_b64`/`e_b64` = 该 key 的模数/指数(base64url,JWK 标准字段)。
pub fn verify_rs256(
    token: &str,
    n_b64: &str,
    e_b64: &str,
    expected_kid: Option<&str>,
) -> Result<VerifiedJwt, Rs256Error> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(Rs256Error::Malformed),
    };

    // header:alg MUST RS256;kid 可选比对。
    let header: serde_json::Value =
        serde_json::from_slice(&b64url_decode(h).ok_or(Rs256Error::Malformed)?)
            .map_err(|_| Rs256Error::Malformed)?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("RS256") {
        return Err(Rs256Error::NotRs256);
    }
    let kid = header.get("kid").and_then(|k| k.as_str()).map(String::from);
    if let Some(exp_kid) = expected_kid {
        if kid.as_deref() != Some(exp_kid) {
            return Err(Rs256Error::KidMismatch);
        }
    }

    // 重建 RSA 公钥(n/e)。
    let n = BigUint::from_bytes_be(&b64url_decode(n_b64).ok_or(Rs256Error::BadKey)?);
    let e = BigUint::from_bytes_be(&b64url_decode(e_b64).ok_or(Rs256Error::BadKey)?);
    let pubkey = RsaPublicKey::new(n, e).map_err(|_| Rs256Error::BadKey)?;
    let vk = VerifyingKey::<Sha256>::new(pubkey);

    // 签名覆盖 `header.payload`(ASCII)。
    let signing_input = format!("{h}.{p}");
    let sig_bytes = b64url_decode(s).ok_or(Rs256Error::Malformed)?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| Rs256Error::BadSignature)?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| Rs256Error::BadSignature)?;

    // 验签通过 → 解 payload claims。
    let claims: serde_json::Value =
        serde_json::from_slice(&b64url_decode(p).ok_or(Rs256Error::Malformed)?)
            .map_err(|_| Rs256Error::Malformed)?;
    Ok(VerifiedJwt { kid, claims })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    // 自生成 RSA keypair,签一枚 RS256 JWT,返回 (token, n_b64, e_b64)。
    fn make_jwt(header: serde_json::Value, claims: serde_json::Value) -> (String, String, String) {
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk = sk.to_public_key();
        let n_b64 = URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be());

        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let signing_key = SigningKey::<Sha256>::new(sk);
        let sig = signing_key.sign(signing_input.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        (format!("{h}.{p}.{s}"), n_b64, e_b64)
    }

    #[test]
    fn verify_valid_rs256() {
        let (tok, n, e) = make_jwt(
            serde_json::json!({"alg":"RS256","kid":"k1","typ":"JWT"}),
            serde_json::json!({"iss":"https://plat","sub":"repo:acme/agent:x","aud":"as","exp":9_999_999_999i64}),
        );
        let v = verify_rs256(&tok, &n, &e, Some("k1")).unwrap();
        assert_eq!(v.kid.as_deref(), Some("k1"));
        assert_eq!(v.claims["sub"], "repo:acme/agent:x");
    }

    #[test]
    fn wrong_key_rejected() {
        let (tok, _n, _e) = make_jwt(
            serde_json::json!({"alg":"RS256","kid":"k1"}),
            serde_json::json!({"sub":"x"}),
        );
        // 用另一把 key 的 n/e 验 → BadSignature。
        let (_t2, n2, e2) = make_jwt(
            serde_json::json!({"alg":"RS256"}),
            serde_json::json!({"sub":"y"}),
        );
        assert_eq!(
            verify_rs256(&tok, &n2, &e2, None),
            Err(Rs256Error::BadSignature)
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let (tok, n, e) = make_jwt(
            serde_json::json!({"alg":"RS256","kid":"k1"}),
            serde_json::json!({"sub":"repo:acme/agent:x"}),
        );
        // 篡改 payload 段。
        let mut parts: Vec<&str> = tok.split('.').collect();
        let evil = URL_SAFE_NO_PAD.encode(br#"{"sub":"repo:evil/x:y"}"#);
        parts[1] = &evil;
        let tampered = parts.join(".");
        assert_eq!(
            verify_rs256(&tampered, &n, &e, None),
            Err(Rs256Error::BadSignature)
        );
    }

    #[test]
    fn non_rs256_alg_rejected() {
        // alg=none / ES256 一律拒(防降级)。
        let (tok, n, e) = make_jwt(
            serde_json::json!({"alg":"none"}),
            serde_json::json!({"sub":"x"}),
        );
        assert_eq!(verify_rs256(&tok, &n, &e, None), Err(Rs256Error::NotRs256));
    }

    #[test]
    fn kid_mismatch_rejected() {
        let (tok, n, e) = make_jwt(
            serde_json::json!({"alg":"RS256","kid":"k1"}),
            serde_json::json!({"sub":"x"}),
        );
        assert_eq!(
            verify_rs256(&tok, &n, &e, Some("other-kid")),
            Err(Rs256Error::KidMismatch)
        );
    }

    #[test]
    fn malformed_rejected() {
        assert_eq!(
            verify_rs256("only.two", "n", "e", None),
            Err(Rs256Error::Malformed)
        );
        assert_eq!(
            verify_rs256("a.b.c.d", "n", "e", None),
            Err(Rs256Error::Malformed)
        );
    }
}
