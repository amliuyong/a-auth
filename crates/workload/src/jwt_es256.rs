//! ES256 JWT 本地验签(spec 012 §1.4 SPIFFE JWT-SVID 验签核心)——纯逻辑,**无网络**。
//!
//! 给定 EC P-256 公钥的 `x`/`y`(base64url,由 IO 层从 trust bundle `jwks_uri` 抓来),对 compact JWT
//! 验签 + 校 `alg=ES256`。**不抓 JWKS、不解 aud/exp/绑定**(那分别是 IO 层 + `spiffe::authorize_spiffe_jwt`)。
//! SPIRE 默认签 ES256(EC P-256)JWT-SVID;与 `jwt_rs256`(平台 OIDC token 多 RS256)并列,按 kty/alg 选。
//!
//! **alg pin(评审 codex/Kiro HIGH,防混淆)**:本函数硬 pin `alg==ES256`,只接受 EC key;RS256 声明
//! 一律 `NotEs256` 拒——与 `verify_rs256` pin RS256 对称,调用方按 `kty` 选验签器、绝不交叉。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::jwt_rs256::VerifiedJwt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Es256Error {
    /// JWT 结构非法(非三段 / base64 解码失败)。
    Malformed,
    /// header.alg 不是 ES256(不接受其它 alg,防降级/none/RS256 混淆)。
    NotEs256,
    /// header 缺 kid,或与期望 kid 不符。
    KidMismatch,
    /// JWK x/y 非法(base64 解码失败 / 非 32B / 非有效 P-256 点)。
    BadKey,
    /// 签名验证失败。
    BadSignature,
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// 从 EC P-256 JWK 的 x/y(base64url)重建验签 key(SEC1 uncompressed 0x04‖x‖y;同 dpop/verify)。
fn verifying_key_from_xy(x_b64: &str, y_b64: &str) -> Option<VerifyingKey> {
    let x = b64url_decode(x_b64)?;
    let y = b64url_decode(y_b64)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// 验 ES256 compact JWT。`expected_kid` = 从 JWKS 依 header.kid 选中的那把 key 的 kid(传 None 不校 kid)。
/// `x_b64`/`y_b64` = 该 EC P-256 key 的公钥坐标(base64url,32B each,JWK 标准字段)。
pub fn verify_es256(
    token: &str,
    x_b64: &str,
    y_b64: &str,
    expected_kid: Option<&str>,
) -> Result<VerifiedJwt, Es256Error> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(Es256Error::Malformed),
    };

    // header:alg MUST ES256(防降级/none/RS256 混淆);kid 可选比对。
    let header: serde_json::Value =
        serde_json::from_slice(&b64url_decode(h).ok_or(Es256Error::Malformed)?)
            .map_err(|_| Es256Error::Malformed)?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
        return Err(Es256Error::NotEs256);
    }
    let kid = header.get("kid").and_then(|k| k.as_str()).map(String::from);
    if let Some(exp_kid) = expected_kid {
        if kid.as_deref() != Some(exp_kid) {
            return Err(Es256Error::KidMismatch);
        }
    }

    // 重建 EC 公钥 + 验签(签名覆盖 `header.payload` ASCII)。
    let vk = verifying_key_from_xy(x_b64, y_b64).ok_or(Es256Error::BadKey)?;
    let signing_input = format!("{h}.{p}");
    let sig_bytes = b64url_decode(s).ok_or(Es256Error::Malformed)?;
    // ES256 签名 = r‖s(64B,IEEE P1363);Signature::from_slice 要求恰 64B。
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Es256Error::BadSignature)?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| Es256Error::BadSignature)?;

    // 验签通过 → 解 payload claims。
    let claims: serde_json::Value =
        serde_json::from_slice(&b64url_decode(p).ok_or(Es256Error::Malformed)?)
            .map_err(|_| Es256Error::Malformed)?;
    Ok(VerifiedJwt { kid, claims })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey};

    // 自生成 EC P-256 keypair,签一枚 ES256 JWT,返回 (token, x_b64, y_b64)。
    fn make_jwt(header: serde_json::Value, claims: serde_json::Value) -> (String, String, String) {
        let sk = SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let ep = vk.to_encoded_point(false);
        let x_b64 = URL_SAFE_NO_PAD.encode(ep.x().unwrap());
        let y_b64 = URL_SAFE_NO_PAD.encode(ep.y().unwrap());
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig: P256Sig = sk.sign(signing_input.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        (format!("{h}.{p}.{s}"), x_b64, y_b64)
    }

    // 另一把 key 的 x/y(用于错 key 验签拒)。
    fn other_xy() -> (String, String) {
        let sk = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let ep = sk.verifying_key().to_encoded_point(false);
        (
            URL_SAFE_NO_PAD.encode(ep.x().unwrap()),
            URL_SAFE_NO_PAD.encode(ep.y().unwrap()),
        )
    }

    #[test]
    fn verify_valid_es256() {
        let (tok, x, y) = make_jwt(
            serde_json::json!({"alg":"ES256","kid":"k1","typ":"JWT"}),
            serde_json::json!({"iss":"https://spire","sub":"spiffe://acme/agent/kb","aud":"as","exp":9_999_999_999i64}),
        );
        let v = verify_es256(&tok, &x, &y, Some("k1")).unwrap();
        assert_eq!(v.kid.as_deref(), Some("k1"));
        assert_eq!(v.claims["sub"], "spiffe://acme/agent/kb");
    }

    #[test]
    fn wrong_key_rejected() {
        let (tok, _x, _y) = make_jwt(
            serde_json::json!({"alg":"ES256","kid":"k1"}),
            serde_json::json!({"sub":"spiffe://acme/agent/x"}),
        );
        let (x2, y2) = other_xy();
        assert_eq!(
            verify_es256(&tok, &x2, &y2, None),
            Err(Es256Error::BadSignature)
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let (tok, x, y) = make_jwt(
            serde_json::json!({"alg":"ES256","kid":"k1"}),
            serde_json::json!({"sub":"spiffe://acme/agent/kb"}),
        );
        let mut parts: Vec<&str> = tok.split('.').collect();
        let evil = URL_SAFE_NO_PAD.encode(br#"{"sub":"spiffe://acme/agent/admin"}"#);
        parts[1] = &evil;
        let tampered = parts.join(".");
        assert_eq!(
            verify_es256(&tampered, &x, &y, None),
            Err(Es256Error::BadSignature)
        );
    }

    #[test]
    fn non_es256_alg_rejected() {
        // alg=none / RS256 一律拒(防降级 + alg 混淆:EC key 不验 RS256 声明)。
        for bad in ["none", "RS256", "HS256"] {
            let (tok, x, y) = make_jwt(
                serde_json::json!({"alg": bad, "kid": "k1"}),
                serde_json::json!({"sub":"spiffe://acme/agent/x"}),
            );
            assert_eq!(
                verify_es256(&tok, &x, &y, None),
                Err(Es256Error::NotEs256),
                "alg={bad} 应拒"
            );
        }
    }

    #[test]
    fn kid_mismatch_rejected() {
        let (tok, x, y) = make_jwt(
            serde_json::json!({"alg":"ES256","kid":"k1"}),
            serde_json::json!({"sub":"spiffe://acme/agent/x"}),
        );
        assert_eq!(
            verify_es256(&tok, &x, &y, Some("other-kid")),
            Err(Es256Error::KidMismatch)
        );
    }

    #[test]
    fn malformed_rejected() {
        assert_eq!(
            verify_es256("only.two", "x", "y", None),
            Err(Es256Error::Malformed)
        );
        assert_eq!(
            verify_es256("a.b.c.d", "x", "y", None),
            Err(Es256Error::Malformed)
        );
    }

    #[test]
    fn bad_key_xy_rejected() {
        let (tok, _x, _y) = make_jwt(
            serde_json::json!({"alg":"ES256"}),
            serde_json::json!({"sub":"spiffe://acme/agent/x"}),
        );
        // x/y 非 32B → BadKey。
        assert_eq!(
            verify_es256(&tok, "AAAA", "BBBB", None),
            Err(Es256Error::BadKey)
        );
    }
}
