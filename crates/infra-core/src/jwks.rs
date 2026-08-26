//! C10.11a — `kid` = JWK thumbprint(RFC 7638),及 JWKS 多公钥双活的选键逻辑。
//!
//! `kid` MUST = 公钥指纹(JWK thumbprint):跨密钥类型 / 跨轮换稳定,是"新旧 key 同时在 JWKS、
//! 按 kid 各自验签"的物理前提(见 DESIGN §8 JWKS / DEPLOYMENT §2 B)。RFC 7638 的 thumbprint =
//! 对**仅含必需成员、按 lexicographic 排序、无空白**的 JSON 做 SHA-256,再 base64url(无 padding)。
//! EC 必需成员 = `crv`/`kty`/`x`/`y`(注意字典序:crv < kty < x < y);RSA = `e`/`kty`/`n`。
//!
//! 本模块纯逻辑、零 AWS 依赖:输入公钥坐标(已 base64url 编码的 x/y 或 n/e),输出 thumbprint 与 kid。
//! 决策真相源:docs/DESIGN §8、docs/DEPLOYMENT §2 B;docs/CONFORMANCE C10.11a;RFC 7638。

use base64::Engine;
use sha2::{Digest, Sha256};

/// base64url **无 padding**(RFC 7638 / JWK 约定)。
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 计算 EC 公钥的 RFC 7638 JWK thumbprint(SHA-256 原始 32 字节)。
/// `crv` 如 "P-256";`x_b64url`/`y_b64url` 是坐标的 base64url(无 padding)串。
pub fn ec_thumbprint(crv: &str, x_b64url: &str, y_b64url: &str) -> [u8; 32] {
    // RFC 7638:成员按 code point 升序 → crv, kty, x, y。无空白、无多余字符。
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        crv, x_b64url, y_b64url
    );
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    h.finalize().into()
}

/// 计算 RSA 公钥的 RFC 7638 JWK thumbprint。字典序 → e, kty, n。
pub fn rsa_thumbprint(e_b64url: &str, n_b64url: &str) -> [u8; 32] {
    let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e_b64url, n_b64url);
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    h.finalize().into()
}

/// `kid` = thumbprint 的 base64url(无 padding)串。EC 版。
pub fn ec_kid(crv: &str, x_b64url: &str, y_b64url: &str) -> String {
    b64url(&ec_thumbprint(crv, x_b64url, y_b64url))
}

/// `kid` = thumbprint 的 base64url(无 padding)串。RSA 版。
pub fn rsa_kid(e_b64url: &str, n_b64url: &str) -> String {
    b64url(&rsa_thumbprint(e_b64url, n_b64url))
}

/// P-256 未压缩公钥点长度:`0x04 || X(32) || Y(32)` = 65 字节。
const P256_UNCOMPRESSED_POINT_LEN: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubKeyError {
    /// SPKI DER 里找不到 P-256 未压缩点(`0x04 || X || Y`),或长度不符。
    NotP256Uncompressed,
}

/// 一把 EC P-256 公钥的 JWK 表示(供 `/jwks.json` 端点直接序列化)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcJwk {
    pub kty: &'static str,   // "EC"
    pub crv: &'static str,   // "P-256"
    pub x: String,           // base64url(无 padding)
    pub y: String,           // base64url(无 padding)
    pub kid: String,         // RFC 7638 thumbprint
    pub alg: &'static str,   // "ES256"
    pub r#use: &'static str, // "sig"
}

/// 一把 RSA 公钥的 JWK 表示(供 `/jwks.json` 端点直接序列化;spec 001 C2.7 RS256 id_token 用)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaJwk {
    pub kty: &'static str,   // "RSA"
    pub n: String,           // modulus,base64url(无 padding,big-endian,去前导 0)
    pub e: String,           // exponent,base64url(无 padding)
    pub kid: String,         // RFC 7638 thumbprint({e,kty,n})
    pub alg: &'static str,   // "RS256"
    pub r#use: &'static str, // "sig"
}

/// 从 RSA modulus/exponent(big-endian 原始字节)构造 RSA JWK。
/// `n`/`e` 由上层(aws 适配器用 rsa/spki crate 从 KMS SPKI DER 解析)传入,infra-core 保持零 AWS 依赖。
pub fn rsa_jwk_from_ne(n_be: &[u8], e_be: &[u8]) -> RsaJwk {
    // JWK 整数:big-endian、无前导 0 字节(RFC 7518 §6.3.1)。
    let strip = |b: &[u8]| -> Vec<u8> {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        b[start..].to_vec()
    };
    let n = b64url(&strip(n_be));
    let e = b64url(&strip(e_be));
    let kid = rsa_kid(&e, &n);
    RsaJwk {
        kty: "RSA",
        n,
        e,
        kid,
        alg: "RS256",
        r#use: "sig",
    }
}

/// 从 KMS `GetPublicKey` 返回的 **SPKI DER** 公钥中解析出 P-256 的 x/y 坐标(各 32 字节)。
///
/// P-256 SPKI 的尾部是固定的未压缩椭圆曲线点 `0x04 || X(32) || Y(32)`(65 字节);
/// SPKI 头是固定的算法标识(id-ecPublicKey + prime256v1 OID),对 P-256 恒 91 字节 DER。
/// 这里稳健地**取 DER 末尾 65 字节**并校验其首字节为未压缩标记 `0x04`,拆出 X、Y——
/// 不引重型 ASN.1/EC 依赖(该转换是 `/jwks.json` 端点接线唯一缺失的一环,见 Explore 报告)。
///
/// 返回 (x_bytes[32], y_bytes[32])。`crates/infra-core` 保持零 AWS 依赖:DER 由上层从 KMS 取来传入。
pub fn p256_xy_from_spki_der(spki_der: &[u8]) -> Result<([u8; 32], [u8; 32]), PubKeyError> {
    if spki_der.len() < P256_UNCOMPRESSED_POINT_LEN {
        return Err(PubKeyError::NotP256Uncompressed);
    }
    let point = &spki_der[spki_der.len() - P256_UNCOMPRESSED_POINT_LEN..];
    if point[0] != 0x04 {
        // 0x04 = 未压缩点标记;压缩点(0x02/0x03)不在支持范围(KMS 返回未压缩)。
        return Err(PubKeyError::NotP256Uncompressed);
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&point[1..33]);
    y.copy_from_slice(&point[33..65]);
    Ok((x, y))
}

/// 从 SPKI DER 直接构造完整 P-256 EC JWK(`kid` = RFC 7638 thumbprint,`alg=ES256`,`use=sig`)。
/// `/jwks.json` 端点用它把 KMS 公钥转成可发布的 JWK。
pub fn ec_jwk_from_spki_der(spki_der: &[u8]) -> Result<EcJwk, PubKeyError> {
    let (x, y) = p256_xy_from_spki_der(spki_der)?;
    let x_b64 = b64url(&x);
    let y_b64 = b64url(&y);
    let kid = ec_kid("P-256", &x_b64, &y_b64);
    Ok(EcJwk {
        kty: "EC",
        crv: "P-256",
        x: x_b64,
        y: y_b64,
        kid,
        alg: "ES256",
        r#use: "sig",
    })
}

/// JWKS 里的一把公钥(仅承载选键需要的最小信息:kid + 是否仍可用于验签)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkEntry {
    pub kid: String,
    /// 是否仍在 JWKS 中发布(轮换 retire 期后移除即 false)。
    pub published: bool,
}

/// 双活选键:给定一个 token header 的 `kid`,在 JWKS 里找到仍发布的对应公钥。
/// 轮换重叠期 JWKS 同时含新旧两把 key,验签方按 token 的 `kid` 精确匹配到其中一把(C10.11a)。
/// 找不到 / 已 retire → None(验签失败,而非"猜一把")。
pub fn select_verifying_key<'a>(jwks: &'a [JwkEntry], token_kid: &str) -> Option<&'a JwkEntry> {
    jwks.iter().find(|k| k.published && k.kid == token_kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7638 §3.1 官方示例向量(RSA)。thumbprint 的 base64url 应为该固定串。
    #[test]
    fn rfc7638_rsa_reference_vector() {
        // 来自 RFC 7638 的示例 n/e。
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let e = "AQAB";
        assert_eq!(rsa_kid(e, n), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    // 成员顺序固定:EC 规范化 JSON 必须是 crv,kty,x,y。
    #[test]
    fn ec_thumbprint_deterministic_and_ordered() {
        let t1 = ec_thumbprint("P-256", "AAAA", "BBBB");
        let t2 = ec_thumbprint("P-256", "AAAA", "BBBB");
        assert_eq!(t1, t2, "同输入 thumbprint 必确定");
        assert_eq!(t1.len(), 32);
    }

    // 坐标不同 → kid 不同(轮换新 key 得新 kid)。
    #[test]
    fn different_key_different_kid() {
        let k1 = ec_kid("P-256", "AAAA", "BBBB");
        let k2 = ec_kid("P-256", "AAAA", "CCCC");
        assert_ne!(k1, k2);
    }

    // kid 是 base64url 无 padding(不含 '=' '+' '/')。
    #[test]
    fn kid_is_base64url_no_pad() {
        let kid = ec_kid("P-256", "AAAA", "BBBB");
        assert!(!kid.contains('='));
        assert!(!kid.contains('+'));
        assert!(!kid.contains('/'));
    }

    // C10.11a 双活:JWKS 含新旧两 key,按 kid 各自选中。
    #[test]
    fn dual_active_selects_by_kid() {
        let jwks = vec![
            JwkEntry {
                kid: "old".into(),
                published: true,
            },
            JwkEntry {
                kid: "new".into(),
                published: true,
            },
        ];
        assert_eq!(select_verifying_key(&jwks, "old").unwrap().kid, "old");
        assert_eq!(select_verifying_key(&jwks, "new").unwrap().kid, "new");
    }

    // 已 retire(published=false)的 key 不再被选中。
    #[test]
    fn retired_key_not_selected() {
        let jwks = vec![JwkEntry {
            kid: "old".into(),
            published: false,
        }];
        assert!(select_verifying_key(&jwks, "old").is_none());
    }

    // 未知 kid → None(不猜一把验签)。
    #[test]
    fn unknown_kid_none() {
        let jwks = vec![JwkEntry {
            kid: "a".into(),
            published: true,
        }];
        assert!(select_verifying_key(&jwks, "zzz").is_none());
    }

    // 真实 P-256 SPKI DER(openssl prime256v1 生成)——91 字节,末尾 65 字节为 04||X||Y。
    // 期望 x/y 由 python cryptography 独立提取(交叉验证)。
    const P256_SPKI_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200043031c32c1c89bc0933d0742df7187f76b3a644c36d53367a006b9b8faf0833067c1b3b9705a1f7dbeb6b840d1d1a2fcdb96f1e3ca353e8045584449b43574548";
    const EXPECT_X: &str = "MDHDLByJvAkz0HQt9xh_drOmRMNtUzZ6AGubj68IMwY";
    const EXPECT_Y: &str = "fBs7lwWh99vra4QNHRovzblvHjyjU-gEVYREm0NXRUg";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // C10.11a:从 KMS SPKI DER 解析 P-256 x/y,与独立工具(python cryptography)一致。
    #[test]
    fn p256_xy_matches_independent_extraction() {
        let der = hex_to_bytes(P256_SPKI_DER_HEX);
        let (x, y) = p256_xy_from_spki_der(&der).unwrap();
        assert_eq!(b64url(&x), EXPECT_X);
        assert_eq!(b64url(&y), EXPECT_Y);
    }

    // C10.11a:从 SPKI DER 构造完整 EC JWK,字段齐、kid = 按坐标算的 thumbprint。
    #[test]
    fn ec_jwk_from_spki_der_complete() {
        let der = hex_to_bytes(P256_SPKI_DER_HEX);
        let jwk = ec_jwk_from_spki_der(&der).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.alg, "ES256");
        assert_eq!(jwk.r#use, "sig");
        assert_eq!(jwk.x, EXPECT_X);
        assert_eq!(jwk.y, EXPECT_Y);
        // kid 应等于用该 x/y 算的 RFC 7638 thumbprint。
        assert_eq!(jwk.kid, ec_kid("P-256", EXPECT_X, EXPECT_Y));
        assert!(!jwk.kid.is_empty());
    }

    // 太短 / 非未压缩点 → 拒(不 panic)。
    #[test]
    fn bad_spki_rejected() {
        assert_eq!(
            p256_xy_from_spki_der(&[0u8; 10]),
            Err(PubKeyError::NotP256Uncompressed)
        );
        // 65 字节但首字节非 0x04(压缩点标记 0x02)→ 拒。
        let mut bad = vec![0u8; 65];
        bad[0] = 0x02;
        assert_eq!(
            p256_xy_from_spki_der(&bad),
            Err(PubKeyError::NotP256Uncompressed)
        );
    }
}
