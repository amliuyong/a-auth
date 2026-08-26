//! C9.3(P0.5 硬 gate)— 一次性账户恢复码纯逻辑。
//!
//! 用户丢邮箱/设备(magic-link/passkey 无密码)是头号接管入口;恢复码是最后防线。
//! 本模块纯逻辑(生成/格式/HMAC/常量时间验证/锁定状态转移),零 IO、零 AWS:
//! - 生成一组(默认 10)一次性码,格式 `v1.{user_lookup}.{secret}`——`user_lookup` **非秘密**
//!   (让 `/recover` 无有效 code 时仍能按 user 定位做锁定,codex 评审关键);`secret` ≥20 Base32 字符
//!   (~97 bit;**单码是接管防线**,故单码熵为准)。
//! - **存 HMAC(不存明文)**:`HMAC-SHA256(server_secret, "recovery:"‖code)`——domain-separated,
//!   不复用 magic-link 的裸 secret 域;DB 泄露 + server_secret 未泄露仍安全。
//! - 验证:重算 HMAC + 常量时间比对(保持与 magic_link/websec 一致的抗时序模式)。
//! - 锁定:per-user 失败计数,达阈值(5)锁定窗口(15min);**成功/管理员解锁才清**(非时间到自动清)。
//!
//! 一次性消费的**原子性**(并发验同码只成功一次)+ 失败计数持久化由上层 RecoveryStore(DynamoDB
//! 条件写)保证;本模块只给判定与哈希。决策真相源:docs/DESIGN §7;docs/CONFORMANCE C9.3。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// 每码 secret 部分的字节数(20 字节 → Base32 后 32 字符 → 160 bit;远超 ≥128 bit 要求)。
pub const SECRET_BYTES: usize = 20;
/// 默认下发码数。
pub const DEFAULT_CODE_COUNT: usize = 10;
/// 验码失败锁定阈值。
pub const MAX_ATTEMPTS: u32 = 5;
/// 锁定窗口(秒)= 15min。
pub const LOCKOUT_SECS: i64 = 900;
/// HMAC domain 前缀(与其它 HMAC 用途隔离)。
const HMAC_DOMAIN: &[u8] = b"recovery:";
/// 码格式版本前缀。
const VERSION: &str = "v1";

/// Crockford-ish Base32(无填充,大写,去易混字符集用标准 RFC4648 字母表足够;此处用标准 A-Z2-7)。
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// 组装一枚恢复码明文:`v1.{user_lookup}.{secret_base32}`。
/// `user_lookup`:非秘密的 user 定位串(如 user_id 的短哈希);`secret_bytes`:CSPRNG 随机(上层提供)。
pub fn format_code(user_lookup: &str, secret_bytes: &[u8]) -> String {
    format!("{VERSION}.{user_lookup}.{}", base32_encode(secret_bytes))
}

/// 解析恢复码 → (user_lookup, secret 部分)。格式不符返回 None。
/// 用于 `/recover`:先取 user_lookup 定位 user + 做锁定判定,再验 secret 的 HMAC。
pub fn parse_code(code: &str) -> Option<(String, String)> {
    let mut it = code.splitn(3, '.');
    let v = it.next()?;
    let lookup = it.next()?;
    let secret = it.next()?;
    if v != VERSION || lookup.is_empty() || secret.is_empty() {
        return None;
    }
    Some((lookup.to_string(), secret.to_string()))
}

/// 计算恢复码的存储哈希:`HMAC-SHA256(server_secret, "recovery:"‖code)`(domain-separated)。
/// 存这个、不存明文;验码时对呈现的 code 重算再常量时间比对。
pub fn code_hash(server_secret: &[u8], code: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(HMAC_DOMAIN);
    mac.update(code.as_bytes());
    mac.finalize().into_bytes().into()
}

/// 常量时间比对两个哈希(防时序侧信道)。
pub fn hash_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// 常量时间比对两个哈希的 base64 串(存储层以 base64 存哈希;避免用 `==` 早退泄露时序)。
/// 长度不同直接 false(不影响安全:HMAC base64 定长 43 字符,正常路径长度恒等)。
pub fn hash_eq_b64(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// 锁定状态判定(纯函数):给定失败计数与锁定截止,判断此刻是否被锁。
/// `locked_until`:锁定截止 Unix 秒(0 = 未锁);`now`:当前 Unix 秒。
pub fn is_locked(locked_until: i64, now: i64) -> bool {
    now < locked_until
}

/// 一次验码失败后的新锁定状态(纯状态转移)。达 MAX_ATTEMPTS 则设锁定截止。
/// 返回 (new_attempt_count, new_locked_until)。
pub fn on_failed_attempt(attempt_count: u32, now: i64) -> (u32, i64) {
    let n = attempt_count.saturating_add(1);
    if n >= MAX_ATTEMPTS {
        (n, now + LOCKOUT_SECS)
    } else {
        (n, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"dev-server-secret-not-for-prod";

    #[test]
    fn secret_gives_128plus_bits() {
        // 20 字节 = 160 bit;Base32 编码后 ≥32 字符。
        let enc = base32_encode(&[0xABu8; SECRET_BYTES]);
        assert!(
            enc.len() >= 32,
            "secret Base32 长度 {} 应 ≥32(≥128 bit)",
            enc.len()
        );
    }

    #[test]
    fn format_parse_roundtrip() {
        let code = format_code("u12345", &[0x11u8; SECRET_BYTES]);
        assert!(code.starts_with("v1.u12345."));
        let (lookup, secret) = parse_code(&code).unwrap();
        assert_eq!(lookup, "u12345");
        assert!(!secret.is_empty());
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_code("noformat").is_none());
        assert!(parse_code("v1.onlylookup").is_none());
        assert!(parse_code("v2.u1.secret").is_none()); // 版本不符
        assert!(parse_code("v1..secret").is_none()); // 空 lookup
        assert!(parse_code("v1.u1.").is_none()); // 空 secret
    }

    #[test]
    fn hash_is_hmac_domain_separated() {
        let code = format_code("u1", &[0x22u8; SECRET_BYTES]);
        let h1 = code_hash(SECRET, &code);
        let h2 = code_hash(SECRET, &code);
        assert_eq!(h1, h2, "同码同 secret HMAC 确定");
        // 不同 server_secret → 不同哈希(DB 泄露 + secret 未泄露仍安全)。
        let h3 = code_hash(b"other-secret", &code);
        assert_ne!(h1, h3);
        // domain separation:HMAC 覆盖 "recovery:" 前缀,与裸 HMAC(code) 不同。
        let mut mac = HmacSha256::new_from_slice(SECRET).unwrap();
        mac.update(code.as_bytes());
        let bare: [u8; 32] = mac.finalize().into_bytes().into();
        assert_ne!(h1, bare, "domain-separated,不复用裸 secret 域");
    }

    #[test]
    fn verify_via_hash_eq() {
        let code = format_code("u1", &[0x33u8; SECRET_BYTES]);
        let stored = code_hash(SECRET, &code);
        // 正确码 → 匹配。
        assert!(hash_eq(&stored, &code_hash(SECRET, &code)));
        // 错误码 → 不匹配。
        let wrong = format_code("u1", &[0x44u8; SECRET_BYTES]);
        assert!(!hash_eq(&stored, &code_hash(SECRET, &wrong)));
    }

    #[test]
    fn lockout_after_max_attempts() {
        let now = 1000;
        // 前 4 次失败:计数增,不锁。
        let mut count = 0;
        for i in 1..MAX_ATTEMPTS {
            let (c, l) = on_failed_attempt(count, now);
            count = c;
            assert_eq!(count, i);
            assert_eq!(l, 0, "第 {i} 次失败不该锁");
            assert!(!is_locked(l, now));
        }
        // 第 5 次失败 → 锁定。
        let (c, l) = on_failed_attempt(count, now);
        assert_eq!(c, MAX_ATTEMPTS);
        assert_eq!(l, now + LOCKOUT_SECS);
        assert!(is_locked(l, now));
        assert!(is_locked(l, now + LOCKOUT_SECS - 1));
        assert!(!is_locked(l, now + LOCKOUT_SECS)); // 窗口到期
    }

    #[test]
    fn hash_eq_b64_matches_and_rejects() {
        assert!(hash_eq_b64("abcDEF123", "abcDEF123"));
        assert!(!hash_eq_b64("abcDEF123", "abcDEF124"));
        assert!(!hash_eq_b64("abc", "abcd"), "长度不同 → false");
    }

    #[test]
    fn base32_no_padding_uppercase() {
        let enc = base32_encode(&[0xFF, 0x00, 0xAB]);
        assert!(!enc.contains('='), "无填充");
        assert!(enc
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }
}
