//! SigV4/STS 兜底路径的**防重放/防转用纯逻辑**(spec 012 C5.3)——零 IO。
//!
//! 关注点(不真调 STS):
//! - **短 TTL**:从预签名请求 `X-Amz-Date` 到 AS 收到的时差 MUST ≤ 60s(含 ±30s 时钟 skew,C10.6)。
//! - **replay key**:`HMAC(server_secret, Authorization 头的 Signature= 段)`——**只哈希签名段**,
//!   改无关头不能绕过(评审 M1)。缓存命中/落库由 IO 层(dpop_jti 同类短命项),此处只算 key。
//! - **STS host allowlist**:`sts.amazonaws.com` / 区域 / FIPS;客户端自带 endpoint 不在集内拒(M3)。

/// 短 TTL 上限(秒):预签名请求签发到 AS 收到的最大时差(评审 M2)。
pub const SIGV4_MAX_AGE_SECS: i64 = 60;
/// 时钟偏移余量(秒;对齐 C10.6)。
pub const CLOCK_SKEW_SECS: i64 = 30;

/// 解析 `X-Amz-Date`(ISO8601 basic:`YYYYMMDDTHHMMSSZ`)→ Unix 秒。纯解析(不用系统时钟)。
/// 失败(格式非法)返回 None(上层 fail-closed 拒)。
pub fn parse_amz_date(s: &str) -> Option<i64> {
    // 形如 20260710T131140Z。定长 16。
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |lo: usize, hi: usize| -> Option<i64> { s.get(lo..hi)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, se) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    // 严格校验(评审 L1):月/日按当月天数校(含闰年),时 0-23、分/秒 0-59(AWS 不发闰秒 `:60`)。
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    if d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// 某年某月的天数(闰年 2 月 = 29)。
fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// 民用历 → 距 1970-01-01 的天数(Howard Hinnant 算法;纯整数,无外部依赖)。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 短 TTL 校验(C5.3①):`amz_date`(签发时刻)与 `now`(AS 收到)时差在 [0−skew, MAX_AGE+skew] 内。
/// 过老(重放旧预签名)或过于未来(时钟异常)均拒。
pub fn within_ttl(amz_date_secs: i64, now: i64) -> bool {
    let age = now - amz_date_secs;
    (-CLOCK_SKEW_SECS..=SIGV4_MAX_AGE_SECS + CLOCK_SKEW_SECS).contains(&age)
}

/// 从 SigV4 `Authorization` 头提取 `Signature=` 段(replay key 只哈希此段,评审 M1)。
/// 找不到返回 None。
pub fn extract_signature(authorization: &str) -> Option<String> {
    authorization.split(',').find_map(|s| {
        let s = s.trim();
        s.strip_prefix("Signature=").map(|v| v.to_string())
    })
}

/// STS host allowlist 校验(C5.3③):只允许固定 STS host(全局 / 区域 / FIPS)。
/// 客户端自带 endpoint 不在集内 → false(拒转发,防 endpoint 伪造)。
pub fn sts_host_allowed(host: &str) -> bool {
    let h = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    h == "sts.amazonaws.com"
        // 区域端点 sts.<region>.amazonaws.com;FIPS sts-fips.<region>.amazonaws.com。
        || (h.starts_with("sts.") && h.ends_with(".amazonaws.com"))
        || (h.starts_with("sts-fips.") && h.ends_with(".amazonaws.com"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_amz_date_basic() {
        // 20260710T131140Z:2026-07-10 13:11:40 UTC。
        let t = parse_amz_date("20260710T131140Z").unwrap();
        // 反算:与已知 epoch 对齐(2026-07-10 ≈ 1783687900s 量级)。
        assert!(
            t > 1_700_000_000 && t < 1_900_000_000,
            "epoch 量级合理: {t}"
        );
        // 逐字段:同日 00:00:00 应差 13:11:40 = 47500s。
        let midnight = parse_amz_date("20260710T000000Z").unwrap();
        assert_eq!(t - midnight, 13 * 3600 + 11 * 60 + 40);
    }

    #[test]
    fn parse_amz_date_rejects_malformed() {
        assert_eq!(parse_amz_date("2026-07-10T13:11:40Z"), None); // 带分隔符
        assert_eq!(parse_amz_date("20260710131140Z"), None); // 缺 T
        assert_eq!(parse_amz_date("20261710T131140Z"), None); // 月 17 非法
        assert_eq!(parse_amz_date(""), None);
        // 评审 L1:非法日/闰秒/超范围时分秒 MUST 拒。
        assert_eq!(parse_amz_date("20260231T000000Z"), None); // 2月31日不存在
        assert_eq!(parse_amz_date("20260229T000000Z"), None); // 2026非闰年,无2月29
        assert_eq!(parse_amz_date("20260710T131160Z"), None); // 秒=60(闰秒)拒
        assert_eq!(parse_amz_date("20260710T246000Z"), None); // 时=24 拒
        assert_eq!(parse_amz_date("20260700T131140Z"), None); // 日=00 拒
                                                              // 闰年 2月29日应接受。
        assert!(parse_amz_date("20240229T120000Z").is_some());
    }

    #[test]
    fn within_ttl_window() {
        let t0 = parse_amz_date("20260710T131140Z").unwrap();
        assert!(within_ttl(t0, t0)); // 同刻
        assert!(within_ttl(t0, t0 + 60)); // 60s 内
        assert!(within_ttl(t0, t0 + 89)); // 60+29 skew 内
        assert!(!within_ttl(t0, t0 + 200)); // 过老(重放旧预签名)拒
        assert!(within_ttl(t0, t0 - 20)); // 轻微未来(skew 内)容忍
        assert!(!within_ttl(t0, t0 - 120)); // 过度未来(时钟异常)拒
    }

    #[test]
    fn extract_signature_segment() {
        let a =
            "AWS4-HMAC-SHA256 Credential=AKIA/x,SignedHeaders=host;x-amz-date,Signature=abc123def";
        assert_eq!(extract_signature(a).as_deref(), Some("abc123def"));
        assert_eq!(extract_signature("AWS4-HMAC-SHA256 Credential=x"), None);
    }

    #[test]
    fn sts_host_allowlist() {
        assert!(sts_host_allowed("sts.amazonaws.com"));
        assert!(sts_host_allowed("sts.us-east-1.amazonaws.com"));
        assert!(sts_host_allowed("sts-fips.us-east-1.amazonaws.com"));
        assert!(sts_host_allowed("STS.US-EAST-1.AMAZONAWS.COM")); // 大小写不敏感
        assert!(sts_host_allowed("sts.amazonaws.com:443")); // 带端口
                                                            // 伪造/非 STS host 拒。
        assert!(!sts_host_allowed("evil.example.com"));
        assert!(!sts_host_allowed("sts.amazonaws.com.evil.com")); // 后缀不符
        assert!(!sts_host_allowed("notsts.amazonaws.com"));
    }
}
