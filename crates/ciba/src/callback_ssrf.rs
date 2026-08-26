//! CIBA ping/push 回调 notification endpoint 的 **SSRF 防护纯逻辑**(spec 013 §4,C7b.5)。
//!
//! AS 会**主动 POST** 到 client 自注册的 `backchannel_client_notification_endpoint`——这是攻击者
//! 可控的任意 URL,SSRF 面很大。防线分两层,本模块是**纯逻辑**层(零 IO、可 UT):
//!   ① `validate_endpoint_url`:URL 结构闸(https、端口、无 userinfo/fragment、host 非字面私网 IP)。
//!   ② `resolved_ips_allowed`:给定 DNS 解析出的 IP 列表,任一落私网/loopback/link-local/元数据 → 拒。
//!
//! DNS 解析本身 + **连接固定到已校验 IP**(防 TOCTOU/rebinding,codex 二轮 Blocker)属 IO 层(http
//! adapter):adapter MUST 在**投递前**用本模块的 `resolved_ips_allowed` 复校解析结果,并把连接钉死到
//! 刚校验通过的那个 IP(不给 HTTP client 二次 DNS 解析的窗)。决策依据:SECURITY.md「不留匿名可达面」
//! + OIDC CIBA Core §10.2(endpoint 元数据,不替 AS 做 SSRF 防护)。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// notification endpoint URL 结构校验的失败原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointUrlError {
    /// 非 `https://`(拒 http/其它 scheme)。
    NotHttps,
    /// 含 userinfo(`user:pass@host`)——防 URL 解析混淆。
    HasUserinfo,
    /// 含 fragment(`#...`)——回调 URL 不应带 fragment。
    HasFragment,
    /// host 缺失或为空。
    EmptyHost,
    /// 端口不在允许集(默认仅 443)。
    PortNotAllowed(u16),
    /// host 是字面私网/loopback/link-local IP(URL 里直接写 IP 的情形,免 DNS 也拦)。
    LiteralPrivateIp,
    /// URL 无法解析(格式非法)。
    Malformed,
}

/// 默认允许的投递端口(仅 https 标准端口)。真机可按需扩 allowlist,但默认最小。
const DEFAULT_ALLOWED_PORTS: &[u16] = &[443];

/// 校验 notification endpoint URL 的**结构**(不含 DNS 解析,那属 IO 层)。
/// 通过返回解析出的 host(供 IO 层 DNS 解析用);否则 Err。
///
/// - MUST `https://`(小写 scheme,绝对 URL);
/// - MUST NOT 带 userinfo / fragment(防解析混淆);
/// - host 非空;端口 ∈ allowlist(缺省 = 443);
/// - host 若是**字面 IP**,直接按 `ip_is_blocked` 判(URL 写死内网 IP 免 DNS 也拦)。
///
/// `allowed_ports` 传 None 用默认(仅 443)。
pub fn validate_endpoint_url<'a>(
    url: &'a str,
    allowed_ports: Option<&[u16]>,
) -> Result<&'a str, EndpointUrlError> {
    // scheme:MUST 恰为 https://(小写)。
    let rest = url
        .strip_prefix("https://")
        .ok_or(EndpointUrlError::NotHttps)?;
    // 空 authority。
    if rest.is_empty() {
        return Err(EndpointUrlError::EmptyHost);
    }
    // fragment:整个 URL 不得含 '#'。
    if url.contains('#') {
        return Err(EndpointUrlError::HasFragment);
    }
    // authority = rest 到第一个 '/'、'?' 之前。
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(EndpointUrlError::EmptyHost);
    }
    // userinfo:authority 含 '@' → 拒(防 `evil.com@169.254...` 混淆)。
    if authority.contains('@') {
        return Err(EndpointUrlError::HasUserinfo);
    }

    // 拆 host 与可选 port。IPv6 字面量形如 `[::1]:443`。
    let (host, port_opt): (&str, Option<&str>) = if let Some(after) = authority.strip_prefix('[') {
        // IPv6:`[addr]` 或 `[addr]:port`。
        let close = after.find(']').ok_or(EndpointUrlError::Malformed)?;
        let addr = &after[..close];
        let tail = &after[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p),
            None if tail.is_empty() => None,
            None => return Err(EndpointUrlError::Malformed),
        };
        (addr, port)
    } else {
        // IPv4 / DNS:host[:port](host 内无 ':';多个 ':' 视为非法)。
        match authority.rsplit_once(':') {
            Some((h, p)) => {
                if h.contains(':') {
                    return Err(EndpointUrlError::Malformed);
                }
                (h, Some(p))
            }
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(EndpointUrlError::EmptyHost);
    }

    // 端口校验(缺省 443)。
    let port: u16 = match port_opt {
        Some(p) => p.parse().map_err(|_| EndpointUrlError::Malformed)?,
        None => 443,
    };
    let allowed = allowed_ports.unwrap_or(DEFAULT_ALLOWED_PORTS);
    if !allowed.contains(&port) {
        return Err(EndpointUrlError::PortNotAllowed(port));
    }

    // host 若是字面 IP,直接判私网(免 DNS,URL 写死内网 IP 也拦)。
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_blocked(&ip) {
            return Err(EndpointUrlError::LiteralPrivateIp);
        }
    }

    Ok(host)
}

/// 给定 DNS 解析出的 IP 列表,是否**全部**可投递(任一被封 → 整体拒,fail-closed)。
/// 空列表(解析不出任何 IP)→ 拒(没有可安全连接的目标)。
/// IO 层 MUST 在**投递前**调用此函数复校(防 rebinding),并把连接钉死到通过的 IP。
pub fn resolved_ips_allowed(ips: &[IpAddr]) -> bool {
    !ips.is_empty() && ips.iter().all(|ip| !ip_is_blocked(ip))
}

/// 单个 IP 是否被封(私网/loopback/link-local/元数据/未指定/多播等非公网可路由地址)。
/// 用保守白判黑:凡不是明确公网可路由的 → 封(fail-closed)。
pub fn ip_is_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_blocked(v4),
        IpAddr::V6(v6) => v6_is_blocked(v6),
    }
}

fn v4_is_blocked(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    // loopback 127/8、私网 10/8·172.16/12·192.168/16、link-local 169.254/16(含 169.254.169.254 云元数据)、
    // 未指定 0.0.0.0、广播、多播、文档/基准/共享地址段——保守全封。
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // 0.0.0.0/8「本网络」整段(is_unspecified 只匹配 0.0.0.0 单点,评审 Kiro M2)。
        || o[0] == 0
        // 100.64.0.0/10 CGNAT 共享地址(RFC 6598)——手动判(std 无 stable API)。
        || (o[0] == 100 && (o[1] & 0xC0) == 0x40)
        // 192.0.0.0/24 IETF 协议分配。
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking(RFC 2544,评审 Kiro M2)。
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        // 240.0.0.0/4 Class E 保留(含 255.255.255.255 广播已由 is_broadcast 覆盖;此处封整段,评审 Kiro M2)。
        || (o[0] & 0xF0) == 0xF0
}

fn v6_is_blocked(ip: &Ipv6Addr) -> bool {
    // loopback ::1、未指定 ::、多播、link-local fe80::/10、唯一本地 fc00::/7(ULA)——保守全封。
    // 另拦所有内嵌 IPv4 的表示——把内嵌 IPv4 再按 v4 规则判(防 ::ffff:169.254.169.254 等绕过)。
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let seg = ip.segments();
    // link-local fe80::/10。
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // 唯一本地 fc00::/7(ULA)。
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // 内嵌 IPv4 的各种表示(评审 Kiro M2:std to_ipv4_mapped 只覆盖 ::ffff:)——统一提取低 32 位按 v4 判:
    //   ① IPv4-mapped ::ffff:a.b.c.d;② IPv4-compatible ::a.b.c.d(deprecated 但仍可解析);
    //   ③ NAT64 64:ff9b::/96 与 64:ff9b:1::/48;④ 6to4 2002::/16(内嵌 IPv4 在 seg[1..3])。
    if let Some(v4) = embedded_ipv4(ip) {
        if v4_is_blocked(&v4) {
            return true;
        }
    }
    false
}

/// 从各种内嵌 IPv4 的 IPv6 表示中提取 IPv4 地址(供 SSRF 复判)。无内嵌 → None。
fn embedded_ipv4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    // ::ffff:a.b.c.d(IPv4-mapped)。
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    // 6to4 2002:AABB:CCDD::/16 → IPv4 = AA.BB.CC.DD(seg[1] 高/低字节 + seg[2] 高/低字节)。
    if seg[0] == 0x2002 {
        let a = (seg[1] >> 8) as u8;
        let b = (seg[1] & 0xff) as u8;
        let c = (seg[2] >> 8) as u8;
        let d = (seg[2] & 0xff) as u8;
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    // NAT64 64:ff9b::/96(well-known)与 64:ff9b:1::/48 → 低 32 位是内嵌 IPv4。
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        let low = ip.octets();
        return Some(Ipv4Addr::new(low[12], low[13], low[14], low[15]));
    }
    // IPv4-compatible ::a.b.c.d(前 96 位全 0、非 ::/::1)——取低 32 位。
    if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && seg[7] == 0) {
        let low = ip.octets();
        return Some(Ipv4Addr::new(low[12], low[13], low[14], low[15]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_https_host() {
        assert_eq!(
            validate_endpoint_url("https://client.example.com/ciba/cb", None),
            Ok("client.example.com")
        );
        // 显式 443 也可。
        assert_eq!(
            validate_endpoint_url("https://client.example.com:443/cb", None),
            Ok("client.example.com")
        );
    }

    #[test]
    fn rejects_non_https() {
        assert_eq!(
            validate_endpoint_url("http://client.example.com/cb", None),
            Err(EndpointUrlError::NotHttps)
        );
        assert_eq!(
            validate_endpoint_url("ftp://x/cb", None),
            Err(EndpointUrlError::NotHttps)
        );
    }

    #[test]
    fn rejects_userinfo_and_fragment() {
        assert_eq!(
            validate_endpoint_url("https://evil.com@169.254.169.254/cb", None),
            Err(EndpointUrlError::HasUserinfo)
        );
        assert_eq!(
            validate_endpoint_url("https://client.example.com/cb#frag", None),
            Err(EndpointUrlError::HasFragment)
        );
    }

    #[test]
    fn rejects_non_443_port_by_default() {
        assert_eq!(
            validate_endpoint_url("https://client.example.com:8080/cb", None),
            Err(EndpointUrlError::PortNotAllowed(8080))
        );
        // 显式 allowlist 8443 → 通过。
        assert_eq!(
            validate_endpoint_url("https://client.example.com:8443/cb", Some(&[443, 8443])),
            Ok("client.example.com")
        );
    }

    #[test]
    fn rejects_literal_private_ip_in_url() {
        // URL 直接写内网/元数据 IP —— 免 DNS 也拦。
        assert_eq!(
            validate_endpoint_url("https://169.254.169.254/latest/meta-data", None),
            Err(EndpointUrlError::LiteralPrivateIp)
        );
        assert_eq!(
            validate_endpoint_url("https://10.0.0.5/cb", None),
            Err(EndpointUrlError::LiteralPrivateIp)
        );
        assert_eq!(
            validate_endpoint_url("https://127.0.0.1/cb", None),
            Err(EndpointUrlError::LiteralPrivateIp)
        );
        // IPv6 loopback/ULA 字面量。
        assert_eq!(
            validate_endpoint_url("https://[::1]/cb", None),
            Err(EndpointUrlError::LiteralPrivateIp)
        );
    }

    #[test]
    fn accepts_literal_public_ip() {
        // 公网 IP 字面量放行(结构层;仍会在投递前复校)。
        assert_eq!(
            validate_endpoint_url("https://93.184.216.34/cb", None),
            Ok("93.184.216.34")
        );
    }

    #[test]
    fn resolved_ips_gate_rejects_any_private() {
        let pub_ip: IpAddr = "93.184.216.34".parse().unwrap();
        let meta: IpAddr = "169.254.169.254".parse().unwrap();
        let priv10: IpAddr = "10.1.2.3".parse().unwrap();
        // 全公网 → 放行。
        assert!(resolved_ips_allowed(&[pub_ip]));
        // 任一私网/元数据 → 拒(rebinding:公网+内网混合也拒)。
        assert!(!resolved_ips_allowed(&[pub_ip, meta]));
        assert!(!resolved_ips_allowed(&[priv10]));
        // 空列表(解析不出)→ 拒(fail-closed)。
        assert!(!resolved_ips_allowed(&[]));
    }

    #[test]
    fn ipv4_mapped_ipv6_metadata_blocked() {
        // ::ffff:169.254.169.254 —— IPv4-mapped 绕过防御。
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(ip_is_blocked(&mapped), "IPv4-mapped 元数据地址必须拦");
    }

    #[test]
    fn cgnat_shared_blocked() {
        let cgnat: IpAddr = "100.64.1.1".parse().unwrap();
        assert!(ip_is_blocked(&cgnat), "CGNAT 100.64/10 应拦");
        // 100.63 与 100.128 不在 100.64/10 内 → 公网。
        let outside: IpAddr = "100.63.0.1".parse().unwrap();
        assert!(!ip_is_blocked(&outside));
    }

    // 评审 Kiro M2:v4 额外保留段。
    #[test]
    fn v4_reserved_ranges_blocked() {
        for s in [
            "0.0.0.0",      // 0/8 本网络(不止单点 unspecified)
            "0.1.2.3",      // 0/8 其余
            "198.18.0.1",   // 198.18/15 benchmarking
            "198.19.255.1", // 198.18/15 高半
            "240.0.0.1",    // 240/4 Class E
            "250.1.2.3",    // Class E
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_is_blocked(&ip), "{s} 应拦(保留段)");
        }
        // 198.17 与 198.20 不在 198.18/15 内 → 公网。
        assert!(!ip_is_blocked(&"198.17.0.1".parse::<IpAddr>().unwrap()));
        assert!(!ip_is_blocked(&"198.20.0.1".parse::<IpAddr>().unwrap()));
    }

    // 评审 Kiro M2:v6 内嵌 IPv4 的各种表示都要解码后按 v4 判(防绕过元数据/内网)。
    #[test]
    fn v6_embedded_ipv4_metadata_blocked() {
        for s in [
            "::ffff:169.254.169.254",   // IPv4-mapped
            "::169.254.169.254",        // IPv4-compatible(deprecated)
            "64:ff9b::169.254.169.254", // NAT64 well-known /96
            "2002:a9fe:a9fe::",         // 6to4 内嵌 169.254.169.254(0xa9fe=169.254)
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_is_blocked(&ip), "{s} 内嵌元数据地址应拦");
        }
        // 6to4 内嵌公网 IPv4(93.184.216.34 = 0x5db8:0xd822)→ 不拦。
        let pub6to4: IpAddr = "2002:5db8:d822::".parse().unwrap();
        assert!(!ip_is_blocked(&pub6to4), "6to4 内嵌公网 IPv4 不应拦");
    }
}
