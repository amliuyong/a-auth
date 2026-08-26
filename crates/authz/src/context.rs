//! §7.2 请求上下文比对(CIDR)+ 声明式 RAR 交集(C8.5a 词汇表内)。纯逻辑,fail-closed。

use crate::AuthzError;
use std::net::IpAddr;

/// §7.2:来源 IP 是否 ∈ 允许 CIDR 集。**空 allowlist = 不限(Ok(true))**;任一坏 CIDR 或坏 IP → **Err(fail-closed)**
/// (坏 allowlist 绝不静默放行;签发热路径调用方遇 Err 一律拒)。
pub fn ip_in_cidrs(source_ip: &str, allowed: &[String]) -> Result<bool, AuthzError> {
    if allowed.is_empty() {
        return Ok(true); // 空 = 不限
    }
    let ip: IpAddr = source_ip
        .parse()
        .map_err(|_| AuthzError::BadIp(source_ip.to_string()))?;
    for cidr in allowed {
        let net: ipnet::IpNet = cidr
            .parse()
            .map_err(|_| AuthzError::BadCidr(cidr.clone()))?;
        if net.contains(&ip) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 声明式 RAR 交集(C8.5a 词汇表内):只保留 `type` ∈ `policy_allowed_types` 的授权项;**未知 type 剔除**
/// (fail-closed:词汇表外/需策略引擎的复杂 RAR 属 C8.5b P3,不在此放行)。缺 `type` 字段的项也剔除。
pub fn intersect_rar(
    authorized: &[serde_json::Value],
    policy_allowed_types: &[String],
) -> Vec<serde_json::Value> {
    authorized
        .iter()
        .filter(|entry| {
            entry
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| policy_allowed_types.iter().any(|a| a == t))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_match_and_failclosed() {
        assert_eq!(ip_in_cidrs("10.0.0.5", &["10.0.0.0/8".into()]), Ok(true));
        assert_eq!(
            ip_in_cidrs("192.168.1.1", &["10.0.0.0/8".into()]),
            Ok(false)
        );
        assert_eq!(ip_in_cidrs("1.2.3.4", &[]), Ok(true)); // 空 = 不限
                                                           // 坏 CIDR / 坏 IP → fail-closed Err。
        assert!(matches!(
            ip_in_cidrs("1.2.3.4", &["bad-cidr".into()]),
            Err(AuthzError::BadCidr(_))
        ));
        assert!(matches!(
            ip_in_cidrs("not-ip", &["10.0.0.0/8".into()]),
            Err(AuthzError::BadIp(_))
        ));
        // IPv6 也支持。
        assert_eq!(
            ip_in_cidrs("2001:db8::1", &["2001:db8::/32".into()]),
            Ok(true)
        );
    }

    #[test]
    fn rar_intersect_drops_unknown_and_typeless() {
        let authorized = vec![
            serde_json::json!({"type":"doc_read","valid_to":"2026"}),
            serde_json::json!({"type":"other"}),
            serde_json::json!({"no_type":"x"}),
        ];
        let out = intersect_rar(&authorized, &["doc_read".into()]);
        assert_eq!(out.len(), 1, "只保留词汇表内 type;未知/缺 type 剔除");
        assert_eq!(out[0]["type"], "doc_read");
        // 空允许集 → 全剔除(fail-closed)。
        assert_eq!(intersect_rar(&authorized, &[]).len(), 0);
    }
}
