//! Shared pinned HTTPS transport and CIBA notifications.

/// CIBA ping/push 回调投递(spec 013 §4,C7b.5)——真机 reqwest 出站到 client 自注册 endpoint。
///
/// **SSRF 纵深防护(codex/Kiro 评审 Blocker/H1)**:
/// - 投递**前**用 `agent_auth_ciba::validate_endpoint_url` 复核 URL 结构(https/端口/非字面私网);
/// - `tokio::net::lookup_host` 解析所有 IP,`resolved_ips_allowed` 复校(防 **DNS rebinding**:注册时公网、
///   投递时 rebind 内网);任一非公网 → `BlockedBySsrf`(**不发出请求**);
/// - **连接固定到已校验 IP**(消除 TOCTOU):per-request `reqwest::Client` 用 `.resolve_to_addrs(host, &[ip])`
///   把该 host 钉死到刚校验的 IP,**不给 reqwest 二次 DNS 解析的窗**;
/// - `redirect::Policy::none()`(禁 30x 跳内网);≤5s 超时。
///
/// 失败区分:SSRF 复校拒 = `BlockedBySsrf`(未发出,token 安全);已发出后失败 = `Failed`(模糊态)。
#[derive(Clone, Default)]
pub struct HttpCibaCallbackDelivery;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinnedHttpsClientError {
    UnsafeTarget,
    DnsResolution,
    ClientBuild,
}

const PINNED_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const PINNED_MAX_RESOLVED_ADDRESSES: usize = 16;

pub(crate) fn pinned_https_client_builder_for_addrs(
    host: &str,
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, addrs)
        .no_proxy()
}

fn pinned_https_client_for_addrs(
    host: &str,
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> Result<reqwest::Client, PinnedHttpsClientError> {
    if addrs.len() > PINNED_MAX_RESOLVED_ADDRESSES {
        return Err(PinnedHttpsClientError::DnsResolution);
    }
    let ips = addrs.iter().map(|address| address.ip()).collect::<Vec<_>>();
    if !agent_auth_ciba::resolved_ips_allowed(&ips) {
        return Err(PinnedHttpsClientError::UnsafeTarget);
    }
    pinned_https_client_builder_for_addrs(host, addrs, timeout)
        .build()
        .map_err(|_| PinnedHttpsClientError::ClientBuild)
}

/// Build a direct HTTPS client whose connection is pinned to the exact public
/// IP set validated immediately before the request. Shared by every
/// receiver-controlled outbound callback so CIBA and SSF cannot drift onto
/// different SSRF policies.
pub(crate) async fn pinned_https_client(
    endpoint: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, PinnedHttpsClientError> {
    let started_at = std::time::Instant::now();
    if agent_auth_ciba::validate_endpoint_url(endpoint, None).is_err() {
        return Err(PinnedHttpsClientError::UnsafeTarget);
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| PinnedHttpsClientError::UnsafeTarget)?;
    let host = url
        .host_str()
        .ok_or(PinnedHttpsClientError::UnsafeTarget)?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        let resolved = tokio::time::timeout(
            std::cmp::min(timeout, PINNED_DNS_TIMEOUT),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| PinnedHttpsClientError::DnsResolution)?
        .map_err(|_| PinnedHttpsClientError::DnsResolution)?;
        let addrs = resolved
            .take(PINNED_MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addrs.len() > PINNED_MAX_RESOLVED_ADDRESSES {
            return Err(PinnedHttpsClientError::DnsResolution);
        }
        addrs
    };

    let request_timeout = timeout
        .checked_sub(started_at.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(PinnedHttpsClientError::DnsResolution)?;
    pinned_https_client_for_addrs(&host, &addrs, request_timeout)
}

impl HttpCibaCallbackDelivery {
    pub fn new() -> Self {
        HttpCibaCallbackDelivery
    }
}

impl crate::ports::CibaCallbackDelivery for HttpCibaCallbackDelivery {
    async fn deliver(
        &self,
        req: crate::ports::CibaCallbackRequest,
    ) -> crate::ports::CibaDeliveryOutcome {
        use crate::ports::CibaDeliveryOutcome as O;
        let client = match pinned_https_client(
            &req.notification_endpoint,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(client) => client,
            Err(PinnedHttpsClientError::ClientBuild) => return O::Failed,
            Err(PinnedHttpsClientError::UnsafeTarget | PinnedHttpsClientError::DnsResolution) => {
                return O::BlockedBySsrf
            }
        };
        match client
            .post(&req.notification_endpoint)
            .bearer_auth(&req.client_notification_token)
            .json(&req.body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => O::Delivered,
            // 已发出请求但非 2xx / 网络失败 → 模糊态(handler 对 push 视为已消费终态)。
            Ok(_) | Err(_) => O::Failed,
        }
    }
}

#[cfg(test)]
mod ciba_delivery_tests {
    use super::HttpCibaCallbackDelivery;
    use crate::ports::{CibaCallbackDelivery, CibaCallbackRequest, CibaDeliveryOutcome as O};

    fn req(endpoint: &str) -> CibaCallbackRequest {
        CibaCallbackRequest {
            notification_endpoint: endpoint.to_string(),
            client_notification_token: "cnt-0123456789abcdef0123456789abcdef".to_string(),
            body: serde_json::json!({ "auth_req_id": "ar-test" }),
        }
    }

    // 评审 Kiro H1:真机 adapter 的 SSRF/钉死路径必须有测试(此前全走 Memory mock,核心裸奔)。
    // 字面私网 IP:validate_endpoint_url 结构层即拒(未发出)。
    #[tokio::test]
    async fn literal_private_ip_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        assert_eq!(
            d.deliver(req("https://127.0.0.1/cb")).await,
            O::BlockedBySsrf
        );
        assert_eq!(
            d.deliver(req("https://169.254.169.254/latest")).await,
            O::BlockedBySsrf
        );
    }

    // 评审 Kiro B1 回归:**大写 host** 走 url 规范化 → localhost 解析到 127.0.0.1 → resolved_ips_allowed 拒。
    // 关键:host 取自 url.host_str()(小写化后 = "localhost"),lookup_host 用它解析到环回 → BlockedBySsrf。
    // 若仍用 validate_endpoint_url 原始切片("LOCALHOST"),lookup_host 大小写不敏感仍解析,但连接键会与
    // reqwest 规范化键不匹配——此测试确保规范化 host 一致贯穿 lookup + pin(不回退 resolver)。
    #[tokio::test]
    async fn uppercase_host_resolving_to_loopback_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        // LOCALHOST(大写)→ url 规范化 localhost → 解析 127.0.0.1/::1 → 私网复校拒。
        assert_eq!(
            d.deliver(req("https://LOCALHOST/cb")).await,
            O::BlockedBySsrf,
            "大写 host 经规范化解析到环回应拒(B1 回归:规范化 host 贯穿 lookup+pin)"
        );
    }

    // 非 https / 非 443 端口 / userinfo 混淆:结构层拒(未发出)。
    #[tokio::test]
    async fn structural_rejects_blocked() {
        let d = HttpCibaCallbackDelivery::new();
        for ep in [
            "http://example.com/cb",
            "https://example.com:8080/cb",
            "https://evil.com@169.254.169.254/x",
        ] {
            assert_eq!(d.deliver(req(ep)).await, O::BlockedBySsrf, "{ep} 应拒");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        pinned_https_client_for_addrs, PinnedHttpsClientError, PINNED_MAX_RESOLVED_ADDRESSES,
    };

    #[test]
    fn pinned_client_rejects_mixed_public_private_dns_answer() {
        let public = "8.8.8.8:443".parse().unwrap();
        let private = "10.0.0.1:443".parse().unwrap();
        let loopback = "127.0.0.1:443".parse().unwrap();
        let link_local = "169.254.169.254:443".parse().unwrap();
        let ipv6_loopback = "[::1]:443".parse().unwrap();
        assert!(pinned_https_client_for_addrs(
            "client.example.com",
            &[public],
            std::time::Duration::from_secs(1),
        )
        .is_ok());
        assert_eq!(
            pinned_https_client_for_addrs(
                "client.example.com",
                &[public, private],
                std::time::Duration::from_secs(1),
            )
            .unwrap_err(),
            PinnedHttpsClientError::UnsafeTarget,
        );
        for blocked in [private, loopback, link_local, ipv6_loopback] {
            assert_eq!(
                pinned_https_client_for_addrs(
                    "client.example.com",
                    &[blocked],
                    std::time::Duration::from_secs(1),
                )
                .unwrap_err(),
                PinnedHttpsClientError::UnsafeTarget,
            );
        }
        assert_eq!(
            pinned_https_client_for_addrs(
                "client.example.com",
                &vec![public; PINNED_MAX_RESOLVED_ADDRESSES + 1],
                std::time::Duration::from_secs(1),
            )
            .unwrap_err(),
            PinnedHttpsClientError::DnsResolution,
        );
    }
}
