//! Registered OIDC token-endpoint exchange with public-IP pinning.

use crate::ports::StoreError;
const TOKEN_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 真机上游 token 交换器(spec 003 §4,联邦/Admin OIDC RP code→token)。每次请求重新解析已登记的
/// HTTPS endpoint，拒绝私网/保留地址，禁止代理和重定向，并把连接钉到校验过的 IP，避免配置型 SSRF
/// 与 DNS rebinding。硬超时 3s；响应体有界。client_secret_basic 的明文只在调用栈内存活。
#[derive(Clone)]
pub struct HttpUpstreamTokenExchanger;

impl Default for HttpUpstreamTokenExchanger {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpUpstreamTokenExchanger {
    pub fn new() -> Self {
        Self
    }

    async fn pinned_client(token_endpoint: &str) -> Result<reqwest::Client, StoreError> {
        agent_auth_ciba::validate_endpoint_url(token_endpoint, None).map_err(|_| {
            StoreError::Permanent("upstream token endpoint blocked by SSRF policy".to_string())
        })?;
        let url = reqwest::Url::parse(token_endpoint)
            .map_err(|_| StoreError::Permanent("invalid upstream token endpoint".to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| StoreError::Permanent("invalid upstream token host".to_string()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            tokio::time::timeout(
                TOKEN_DNS_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .map_err(|_| StoreError::Transient("upstream token DNS timeout".to_string()))?
            .map_err(|error| {
                StoreError::Transient(format!("upstream token DNS resolution: {error}"))
            })?
            .collect()
        };
        let Some(pinned) = addrs.first().copied() else {
            return Err(StoreError::Transient(
                "upstream token DNS returned no addresses".to_string(),
            ));
        };
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|address| address.ip()).collect();
        if !agent_auth_ciba::resolved_ips_allowed(&ips) {
            return Err(StoreError::Permanent(
                "upstream token host blocked by SSRF policy".to_string(),
            ));
        }
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &[pinned])
            .no_proxy()
            .build()
            .map_err(|error| StoreError::Permanent(format!("upstream token HTTP client: {error}")))
    }
}

const UPSTREAM_TOKEN_MAX_RESPONSE_BYTES: usize = 128 * 1024;

impl crate::ports::UpstreamTokenExchanger for HttpUpstreamTokenExchanger {
    async fn exchange_code(
        &self,
        req: &crate::ports::UpstreamTokenExchangeRequest<'_>,
    ) -> Result<Option<crate::ports::UpstreamTokenSet>, StoreError> {
        // RFC 6749 §4.1.3 授权码交换 form + PKCE code_verifier;client 认证走 basic(§2.3.1)。
        // client_id 也放 body(部分上游 basic + body 双要;冗余无害)。
        let form = [
            ("grant_type", "authorization_code"),
            ("code", req.code),
            ("redirect_uri", req.redirect_uri),
            ("code_verifier", req.code_verifier),
            ("client_id", req.client_id),
        ];
        let client = Self::pinned_client(req.token_endpoint).await?;
        let mut resp = client
            .post(req.token_endpoint) // URL 来自登记 config(SSRF 防线,已 validate https)
            .basic_auth(req.client_id, Some(req.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| StoreError::Transient(format!("upstream token POST: {e}")))?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(StoreError::Transient(format!(
                "upstream token 5xx {status}"
            )));
        }
        if !status.is_success() {
            return Ok(None); // 4xx:上游拒(code 无效/client 认证失败)→ 登录失败,非重试
        }
        if resp
            .content_length()
            .is_some_and(|length| length > UPSTREAM_TOKEN_MAX_RESPONSE_BYTES as u64)
        {
            return Err(StoreError::Permanent(
                "upstream token response exceeds size limit".to_string(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|error| StoreError::Transient(format!("upstream token body: {error}")))?
        {
            if body.len() + chunk.len() > UPSTREAM_TOKEN_MAX_RESPONSE_BYTES {
                return Err(StoreError::Permanent(
                    "upstream token response exceeds size limit".to_string(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        // 解析 JSON;缺 id_token 或解析失败 = 响应异常 → Ok(None)(fail-closed,不臆测)。
        let v: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let Some(id_token) = v.get("id_token").and_then(|x| x.as_str()) else {
            return Ok(None); // OIDC 换 token 必带 id_token;缺 = 异常
        };
        Ok(Some(crate::ports::UpstreamTokenSet {
            id_token: id_token.to_string(),
            access_token: v
                .get("access_token")
                .and_then(|x| x.as_str())
                .map(String::from),
        }))
    }
}

#[cfg(test)]
mod upstream_token_exchanger_tests {
    use super::HttpUpstreamTokenExchanger;
    use crate::ports::{StoreError, UpstreamTokenExchangeRequest, UpstreamTokenExchanger};

    #[tokio::test]
    async fn private_and_metadata_token_endpoints_are_blocked_before_network_io() {
        let exchanger = HttpUpstreamTokenExchanger::new();
        for endpoint in [
            "https://127.0.0.1/token",
            "https://169.254.169.254/latest/token",
        ] {
            let result = exchanger
                .exchange_code(&UpstreamTokenExchangeRequest {
                    token_endpoint: endpoint,
                    client_id: "client",
                    client_secret: "secret",
                    code: "code",
                    code_verifier: "verifier",
                    redirect_uri: "https://rp.example.com/callback",
                })
                .await;
            assert!(
                matches!(result, Err(StoreError::Permanent(_))),
                "{endpoint} must fail the SSRF policy before a request is sent"
            );
        }
    }
}
