//! Bounded public OIDC/JWKS reads with one validated DNS resolution.

use std::{sync::Arc, time::Duration};

use crate::ports::{OidcMetadata, OidcMetadataFetcher, StoreError};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Shared by discovery and JWKS. No redirects, proxies or credentials.
pub(super) async fn fetch_public_document(endpoint: &str) -> Result<Vec<u8>, StoreError> {
    crate::federation_checks::validate_public_endpoint(endpoint, false)
        .map_err(|_| StoreError::Permanent("endpoint blocked by SSRF policy".into()))?;
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| StoreError::Permanent("invalid endpoint".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| StoreError::Permanent("missing host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<std::net::SocketAddr> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| StoreError::Transient("DNS timeout".into()))?
    .map_err(|_| StoreError::Transient("DNS unavailable".into()))?
    .collect();
    if !agent_auth_ciba::resolved_ips_allowed(
        &addresses
            .iter()
            .map(|address| address.ip())
            .collect::<Vec<_>>(),
    ) {
        return Err(StoreError::Permanent(
            "resolved host blocked by SSRF policy".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &[addresses[0]])
        .no_proxy()
        .build()
        .map_err(|_| StoreError::Permanent("HTTP client unavailable".into()))?;
    let mut response = client
        .get(endpoint)
        .send()
        .await
        .map_err(|_| StoreError::Transient("HTTP unavailable".into()))?;
    if !response.status().is_success() {
        return Err(StoreError::Transient("HTTP response unavailable".into()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(StoreError::Permanent("response exceeds size limit".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StoreError::Transient("HTTP body unavailable".into()))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(StoreError::Permanent("response exceeds size limit".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone)]
pub struct HttpOidcMetadataFetcher {
    capacity: Arc<tokio::sync::Semaphore>,
}

impl Default for HttpOidcMetadataFetcher {
    fn default() -> Self {
        Self {
            capacity: Arc::new(tokio::sync::Semaphore::new(8)),
        }
    }
}

impl OidcMetadataFetcher for HttpOidcMetadataFetcher {
    async fn fetch(&self, discovery_url: &str) -> Result<OidcMetadata, StoreError> {
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| StoreError::Transient("diagnostics capacity unavailable".into()))?;
        let bytes = fetch_public_document(discovery_url).await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| StoreError::Permanent("invalid discovery document".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forbidden_endpoints_are_rejected_before_network_io() {
        for url in [
            "http://idp.example.com",
            "https://127.0.0.1/metadata",
            "https://2130706433/metadata",
            "https://[fec0::1]/metadata",
            "https://[2001:db8::1]/metadata",
            "https://idp.example.com:8443/metadata",
            "https://test.lambda-url.us-east-1.on.aws/metadata",
            "https://test.LAMBDA-URL.us-east-1.on.aws./metadata",
            "https://idp.local/metadata",
        ] {
            let result =
                tokio::time::timeout(Duration::from_millis(100), fetch_public_document(url))
                    .await
                    .expect("URL guard must run before DNS or HTTP");
            assert!(matches!(result, Err(StoreError::Permanent(_))), "{url}");
        }
    }
}
