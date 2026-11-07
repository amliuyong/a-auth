use super::{pinned_https_client, PinnedHttpsClientError};
use crate::ssf_worker::{SsfPushClient, SsfPushRequest, SsfPushResult};

/// Production Shared Signals push client. Only an exact HTTP 202 is accepted
/// by the worker; this adapter intentionally returns every response code.
#[derive(Clone, Default)]
pub struct HttpSsfPushClient;

const SSF_MAX_RESPONSE_HEADERS: usize = 100;
const SSF_MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const SSF_MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

fn response_headers_within_limit(headers: &reqwest::header::HeaderMap) -> bool {
    headers.len() <= SSF_MAX_RESPONSE_HEADERS
        && headers
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.as_str().len())
                    .and_then(|total| total.checked_add(value.as_bytes().len()))
                    .filter(|total| *total <= SSF_MAX_RESPONSE_HEADER_BYTES)
            })
            .is_some()
}

fn request_error(error: &reqwest::Error) -> SsfPushResult {
    if error.is_timeout() {
        SsfPushResult::NetworkError("timeout".to_string())
    } else if error.is_connect() {
        SsfPushResult::NetworkError("connect_failed".to_string())
    } else {
        SsfPushResult::NetworkError("request_failed".to_string())
    }
}

impl HttpSsfPushClient {
    pub fn new() -> Self {
        Self
    }
}

impl SsfPushClient for HttpSsfPushClient {
    async fn push(&self, request: SsfPushRequest) -> SsfPushResult {
        let client = match pinned_https_client(
            &request.endpoint,
            std::time::Duration::from_secs(10),
        )
        .await
        {
            Ok(client) => client,
            Err(PinnedHttpsClientError::UnsafeTarget) => {
                return SsfPushResult::NetworkError("ssrf_blocked".to_string())
            }
            Err(PinnedHttpsClientError::DnsResolution) => {
                return SsfPushResult::NetworkError("dns_failed".to_string())
            }
            Err(PinnedHttpsClientError::ClientBuild) => {
                return SsfPushResult::NetworkError("client_build_failed".to_string())
            }
        };
        let mut response = match client
            .post(&request.endpoint)
            .header(reqwest::header::CONTENT_TYPE, request.content_type)
            .header(reqwest::header::ACCEPT, "application/json")
            .body(request.body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return request_error(&error),
        };
        // Once response headers have arrived, the HTTP status is authoritative.
        // The receiver may already have committed the SET, so body framing,
        // timeout, or size must not turn a known 202/4xx into an ambiguous retry.
        let status = response.status().as_u16();
        if !response_headers_within_limit(response.headers())
            || response
                .content_length()
                .is_some_and(|length| length > SSF_MAX_RESPONSE_BODY_BYTES as u64)
        {
            return SsfPushResult::Response(status);
        }
        let mut received = 0usize;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    received = match received.checked_add(chunk.len()) {
                        Some(total) if total <= SSF_MAX_RESPONSE_BODY_BYTES => total,
                        _ => return SsfPushResult::Response(status),
                    };
                }
                Ok(None) => return SsfPushResult::Response(status),
                Err(_) => return SsfPushResult::Response(status),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        response_headers_within_limit, HttpSsfPushClient, SSF_MAX_RESPONSE_HEADERS,
        SSF_MAX_RESPONSE_HEADER_BYTES,
    };
    use crate::ssf_worker::{SsfPushClient, SsfPushRequest, SsfPushResult};

    async fn push(endpoint: &str) -> SsfPushResult {
        HttpSsfPushClient::new()
            .push(SsfPushRequest {
                endpoint: endpoint.to_string(),
                content_type: "application/secevent+jwt",
                body: "header.payload.signature".to_string(),
            })
            .await
    }

    #[tokio::test]
    async fn private_and_metadata_targets_are_blocked_before_connect() {
        for endpoint in [
            "https://127.0.0.1/events",
            "https://169.254.169.254/latest",
            "https://[::1]/events",
            "https://LOCALHOST/events",
        ] {
            assert_eq!(
                push(endpoint).await,
                SsfPushResult::NetworkError("ssrf_blocked".to_string()),
                "{endpoint}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_scheme_port_userinfo_and_fragment_are_blocked() {
        for endpoint in [
            "http://example.com/events",
            "https://example.com:8443/events",
            "https://user@example.com/events",
            "https://example.com/events#fragment",
        ] {
            assert_eq!(
                push(endpoint).await,
                SsfPushResult::NetworkError("ssrf_blocked".to_string()),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn response_header_count_and_bytes_are_bounded() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-small", reqwest::header::HeaderValue::from_static("ok"));
        assert!(response_headers_within_limit(&headers));

        let mut too_many = reqwest::header::HeaderMap::new();
        for index in 0..=SSF_MAX_RESPONSE_HEADERS {
            let name =
                reqwest::header::HeaderName::from_bytes(format!("x-{index}").as_bytes()).unwrap();
            too_many.insert(name, reqwest::header::HeaderValue::from_static("v"));
        }
        assert!(!response_headers_within_limit(&too_many));

        let mut too_large = reqwest::header::HeaderMap::new();
        too_large.insert(
            "x-large",
            reqwest::header::HeaderValue::from_bytes(&vec![
                b'a';
                SSF_MAX_RESPONSE_HEADER_BYTES + 1
            ])
            .unwrap(),
        );
        assert!(!response_headers_within_limit(&too_large));
    }
}
