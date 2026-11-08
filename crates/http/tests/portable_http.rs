#![cfg(feature = "postgres")]

use agent_auth_http::{
    adapters::http_transport::{
        HttpCibaCallbackDelivery, HttpJwksFetcher, HttpOidcMetadataFetcher, HttpSsfPushClient,
        HttpUpstreamTokenExchanger,
    },
    cimd::{CimdFetchError, CimdHttpClient, HttpCimdHttpClient},
    ports::{
        CibaCallbackDelivery, CibaCallbackRequest, CibaDeliveryOutcome, JwksFetcher,
        OidcMetadataFetcher, StoreError, UpstreamTokenExchangeRequest, UpstreamTokenExchanger,
    },
    ssf_worker::{SsfPushClient, SsfPushRequest, SsfPushResult},
    state::{
        CibaCallbackDeliveryImpl, JwksFetcherImpl, OidcMetadataFetcherImpl,
        UpstreamTokenExchangerImpl,
    },
};

const BLOCKED: &[&str] = &[
    "http://idp.example.com/document",
    "https://127.0.0.1/document",
    "https://169.254.169.254/document",
    "https://[::1]/document",
    "https://user@example.com/document",
    "https://example.com:8443/document",
    "https://test.lambda-url.us-east-1.on.aws/document",
    "https://test.LAMBDA-URL.us-east-1.on.aws./document",
    "https://test%2elambda-url.us-east-1.on.aws/document",
];

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_millis(250), future)
        .await
        .expect("unsafe targets must be rejected before DNS or network I/O")
}

#[tokio::test]
async fn portable_jwks_and_oidc_runtime_reject_unsafe_destinations() {
    let jwks = JwksFetcherImpl::Http(HttpJwksFetcher::new());
    let metadata = OidcMetadataFetcherImpl::Http(HttpOidcMetadataFetcher::default());
    for endpoint in BLOCKED {
        assert!(matches!(
            bounded(jwks.fetch(endpoint)).await,
            Err(StoreError::Permanent(_))
        ));
        assert!(matches!(
            bounded(metadata.fetch(endpoint)).await,
            Err(StoreError::Permanent(_))
        ));
    }
}

#[tokio::test]
async fn portable_token_exchange_runtime_rejects_before_sending_credentials() {
    let exchanger = UpstreamTokenExchangerImpl::Http(HttpUpstreamTokenExchanger::new());
    for endpoint in BLOCKED {
        assert!(matches!(
            bounded(exchanger.exchange_code(&UpstreamTokenExchangeRequest {
                token_endpoint: endpoint,
                client_id: "local-fixture-client",
                client_secret: "local-fixture-secret",
                code: "local-fixture-code",
                code_verifier: "local-fixture-verifier",
                redirect_uri: "https://rp.example.com/callback",
            }))
            .await,
            Err(StoreError::Permanent(_))
        ));
    }
}

#[tokio::test]
async fn portable_ciba_runtime_rejects_before_sending_notification_tokens() {
    let callback = CibaCallbackDeliveryImpl::Http(HttpCibaCallbackDelivery::new());
    for endpoint in BLOCKED {
        assert_eq!(
            bounded(callback.deliver(CibaCallbackRequest {
                notification_endpoint: endpoint.to_string(),
                client_notification_token: "local-fixture-notification-token".into(),
                body: serde_json::json!({"auth_req_id": "local-fixture-request"}),
            }))
            .await,
            CibaDeliveryOutcome::BlockedBySsrf,
        );
    }
}

#[tokio::test]
async fn portable_ssf_rejects_before_sending_security_events() {
    let push = HttpSsfPushClient::new();
    for endpoint in BLOCKED {
        assert_eq!(
            bounded(push.push(SsfPushRequest {
                endpoint: endpoint.to_string(),
                content_type: "application/secevent+jwt",
                body: "local-fixture-set".into(),
            }))
            .await,
            SsfPushResult::NetworkError("ssrf_blocked".into()),
        );
    }
}

#[tokio::test]
async fn portable_cimd_rejects_unsafe_destinations() {
    let client = HttpCimdHttpClient;
    for endpoint in BLOCKED {
        assert!(matches!(
            bounded(client.get(endpoint)).await,
            Err(CimdFetchError::UnsafeTarget)
        ));
    }
}
