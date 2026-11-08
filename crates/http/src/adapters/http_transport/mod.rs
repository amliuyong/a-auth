//! Portable HTTP adapters shared by AWS and PostgreSQL deployments.

mod callback;
mod jwks;
mod oidc_metadata;
mod ssf_push;
mod upstream;

pub use callback::HttpCibaCallbackDelivery;
pub use jwks::HttpJwksFetcher;
pub use oidc_metadata::HttpOidcMetadataFetcher;
pub use ssf_push::HttpSsfPushClient;
pub use upstream::HttpUpstreamTokenExchanger;

#[cfg(all(test, feature = "portable-transport-test"))]
pub(crate) use callback::pinned_https_client_builder_for_addrs;
pub(crate) use callback::{pinned_https_client, PinnedHttpsClientError};
