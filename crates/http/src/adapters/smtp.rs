//! Operator-configured SMTP delivery. TLS is mandatory and errors are sanitized.
//! Durable notification authority, claims and ambiguous-send handling belong
//! to the PostgreSQL notifier; this transport never retries a mail submission.

use crate::ports::{SentMessage, StoreError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lettre::{
    message::Mailbox,
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, Tls, TlsParameters},
    },
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

pub enum SmtpTlsMode {
    Implicit,
    StartTls,
}

/// Credentials have no Debug/serialization representation. A mounted-secret
/// resolver supplies them; they never enter notification records.
pub struct SmtpCredentials {
    username: String,
    password: Zeroizing<String>,
}

impl SmtpCredentials {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password: Zeroizing::new(password),
        }
    }
}

/// Trusted operator configuration; both modes require certificate and hostname
/// validation. An additional root CA supports private SMTP services.
pub struct SmtpRelayConfig {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTlsMode,
    pub from: String,
    pub root_ca_pem: Option<Vec<u8>>,
    pub credentials: Option<SmtpCredentials>,
}

#[derive(Clone)]
pub struct SmtpRelay {
    client: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid SMTP configuration or notification".into())
}

fn unconfirmed() -> StoreError {
    // SMTP may have accepted DATA before a connection or receipt was lost.
    // The caller must preserve ambiguous-send authority, not retry blindly.
    StoreError::Transient("SMTP delivery was not confirmed".into())
}

fn root_certificate(pem: &[u8]) -> Result<Certificate, StoreError> {
    let pem = std::str::from_utf8(pem).map_err(|_| invalid())?;
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|body| body.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or_else(invalid)?;
    let encoded = body
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid())?;
    if der.is_empty() {
        return Err(invalid());
    }
    Certificate::from_der(der).map_err(|_| invalid())
}

impl SmtpRelay {
    pub fn new(config: SmtpRelayConfig) -> Result<Self, StoreError> {
        if config.host.is_empty()
            || config.host.len() > 253
            || config
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || (config.host.parse::<std::net::IpAddr>().is_err()
                && !matches!(url::Host::parse(&config.host), Ok(url::Host::Domain(_))))
            || config.port == 0
            || config.from.len() > 1024
            || config.from.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let from = config.from.parse::<Mailbox>().map_err(|_| invalid())?;
        let mut parameters = TlsParameters::builder(config.host.clone());
        if let Some(pem) = config.root_ca_pem {
            if pem.is_empty() || pem.len() > 128 * 1024 {
                return Err(invalid());
            }
            parameters = parameters.add_root_certificate(root_certificate(&pem)?);
        }
        let parameters = parameters.build().map_err(|_| invalid())?;
        let tls = match config.tls {
            SmtpTlsMode::Implicit => Tls::Wrapper(parameters),
            SmtpTlsMode::StartTls => Tls::Required(parameters),
        };
        // Both supported modes override the builder's plaintext default before
        // constructing a client. No plaintext or opportunistic mode is exposed.
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.host)
            .port(config.port)
            .tls(tls)
            .timeout(Some(Duration::from_secs(3)));
        if let Some(credentials) = config.credentials {
            if credentials.username.is_empty()
                || credentials.username.len() > 1024
                || credentials.username.chars().any(char::is_control)
                || credentials.password.is_empty()
                || credentials.password.len() > 65_536
                || credentials.password.contains('\0')
            {
                return Err(invalid());
            }
            builder = builder.credentials(Credentials::new(
                credentials.username,
                credentials.password.as_str().to_owned(),
            ));
        }
        Ok(Self {
            client: builder.build(),
            from,
        })
    }

    /// Submit one message. Accepted means SMTP returned a positive DATA receipt;
    /// it does not establish delivery to a mailbox. A durable caller owns the
    /// single-attempt admission and records uncertain outcomes.
    pub async fn deliver(&self, message: &SentMessage) -> Result<(), StoreError> {
        if message.message_id.is_empty()
            || message.message_id.len() > 1024
            || message.tenant.len() > 1024
            || message.recipient.len() > 1024
            || message.recipient.chars().any(char::is_control)
            || message.body.len() > 65_536
            || message.body.contains('\0')
            || message.ttl <= crate::current_unix_secs()
            || message.created_at >= message.ttl
        {
            return Err(invalid());
        }
        let recipient = message
            .recipient
            .parse::<Address>()
            .map_err(|_| invalid())?;
        let subject = match message.kind.as_str() {
            "magic_link" => "Your sign-in link",
            "recovery" => "Account recovery notification",
            _ => return Err(invalid()),
        };
        let identity =
            serde_json::to_vec(&("smtp-message-id-v1", &message.tenant, &message.message_id))
                .map_err(|_| invalid())?;
        let header_id = format!(
            "<{}@a-auth.invalid>",
            URL_SAFE_NO_PAD.encode(Sha256::digest(identity))
        );
        let mail = Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(None, recipient))
            .subject(subject)
            .message_id(Some(header_id))
            .body(message.body.clone())
            .map_err(|_| invalid())?;
        tokio::time::timeout(Duration::from_secs(10), self.client.send(mail))
            .await
            .map_err(|_| unconfirmed())?
            .map(|_| ())
            .map_err(|_| unconfirmed())
    }
}
