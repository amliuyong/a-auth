#![cfg(feature = "postgres")]

use agent_auth_http::{
    adapters::smtp::{SmtpCredentials, SmtpRelay, SmtpRelayConfig, SmtpTlsMode},
    ports::{SentMessage, StoreError},
};

fn config() -> SmtpRelayConfig {
    SmtpRelayConfig {
        host: "127.0.0.1".into(),
        port: 465,
        tls: SmtpTlsMode::Implicit,
        from: "no-reply@example.com".into(),
        root_ca_pem: None,
        credentials: None,
    }
}

fn message() -> SentMessage {
    let now = agent_auth_http::current_unix_secs();
    SentMessage {
        message_id: "opaque-recovery-operation".into(),
        tenant: "".into(),
        kind: "recovery".into(),
        recipient: "recipient@example.com".into(),
        body: "account recovered".into(),
        created_at: now,
        ttl: now + 300,
    }
}

#[tokio::test]
async fn smtp_rejects_invalid_configuration_and_messages_before_networking() {
    for host in [
        "",
        "smtp.example.com\n",
        "https://smtp.example.com",
        "bad host",
    ] {
        let mut invalid = config();
        invalid.host = host.into();
        assert!(matches!(
            SmtpRelay::new(invalid),
            Err(StoreError::Permanent(_))
        ));
    }
    let mut invalid = config();
    invalid.port = 0;
    assert!(SmtpRelay::new(invalid).is_err());
    let mut invalid = config();
    invalid.from = "sender@example.com\r\nBcc: victim@example.com".into();
    assert!(SmtpRelay::new(invalid).is_err());
    for pem in [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\nanVuaw==\n-----END CERTIFICATE-----",
    ] {
        let mut invalid = config();
        invalid.root_ca_pem = Some(pem.as_bytes().to_vec());
        assert!(SmtpRelay::new(invalid).is_err());
    }
    let mut invalid = config();
    invalid.credentials = Some(SmtpCredentials::new("".into(), "secret".into()));
    assert!(SmtpRelay::new(invalid).is_err());
    let relay = SmtpRelay::new(config()).unwrap();
    let mut invalid = message();
    invalid.recipient = "recipient@example.com\r\nBcc: victim@example.com".into();
    assert!(matches!(
        relay.deliver(&invalid).await,
        Err(StoreError::Permanent(_))
    ));
    let mut invalid = message();
    invalid.kind = "unsupported".into();
    assert!(matches!(
        relay.deliver(&invalid).await,
        Err(StoreError::Permanent(_))
    ));
    let mut invalid = message();
    invalid.ttl = agent_auth_http::current_unix_secs() - 1;
    assert!(matches!(
        relay.deliver(&invalid).await,
        Err(StoreError::Permanent(_))
    ));
}

#[cfg(feature = "portable-transport-test")]
mod tls {
    use super::*;
    use base64::Engine;
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::{
        rustls::{self, pki_types::PrivateKeyDer},
        TlsAcceptor,
    };

    #[tokio::test]
    async fn smtp_starttls_is_required_before_authentication_or_mail() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            socket
                .get_mut()
                .write_all(b"220 smtp fixture\r\n")
                .await
                .unwrap();
            let mut line = String::new();
            socket.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("EHLO "));
            socket
                .get_mut()
                .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            line.clear();
            let _ = socket.read_line(&mut line).await;
            assert!(!line.starts_with("AUTH ") && !line.starts_with("MAIL "));
        });
        let mut cfg = config();
        cfg.port = port;
        cfg.tls = SmtpTlsMode::StartTls;
        cfg.credentials = Some(SmtpCredentials::new(
            "smtp-user".into(),
            "smtp-secret".into(),
        ));
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            SmtpRelay::new(cfg).unwrap().deliver(&message()).await
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(StoreError::Transient(_))));
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    fn acceptor(host: &str) -> (TlsAcceptor, Vec<u8>) {
        let material = rcgen::generate_simple_self_signed(vec![host.into()]).unwrap();
        let key = PrivateKeyDer::try_from(material.signing_key.serialize_der()).unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![material.cert.der().clone()], key)
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(material.cert.der());
        let encoded = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
        (TlsAcceptor::from(Arc::new(server)), pem.into_bytes())
    }

    async fn receive_one(
        listener: tokio::net::TcpListener,
        acceptor: TlsAcceptor,
        disconnect_after_data: bool,
    ) -> String {
        let (socket, _) = listener.accept().await.unwrap();
        let socket = acceptor.accept(socket).await.unwrap();
        let mut socket = BufReader::new(socket);
        socket
            .get_mut()
            .write_all(b"220 smtp fixture\r\n")
            .await
            .unwrap();
        let mut data = String::new();
        loop {
            let mut line = String::new();
            if socket.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let response: &[u8] = if line.starts_with("EHLO ") {
                b"250-fixture\r\n250 8BITMIME\r\n"
            } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                b"250 accepted\r\n"
            } else if line == "DATA\r\n" {
                socket
                    .get_mut()
                    .write_all(b"354 send message\r\n")
                    .await
                    .unwrap();
                loop {
                    let mut body = String::new();
                    assert_ne!(socket.read_line(&mut body).await.unwrap(), 0);
                    if body == ".\r\n" {
                        break;
                    }
                    data.push_str(&body);
                }
                if disconnect_after_data {
                    return data;
                }
                b"250 queued\r\n"
            } else if line == "QUIT\r\n" {
                socket.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                break;
            } else {
                panic!("unexpected SMTP fixture command");
            };
            socket.get_mut().write_all(response).await.unwrap();
        }
        data
    }

    #[tokio::test]
    async fn smtp_tls_validates_the_host_and_delivers_one_encoded_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (acceptor, pem) = acceptor("127.0.0.1");
        let server = tokio::spawn(receive_one(listener, acceptor, false));
        let mut cfg = config();
        cfg.port = port;
        cfg.root_ca_pem = Some(pem);
        let relay = SmtpRelay::new(cfg).unwrap();
        tokio::time::timeout(Duration::from_secs(5), relay.deliver(&message()))
            .await
            .unwrap()
            .unwrap();
        let data = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(data.contains("recipient@example.com"));
        assert!(data.contains("account recovered"));
        assert_eq!(data.matches("Message-ID:").count(), 1);
        assert!(!data.contains("opaque-recovery-operation"));
    }

    #[tokio::test]
    async fn smtp_tls_rejects_a_trusted_certificate_for_another_host() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (acceptor, pem) = acceptor("different.example.com");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(acceptor.accept(socket).await.is_err());
        });
        let mut cfg = config();
        cfg.port = port;
        cfg.root_ca_pem = Some(pem);
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            SmtpRelay::new(cfg).unwrap().deliver(&message()).await
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(StoreError::Transient(_))));
        server.await.unwrap();
    }

    async fn postgres_delivery_is_single_submission(disconnect_after_data: bool) {
        use agent_auth_http::{
            adapters::{
                mounted_crypto::EncryptionKeyring,
                postgres::{
                    PostgresMessageOutbox, PostgresSmtpNotifier, PostgresStore, PostgresUsersStore,
                    UserAuthorityKey,
                },
            },
            ports::{MessageOutbox, Notifier},
        };
        use tokio::sync::Barrier;

        let base_url = std::env::var("A_AUTH_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base_url).await.unwrap();
        let name = format!("contract_smtp_transport_{:032x}", rand::random::<u128>());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base_url).unwrap();
        url.set_path(&format!("/{name}"));
        let first = PostgresStore::connect(url.as_str(), 8).await.unwrap();
        first.migrate().await.unwrap();
        let second = PostgresStore::connect(url.as_str(), 8).await.unwrap();
        let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (acceptor, pem) = acceptor("127.0.0.1");
        let server = tokio::spawn(receive_one(listener, acceptor, disconnect_after_data));
        let mut cfg = config();
        cfg.port = port;
        cfg.root_ca_pem = Some(pem);
        let relay = SmtpRelay::new(cfg).unwrap();
        let keys =
            EncryptionKeyring::new("smtp-test", vec![("smtp-test".into(), [0x71; 32])]).unwrap();
        let notifier = |store: PostgresStore| {
            let users =
                PostgresUsersStore::new(store.clone(), UserAuthorityKey::new([0x57; 32]).unwrap());
            PostgresSmtpNotifier::new(store, users, keys.clone(), relay.clone()).unwrap()
        };
        let notifiers = [notifier(first.clone()), notifier(second)];
        let at = agent_auth_http::current_unix_secs();
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = Vec::new();
        for index in 0..16 {
            let notifier = notifiers[index % 2].clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                notifier
                    .notify_recovery("", "recovery-operation", "recipient@example.com", at, None)
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = Vec::new();
        for index in 0..16 {
            let notifier = notifiers[index % 2].clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                notifier.run_once(at, 1).await.unwrap()
            }));
        }
        let mut claimed = 0;
        let mut accepted = 0;
        let mut uncertain = 0;
        for task in tasks {
            let report = task.await.unwrap();
            claimed += report.claimed;
            accepted += report.accepted;
            uncertain += report.uncertain;
        }
        let data = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed, 1);
        assert_eq!(accepted, usize::from(!disconnect_after_data));
        assert_eq!(uncertain, usize::from(disconnect_after_data));
        assert_eq!(data.matches("Message-ID:").count(), 1);
        let outbox = PostgresMessageOutbox::new(first, keys);
        assert_eq!(
            outbox.list_recent("", 10).await.unwrap().len(),
            usize::from(!disconnect_after_data)
        );
        for notifier in &notifiers {
            notifier
                .notify_recovery("", "recovery-operation", "recipient@example.com", at, None)
                .await
                .unwrap();
            assert_eq!(notifier.run_once(at + 1000, 1).await.unwrap().claimed, 0);
        }
        let status: String = sqlx::query_scalar("SELECT status FROM a_auth.smtp_notifications")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status,
            if disconnect_after_data {
                "uncertain"
            } else {
                "accepted"
            }
        );
        // Only retire this owned database after every assertion passes.
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn postgres_smtp_workers_submit_one_recovery_mail_across_independent_pools() {
        postgres_delivery_is_single_submission(false).await;
    }

    #[tokio::test]
    async fn postgres_smtp_workers_do_not_resubmit_when_the_data_receipt_is_lost() {
        postgres_delivery_is_single_submission(true).await;
    }
}
