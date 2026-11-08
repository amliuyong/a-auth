//! Production single-tenant PostgreSQL composition. Required authority and
//! transports have no development-store or generated-key fallback.

use crate::{
    adapters::{
        file_secrets::FileSecretResolver,
        http_transport::{
            HttpCibaCallbackDelivery, HttpJwksFetcher, HttpOidcMetadataFetcher,
            HttpUpstreamTokenExchanger,
        },
        memory::LogAuthzEventSink,
        mounted_crypto::EncryptionKeyring,
        mounted_signer::MountedSignerRing,
        postgres::*,
        smtp::{SmtpCredentials, SmtpRelay, SmtpRelayConfig, SmtpTlsMode},
    },
    admin_credentials::{AdminCredentialOwner, AdminCredentialResolver},
    governance::{
        GovernanceConfig, GovernanceJobQueueImpl, GovernanceSecretReference, GovernanceStoreImpl,
    },
    governance_resources::{
        GovernanceResourceBackendImpl, PostgresGovernanceResourceBackend,
        PostgresGovernanceResourceConfig,
    },
    ports::{SecretResolver, StoreError},
    state::*,
};
use agent_auth_discovery::{Form, Phase, SubjectType};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u32,
    host: String,
    namespace: String,
    web_base_url: String,
    deployment_commit: String,
    logical_region: String,
    jurisdiction: String,
    max_connections: u32,
    database: FileReference,
    secrets: CryptoFiles,
    signing: SigningFiles,
    administrators: FileReference,
    external_secrets: ExternalFiles,
    smtp: SmtpConfig,
    phase: String,
    subject_type: String,
    dcr_mode: String,
    capabilities: Capabilities,
    redirect_hosts: Vec<String>,
    cimd_domains: Vec<String>,
    ema_policies: Vec<serde_json::Value>,
    invitation_ttl_secs: i64,
    grace_window_secs: i64,
    password_workers: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReference {
    root: PathBuf,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoFiles {
    root: PathBuf,
    server_key: String,
    governance_key: String,
    grace: String,
    ciba: String,
    outbox: String,
    ssf: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningFiles {
    root: PathBuf,
    manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalFiles {
    root: PathBuf,
    bindings: BTreeMap<String, String>,
    retention_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    federation: bool,
    passkey: bool,
    ciba_ping_push: bool,
    byod: bool,
    mtls_svid: bool,
    ema: bool,
    authz: bool,
    cimd: bool,
}

fn required_option<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpConfig {
    host: String,
    port: u16,
    tls: String,
    from: String,
    #[serde(deserialize_with = "required_option")]
    root_ca_key: Option<String>,
    #[serde(deserialize_with = "required_option")]
    username_key: Option<String>,
    #[serde(deserialize_with = "required_option")]
    password_key: Option<String>,
}

/// Keep these handles for readiness, key reload and worker scheduling. The
/// server/worker entrypoints own listener lifetime and shutdown.
pub struct PostgresRuntime {
    pub state: AppState,
    pub database: PostgresStore,
    pub signing_keys: MountedSignerRing,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid PostgreSQL runtime configuration".into())
}

fn config_file(path: &Path) -> Result<Config, StoreError> {
    use std::os::unix::fs::PermissionsExt;
    let file = std::fs::File::open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

async fn resolve(
    files: &FileSecretResolver,
    reference: &str,
) -> Result<Zeroizing<String>, StoreError> {
    files
        .resolve(reference)
        .await?
        .map(Zeroizing::new)
        .ok_or_else(invalid)
}

async fn hmac_key(files: &FileSecretResolver, reference: &str) -> Result<[u8; 32], StoreError> {
    let text = resolve(files, reference).await?;
    let bytes = Zeroizing::new(STANDARD.decode(text.trim()).map_err(|_| invalid())?);
    let value: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid())?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(invalid());
    }
    Ok(value)
}

async fn encryption_key(
    files: &FileSecretResolver,
    reference: &str,
) -> Result<EncryptionKeyring, StoreError> {
    let text = resolve(files, reference).await?;
    EncryptionKeyring::from_json(text.as_bytes())
}

fn disjoint_root(root: &Path, external: &Path) -> Result<(), StoreError> {
    let root = root.canonicalize().map_err(|_| invalid())?;
    let external = external.canonicalize().map_err(|_| invalid())?;
    if root.starts_with(&external) || external.starts_with(&root) {
        return Err(invalid());
    }
    Ok(())
}

fn database_uri(text: &str) -> Result<url::Url, StoreError> {
    let uri = url::Url::parse(text).map_err(|_| invalid())?;
    if !matches!(uri.scheme(), "postgres" | "postgresql")
        || uri.fragment().is_some()
        || uri.username().is_empty()
        || uri.password().is_none()
        || uri.path().trim_start_matches('/').is_empty()
    {
        return Err(invalid());
    }
    let loopback = match uri.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) if !host.is_empty() && !host.contains('%') => {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        _ => return Err(invalid()),
    };
    // SQLx accepts aliases and query-level host overrides. Restrict the URL
    // grammar so later parameters cannot override verified transport policy.
    let mut parameters = BTreeMap::new();
    for (key, value) in uri.query_pairs() {
        if !matches!(
            key.as_ref(),
            "sslmode" | "sslrootcert" | "sslcert" | "sslkey" | "application_name"
        ) || parameters
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(invalid());
        }
    }
    if !loopback && parameters.get("sslmode").map(String::as_str) != Some("verify-full") {
        return Err(invalid());
    }
    Ok(uri)
}

impl PostgresRuntime {
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let config = config_file(path.as_ref())?;
        let issuer = url::Url::parse(&format!("https://{}", config.host)).map_err(|_| invalid())?;
        let web = url::Url::parse(&config.web_base_url).map_err(|_| invalid())?;
        let phase = Phase::from_env_str(&config.phase).ok_or_else(invalid)?;
        let subject_type = match config.subject_type.as_str() {
            "public" => SubjectType::Public,
            "pairwise" => SubjectType::Pairwise,
            _ => return Err(invalid()),
        };
        let dcr_mode = DcrMode::from_env_str(&config.dcr_mode).ok_or_else(invalid)?;
        if config.schema_version != 1
            || config.namespace.is_empty()
            || config.namespace.len() > 256
            || issuer.host_str() != Some(config.host.as_str())
            || issuer.port().is_some()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.path() != "/"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || web.scheme() != "https"
            || web.host_str().is_none()
            || !web.username().is_empty()
            || web.password().is_some()
            || web.fragment().is_some()
            || config.deployment_commit.len() != 40
            || !config
                .deployment_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=64).contains(&config.max_connections)
            || config.jurisdiction.is_empty()
            || config.jurisdiction.len() > 64
            || !(300..=604_800).contains(&config.invitation_ttl_secs)
            || !(1..=5).contains(&config.grace_window_secs)
            || !(1..=8).contains(&config.password_workers)
            || dcr_mode == DcrMode::SoftwareStatement
            || (config.capabilities.ciba_ping_push && phase < Phase::P3)
            || ((config.capabilities.byod || config.capabilities.mtls_svid) && phase < Phase::P3)
            || (config.capabilities.ema && phase < Phase::P2)
        {
            return Err(invalid());
        }
        let form = Form::SelfHosted {
            configured_host: config.host.clone(),
        };
        let region = crate::region::RegionRuntime::single_region_in(&config.logical_region)
            .map_err(|_| invalid())?;
        let governance_config = GovernanceConfig::parse_json(&serde_json::to_string(&serde_json::json!({
            "default": {"jurisdiction":config.jurisdiction,"allowed_regions":[config.logical_region],"governance_region":config.logical_region}
        })).map_err(|_| invalid())?, &["default".into()]).map_err(|_| invalid())?;
        let mut redirect_hosts = BTreeSet::new();
        for host in config.redirect_hosts {
            if !matches!(url::Host::parse(&host), Ok(url::Host::Domain(ref parsed)) if parsed == &host)
                || !redirect_hosts.insert(host)
            {
                return Err(invalid());
            }
        }
        let cimd_policy = crate::cimd::CimdTrustPolicy::new(config.cimd_domains, HashMap::new())
            .map_err(|_| invalid())?;
        let cimd = crate::cimd::CimdResolver::new(
            config.capabilities.cimd,
            cimd_policy,
            Arc::new(crate::cimd::HttpCimdHttpClient),
        )
        .map_err(|_| invalid())?;
        let ema_json = (!config.ema_policies.is_empty())
            .then(|| serde_json::to_string(&config.ema_policies))
            .transpose()
            .map_err(|_| invalid())?;
        let ema_policies = crate::ema_flow::parse_tenant_policies(ema_json.as_deref(), &form, &[])
            .map_err(|_| invalid())?;
        if config.capabilities.ema && ema_policies.is_empty() {
            return Err(invalid());
        }

        for root in [
            &config.signing.root,
            &config.secrets.root,
            &config.administrators.root,
            &config.database.root,
        ] {
            disjoint_root(root, &config.external_secrets.root)?;
        }
        let signing_keys = MountedSignerRing::load(&config.signing.root, &config.signing.manifest)
            .await
            .map_err(|_| invalid())?;
        let signer = Arc::new(SignerImpl::Mounted(
            signing_keys.snapshot().await.map_err(|_| invalid())?,
        ));
        let crypto = FileSecretResolver::new(
            &config.secrets.root,
            [
                ("server".into(), config.secrets.server_key),
                ("governance".into(), config.secrets.governance_key),
                ("grace".into(), config.secrets.grace),
                ("ciba".into(), config.secrets.ciba),
                ("outbox".into(), config.secrets.outbox),
                ("ssf".into(), config.secrets.ssf),
            ],
        )?;
        let server_key = Zeroizing::new(hmac_key(&crypto, "server").await?);
        let governance_key = Zeroizing::new(hmac_key(&crypto, "governance").await?);
        if *server_key == *governance_key {
            return Err(invalid());
        }
        let grace_keys = encryption_key(&crypto, "grace").await?;
        let ciba_keys = encryption_key(&crypto, "ciba").await?;
        let outbox_keys = encryption_key(&crypto, "outbox").await?;
        let ssf_keys = encryption_key(&crypto, "ssf").await?;
        let external = FileSecretResolver::new(
            &config.external_secrets.root,
            config.external_secrets.bindings.clone(),
        )?;
        let retention_ref = "operator:governance-retention".to_owned();
        if config
            .external_secrets
            .bindings
            .contains_key(&retention_ref)
        {
            return Err(invalid());
        }
        let mut resource_bindings = config.external_secrets.bindings.clone();
        resource_bindings.insert(retention_ref.clone(), config.external_secrets.retention_key);
        let resource_files =
            FileSecretResolver::new(&config.external_secrets.root, resource_bindings)?;
        let root_ca_pem = match config.smtp.root_ca_key {
            Some(reference) => Some(resolve(&external, &reference).await?.as_bytes().to_vec()),
            None => None,
        };
        let credentials = match (config.smtp.username_key, config.smtp.password_key) {
            (Some(username), Some(password)) => Some(SmtpCredentials::new(
                resolve(&external, &username).await?.to_string(),
                resolve(&external, &password).await?.to_string(),
            )),
            (None, None) => None,
            _ => return Err(invalid()),
        };
        let tls = match config.smtp.tls.as_str() {
            "implicit" => SmtpTlsMode::Implicit,
            "starttls" => SmtpTlsMode::StartTls,
            _ => return Err(invalid()),
        };
        let relay = SmtpRelay::new(SmtpRelayConfig {
            host: config.smtp.host,
            port: config.smtp.port,
            tls,
            from: config.smtp.from,
            root_ca_pem,
            credentials,
        })?;
        let database_files = FileSecretResolver::new(
            &config.database.root,
            [("database".into(), config.database.key)],
        )?;
        let uri = resolve(&database_files, "database").await?;
        database_uri(uri.trim())?;
        let database = PostgresStore::connect(uri.trim(), config.max_connections).await?;
        database.verify_schema().await?;
        let users =
            PostgresUsersStore::new(database.clone(), UserAuthorityKey::new(*governance_key)?);
        users.verify_authority().await?;
        let administrators = FileSecretResolver::new(
            &config.administrators.root,
            [("operator:administrators".into(), config.administrators.key)],
        )?;
        let admin_credentials = AdminCredentialResolver::mounted(
            database.clone(),
            administrators,
            config.namespace.clone(),
            "operator:administrators".into(),
            Duration::ZERO,
        )
        .map_err(|_| invalid())?;
        // Loading the complete registry validates current lifecycle authority
        // and its durable checkpoint without an authentication success.
        admin_credentials
            .verify(
                &AdminCredentialOwner::platform(),
                "",
                crate::current_unix_secs(),
            )
            .await
            .map_err(|_| invalid())?;
        let ssf = PostgresSsfStore::new(database.clone(), ssf_keys);
        let governance_resources = PostgresGovernanceResourceBackend::new(
            database.clone(),
            ssf.clone(),
            resource_files,
            PostgresGovernanceResourceConfig {
                region: config.logical_region,
                tenant_id: "default".into(),
                storage_tenant: "".into(),
                retention_reference: retention_ref,
                operator_secret_references: config
                    .external_secrets
                    .bindings
                    .keys()
                    .cloned()
                    .collect(),
            },
        )?;
        let secret_references = config
            .external_secrets
            .bindings
            .keys()
            .map(|reference| {
                GovernanceSecretReference::historical_external("mounted_client", reference)
            })
            .collect();
        let notifier =
            PostgresSmtpNotifier::new(database.clone(), users.clone(), outbox_keys.clone(), relay)?;
        let state = AppState {
            form,
            phase,
            subject_type,
            tenant_subject_types: Arc::new(BTreeMap::new()),
            redirect_prefix_allowed_hosts: Arc::new(BTreeMap::from([(
                "default".into(),
                redirect_hosts,
            )])),
            region: region.clone(),
            governance_config: Arc::new(governance_config),
            deployment_commit: config.deployment_commit,
            governance_hmac_key: Arc::new(governance_key.to_vec()),
            governance: Arc::new(GovernanceStoreImpl::Postgres(PostgresGovernanceStore::new(
                database.clone(),
            ))),
            governance_jobs: Arc::new(GovernanceJobQueueImpl::Postgres(
                PostgresGovernanceQueue::new(database.clone()),
            )),
            tenant_secret_references: Arc::new(BTreeMap::from([(
                "default".into(),
                secret_references,
            )])),
            governance_resources: Arc::new(GovernanceResourceBackendImpl::Postgres(
                governance_resources,
            )),
            assurance_policy: Arc::new(agent_auth_authn::assurance::AssurancePolicy::default()),
            tenant_partitioning: false,
            server_secret: Arc::new(server_key.to_vec()),
            saas_origin_auth: Arc::new(crate::origin_auth::SaasOriginAuth::single_tenant()),
            credential_audit: Arc::new(crate::credential::CredentialAuditSink::Stderr),
            security_events: Arc::new(SecurityEventStoreImpl::Postgres(database.clone())),
            ssf: Arc::new(SsfStoreImpl::Postgres(ssf)),
            ssf_management_enabled: true,
            security_event_fallback: Some(Arc::new(SecurityEventFallbackImpl::Postgres(
                PostgresSecurityEventFallback::new(database.clone()),
            ))),
            admin_credentials: Arc::new(admin_credentials),
            admin_auth: Arc::new(AdminAuthStoreImpl::Postgres(database.clone())),
            branding: Arc::new(crate::branding_store::BrandingStore::postgres(
                database.clone(),
            )),
            saas_tenants: Arc::new(Vec::new()),
            allow_login_placeholder: false,
            dcr_mode,
            initial_access_tokens: Arc::new(InitialAccessTokenStoreImpl::Postgres(
                database.clone(),
            )),
            tenant_keys: Arc::new(
                crate::tenant_keys::TenantKeyService::mounted(signing_keys.clone())
                    .with_region(region),
            ),
            signer,
            codes: Arc::new(CodeStoreImpl::Postgres(database.clone())),
            clients: Arc::new(ClientStoreImpl::Postgres(database.clone())),
            cimd: Arc::new(cimd),
            refresh: Arc::new(RefreshStoreImpl::Postgres(database.clone())),
            par: Arc::new(ParStoreImpl::Postgres(database.clone())),
            grace: Some(Arc::new(GraceStoreImpl::Postgres(PostgresGraceStore::new(
                database.clone(),
                grace_keys,
            )))),
            grace_window_secs: config.grace_window_secs,
            sessions: Arc::new(SessionStoreImpl::Postgres(database.clone())),
            magic_links: Arc::new(MagicLinkStoreImpl::Postgres(database.clone())),
            invitations: Arc::new(InvitationStoreImpl::Postgres(PostgresInvitationStore::new(
                users.clone(),
            ))),
            invitation_ttl_secs: config.invitation_ttl_secs,
            users: Arc::new(UsersStoreImpl::Postgres(users)),
            attribute_namespaces: Arc::new(AttributeNamespaceStoreImpl::Postgres(database.clone())),
            attribute_namespace_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            scim_groups: Arc::new(ScimGroupsStoreImpl::Postgres(database.clone())),
            passwords: Arc::new(PasswordStoreImpl::Postgres(database.clone())),
            password_workers: Arc::new(tokio::sync::Semaphore::new(config.password_workers)),
            recovery: Arc::new(RecoveryStoreImpl::Postgres(database.clone())),
            notifier: Arc::new(NotifierImpl::Postgres(notifier)),
            messages: Arc::new(MessageOutboxImpl::Postgres(PostgresMessageOutbox::new(
                database.clone(),
                outbox_keys,
            ))),
            workload_trust: Arc::new(WorkloadTrustStoreImpl::Postgres(database.clone())),
            federation_config: Arc::new(FederationConfigStoreImpl::Postgres(database.clone())),
            federation_attribute_mappings: Arc::new(
                FederationAttributeMappingsStoreImpl::Postgres(database.clone()),
            ),
            upstream_token_exchanger: Arc::new(UpstreamTokenExchangerImpl::Http(
                HttpUpstreamTokenExchanger::new(),
            )),
            secret_resolver: Arc::new(SecretResolverImpl::File(external)),
            federation_flow: Arc::new(FederationFlowStoreImpl::Postgres(database.clone())),
            federation_enabled: config.capabilities.federation,
            passkey_challenges: Arc::new(PasskeyChallengeStoreImpl::Postgres(database.clone())),
            passkeys: Arc::new(PasskeyStoreImpl::Postgres(database.clone())),
            passkey_enabled: config.capabilities.passkey,
            ciba_ping_push_enabled: config.capabilities.ciba_ping_push,
            ciba_delivery: Arc::new(CibaCallbackDeliveryImpl::Http(
                HttpCibaCallbackDelivery::new(),
            )),
            jwks_fetcher: Arc::new(JwksFetcherImpl::Http(HttpJwksFetcher::new())),
            oidc_metadata_fetcher: Arc::new(OidcMetadataFetcherImpl::Http(
                HttpOidcMetadataFetcher::default(),
            )),
            sts_caller: None,
            sts_circuit: Arc::new(tokio::sync::Mutex::new(
                agent_auth_workload::CircuitBreaker::default(),
            )),
            replay_store: Some(Arc::new(ReplayStoreImpl::Postgres(database.clone()))),
            grants: Arc::new(GrantStoreImpl::Postgres(database.clone())),
            domain_map: Arc::new(DomainMapStoreImpl::Postgres(database.clone())),
            byod_enabled: config.capabilities.byod,
            mtls_svid_enabled: config.capabilities.mtls_svid,
            ema_enabled: config.capabilities.ema,
            ema_policies: Arc::new(ema_policies),
            policy_versions: Arc::new(PolicyVersionStoreImpl::Postgres(database.clone())),
            policy_artifacts: Arc::new(PolicyArtifactStoreImpl::Postgres(database.clone())),
            authz_enabled: config.capabilities.authz,
            current_pv_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            jti_store: Some(Arc::new(JtiStoreImpl::Postgres(database.clone()))),
            ciba: Arc::new(CibaStoreImpl::Postgres(PostgresCibaStore::new(
                database.clone(),
                ciba_keys,
            ))),
            device: Arc::new(DeviceStoreImpl::Postgres(database.clone())),
            authz_sessions: Arc::new(AuthzSessionStoreImpl::Postgres(database.clone())),
            authz_events: Arc::new(AuthzEventSinkImpl::Log(LogAuthzEventSink)),
            web_base_url: config.web_base_url,
            rate_limit: Some(Arc::new(RateLimitStoreImpl::Postgres(database.clone()))),
            payments: None,
        };
        Ok(Self {
            state,
            database,
            signing_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::database_uri;

    #[test]
    fn database_tls_cannot_be_bypassed_by_query_aliases_duplicates_or_host_overrides() {
        for uri in [
            "postgres://user:secret@db.example.test/auth",
            "postgres://user:secret@db.example.test/auth?sslmode=require",
            "postgres://user:secret@db.example.test/auth?sslmode=verify-full&sslmode=disable",
            "postgres://user:secret@db.example.test/auth?sslmode=verify-full&ssl-mode=disable",
            "postgres://user:secret@localhost/auth?host=db.example.test",
            "postgres://user:secret@127.0.0.1/auth?hostaddr=192.0.2.1",
            "postgres://user:secret@%2Ftmp/auth?sslmode=verify-full",
            "postgres://user:secret@db.example.test/auth?sslmode=verify-full#ignored",
            "postgres://user:secret@db.example.test/auth?sslmode=verify-full&unknown=secret",
        ] {
            assert!(
                database_uri(uri).is_err(),
                "unsafe connection grammar admitted"
            );
        }
        for uri in [
            "postgres://user:secret@db.example.test/auth?sslmode=verify-full&sslrootcert=/mount/ca.pem",
            "postgresql://user:secret@127.0.0.1:15432/auth",
            "postgres://user:secret@[::1]/auth?sslmode=disable",
        ] {
            assert!(database_uri(uri).is_ok());
        }
    }
}
