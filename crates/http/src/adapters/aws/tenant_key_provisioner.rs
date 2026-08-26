use agent_auth_infra_core::{
    ec_jwk_from_spki_der, rsa_jwk_from_ne, EcPublicJwk, RsaPublicJwk, TenantKeyAlgorithm,
};
use aws_sdk_kms::{
    error::ProvideErrorMetadata,
    types::{
        KeySpec, KeyState, KeyUsageType, MessageType, MultiRegionKeyType, SigningAlgorithmSpec, Tag,
    },
};
use aws_sdk_resourcegroupstagging::types::TagFilter;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::tenant_key_provisioner::{ProvisioningBackendError, TenantKeyProvisioningBackend};

const PROBE_MESSAGE: &[u8] = b"agent-auth-tenant-key-readiness-v1";
const REPLICATION_TAG_KEYS: [&str; 6] = [
    "agent-auth-managed",
    "agent-auth-deployment",
    "agent-auth-tenant",
    "agent-auth-operation",
    "agent-auth-algorithm",
    "agent-auth-generation",
];

fn service_error(code: &str, message: &str) -> ProvisioningBackendError {
    if code.contains("Throttling")
        || code.contains("KmsInternal")
        || code.contains("KMSInternal")
        || code.contains("KeyUnavailable")
        || code.contains("DependencyTimeout")
        || code.contains("LimitExceeded")
        || code.contains("InternalService")
        || code.contains("Throttled")
        || code.contains("NotFound")
        || code.contains("KMSInvalidState")
    {
        ProvisioningBackendError::Transient(code.to_string())
    } else {
        ProvisioningBackendError::Permanent(format!("{code}: {message}"))
    }
}

fn probe_service_error(code: &str, message: &str) -> ProvisioningBackendError {
    if code.contains("AccessDenied")
        || code.contains("NotFound")
        || code.contains("KMSInvalidState")
    {
        ProvisioningBackendError::ReadinessPending(format!("{code}: {message}"))
    } else {
        service_error(code, message)
    }
}

fn backend_error<E, R>(error: aws_sdk_kms::error::SdkError<E, R>) -> ProvisioningBackendError
where
    aws_sdk_kms::error::SdkError<E, R>: ProvideErrorMetadata,
{
    if matches!(
        &error,
        aws_sdk_kms::error::SdkError::TimeoutError(_)
            | aws_sdk_kms::error::SdkError::DispatchFailure(_)
            | aws_sdk_kms::error::SdkError::ResponseError(_)
    ) {
        return ProvisioningBackendError::Transient("KMS transport failure".to_string());
    }
    let code = error.code().unwrap_or("");
    let message = error.message().unwrap_or("");
    service_error(code, message)
}

fn probe_backend_error<E, R>(error: aws_sdk_kms::error::SdkError<E, R>) -> ProvisioningBackendError
where
    aws_sdk_kms::error::SdkError<E, R>: ProvideErrorMetadata,
{
    if matches!(
        &error,
        aws_sdk_kms::error::SdkError::TimeoutError(_)
            | aws_sdk_kms::error::SdkError::DispatchFailure(_)
            | aws_sdk_kms::error::SdkError::ResponseError(_)
    ) {
        return ProvisioningBackendError::Transient("KMS transport failure".to_string());
    }
    probe_service_error(error.code().unwrap_or(""), error.message().unwrap_or(""))
}

fn replica_readiness_error(error: ProvisioningBackendError) -> ProvisioningBackendError {
    match error {
        ProvisioningBackendError::ReadinessPending(message)
        | ProvisioningBackendError::Transient(message) => {
            ProvisioningBackendError::ReplicaReadinessPending(message)
        }
        other => other,
    }
}

fn select_replication_tags(
    tags: &[Tag],
    key_arn: &str,
) -> Result<Vec<Tag>, ProvisioningBackendError> {
    let mut replication_tags = Vec::with_capacity(REPLICATION_TAG_KEYS.len());
    for required in REPLICATION_TAG_KEYS {
        let Some(tag) = tags.iter().find(|tag| tag.tag_key() == required) else {
            return Err(ProvisioningBackendError::Permanent(format!(
                "KMS primary key {key_arn} is missing required tag {required}"
            )));
        };
        if (required == "agent-auth-managed" && tag.tag_value() != "true")
            || tag.tag_value().is_empty()
        {
            return Err(ProvisioningBackendError::Permanent(format!(
                "KMS primary key {key_arn} has invalid required tag {required}"
            )));
        }
        replication_tags.push(tag.clone());
    }
    Ok(replication_tags)
}

#[derive(Clone)]
pub struct AwsTenantKeyProvisioningBackend {
    kms: aws_sdk_kms::Client,
    tagging: aws_sdk_resourcegroupstagging::Client,
    deployment_id: String,
    replica_kms: Vec<(String, aws_sdk_kms::Client)>,
}

impl AwsTenantKeyProvisioningBackend {
    pub fn new(
        kms: aws_sdk_kms::Client,
        tagging: aws_sdk_resourcegroupstagging::Client,
        deployment_id: impl Into<String>,
        replica_kms: Vec<(String, aws_sdk_kms::Client)>,
    ) -> Self {
        Self {
            kms,
            tagging,
            deployment_id: deployment_id.into(),
            replica_kms,
        }
    }

    fn tag(key: &str, value: impl Into<String>) -> Result<Tag, ProvisioningBackendError> {
        Tag::builder()
            .tag_key(key)
            .tag_value(value.into())
            .build()
            .map_err(|error| {
                ProvisioningBackendError::Permanent(format!("invalid KMS tag: {error}"))
            })
    }

    fn tag_filter(key: &str, value: impl Into<String>) -> TagFilter {
        TagFilter::builder().key(key).values(value.into()).build()
    }

    fn managed_key_filters(&self, tenant_id: &str) -> Vec<TagFilter> {
        vec![
            Self::tag_filter("agent-auth-managed", "true"),
            Self::tag_filter("agent-auth-deployment", self.deployment_id.clone()),
            Self::tag_filter("agent-auth-tenant", tenant_id),
        ]
    }

    async fn find_tagged_keys(
        &self,
        filters: Vec<TagFilter>,
    ) -> Result<Vec<String>, ProvisioningBackendError> {
        let mut pagination_token = None;
        let mut matches = Vec::new();
        loop {
            let output = self
                .tagging
                .get_resources()
                .resource_type_filters("kms:key")
                .set_tag_filters(Some(filters.clone()))
                .set_pagination_token(pagination_token)
                .send()
                .await
                .map_err(backend_error)?;
            for mapping in output.resource_tag_mapping_list() {
                if let Some(key_arn) = mapping.resource_arn() {
                    matches.push(key_arn.to_string());
                }
            }
            pagination_token = output
                .pagination_token()
                .filter(|token| !token.is_empty())
                .map(str::to_string);
            if pagination_token.is_none() {
                break;
            }
        }
        Ok(matches)
    }

    fn kms_for_region(&self, region: &str) -> aws_sdk_kms::Client {
        self.replica_kms
            .iter()
            .find_map(|(configured_region, kms)| (configured_region == region).then(|| kms.clone()))
            .unwrap_or_else(|| {
                aws_sdk_kms::Client::from_conf(
                    self.kms
                        .config()
                        .to_builder()
                        .region(aws_sdk_kms::config::Region::new(region.to_string()))
                        .build(),
                )
            })
    }

    async fn public_key(
        kms: &aws_sdk_kms::Client,
        key_arn: &str,
        expected: TenantKeyAlgorithm,
    ) -> Result<Vec<u8>, ProvisioningBackendError> {
        let output = kms
            .get_public_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(probe_backend_error)?;
        let valid_spec = match expected {
            TenantKeyAlgorithm::Es256 => output.key_spec() == Some(&KeySpec::EccNistP256),
            TenantKeyAlgorithm::Rs256 => matches!(
                output.key_spec(),
                Some(KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096)
            ),
        };
        if !valid_spec || output.key_usage() != Some(&KeyUsageType::SignVerify) {
            return Err(ProvisioningBackendError::Permanent(format!(
                "KMS key {key_arn} has incompatible spec or usage"
            )));
        }
        output
            .public_key()
            .map(|blob| blob.as_ref().to_vec())
            .ok_or_else(|| {
                ProvisioningBackendError::Permanent(
                    "KMS GetPublicKey returned no public key".to_string(),
                )
            })
    }

    async fn replication_tags(&self, key_arn: &str) -> Result<Vec<Tag>, ProvisioningBackendError> {
        let mut marker = None;
        let mut tags = Vec::new();
        loop {
            let output = self
                .kms
                .list_resource_tags()
                .key_id(key_arn)
                .set_marker(marker)
                .send()
                .await
                .map_err(probe_backend_error)?;
            tags.extend_from_slice(output.tags());
            if !output.truncated() {
                break;
            }
            marker = output.next_marker().map(str::to_string);
            if marker.is_none() {
                return Err(ProvisioningBackendError::Permanent(
                    "KMS ListResourceTags returned truncated output without marker".to_string(),
                ));
            }
        }
        select_replication_tags(&tags, key_arn)
    }

    async fn ensure_replicas(
        &self,
        key_arn: &str,
    ) -> Result<Vec<(String, aws_sdk_kms::Client)>, ProvisioningBackendError> {
        super::kms_regions::require_primary_mrk(key_arn).map_err(|error| {
            ProvisioningBackendError::Permanent(format!(
                "tenant signing candidate must be a multi-Region primary key: {error:?}"
            ))
        })?;
        let described = self
            .kms
            .describe_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(probe_backend_error)?;
        let configuration = described
            .key_metadata()
            .and_then(|metadata| metadata.multi_region_configuration())
            .ok_or_else(|| {
                ProvisioningBackendError::Permanent(format!(
                    "KMS key {key_arn} has no multi-Region configuration"
                ))
            })?;
        if configuration.multi_region_key_type() != Some(&MultiRegionKeyType::Primary) {
            return Err(ProvisioningBackendError::Permanent(format!(
                "KMS key {key_arn} is not a multi-Region primary"
            )));
        }
        if self.replica_kms.is_empty() {
            return Ok(Vec::new());
        }

        let tags = self.replication_tags(key_arn).await?;
        let mut replicas = Vec::with_capacity(self.replica_kms.len());
        for (region, kms) in &self.replica_kms {
            let replica_arn =
                super::kms_regions::key_arn_for_region(key_arn, region).map_err(|error| {
                    ProvisioningBackendError::Permanent(format!(
                        "cannot derive KMS replica ARN for {region}: {error:?}"
                    ))
                })?;
            let result = self
                .kms
                .replicate_key()
                .key_id(key_arn)
                .replica_region(region)
                .description(format!("Agent Auth tenant signing replica in {region}"))
                .set_tags(Some(tags.clone()))
                .send()
                .await;
            match result {
                Ok(output) => {
                    let returned_arn = output
                        .replica_key_metadata()
                        .and_then(|metadata| metadata.arn())
                        .ok_or_else(|| {
                            ProvisioningBackendError::Permanent(
                                "KMS ReplicateKey returned no replica ARN".to_string(),
                            )
                        })?;
                    if returned_arn != replica_arn {
                        return Err(ProvisioningBackendError::Permanent(format!(
                            "KMS ReplicateKey returned unexpected ARN {returned_arn}"
                        )));
                    }
                }
                Err(error)
                    if error
                        .code()
                        .is_some_and(|code| code.contains("AlreadyExists")) => {}
                Err(error) => return Err(probe_backend_error(error)),
            }
            replicas.push((replica_arn, kms.clone()));
        }
        Ok(replicas)
    }

    async fn probe_ec_in(
        kms: &aws_sdk_kms::Client,
        key_arn: &str,
    ) -> Result<EcPublicJwk, ProvisioningBackendError> {
        use p256::ecdsa::signature::Verifier;

        let spki = Self::public_key(kms, key_arn, TenantKeyAlgorithm::Es256).await?;
        let jwk = ec_jwk_from_spki_der(&spki).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("EC public key parse failed: {error:?}"))
        })?;
        let output = kms
            .sign()
            .key_id(key_arn)
            .message(aws_sdk_kms::primitives::Blob::new(PROBE_MESSAGE))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(probe_backend_error)?;
        let der = output.signature().ok_or_else(|| {
            ProvisioningBackendError::Permanent("KMS EC probe returned no signature".to_string())
        })?;
        let jose = agent_auth_infra_core::der_to_jose(der.as_ref()).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("KMS EC probe DER invalid: {error:?}"))
        })?;
        let x = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .map_err(|_| ProvisioningBackendError::Permanent("KMS EC JWK x invalid".to_string()))?;
        let y = URL_SAFE_NO_PAD
            .decode(&jwk.y)
            .map_err(|_| ProvisioningBackendError::Permanent("KMS EC JWK y invalid".to_string()))?;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("KMS EC verifier invalid: {error}"))
        })?;
        let signature = p256::ecdsa::Signature::from_slice(&jose).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("KMS EC signature invalid: {error}"))
        })?;
        verifier.verify(PROBE_MESSAGE, &signature).map_err(|_| {
            ProvisioningBackendError::Permanent(
                "KMS EC readiness signature failed local verification".to_string(),
            )
        })?;
        Ok(EcPublicJwk {
            x: jwk.x,
            y: jwk.y,
            kid: jwk.kid,
        })
    }

    async fn probe_rsa_in(
        kms: &aws_sdk_kms::Client,
        key_arn: &str,
    ) -> Result<RsaPublicJwk, ProvisioningBackendError> {
        use rsa::{
            pkcs1v15::{Signature, VerifyingKey},
            pkcs8::DecodePublicKey,
            signature::Verifier,
            traits::PublicKeyParts,
        };

        let spki = Self::public_key(kms, key_arn, TenantKeyAlgorithm::Rs256).await?;
        let public_key = rsa::RsaPublicKey::from_public_key_der(&spki).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("RSA public key parse failed: {error}"))
        })?;
        let jwk = rsa_jwk_from_ne(&public_key.n().to_bytes_be(), &public_key.e().to_bytes_be());
        let output = kms
            .sign()
            .key_id(key_arn)
            .message(aws_sdk_kms::primitives::Blob::new(PROBE_MESSAGE))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .map_err(probe_backend_error)?;
        let signature = output.signature().ok_or_else(|| {
            ProvisioningBackendError::Permanent("KMS RSA probe returned no signature".to_string())
        })?;
        let signature = Signature::try_from(signature.as_ref()).map_err(|error| {
            ProvisioningBackendError::Permanent(format!("KMS RSA signature invalid: {error}"))
        })?;
        VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(PROBE_MESSAGE, &signature)
            .map_err(|_| {
                ProvisioningBackendError::Permanent(
                    "KMS RSA readiness signature failed local verification".to_string(),
                )
            })?;
        Ok(RsaPublicJwk {
            n: jwk.n,
            e: jwk.e,
            kid: jwk.kid,
        })
    }
}

impl TenantKeyProvisioningBackend for AwsTenantKeyProvisioningBackend {
    async fn find_managed_keys(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<String>, ProvisioningBackendError> {
        self.find_tagged_keys(self.managed_key_filters(tenant_id))
            .await
    }

    async fn find_created_keys(
        &self,
        tenant_id: &str,
        operation_id: &str,
        generation: u64,
        algorithm: TenantKeyAlgorithm,
    ) -> Result<Vec<String>, ProvisioningBackendError> {
        let expected_algorithm = match algorithm {
            TenantKeyAlgorithm::Es256 => "es256",
            TenantKeyAlgorithm::Rs256 => "rs256",
        };
        let expected_generation = generation.to_string();
        let mut filters = self.managed_key_filters(tenant_id);
        filters.extend([
            Self::tag_filter("agent-auth-operation", operation_id),
            Self::tag_filter("agent-auth-algorithm", expected_algorithm),
            Self::tag_filter("agent-auth-generation", expected_generation),
        ]);
        self.find_tagged_keys(filters).await
    }

    async fn create_key(
        &self,
        tenant_id: &str,
        operation_id: &str,
        generation: u64,
        algorithm: TenantKeyAlgorithm,
    ) -> Result<String, ProvisioningBackendError> {
        let (key_spec, algorithm_name) = match algorithm {
            TenantKeyAlgorithm::Es256 => (KeySpec::EccNistP256, "es256"),
            TenantKeyAlgorithm::Rs256 => (KeySpec::Rsa2048, "rs256"),
        };
        let tags = vec![
            Self::tag("agent-auth-managed", "true")?,
            Self::tag("agent-auth-deployment", self.deployment_id.clone())?,
            Self::tag("agent-auth-tenant", tenant_id)?,
            Self::tag("agent-auth-operation", operation_id)?,
            Self::tag("agent-auth-algorithm", algorithm_name)?,
            Self::tag("agent-auth-generation", generation.to_string())?,
        ];
        let output = self
            .kms
            .create_key()
            .description(format!(
                "Agent Auth tenant {tenant_id} {algorithm_name} signing generation {generation}"
            ))
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(key_spec)
            .multi_region(true)
            .set_tags(Some(tags))
            .send()
            .await
            .map_err(backend_error)?;
        output
            .key_metadata()
            .and_then(|metadata| metadata.arn())
            .map(str::to_string)
            .ok_or_else(|| {
                ProvisioningBackendError::Permanent("KMS CreateKey returned no key ARN".to_string())
            })
    }

    async fn probe_ec(&self, key_arn: &str) -> Result<EcPublicJwk, ProvisioningBackendError> {
        let primary = Self::probe_ec_in(&self.kms, key_arn).await?;
        for (replica_arn, kms) in self
            .ensure_replicas(key_arn)
            .await
            .map_err(replica_readiness_error)?
        {
            let replica = Self::probe_ec_in(&kms, &replica_arn)
                .await
                .map_err(replica_readiness_error)?;
            if replica != primary {
                return Err(ProvisioningBackendError::Permanent(format!(
                    "KMS EC replica {replica_arn} public key differs from primary"
                )));
            }
        }
        Ok(primary)
    }

    async fn probe_rsa(&self, key_arn: &str) -> Result<RsaPublicJwk, ProvisioningBackendError> {
        let primary = Self::probe_rsa_in(&self.kms, key_arn).await?;
        for (replica_arn, kms) in self
            .ensure_replicas(key_arn)
            .await
            .map_err(replica_readiness_error)?
        {
            let replica = Self::probe_rsa_in(&kms, &replica_arn)
                .await
                .map_err(replica_readiness_error)?;
            if replica != primary {
                return Err(ProvisioningBackendError::Permanent(format!(
                    "KMS RSA replica {replica_arn} public key differs from primary"
                )));
            }
        }
        Ok(primary)
    }

    async fn schedule_deletion(&self, key_arn: &str) -> Result<(), ProvisioningBackendError> {
        let described = match self.kms.describe_key().key_id(key_arn).send().await {
            Ok(described) => described,
            Err(error) if error.code().is_some_and(|code| code.contains("NotFound")) => {
                return Ok(())
            }
            Err(error) => return Err(backend_error(error)),
        };
        let metadata = described.key_metadata().ok_or_else(|| {
            ProvisioningBackendError::Permanent("KMS DescribeKey returned no metadata".to_string())
        })?;
        if metadata.multi_region() == Some(true) {
            let configuration = metadata.multi_region_configuration().ok_or_else(|| {
                ProvisioningBackendError::Permanent(
                    "KMS multi-Region key has no configuration".to_string(),
                )
            })?;
            for replica in configuration.replica_keys() {
                let region = replica.region().ok_or_else(|| {
                    ProvisioningBackendError::Permanent(
                        "KMS replica metadata has no region".to_string(),
                    )
                })?;
                let replica_arn = replica.arn().ok_or_else(|| {
                    ProvisioningBackendError::Permanent(
                        "KMS replica metadata has no ARN".to_string(),
                    )
                })?;
                let replica_kms = self.kms_for_region(region);
                Self::schedule_key_deletion_in(&replica_kms, replica_arn).await?;
            }
        }
        Self::schedule_key_deletion_in(&self.kms, key_arn).await
    }
}

impl AwsTenantKeyProvisioningBackend {
    async fn schedule_key_deletion_in(
        kms: &aws_sdk_kms::Client,
        key_arn: &str,
    ) -> Result<(), ProvisioningBackendError> {
        let described = match kms.describe_key().key_id(key_arn).send().await {
            Ok(described) => described,
            Err(error) if error.code().is_some_and(|code| code.contains("NotFound")) => {
                return Ok(())
            }
            Err(error) => return Err(backend_error(error)),
        };
        if matches!(
            described
                .key_metadata()
                .and_then(|metadata| metadata.key_state()),
            Some(KeyState::PendingDeletion | KeyState::PendingReplicaDeletion)
        ) {
            return Ok(());
        }
        match kms
            .schedule_key_deletion()
            .key_id(key_arn)
            .pending_window_in_days(7)
            .send()
            .await
        {
            Ok(_) => {}
            Err(error) if error.code().is_some_and(|code| code.contains("NotFound")) => {}
            Err(error) => return Err(backend_error(error)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_runtime_api::http::Request as SmithyRequest;
    use aws_smithy_types::body::SdkBody;
    use base64::engine::general_purpose::STANDARD;
    use p256::pkcs8::EncodePublicKey as _;
    use rand::SeedableRng;
    use serde_json::{json, Value};

    const PRIMARY_REGION: &str = "us-east-1";
    const REPLICA_REGION: &str = "us-west-2";
    const PRIMARY_KEY_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/mrk-11111111111111111111111111111111";
    const REPLICA_KEY_ARN: &str =
        "arn:aws:kms:us-west-2:123456789012:key/mrk-11111111111111111111111111111111";

    struct ProbeFixture {
        spki: Vec<u8>,
        signature: Vec<u8>,
        key_spec: &'static str,
        signing_algorithm: &'static str,
        algorithm_tag: &'static str,
    }

    fn response(body: Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body.to_string()))
            .expect("KMS response")
    }

    fn error_response(code: &str, message: &str) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amzn-errortype", code)
            .body(SdkBody::from(
                json!({"__type": code, "message": message}).to_string(),
            ))
            .expect("KMS error response")
    }

    fn placeholder_request(region: &str) -> axum::http::Request<SdkBody> {
        axum::http::Request::builder()
            .uri(format!("https://kms.{region}.amazonaws.com/"))
            .body(SdkBody::empty())
            .expect("placeholder KMS request")
    }

    fn kms_with_replay(region: &str, http: StaticReplayClient) -> aws_sdk_kms::Client {
        aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new(region.to_string()))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url(format!("https://kms.{region}.amazonaws.com"))
                .retry_config(
                    aws_sdk_kms::config::retry::RetryConfig::standard().with_max_attempts(1),
                )
                .http_client(http)
                .build(),
        )
    }

    fn tagging() -> aws_sdk_resourcegroupstagging::Client {
        aws_sdk_resourcegroupstagging::Client::from_conf(
            aws_sdk_resourcegroupstagging::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_resourcegroupstagging::config::Region::new(
                    PRIMARY_REGION,
                ))
                .credentials_provider(
                    aws_sdk_resourcegroupstagging::config::Credentials::for_tests(),
                )
                .endpoint_url(format!("https://tagging.{PRIMARY_REGION}.amazonaws.com"))
                .build(),
        )
    }

    fn request_json(request: &SmithyRequest<SdkBody>) -> Value {
        serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured KMS request body is in memory"),
        )
        .expect("captured KMS request is JSON")
    }

    fn request_target(request: &SmithyRequest<SdkBody>) -> &str {
        request
            .headers()
            .get("x-amz-target")
            .expect("KMS request target")
    }

    fn ec_fixture(seed: u8) -> ProbeFixture {
        use p256::ecdsa::signature::Signer as _;

        let signing_key =
            p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid P-256 scalar");
        let signature: p256::ecdsa::Signature = signing_key.sign(PROBE_MESSAGE);
        ProbeFixture {
            spki: signing_key
                .verifying_key()
                .to_public_key_der()
                .expect("P-256 SPKI")
                .as_bytes()
                .to_vec(),
            signature: signature.to_der().as_bytes().to_vec(),
            key_spec: "ECC_NIST_P256",
            signing_algorithm: "ECDSA_SHA_256",
            algorithm_tag: "es256",
        }
    }

    fn rsa_fixture(seed: u64) -> ProbeFixture {
        use rsa::signature::{SignatureEncoding as _, Signer as _};

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA key");
        let public = rsa::RsaPublicKey::from(&private);
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
        ProbeFixture {
            spki: public
                .to_public_key_der()
                .expect("RSA SPKI")
                .as_bytes()
                .to_vec(),
            signature: signing_key.sign(PROBE_MESSAGE).to_vec(),
            key_spec: "RSA_2048",
            signing_algorithm: "RSASSA_PKCS1_V1_5_SHA_256",
            algorithm_tag: "rs256",
        }
    }

    fn public_key_response(key_arn: &str, fixture: &ProbeFixture) -> Value {
        json!({
            "KeyId": key_arn,
            "PublicKey": STANDARD.encode(&fixture.spki),
            "KeySpec": fixture.key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [fixture.signing_algorithm]
        })
    }

    fn sign_response(key_arn: &str, fixture: &ProbeFixture) -> Value {
        json!({
            "KeyId": key_arn,
            "Signature": STANDARD.encode(&fixture.signature),
            "SigningAlgorithm": fixture.signing_algorithm
        })
    }

    fn managed_tags(algorithm: &str) -> Value {
        json!([
            {"TagKey": "agent-auth-managed", "TagValue": "true"},
            {"TagKey": "agent-auth-deployment", "TagValue": "registry-a"},
            {"TagKey": "agent-auth-tenant", "TagValue": "t1"},
            {"TagKey": "agent-auth-operation", "TagValue": "op-1"},
            {"TagKey": "agent-auth-algorithm", "TagValue": algorithm},
            {"TagKey": "agent-auth-generation", "TagValue": "7"}
        ])
    }

    fn primary_probe_events(
        fixture: &ProbeFixture,
        replica_already_exists: bool,
    ) -> Vec<ReplayEvent> {
        let replicate_response = if replica_already_exists {
            error_response(
                "AlreadyExistsException",
                "a replica with this key ID already exists in us-west-2",
            )
        } else {
            response(json!({
                "ReplicaKeyMetadata": {
                    "Arn": REPLICA_KEY_ARN,
                    "KeyId": "mrk-11111111111111111111111111111111",
                    "MultiRegion": true
                }
            }))
        };
        vec![
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(public_key_response(PRIMARY_KEY_ARN, fixture)),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(sign_response(PRIMARY_KEY_ARN, fixture)),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(json!({
                    "KeyMetadata": {
                        "Arn": PRIMARY_KEY_ARN,
                        "KeyId": "mrk-11111111111111111111111111111111",
                        "MultiRegion": true,
                        "MultiRegionConfiguration": {
                            "MultiRegionKeyType": "PRIMARY",
                            "PrimaryKey": {
                                "Arn": PRIMARY_KEY_ARN,
                                "Region": PRIMARY_REGION
                            },
                            "ReplicaKeys": []
                        }
                    }
                })),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(json!({
                    "Tags": managed_tags(fixture.algorithm_tag),
                    "Truncated": false
                })),
            ),
            ReplayEvent::new(placeholder_request(PRIMARY_REGION), replicate_response),
        ]
    }

    fn replica_probe_events(fixture: &ProbeFixture) -> Vec<ReplayEvent> {
        vec![
            ReplayEvent::new(
                placeholder_request(REPLICA_REGION),
                response(public_key_response(REPLICA_KEY_ARN, fixture)),
            ),
            ReplayEvent::new(
                placeholder_request(REPLICA_REGION),
                response(sign_response(REPLICA_KEY_ARN, fixture)),
            ),
        ]
    }

    fn probe_backend(
        primary_fixture: &ProbeFixture,
        replica_fixture: &ProbeFixture,
        replica_already_exists: bool,
    ) -> (
        AwsTenantKeyProvisioningBackend,
        StaticReplayClient,
        StaticReplayClient,
    ) {
        let primary_http = StaticReplayClient::new(primary_probe_events(
            primary_fixture,
            replica_already_exists,
        ));
        let replica_http = StaticReplayClient::new(replica_probe_events(replica_fixture));
        let backend = AwsTenantKeyProvisioningBackend::new(
            kms_with_replay(PRIMARY_REGION, primary_http.clone()),
            tagging(),
            "registry-a",
            vec![(
                REPLICA_REGION.to_string(),
                kms_with_replay(REPLICA_REGION, replica_http.clone()),
            )],
        );
        (backend, primary_http, replica_http)
    }

    fn assert_regional_probe_requests(
        primary_http: &StaticReplayClient,
        replica_http: &StaticReplayClient,
        fixture: &ProbeFixture,
    ) {
        let primary_requests: Vec<_> = primary_http.actual_requests().collect();
        assert_eq!(
            primary_requests
                .iter()
                .map(|request| request_target(request))
                .collect::<Vec<_>>(),
            [
                "TrentService.GetPublicKey",
                "TrentService.Sign",
                "TrentService.DescribeKey",
                "TrentService.ListResourceTags",
                "TrentService.ReplicateKey",
            ]
        );
        let primary_public = request_json(primary_requests[0]);
        assert_eq!(primary_public["KeyId"], PRIMARY_KEY_ARN);
        let primary_sign = request_json(primary_requests[1]);
        assert_eq!(primary_sign["KeyId"], PRIMARY_KEY_ARN);
        assert_eq!(primary_sign["Message"], STANDARD.encode(PROBE_MESSAGE));
        assert_eq!(primary_sign["MessageType"], "RAW");
        assert_eq!(primary_sign["SigningAlgorithm"], fixture.signing_algorithm);
        let describe = request_json(primary_requests[2]);
        assert_eq!(describe["KeyId"], PRIMARY_KEY_ARN);
        let list_tags = request_json(primary_requests[3]);
        assert_eq!(list_tags["KeyId"], PRIMARY_KEY_ARN);

        let replicate = request_json(primary_requests[4]);
        assert_eq!(replicate["KeyId"], PRIMARY_KEY_ARN);
        assert_eq!(replicate["ReplicaRegion"], REPLICA_REGION);
        assert_eq!(replicate["Tags"], managed_tags(fixture.algorithm_tag));

        let replica_requests: Vec<_> = replica_http.actual_requests().collect();
        assert_eq!(
            replica_requests
                .iter()
                .map(|request| request_target(request))
                .collect::<Vec<_>>(),
            ["TrentService.GetPublicKey", "TrentService.Sign"]
        );
        let replica_public = request_json(replica_requests[0]);
        assert_eq!(replica_public["KeyId"], REPLICA_KEY_ARN);
        let replica_sign = request_json(replica_requests[1]);
        assert_eq!(replica_sign["KeyId"], REPLICA_KEY_ARN);
        assert_eq!(replica_sign["Message"], STANDARD.encode(PROBE_MESSAGE));
        assert_eq!(replica_sign["MessageType"], "RAW");
        assert_eq!(replica_sign["SigningAlgorithm"], fixture.signing_algorithm);
    }

    fn tag(key: &str, value: &str) -> Tag {
        Tag::builder()
            .tag_key(key)
            .tag_value(value)
            .build()
            .unwrap()
    }

    fn kms(region: &str) -> aws_sdk_kms::Client {
        aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new(region.to_string()))
                .build(),
        )
    }

    #[test]
    fn new_key_eventual_consistency_errors_are_retryable() {
        assert!(matches!(
            service_error("NotFoundException", "not propagated"),
            ProvisioningBackendError::Transient(_)
        ));
        assert!(matches!(
            service_error("KMSInvalidStateException", "creating"),
            ProvisioningBackendError::Transient(_)
        ));
        assert!(matches!(
            service_error("InternalServiceException", "tagging unavailable"),
            ProvisioningBackendError::Transient(_)
        ));
        assert!(matches!(
            service_error("ThrottledException", "tagging throttled"),
            ProvisioningBackendError::Transient(_)
        ));
        assert!(matches!(
            service_error("AccessDeniedException", "denied"),
            ProvisioningBackendError::Permanent(_)
        ));
        assert!(matches!(
            probe_service_error("AccessDeniedException", "tag authorization pending"),
            ProvisioningBackendError::ReadinessPending(_)
        ));
        assert!(matches!(
            probe_service_error("NotFoundException", "replica not propagated"),
            ProvisioningBackendError::ReadinessPending(_)
        ));
        assert!(matches!(
            probe_service_error("KMSInvalidStateException", "replica creating"),
            ProvisioningBackendError::ReadinessPending(_)
        ));
        assert!(matches!(
            replica_readiness_error(probe_service_error(
                "NotFoundException",
                "replica not propagated"
            )),
            ProvisioningBackendError::ReplicaReadinessPending(_)
        ));
        assert!(matches!(
            replica_readiness_error(service_error(
                "LimitExceededException",
                "replica quota exhausted"
            )),
            ProvisioningBackendError::ReplicaReadinessPending(_)
        ));
        assert!(matches!(
            replica_readiness_error(ProvisioningBackendError::Transient(
                "KMS transport failure".to_string()
            )),
            ProvisioningBackendError::ReplicaReadinessPending(_)
        ));
    }

    #[test]
    fn replication_uses_only_the_required_managed_tags() {
        let tags = [
            tag("agent-auth-generation", "7"),
            tag("cost-center", "security"),
            tag("agent-auth-operation", "op"),
            tag("agent-auth-managed", "true"),
            tag("agent-auth-deployment", "registry-a"),
            tag("agent-auth-algorithm", "es256"),
            tag("agent-auth-tenant", "t1"),
        ];

        let selected = select_replication_tags(&tags, "arn").unwrap();
        assert_eq!(
            selected.iter().map(|tag| tag.tag_key()).collect::<Vec<_>>(),
            REPLICATION_TAG_KEYS
        );
    }

    #[test]
    fn cleanup_can_address_a_replica_removed_from_current_configuration() {
        let backend = AwsTenantKeyProvisioningBackend::new(
            kms("us-east-1"),
            aws_sdk_resourcegroupstagging::Client::from_conf(
                aws_sdk_resourcegroupstagging::Config::builder()
                    .behavior_version_latest()
                    .region(aws_sdk_resourcegroupstagging::config::Region::new(
                        "us-east-1",
                    ))
                    .build(),
            ),
            "registry-a",
            vec![("us-west-2".to_string(), kms("us-west-2"))],
        );

        assert_eq!(
            backend
                .kms_for_region("eu-west-1")
                .config()
                .region()
                .map(|region| region.as_ref()),
            Some("eu-west-1")
        );

        let filters = backend.managed_key_filters("t1");
        assert!(filters.iter().any(|filter| {
            filter.key() == Some("agent-auth-deployment") && filter.values() == ["registry-a"]
        }));
        assert!(filters
            .iter()
            .any(|filter| filter.key() == Some("agent-auth-tenant") && filter.values() == ["t1"]));
    }

    #[tokio::test]
    async fn tenant_key_creation_requests_multi_region_signing_keys_for_both_algorithms() {
        let response_for = |key_arn: &str| {
            response(json!({
                "KeyMetadata": {
                    "Arn": key_arn,
                    "KeyId": key_arn.rsplit('/').next().unwrap(),
                    "MultiRegion": true
                }
            }))
        };
        let http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response_for(PRIMARY_KEY_ARN),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response_for(
                    "arn:aws:kms:us-east-1:123456789012:key/mrk-22222222222222222222222222222222",
                ),
            ),
        ]);
        let backend = AwsTenantKeyProvisioningBackend::new(
            kms_with_replay(PRIMARY_REGION, http.clone()),
            tagging(),
            "registry-a",
            Vec::new(),
        );

        backend
            .create_key("t1", "op-1", 7, TenantKeyAlgorithm::Es256)
            .await
            .expect("create EC MRK");
        backend
            .create_key("t1", "op-1", 7, TenantKeyAlgorithm::Rs256)
            .await
            .expect("create RSA MRK");

        let requests: Vec<_> = http.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        for (request, expected_spec, expected_algorithm) in [
            (requests[0], "ECC_NIST_P256", "es256"),
            (requests[1], "RSA_2048", "rs256"),
        ] {
            assert_eq!(request_target(request), "TrentService.CreateKey");
            let body = request_json(request);
            assert_eq!(body["MultiRegion"], true);
            assert_eq!(body["KeyUsage"], "SIGN_VERIFY");
            assert_eq!(body["KeySpec"], expected_spec);
            assert_eq!(body["Tags"], managed_tags(expected_algorithm));
        }
    }

    #[tokio::test]
    async fn tenant_key_readiness_probes_ec_and_rsa_in_every_configured_region() {
        let ec = ec_fixture(7);
        let (backend, primary_http, replica_http) = probe_backend(&ec, &ec, false);
        backend
            .probe_ec(PRIMARY_KEY_ARN)
            .await
            .expect("all EC regions are ready");
        assert_regional_probe_requests(&primary_http, &replica_http, &ec);

        let rsa = rsa_fixture(11);
        let (backend, primary_http, replica_http) = probe_backend(&rsa, &rsa, false);
        backend
            .probe_rsa(PRIMARY_KEY_ARN)
            .await
            .expect("all RSA regions are ready");
        assert_regional_probe_requests(&primary_http, &replica_http, &rsa);

        let (backend, primary_http, replica_http) = probe_backend(&ec, &ec, true);
        backend
            .probe_ec(PRIMARY_KEY_ARN)
            .await
            .expect("an existing replica is still probed locally");
        assert_regional_probe_requests(&primary_http, &replica_http, &ec);
    }

    #[tokio::test]
    async fn tenant_key_readiness_fails_closed_on_bad_signature_or_replica_identity() {
        let ec = ec_fixture(7);
        let wrong_signer = ec_fixture(8);
        let bad_signature_http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(public_key_response(PRIMARY_KEY_ARN, &ec)),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(sign_response(PRIMARY_KEY_ARN, &wrong_signer)),
            ),
        ]);
        let error = AwsTenantKeyProvisioningBackend::probe_ec_in(
            &kms_with_replay(PRIMARY_REGION, bad_signature_http),
            PRIMARY_KEY_ARN,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ProvisioningBackendError::Permanent(message)
                if message.contains("failed local verification")
        ));

        let replica = ec_fixture(9);
        let (backend, _, _) = probe_backend(&ec, &replica, false);
        let error = backend.probe_ec(PRIMARY_KEY_ARN).await.unwrap_err();
        assert!(matches!(
            error,
            ProvisioningBackendError::Permanent(message)
                if message.contains("public key differs from primary")
        ));

        let rsa = rsa_fixture(11);
        let wrong_signer = rsa_fixture(12);
        let bad_signature_http = StaticReplayClient::new(vec![
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(public_key_response(PRIMARY_KEY_ARN, &rsa)),
            ),
            ReplayEvent::new(
                placeholder_request(PRIMARY_REGION),
                response(sign_response(PRIMARY_KEY_ARN, &wrong_signer)),
            ),
        ]);
        let error = AwsTenantKeyProvisioningBackend::probe_rsa_in(
            &kms_with_replay(PRIMARY_REGION, bad_signature_http),
            PRIMARY_KEY_ARN,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ProvisioningBackendError::Permanent(message)
                if message.contains("failed local verification")
        ));

        let replica = rsa_fixture(13);
        let (backend, _, _) = probe_backend(&rsa, &replica, false);
        let error = backend.probe_rsa(PRIMARY_KEY_ARN).await.unwrap_err();
        assert!(matches!(
            error,
            ProvisioningBackendError::Permanent(message)
                if message.contains("public key differs from primary")
        ));
    }
}
