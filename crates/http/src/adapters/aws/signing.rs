//! AWS KMS signing adapters.

use super::*;

/// KMS 签名器:EC_NIST_P256(ES256,access token)CMK + 可选 RSA_2048(RS256,id_token)CMK。
/// 公钥/kid 启动时各取一次缓存。**轮换 P3(spec 005 §8 / C10.11b)**:持**活跃签名 key + 已发布 key 集**——
/// `key_id`/`jwk` = 活跃 EC(签 + active_kid);`published_jwks` = 发布集(活跃 + publish-ahead 新 + retiring 旧);
/// RSA 同构。`public_jwks` 返发布集全部,轮换全程新旧 token 都可验。
#[derive(Clone)]
pub struct KmsSigner {
    kms: aws_sdk_kms::Client,
    key_id: String,             // 活跃 EC 签名 key ARN(sign_es256 用)
    jwk: EcJwk,                 // 活跃 EC 公钥(active_kid 用)
    published_jwks: Vec<EcJwk>, // 已发布 EC 公钥集(含活跃;public_jwks 返此;≥1 且含 jwk)
    /// 活跃 RSA 签名 key(id_token,spec 001 C2.7);None = 本部署未配 RSA。
    rsa_key_id: Option<String>,
    rsa_jwk: Option<agent_auth_infra_core::RsaJwk>, // 活跃 RSA 公钥(active_rsa_kid 用)
    published_rsa_jwks: Vec<agent_auth_infra_core::RsaJwk>, // 已发布 RSA 公钥集(无 RSA 时空)
}

/// GetPublicKey 错误分类(spec 005 §8 评审 Blocker b):区别于 `kms_err`(sign 用),启动批量取公钥需分
/// 瞬时(throttle/内部错/依赖超时 → 可重试)vs 永久(key 不存在/坏 ARN → fail-closed)。
fn get_pubkey_err(
    e: &aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::get_public_key::GetPublicKeyError>,
) -> SignerError {
    let code = e.code().unwrap_or("");
    let transient = code.contains("Throttling")
        || code.contains("KmsInternal")
        || code.contains("KMSInternal")
        || code.contains("KeyUnavailable")
        || code.contains("DependencyTimeout")
        || code.contains("LimitExceeded");
    if transient {
        SignerError::Transient(code.to_string())
    } else {
        SignerError::Permanent(format!("{code}: {}", e.message().unwrap_or("")))
    }
}

impl KmsSigner {
    pub fn from_tenant_snapshot(
        kms: aws_sdk_kms::Client,
        snapshot: &agent_auth_infra_core::TenantKeySnapshot,
    ) -> Result<Self, SignerError> {
        snapshot.validate().map_err(|error| {
            SignerError::Permanent(format!("invalid tenant key snapshot: {error:?}"))
        })?;
        let current_region = kms
            .config()
            .region()
            .ok_or_else(|| {
                SignerError::Permanent("KMS client has no configured region".to_string())
            })?
            .as_ref()
            .to_string();
        let regional_key_arn = |key_arn: &str| {
            kms_regions::key_arn_for_region(key_arn, &current_region).map_err(|error| {
                SignerError::Permanent(format!(
                    "tenant key {key_arn} is unavailable in region {current_region}: {error:?}"
                ))
            })
        };
        let ec =
            |key: &agent_auth_infra_core::KeyMaterial<agent_auth_infra_core::EcPublicJwk>| EcJwk {
                kty: "EC",
                crv: "P-256",
                x: key.public_jwk.x.clone(),
                y: key.public_jwk.y.clone(),
                kid: key.public_jwk.kid.clone(),
                alg: "ES256",
                r#use: "sig",
            };
        let rsa = |key: &agent_auth_infra_core::KeyMaterial<
            agent_auth_infra_core::RsaPublicJwk,
        >| agent_auth_infra_core::RsaJwk {
            kty: "RSA",
            n: key.public_jwk.n.clone(),
            e: key.public_jwk.e.clone(),
            kid: key.public_jwk.kid.clone(),
            alg: "RS256",
            r#use: "sig",
        };
        Ok(Self {
            kms,
            key_id: regional_key_arn(&snapshot.ec.active.key_arn)?,
            jwk: ec(&snapshot.ec.active),
            published_jwks: snapshot.ec.published.iter().map(ec).collect(),
            rsa_key_id: Some(regional_key_arn(&snapshot.rsa.active.key_arn)?),
            rsa_jwk: Some(rsa(&snapshot.rsa.active)),
            published_rsa_jwks: snapshot.rsa.published.iter().map(rsa).collect(),
        })
    }

    /// 取一把 EC 公钥 JWK(有界重试瞬时错;永久错立即返)。`label` 仅用于错误信息。
    /// **同质校验(评审 H1)**:GetPublicKey 响应带 `KeySpec`——MUST == `ECC_NIST_P256`,拒任何其它 EC 曲线
    /// (P-384/P-521)或 RSA。**不能只靠 `ec_jwk_from_spki_der`**——它硬编码 crv/alg 且只截末 65 字节,一把
    /// P-384 CMK 的 SPKI 末 65 字节可能碰巧 0x04 开头 → 被误解析成带垃圾 x/y 的假 "P-256" JWK,发布进 JWKS
    /// = 对 access token 恒 ES256 不变量(C10.15a)制造 alg 混淆面。故先按 KeySpec 卡死曲线,再解析。
    async fn fetch_ec_jwk(
        kms: &aws_sdk_kms::Client,
        arn: &str,
        label: &str,
    ) -> Result<EcJwk, SignerError> {
        use aws_sdk_kms::types::KeySpec;
        for attempt in 0..3u32 {
            match kms.get_public_key().key_id(arn).send().await {
                Ok(out) => {
                    // KeySpec 卡死 P-256(GetPublicKey 响应含 key_spec;权威于 SPKI 字节形状)。
                    match out.key_spec() {
                        Some(KeySpec::EccNistP256) => {}
                        other => {
                            return Err(SignerError::Permanent(format!(
                                "{label} key_spec={other:?} 非 ECC_NIST_P256(EC 发布集须全 P-256/ES256,fail-closed)"
                            )))
                        }
                    }
                    let spki = out
                        .public_key()
                        .ok_or_else(|| {
                            SignerError::Permanent(format!("{label} GetPublicKey 无 public_key"))
                        })?
                        .as_ref();
                    return ec_jwk_from_spki_der(spki)
                        .map_err(|e| SignerError::Permanent(format!("{label} SPKI→JWK: {e:?}")));
                }
                Err(e) => {
                    let cls = get_pubkey_err(&e);
                    // 瞬时错有界重试(启动批量取 N 把,防单次 throttle 抖动使 init 不可恢复);永久错立即 fail-closed。
                    if matches!(cls, SignerError::Transient(_)) && attempt < 2 {
                        continue;
                    }
                    return Err(cls);
                }
            }
        }
        unreachable!()
    }

    async fn fetch_rsa_jwk(
        kms: &aws_sdk_kms::Client,
        arn: &str,
        label: &str,
    ) -> Result<agent_auth_infra_core::RsaJwk, SignerError> {
        use aws_sdk_kms::types::KeySpec;
        for attempt in 0..3u32 {
            match kms.get_public_key().key_id(arn).send().await {
                Ok(out) => {
                    // KeySpec 卡死 RSA(RSA 发布集须全 RSA/RS256;拒 EC/非 RSA 混入,评审 H1)。
                    // RS256 = RSASSA-PKCS1-v1_5 SHA-256;KMS RSA_2048/3072/4096 都可(alg 由签名算法定,非 key_spec)。
                    match out.key_spec() {
                        Some(KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096) => {}
                        other => {
                            return Err(SignerError::Permanent(format!(
                                "{label} key_spec={other:?} 非 RSA(RSA 发布集须全 RSA,fail-closed)"
                            )))
                        }
                    }
                    let spki = out
                        .public_key()
                        .ok_or_else(|| {
                            SignerError::Permanent(format!("{label} GetPublicKey 无 public_key"))
                        })?
                        .as_ref();
                    use rsa::pkcs8::DecodePublicKey;
                    use rsa::traits::PublicKeyParts;
                    let pk = rsa::RsaPublicKey::from_public_key_der(spki)
                        .map_err(|e| SignerError::Permanent(format!("{label} SPKI→pk: {e}")))?;
                    return Ok(agent_auth_infra_core::rsa_jwk_from_ne(
                        &pk.n().to_bytes_be(),
                        &pk.e().to_bytes_be(),
                    ));
                }
                Err(e) => {
                    let cls = get_pubkey_err(&e);
                    if matches!(cls, SignerError::Transient(_)) && attempt < 2 {
                        continue;
                    }
                    return Err(cls);
                }
            }
        }
        unreachable!()
    }

    /// comma-list → 去空白/空项 + 去重(保序)。活跃 ARN 恒并入。
    fn parse_published(active: &str, published_csv: Option<&str>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |a: &str| {
            let a = a.trim();
            if !a.is_empty() && !out.iter().any(|x| x == a) {
                out.push(a.to_string());
            }
        };
        push(active); // 活跃 key 恒 ∈ published(评审:active MUST ∈ published)
        if let Some(csv) = published_csv {
            for a in csv.split(',') {
                push(a);
            }
        }
        out
    }

    /// 构造(spec 005 §8 轮换):活跃 EC key + 可选 RSA key + 各自发布集。
    /// - `published_ec_csv` / `published_rsa_csv` 未配 → 退化为仅活跃(现状字节等价)。
    /// - 启动拉每把发布 key 公钥(有界重试瞬时);活跃 key 任何错 → fail-closed;非活跃永久错 → fail-closed
    ///   (运维误配响亮报错)、**绝不 skip**(skip 会致切签名/验旧签失败)。
    /// - 发布集按 kid 去重;**活跃 kid MUST ∈ 发布集**(结构上恒成立,因活跃 ARN 已并入)。
    pub async fn new(
        kms: aws_sdk_kms::Client,
        key_id: String,
        rsa_key_id: Option<String>,
        published_ec_csv: Option<String>,
        published_rsa_csv: Option<String>,
    ) -> Result<Self, SignerError> {
        // 活跃 EC:任何错 fail-closed。
        let jwk = Self::fetch_ec_jwk(&kms, &key_id, "active EC").await?;
        // 发布 EC 集(含活跃 ARN 去重)。
        let ec_arns = Self::parse_published(&key_id, published_ec_csv.as_deref());
        let mut published_jwks: Vec<EcJwk> = Vec::new();
        for arn in &ec_arns {
            let j = if arn == &key_id {
                jwk.clone() // 活跃已取,不重复调 KMS
            } else {
                Self::fetch_ec_jwk(&kms, arn, "published EC").await? // 非活跃永久错 fail-closed、绝不 skip
            };
            if !published_jwks.iter().any(|x| x.kid == j.kid) {
                published_jwks.push(j); // 按 kid 去重(RFC 7517)
            }
        }
        // 不变量:活跃 kid ∈ 发布集(活跃 ARN 已并入,结构性成立;防御性断言)。
        if !published_jwks.iter().any(|x| x.kid == jwk.kid) {
            return Err(SignerError::Permanent(
                "活跃 EC key 不在发布集(自我拒签,fail-closed)".into(),
            ));
        }

        // RSA(若配):活跃 + 发布集。
        let (rsa_jwk, published_rsa_jwks) = match &rsa_key_id {
            Some(rid) => {
                let active_rsa = Self::fetch_rsa_jwk(&kms, rid, "active RSA").await?;
                let rsa_arns = Self::parse_published(rid, published_rsa_csv.as_deref());
                let mut pubs: Vec<agent_auth_infra_core::RsaJwk> = Vec::new();
                for arn in &rsa_arns {
                    let j = if arn == rid {
                        active_rsa.clone()
                    } else {
                        Self::fetch_rsa_jwk(&kms, arn, "published RSA").await?
                    };
                    if !pubs.iter().any(|x| x.kid == j.kid) {
                        pubs.push(j);
                    }
                }
                if !pubs.iter().any(|x| x.kid == active_rsa.kid) {
                    return Err(SignerError::Permanent(
                        "活跃 RSA key 不在发布集(fail-closed)".into(),
                    ));
                }
                (Some(active_rsa), pubs)
            }
            // 未配 RSA:发布集 MUST 空(不发布无签名者的孤儿 RSA kid,评审 High a)。
            None => {
                if published_rsa_csv.as_deref().map(|s| !s.trim().is_empty()) == Some(true) {
                    return Err(SignerError::Permanent(
                        "配了 RSA 发布集但无活跃 RSA 签名 key(孤儿 kid,fail-closed)".into(),
                    ));
                }
                (None, Vec::new())
            }
        };

        Ok(KmsSigner {
            kms,
            key_id,
            jwk,
            published_jwks,
            rsa_key_id,
            rsa_jwk,
            published_rsa_jwks,
        })
    }
}

/// KMS 错误分类(修评审 中):用 SDK **结构化错误 code**(非字符串匹配)判瞬时/永久。
/// 节流(ThrottlingException)、内部错(KMSInternal)、key 暂不可用(KeyUnavailable/InvalidState)
/// → Transient(C10.2 可重试);其余(key 不存在、算法不符等)→ Permanent。
fn kms_err(
    e: aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::sign::SignError>,
) -> SignerError {
    let code = e.code().unwrap_or("");
    let transient = code.contains("Throttling")
        || code.contains("KmsInternal")
        || code.contains("KMSInternal")
        || code.contains("KeyUnavailable")
        || code.contains("DependencyTimeout")
        || code.contains("LimitExceeded");
    if transient {
        SignerError::Transient(code.to_string())
    } else {
        SignerError::Permanent(format!("{code}: {}", e.message().unwrap_or("")))
    }
}

impl Signer for KmsSigner {
    async fn sign_es256(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignerError> {
        let out = self
            .kms
            .sign()
            .key_id(&self.key_id)
            .message(aws_sdk_kms::primitives::Blob::new(signing_input.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(kms_err)?;
        let der = out
            .signature()
            .ok_or_else(|| SignerError::Permanent("Sign 无 signature".into()))?
            .as_ref();
        der_to_jose(der)
            .map(|s| s.to_vec())
            .map_err(|e| SignerError::Permanent(format!("der_to_jose: {e:?}")))
    }

    async fn public_jwks(&self) -> Result<Vec<EcJwk>, SignerError> {
        Ok(self.published_jwks.clone()) // 发布集全部(轮换重叠期含新旧;单 key 部署 = [活跃])
    }

    async fn active_kid(&self) -> Result<String, SignerError> {
        Ok(self.jwk.kid.clone()) // 活跃 EC key(sign_es256 用同一把)
    }

    async fn sign_rs256(&self, signing_input: &[u8]) -> Result<(String, Vec<u8>), SignerError> {
        // RS256 = RSASSA-PKCS1-v1_5 + SHA-256(codex 评审:不是 PSS)。KMS RSA 签名 blob 即 JWS 签名,
        // 不做 EC 的 DER→JOSE 转换。
        let (rid, rjwk) = match (&self.rsa_key_id, &self.rsa_jwk) {
            (Some(rid), Some(rjwk)) => (rid, rjwk),
            _ => {
                return Err(SignerError::Permanent(
                    "本部署未配 RSA 签名 key(无法签 RS256 id_token)".into(),
                ))
            }
        };
        let out = self
            .kms
            .sign()
            .key_id(rid)
            .message(aws_sdk_kms::primitives::Blob::new(signing_input.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .map_err(kms_err)?;
        let sig = out
            .signature()
            .ok_or_else(|| SignerError::Permanent("RSA Sign 无 signature".into()))?
            .as_ref()
            .to_vec();
        Ok((rjwk.kid.clone(), sig))
    }

    async fn public_rsa_jwks(&self) -> Result<Vec<agent_auth_infra_core::RsaJwk>, SignerError> {
        Ok(self.published_rsa_jwks.clone()) // 发布集(无 RSA 时空;轮换重叠期含新旧)
    }

    async fn active_rsa_kid(&self) -> Result<String, SignerError> {
        // 活跃 RSA key 的 kid（与 sign_rs256 用同一把）；未配 RSA → Permanent（无法签 RS256 id_token）。
        match &self.rsa_jwk {
            Some(j) => Ok(j.kid.clone()),
            None => Err(SignerError::Permanent(
                "本部署未配 RSA 签名 key(无 active_rsa_kid)".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KmsSigner, SignerError};
    use crate::ports::Signer;
    use agent_auth_infra_core::{
        jose_to_der, AlgorithmSnapshot, EcJwk, EcPublicJwk, KeyMaterial, RsaPublicJwk,
        TenantKeySnapshot, ES256_JOSE_SIG_LEN, P256_COORD_LEN,
    };
    use aws_smithy_http_client::test_util::capture_request;
    use aws_smithy_types::body::SdkBody;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn response(body: serde_json::Value) -> axum::http::Response<SdkBody> {
        axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body.to_string()))
            .expect("response")
    }

    fn kms(region: &str) -> aws_sdk_kms::Client {
        let config = aws_sdk_kms::Config::builder()
            .region(aws_sdk_kms::config::Region::new(region.to_string()))
            .behavior_version_latest()
            .build();
        aws_sdk_kms::Client::from_conf(config)
    }

    fn snapshot(ec_arn: &str, rsa_arn: &str) -> TenantKeySnapshot {
        let ec = KeyMaterial {
            key_arn: ec_arn.to_string(),
            generation: 1,
            public_jwk: EcPublicJwk {
                x: "x".to_string(),
                y: "y".to_string(),
                kid: "ec-kid".to_string(),
            },
            created_at: 1,
            verified_at: 2,
        };
        let rsa = KeyMaterial {
            key_arn: rsa_arn.to_string(),
            generation: 1,
            public_jwk: RsaPublicJwk {
                n: "n".to_string(),
                e: "AQAB".to_string(),
                kid: "rsa-kid".to_string(),
            },
            created_at: 1,
            verified_at: 2,
        };
        TenantKeySnapshot {
            generation: 1,
            ec: AlgorithmSnapshot {
                active: ec.clone(),
                published: vec![ec],
            },
            rsa: AlgorithmSnapshot {
                active: rsa.clone(),
                published: vec![rsa],
            },
            committed_at: 3,
        }
    }

    #[tokio::test]
    async fn kms_signer_requests_ecdsa_raw_and_converts_der_to_jose() {
        const KEY_ID: &str =
            "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111";
        let mut expected_jose = [0u8; ES256_JOSE_SIG_LEN];
        expected_jose[..P256_COORD_LEN].fill(0x80);
        expected_jose[ES256_JOSE_SIG_LEN - 1] = 0x07;
        let der = jose_to_der(&expected_jose).expect("valid ES256 JOSE signature");
        let (http, request) = capture_request(Some(response(serde_json::json!({
            "KeyId": KEY_ID,
            "Signature": STANDARD.encode(der),
            "SigningAlgorithm": "ECDSA_SHA_256"
        }))));
        let kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_kms::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_kms::config::Credentials::for_tests())
                .endpoint_url("https://kms.us-east-1.amazonaws.com")
                .http_client(http)
                .build(),
        );
        let jwk = EcJwk {
            kty: "EC",
            crv: "P-256",
            x: "x".to_string(),
            y: "y".to_string(),
            kid: "ec-kid".to_string(),
            alg: "ES256",
            r#use: "sig",
        };
        let signer = KmsSigner {
            kms,
            key_id: KEY_ID.to_string(),
            jwk: jwk.clone(),
            published_jwks: vec![jwk],
            rsa_key_id: None,
            rsa_jwk: None,
            published_rsa_jwks: Vec::new(),
        };

        let actual = signer
            .sign_es256(b"header.payload")
            .await
            .expect("KMS DER signature converts to JOSE");
        assert_eq!(actual, expected_jose);

        let request = request.expect_request();
        let body: serde_json::Value = serde_json::from_slice(
            request
                .body()
                .bytes()
                .expect("captured KMS request body is in memory"),
        )
        .expect("captured KMS request is JSON");
        assert_eq!(body["KeyId"], KEY_ID);
        assert_eq!(body["MessageType"], "RAW");
        assert_eq!(body["SigningAlgorithm"], "ECDSA_SHA_256");
    }

    #[test]
    fn tenant_signer_rebinds_mrk_arns_to_the_client_region() {
        let snapshot = snapshot(
            "arn:aws:kms:us-east-1:123456789012:key/mrk-11111111111111111111111111111111",
            "arn:aws:kms:us-east-1:123456789012:key/mrk-22222222222222222222222222222222",
        );
        let signer = KmsSigner::from_tenant_snapshot(kms("us-west-2"), &snapshot).unwrap();
        assert_eq!(
            signer.key_id,
            "arn:aws:kms:us-west-2:123456789012:key/mrk-11111111111111111111111111111111"
        );
        assert_eq!(
            signer.rsa_key_id.as_deref(),
            Some("arn:aws:kms:us-west-2:123456789012:key/mrk-22222222222222222222222222222222")
        );
    }

    #[test]
    fn tenant_signer_rejects_cross_region_single_region_keys() {
        let snapshot = snapshot(
            "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111",
            "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222",
        );
        assert!(matches!(
            KmsSigner::from_tenant_snapshot(kms("us-west-2"), &snapshot),
            Err(SignerError::Permanent(message)) if message.contains("SingleRegionKey")
        ));
        let signer = KmsSigner::from_tenant_snapshot(kms("us-east-1"), &snapshot).unwrap();
        assert_eq!(signer.key_id, snapshot.ec.active.key_arn);
    }
}

#[cfg(test)]
mod kms_signer_rotation_tests {
    use super::KmsSigner;

    // parse_published(spec 005 §8):活跃 ARN 恒并入 + trim 空白 + 丢空项(尾逗号)+ 保序去重。
    #[test]
    fn parse_published_includes_active_and_dedups() {
        // 未配 PUBLISHED → 仅活跃(现状字节等价)。
        assert_eq!(KmsSigner::parse_published("arn:a", None), vec!["arn:a"]);
        // 配了 → 活跃 + 其余;活跃在 csv 里重复 → 去重(只一次)、保序。
        assert_eq!(
            KmsSigner::parse_published("arn:a", Some("arn:a, arn:b ,arn:c")),
            vec!["arn:a", "arn:b", "arn:c"]
        );
        // 尾逗号 / 空项 / 多空白 → 丢弃。
        assert_eq!(
            KmsSigner::parse_published("arn:a", Some(" arn:b , , arn:c,")),
            vec!["arn:a", "arn:b", "arn:c"]
        );
        // csv 内自身重复 → 去重。
        assert_eq!(
            KmsSigner::parse_published("arn:a", Some("arn:b,arn:b,arn:a")),
            vec!["arn:a", "arn:b"]
        );
        // 空 csv → 仅活跃。
        assert_eq!(
            KmsSigner::parse_published("arn:a", Some("  ")),
            vec!["arn:a"]
        );
    }
}
