//! Stable MCP Enterprise-Managed Authorization (EMA) pure decision core.
//!
//! This crate owns operator policy validation and ID-JAG parsing/authorization.
//! It performs no network, storage, HTTP, or AWS operations.

pub const GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

mod decision;
mod identity;
mod jwt;
mod policy;
mod verification;

pub use decision::{
    authorize_verified_id_jag, AuthorizationDecision, AuthorizationError, AuthorizationRequest,
    OAuthErrorCode,
};
pub use identity::{derive_enterprise_user_id, derive_replay_key};
pub use jwt::{
    parse_compact_id_jag, IdJagClaims, IdJagHeader, JwtParseError, ParsedIdJag, StringListClaim,
    VerifiedIdJag,
};
pub use policy::{
    EmaPolicy, PolicyConfig, PolicyError, ResourcePolicy, ResourcePolicyConfig, SigningAlgorithm,
};
pub use verification::{verify_parsed_id_jag, EmaJwk, IdJagVerificationError};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::signature::SignatureEncoding;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    fn compact(header: serde_json::Value, claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signature = URL_SAFE_NO_PAD.encode([7u8; 64]);
        format!("{header}.{claims}.{signature}")
    }

    fn signed_es256(seed: u8, kid: Option<&str>, claims: serde_json::Value) -> (String, EmaJwk) {
        let signing_key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut header = serde_json::json!({
            "alg": "ES256",
            "typ": "oauth-id-jag+jwt",
        });
        if let Some(kid) = kid {
            header["kid"] = serde_json::Value::String(kid.to_string());
        }
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        (
            token,
            EmaJwk {
                kid: kid.map(str::to_string),
                kty: "EC".into(),
                alg: Some("ES256".into()),
                crv: Some("P-256".into()),
                n: None,
                e: None,
                x: Some(URL_SAFE_NO_PAD.encode(point.x().unwrap())),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
            },
        )
    }

    fn signed_rs256(kid: &str, claims: serde_json::Value) -> (String, EmaJwk) {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public_key = private_key.to_public_key();
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "oauth-id-jag+jwt",
            "kid": kid,
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = RsaSigningKey::<Sha256>::new(private_key).sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        (
            token,
            EmaJwk {
                kid: Some(kid.to_string()),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                crv: None,
                n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
                e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
                x: None,
                y: None,
            },
        )
    }

    fn verified(claims: serde_json::Value) -> VerifiedIdJag {
        let token = compact(
            serde_json::json!({
                "alg": "ES256",
                "typ": "oauth-id-jag+jwt",
                "kid": "key-1"
            }),
            claims,
        );
        VerifiedIdJag::assume_verified_for_test(parse_compact_id_jag(&token).unwrap())
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://login.example.com/acme/v2.0",
            "tenant": "acme",
            "sub": "enterprise-user-1",
            "aud": "https://auth.example.com",
            "client_id": "enterprise-mcp-client",
            "exp": 1_300,
            "iat": 1_000,
            "nbf": 990,
            "jti": "grant-1",
            "scope": "mcp:read mcp:write",
            "resource": "https://mcp.example.com",
            "cnf": {"jkt": "proof-thumbprint"},
            "aud_tenant": "agent-tenant-1"
        })
    }

    fn authorization_request() -> AuthorizationRequest<'static> {
        AuthorizationRequest {
            agent_auth_tenant: "agent-tenant-1",
            as_issuer: "https://auth.example.com",
            authenticated_client_id: "mcp-client",
            resource: "https://mcp.example.com",
            requested_scope: "mcp:read",
            request_has_authorization_details: false,
            presented_dpop_jkt: Some("proof-thumbprint"),
            now: 1_100,
        }
    }

    fn policy_config() -> PolicyConfig {
        PolicyConfig {
            policy_id: "entra-acme".into(),
            trusted_issuer: "https://login.example.com/acme/v2.0".into(),
            issuer_tenant: Some("acme".into()),
            jwks_uri: "https://login.example.com/acme/discovery/keys".into(),
            allowed_algorithms: vec![SigningAlgorithm::Rs256, SigningAlgorithm::Es256],
            authenticated_client_id: "mcp-client".into(),
            assertion_client_id: "enterprise-mcp-client".into(),
            resources: vec![ResourcePolicyConfig {
                resource: "https://mcp.example.com".into(),
                scopes: vec!["mcp:read".into(), "mcp:write".into()],
            }],
            allow_legacy_missing_resource: false,
            max_assertion_lifetime_secs: 300,
            allowed_clock_skew_secs: 30,
        }
    }

    #[test]
    fn validates_and_indexes_tenant_policy() {
        let policy = EmaPolicy::try_from(policy_config()).unwrap();
        assert_eq!(policy.policy_id(), "entra-acme");
        assert_eq!(
            policy.trusted_issuer(),
            "https://login.example.com/acme/v2.0"
        );
        assert_eq!(policy.issuer_tenant(), Some("acme"));
        assert_eq!(
            policy.jwks_uri(),
            "https://login.example.com/acme/discovery/keys"
        );
        assert!(policy.allows_algorithm(SigningAlgorithm::Rs256));
        assert!(policy.allows_algorithm(SigningAlgorithm::Es256));
        assert_eq!(policy.authenticated_client_id(), "mcp-client");
        assert_eq!(policy.assertion_client_id(), "enterprise-mcp-client");
        assert_eq!(policy.resources().len(), 1);
        assert_eq!(
            policy.resource("https://mcp.example.com").unwrap().scopes(),
            &["mcp:read".to_string(), "mcp:write".to_string()]
        );
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_policy_configuration() {
        let mut cases = Vec::new();

        let mut empty_policy_id = policy_config();
        empty_policy_id.policy_id.clear();
        cases.push(empty_policy_id);

        let mut insecure_issuer = policy_config();
        insecure_issuer.trusted_issuer = "http://login.example.com".into();
        cases.push(insecure_issuer);

        let mut invalid_issuer_tenant = policy_config();
        invalid_issuer_tenant.issuer_tenant = Some("acme\nother".into());
        cases.push(invalid_issuer_tenant);

        let mut insecure_jwks = policy_config();
        insecure_jwks.jwks_uri = "http://login.example.com/keys".into();
        cases.push(insecure_jwks);

        let mut unsafe_jwks = policy_config();
        unsafe_jwks.jwks_uri = "https://127.0.0.1/jwks".into();
        cases.push(unsafe_jwks);

        let mut empty_algorithm_set = policy_config();
        empty_algorithm_set.allowed_algorithms.clear();
        cases.push(empty_algorithm_set);

        let mut duplicate_algorithm = policy_config();
        duplicate_algorithm.allowed_algorithms =
            vec![SigningAlgorithm::Rs256, SigningAlgorithm::Rs256];
        cases.push(duplicate_algorithm);

        let mut empty_authenticated_client = policy_config();
        empty_authenticated_client.authenticated_client_id.clear();
        cases.push(empty_authenticated_client);

        let mut empty_assertion_client = policy_config();
        empty_assertion_client.assertion_client_id.clear();
        cases.push(empty_assertion_client);

        let mut empty_resources = policy_config();
        empty_resources.resources.clear();
        cases.push(empty_resources);

        let mut duplicate_resource = policy_config();
        duplicate_resource
            .resources
            .push(duplicate_resource.resources[0].clone());
        cases.push(duplicate_resource);

        let mut duplicate_scope = policy_config();
        duplicate_scope.resources[0].scopes.push("mcp:read".into());
        cases.push(duplicate_scope);

        let mut empty_scopes = policy_config();
        empty_scopes.resources[0].scopes.clear();
        cases.push(empty_scopes);

        let mut ambiguous_legacy_target = policy_config();
        ambiguous_legacy_target.allow_legacy_missing_resource = true;
        ambiguous_legacy_target
            .resources
            .push(ResourcePolicyConfig {
                resource: "https://other.example.com".into(),
                scopes: vec!["other:read".into()],
            });
        cases.push(ambiguous_legacy_target);

        for config in cases {
            assert!(
                EmaPolicy::try_from(config).is_err(),
                "invalid EMA policy must fail startup validation"
            );
        }
    }

    #[test]
    fn parses_bounded_id_jag_without_selecting_header_trust_inputs() {
        let token = compact(
            serde_json::json!({
                "alg": "ES256",
                "typ": "oauth-id-jag+jwt",
                "kid": "key-1",
                "jku": "https://attacker.example/jwks"
            }),
            serde_json::json!({
                "iss": "https://login.example.com/acme/v2.0",
                "tenant": "acme",
                "sub": "enterprise-user-1",
                "aud": ["https://auth.example.com"],
                "client_id": "enterprise-mcp-client",
                "exp": 1_300,
                "iat": 1_000,
                "nbf": 990,
                "jti": "grant-1",
                "scope": "mcp:read",
                "resource": ["https://mcp.example.com"],
                "cnf": {"jkt": "proof-thumbprint"}
            }),
        );

        let parsed = parse_compact_id_jag(&token).unwrap();
        assert_eq!(parsed.header().algorithm, SigningAlgorithm::Es256);
        assert_eq!(parsed.header().kid.as_deref(), Some("key-1"));
        assert_eq!(
            parsed.claims().issuer.as_deref(),
            Some("https://login.example.com/acme/v2.0")
        );
        assert_eq!(parsed.claims().tenant.as_deref(), Some("acme"));
        assert_eq!(
            parsed.claims().subject.as_deref(),
            Some("enterprise-user-1")
        );
        assert_eq!(parsed.signature(), &[7u8; 64]);
        assert_eq!(
            parsed.signing_input(),
            token.rsplit_once('.').unwrap().0.as_bytes()
        );
    }

    #[test]
    fn verifies_es256_with_exact_unique_kid() {
        let (token, key) = signed_es256(3, Some("key-1"), valid_claims());
        let (_, unrelated_key) = signed_es256(9, Some("key-2"), valid_claims());

        let verified =
            verify_parsed_id_jag(parse_compact_id_jag(&token).unwrap(), &[unrelated_key, key])
                .unwrap();

        assert_eq!(verified.header().kid.as_deref(), Some("key-1"));
        assert_eq!(
            verified.claims().subject.as_deref(),
            Some("enterprise-user-1")
        );
    }

    #[test]
    fn no_kid_requires_exactly_one_compatible_key() {
        let (token, key) = signed_es256(3, None, valid_claims());
        let (_, second_key) = signed_es256(9, Some("key-2"), valid_claims());
        let parsed = parse_compact_id_jag(&token).unwrap();

        assert!(verify_parsed_id_jag(parsed.clone(), std::slice::from_ref(&key)).is_ok());
        assert_eq!(
            verify_parsed_id_jag(parsed, &[key, second_key]),
            Err(IdJagVerificationError::AmbiguousKey)
        );
    }

    #[test]
    fn rejects_ambiguous_incompatible_and_bad_signature_keys() {
        let (token, key) = signed_es256(3, Some("key-1"), valid_claims());
        let (_, duplicate_kid) = signed_es256(9, Some("key-1"), valid_claims());
        let parsed = parse_compact_id_jag(&token).unwrap();

        assert_eq!(
            verify_parsed_id_jag(parsed.clone(), &[key.clone(), duplicate_kid.clone()]),
            Err(IdJagVerificationError::AmbiguousKey)
        );

        let incompatible = EmaJwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            crv: None,
            n: Some("AQAB".into()),
            e: Some("AQAB".into()),
            x: None,
            y: None,
            ..key.clone()
        };
        assert_eq!(
            verify_parsed_id_jag(parsed.clone(), &[incompatible]),
            Err(IdJagVerificationError::IncompatibleKey)
        );

        assert_eq!(
            verify_parsed_id_jag(parsed, &[duplicate_kid]),
            Err(IdJagVerificationError::BadSignature)
        );
    }

    #[test]
    fn verifies_rs256_with_exact_unique_kid() {
        let (token, key) = signed_rs256("rsa-key-1", valid_claims());
        let verified = verify_parsed_id_jag(parse_compact_id_jag(&token).unwrap(), &[key]).unwrap();

        assert_eq!(verified.header().algorithm, SigningAlgorithm::Rs256);
        assert_eq!(verified.header().kid.as_deref(), Some("rsa-key-1"));
    }

    #[test]
    fn derives_domain_separated_partitioned_replay_and_user_keys() {
        const SECRET: &[u8] = b"ema-derivation-test-secret";
        let replay = derive_replay_key(
            SECRET,
            "agent-tenant-1",
            "https://login.example.com/acme/v2.0",
            Some("acme"),
            "grant-1",
        );
        let user_id = derive_enterprise_user_id(
            SECRET,
            "agent-tenant-1",
            "https://login.example.com/acme/v2.0",
            Some("acme"),
            "enterprise-user-1",
        );

        assert_eq!(
            replay,
            "ema-replay:v1:NNLej1lv6Wjs6dmnnylVsriPLEADXWpuPOtitvLF0Wg"
        );
        assert_eq!(
            user_id,
            "user:ema:v1:e2azEpm9aXRy5lt2Pr0Ab2IXKaX1cO3vPLHj9nPKrtg"
        );
        assert_ne!(replay, user_id);
        assert_ne!(
            replay,
            derive_replay_key(
                SECRET,
                "agent-tenant-2",
                "https://login.example.com/acme/v2.0",
                Some("acme"),
                "grant-1",
            )
        );
        assert_ne!(
            replay,
            derive_replay_key(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/other/v2.0",
                Some("acme"),
                "grant-1",
            )
        );
        assert_ne!(
            replay,
            derive_replay_key(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/acme/v2.0",
                Some("other"),
                "grant-1",
            )
        );
        assert_ne!(
            replay,
            derive_replay_key(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/acme/v2.0",
                None,
                "grant-1",
            )
        );
        assert_ne!(
            user_id,
            derive_enterprise_user_id(
                SECRET,
                "agent-tenant-2",
                "https://login.example.com/acme/v2.0",
                Some("acme"),
                "enterprise-user-1",
            )
        );
        assert_ne!(
            user_id,
            derive_enterprise_user_id(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/other/v2.0",
                Some("acme"),
                "enterprise-user-1",
            )
        );
        assert_ne!(
            user_id,
            derive_enterprise_user_id(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/acme/v2.0",
                Some("other"),
                "enterprise-user-1",
            )
        );
        assert_ne!(
            user_id,
            derive_enterprise_user_id(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/acme/v2.0",
                None,
                "enterprise-user-1",
            )
        );
        assert_ne!(
            user_id,
            derive_enterprise_user_id(
                SECRET,
                "agent-tenant-1",
                "https://login.example.com/acme/v2.0",
                Some("acme"),
                "enterprise-user-2",
            )
        );
    }

    #[test]
    fn rejects_malformed_or_unprofiled_compact_assertions() {
        let valid_claims = serde_json::json!({
            "iss": "https://login.example.com",
            "sub": "user",
            "aud": "https://auth.example.com",
            "client_id": "client",
            "exp": 1_300,
            "iat": 1_000,
            "jti": "grant",
            "scope": "mcp:read"
        });
        let cases = [
            "only.two".to_string(),
            compact(
                serde_json::json!({"alg":"none","typ":"oauth-id-jag+jwt"}),
                valid_claims.clone(),
            ),
            compact(
                serde_json::json!({"alg":"ES256","typ":"JWT"}),
                valid_claims.clone(),
            ),
            compact(
                serde_json::json!({
                    "alg":"ES256",
                    "typ":"oauth-id-jag+jwt",
                    "crit":["unknown"]
                }),
                valid_claims.clone(),
            ),
            compact(
                serde_json::json!({"alg":"ES256","typ":"oauth-id-jag+jwt"}),
                serde_json::json!({"aud": 42}),
            ),
        ];

        for token in cases {
            assert!(parse_compact_id_jag(&token).is_err());
        }
    }

    #[test]
    fn authorizes_verified_id_jag_into_bounded_issuance_decision() {
        let policy = EmaPolicy::try_from(policy_config()).unwrap();
        let assertion = verified(valid_claims());
        let request = authorization_request();

        let decision = authorize_verified_id_jag(&policy, &assertion, &request).unwrap();
        assert_eq!(decision.policy_id, "entra-acme");
        assert_eq!(
            decision.trusted_issuer,
            "https://login.example.com/acme/v2.0"
        );
        assert_eq!(decision.issuer_tenant.as_deref(), Some("acme"));
        assert_eq!(decision.subject, "enterprise-user-1");
        assert_eq!(decision.authenticated_client_id, "mcp-client");
        assert_eq!(decision.resource, "https://mcp.example.com");
        assert_eq!(decision.scopes, vec!["mcp:read"]);
        assert_eq!(decision.jwt_id, "grant-1");
        assert_eq!(decision.replay_expires_at, 1_330);
        assert_eq!(decision.cnf_jkt.as_deref(), Some("proof-thumbprint"));
    }

    #[test]
    fn rejects_identity_client_algorithm_and_time_confusion() {
        let policy = EmaPolicy::try_from(policy_config()).unwrap();
        let request = authorization_request();
        let mut cases = Vec::new();

        let mut wrong_issuer = valid_claims();
        wrong_issuer["iss"] = serde_json::json!("https://attacker.example");
        cases.push((wrong_issuer, AuthorizationError::IssuerMismatch));

        let mut missing_tenant = valid_claims();
        missing_tenant.as_object_mut().unwrap().remove("tenant");
        cases.push((missing_tenant, AuthorizationError::IssuerTenantMismatch));

        let mut extra_audience = valid_claims();
        extra_audience["aud"] =
            serde_json::json!(["https://auth.example.com", "https://other.example"]);
        cases.push((extra_audience, AuthorizationError::AudienceMismatch));

        let mut wrong_client = valid_claims();
        wrong_client["client_id"] = serde_json::json!("other-client");
        cases.push((wrong_client, AuthorizationError::AssertionClientMismatch));

        let mut expired = valid_claims();
        expired["exp"] = serde_json::json!(1_070);
        cases.push((expired, AuthorizationError::InvalidTime));

        let mut future_iat = valid_claims();
        future_iat["iat"] = serde_json::json!(1_131);
        cases.push((future_iat, AuthorizationError::InvalidTime));

        let mut future_nbf = valid_claims();
        future_nbf["nbf"] = serde_json::json!(1_131);
        cases.push((future_nbf, AuthorizationError::InvalidTime));

        let mut overlong_lifetime = valid_claims();
        overlong_lifetime["exp"] = serde_json::json!(1_301);
        cases.push((overlong_lifetime, AuthorizationError::InvalidTime));

        let mut overflowing_lifetime = valid_claims();
        overflowing_lifetime["iat"] = serde_json::json!(i64::MIN);
        overflowing_lifetime["exp"] = serde_json::json!(i64::MAX);
        cases.push((overflowing_lifetime, AuthorizationError::InvalidTime));

        let mut wrong_audience_tenant = valid_claims();
        wrong_audience_tenant["aud_tenant"] = serde_json::json!("other-agent-tenant");
        cases.push((
            wrong_audience_tenant,
            AuthorizationError::AudienceTenantMismatch,
        ));

        let mut missing_subject = valid_claims();
        missing_subject.as_object_mut().unwrap().remove("sub");
        cases.push((missing_subject, AuthorizationError::MissingClaim("sub")));

        for (claims, expected) in cases {
            assert_eq!(
                authorize_verified_id_jag(&policy, &verified(claims), &request),
                Err(expected)
            );
        }

        let mut rs_only = policy_config();
        rs_only.allowed_algorithms = vec![SigningAlgorithm::Rs256];
        let rs_only = EmaPolicy::try_from(rs_only).unwrap();
        assert_eq!(
            authorize_verified_id_jag(&rs_only, &verified(valid_claims()), &request),
            Err(AuthorizationError::AlgorithmNotAllowed)
        );

        let mut no_issuer_tenant = policy_config();
        no_issuer_tenant.issuer_tenant = None;
        let no_issuer_tenant = EmaPolicy::try_from(no_issuer_tenant).unwrap();
        let mut claim_without_tenant = valid_claims();
        claim_without_tenant
            .as_object_mut()
            .unwrap()
            .remove("tenant");
        assert!(authorize_verified_id_jag(
            &no_issuer_tenant,
            &verified(claim_without_tenant),
            &request
        )
        .is_ok());
        assert_eq!(
            authorize_verified_id_jag(&no_issuer_tenant, &verified(valid_claims()), &request),
            Err(AuthorizationError::IssuerTenantMismatch)
        );
    }

    #[test]
    fn resource_and_scope_never_expand_the_enterprise_grant() {
        let policy = EmaPolicy::try_from(policy_config()).unwrap();
        let decision =
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &authorization_request())
                .unwrap();
        assert_eq!(decision.resource, "https://mcp.example.com");
        assert_eq!(decision.scopes, ["mcp:read"]);

        let mut malformed_target = authorization_request();
        malformed_target.resource = "not-a-uri";
        let error =
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &malformed_target)
                .unwrap_err();
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidTarget);

        let mut unknown_target = authorization_request();
        unknown_target.resource = "https://other.example.com";
        let error = authorize_verified_id_jag(&policy, &verified(valid_claims()), &unknown_target)
            .unwrap_err();
        assert_eq!(error, AuthorizationError::ResourceNotAllowed);
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidTarget);

        let mut missing_resource = valid_claims();
        missing_resource.as_object_mut().unwrap().remove("resource");
        let error = authorize_verified_id_jag(
            &policy,
            &verified(missing_resource.clone()),
            &authorization_request(),
        )
        .unwrap_err();
        assert_eq!(error, AuthorizationError::AssertionResourceMismatch);
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidGrant);

        let mut legacy = policy_config();
        legacy.allow_legacy_missing_resource = true;
        let legacy = EmaPolicy::try_from(legacy).unwrap();
        assert!(authorize_verified_id_jag(
            &legacy,
            &verified(missing_resource),
            &authorization_request()
        )
        .is_ok());

        let mut ambiguous_legacy = policy_config();
        ambiguous_legacy.allow_legacy_missing_resource = true;
        ambiguous_legacy.resources.push(ResourcePolicyConfig {
            resource: "https://other.example.com".into(),
            scopes: vec!["mcp:read".into()],
        });
        assert_eq!(
            EmaPolicy::try_from(ambiguous_legacy),
            Err(PolicyError::AmbiguousLegacyTarget)
        );

        let mut resource_array = valid_claims();
        resource_array["resource"] =
            serde_json::json!(["https://other.example.com", "https://mcp.example.com"]);
        let decision =
            authorize_verified_id_jag(&policy, &verified(resource_array), &authorization_request())
                .unwrap();
        assert_eq!(decision.resource, "https://mcp.example.com");
        assert_eq!(decision.scopes, ["mcp:read"]);

        for invalid_resource in [
            serde_json::json!([]),
            serde_json::json!(["https://mcp.example.com", "https://mcp.example.com"]),
            serde_json::json!(["http://mcp.example.com"]),
            serde_json::json!(["https://other.example.com"]),
        ] {
            let mut claims = valid_claims();
            claims["resource"] = invalid_resource;
            assert_eq!(
                authorize_verified_id_jag(&policy, &verified(claims), &authorization_request()),
                Err(AuthorizationError::AssertionResourceMismatch)
            );
        }

        let mut invalid_scope = authorization_request();
        invalid_scope.requested_scope = "mcp:read  mcp:write";
        let error = authorize_verified_id_jag(&policy, &verified(valid_claims()), &invalid_scope)
            .unwrap_err();
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidScope);

        let mut empty_scope = authorization_request();
        empty_scope.requested_scope = "";
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &empty_scope),
            Err(AuthorizationError::InvalidRequestedScope)
        );

        let mut duplicate_scope = authorization_request();
        duplicate_scope.requested_scope = "mcp:read mcp:read";
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &duplicate_scope),
            Err(AuthorizationError::InvalidRequestedScope)
        );

        for invalid_asserted_scope in ["", "mcp:read mcp:read", "mcp:read\nmcp:write"] {
            let mut claims = valid_claims();
            claims["scope"] = serde_json::json!(invalid_asserted_scope);
            assert_eq!(
                authorize_verified_id_jag(&policy, &verified(claims), &authorization_request()),
                Err(AuthorizationError::InvalidClaim("scope"))
            );
        }

        let mut beyond_assertion = valid_claims();
        beyond_assertion["scope"] = serde_json::json!("mcp:read");
        let mut write_request = authorization_request();
        write_request.requested_scope = "mcp:write";
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(beyond_assertion), &write_request),
            Err(AuthorizationError::ScopeExceedsAssertion)
        );

        let mut beyond_policy = valid_claims();
        beyond_policy["scope"] = serde_json::json!("mcp:read mcp:admin");
        let mut admin_request = authorization_request();
        admin_request.requested_scope = "mcp:admin";
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(beyond_policy), &admin_request),
            Err(AuthorizationError::ScopeExceedsPolicy)
        );
    }

    #[test]
    fn rejects_unsupported_authorization_semantics_and_binds_dpop() {
        let policy = EmaPolicy::try_from(policy_config()).unwrap();
        assert!(authorize_verified_id_jag(
            &policy,
            &verified(valid_claims()),
            &authorization_request()
        )
        .is_ok());

        let mut request_rar = authorization_request();
        request_rar.request_has_authorization_details = true;
        let error = authorize_verified_id_jag(&policy, &verified(valid_claims()), &request_rar)
            .unwrap_err();
        assert_eq!(
            error.oauth_error(),
            OAuthErrorCode::InvalidAuthorizationDetails
        );

        let mut empty_rar = valid_claims();
        empty_rar["authorization_details"] = serde_json::json!([]);
        assert!(
            authorize_verified_id_jag(&policy, &verified(empty_rar), &authorization_request())
                .is_ok()
        );

        let mut nonempty_rar = valid_claims();
        nonempty_rar["authorization_details"] = serde_json::json!([{"type":"account_information"}]);
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(nonempty_rar), &authorization_request()),
            Err(AuthorizationError::UnsupportedAuthorizationDetails)
        );

        for malformed in [
            serde_json::json!([null]),
            serde_json::json!([{}]),
            serde_json::json!([{"type":""}]),
            serde_json::json!([{"type":1}]),
        ] {
            let mut malformed_rar = valid_claims();
            malformed_rar["authorization_details"] = malformed;
            assert_eq!(
                authorize_verified_id_jag(
                    &policy,
                    &verified(malformed_rar),
                    &authorization_request()
                ),
                Err(AuthorizationError::InvalidClaim("authorization_details"))
            );
        }

        for malformed in [
            serde_json::json!({}),
            serde_json::json!("account_information"),
            serde_json::json!(42),
        ] {
            let mut malformed_rar = valid_claims();
            malformed_rar["authorization_details"] = malformed;
            assert_eq!(
                authorize_verified_id_jag(
                    &policy,
                    &verified(malformed_rar),
                    &authorization_request()
                ),
                Err(AuthorizationError::InvalidClaim("authorization_details"))
            );
        }

        let mut actor = valid_claims();
        actor["act"] = serde_json::json!({"sub":"delegating-agent"});
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(actor), &authorization_request()),
            Err(AuthorizationError::UnsupportedActor)
        );

        let mut missing_proof = authorization_request();
        missing_proof.presented_dpop_jkt = None;
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &missing_proof),
            Err(AuthorizationError::DpopBindingMismatch)
        );

        let mut wrong_proof = authorization_request();
        wrong_proof.presented_dpop_jkt = Some("other-thumbprint");
        assert_eq!(
            authorize_verified_id_jag(&policy, &verified(valid_claims()), &wrong_proof),
            Err(AuthorizationError::DpopBindingMismatch)
        );

        for malformed_cnf in [
            serde_json::json!("proof-thumbprint"),
            serde_json::json!({}),
            serde_json::json!({"jkt": ""}),
            serde_json::json!({"jkt": "proof-thumbprint", "extra": true}),
            serde_json::json!({"jkt": "proof\nthumbprint"}),
            serde_json::json!({"jkt": "x".repeat(257)}),
        ] {
            let mut claims = valid_claims();
            claims["cnf"] = malformed_cnf;
            assert_eq!(
                authorize_verified_id_jag(&policy, &verified(claims), &authorization_request()),
                Err(AuthorizationError::InvalidClaim("cnf"))
            );
        }

        let mut bearer_claims = valid_claims();
        bearer_claims.as_object_mut().unwrap().remove("cnf");
        let decision =
            authorize_verified_id_jag(&policy, &verified(bearer_claims), &authorization_request())
                .unwrap();
        assert_eq!(decision.cnf_jkt.as_deref(), Some("proof-thumbprint"));

        let mut proof_free_claims = valid_claims();
        proof_free_claims.as_object_mut().unwrap().remove("cnf");
        let mut proof_free_request = authorization_request();
        proof_free_request.presented_dpop_jkt = None;
        let decision =
            authorize_verified_id_jag(&policy, &verified(proof_free_claims), &proof_free_request)
                .unwrap();
        assert!(decision.cnf_jkt.is_none());
    }
}
