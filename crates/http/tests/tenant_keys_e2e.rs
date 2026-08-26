use std::{collections::BTreeMap, sync::Arc};

use agent_auth_http::{
    adapters::memory::MemorySigner,
    build_router,
    ports::Signer,
    security_event::{
        SecurityActor, SecurityEvent, SecurityEventCategory, SecurityEventCorrelation,
        SecurityEventOutcome, SecuritySubject,
    },
    ssf::{project_security_event, sign_projected_set, SetSigningContext},
    state::{AppState, SignerImpl},
    tenant_keys::{TenantKeyRegistry, TenantKeyRegistryImpl, TenantKeyService},
};
use agent_auth_infra_core::{
    EcPublicJwk, RsaPublicJwk, TenantKeyAlgorithm, TenantKeyLifecycle, TenantKeyRecord,
    TenantKeyStateError,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn memory_registry(
    service: &TenantKeyService,
) -> &agent_auth_http::tenant_keys::MemoryTenantKeyRegistry {
    #[cfg(not(feature = "aws"))]
    {
        let TenantKeyRegistryImpl::Memory(registry) = service.registry();
        registry
    }
    #[cfg(feature = "aws")]
    {
        match service.registry() {
            TenantKeyRegistryImpl::Memory(registry) => registry,
            TenantKeyRegistryImpl::Dynamo(_) => panic!("expected memory registry"),
        }
    }
}

async fn install_ready(service: &TenantKeyService, tenant: &str, seed: u8) {
    let signer = MemorySigner::from_seed([seed; 32]);
    let ec = signer.public_jwks().await.unwrap().remove(0);
    let rsa = signer.public_rsa_jwks().await.unwrap().remove(0);
    let operation = format!("onboard-{tenant}");
    let mut record = TenantKeyRecord::begin_onboarding(tenant, &operation, 1).unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Es256,
            format!("arn:{tenant}:ec"),
            2,
        )
        .unwrap();
    record
        .record_verified_ec(
            &operation,
            EcPublicJwk {
                x: ec.x,
                y: ec.y,
                kid: ec.kid,
            },
            3,
        )
        .unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Rs256,
            format!("arn:{tenant}:rsa"),
            4,
        )
        .unwrap();
    record
        .record_verified_rsa(
            &operation,
            RsaPublicJwk {
                n: rsa.n,
                e: rsa.e,
                kid: rsa.kid,
            },
            5,
        )
        .unwrap();
    record.publish_candidate(&operation, 6).unwrap();
    assert!(memory_registry(service).create(record).await.unwrap());
    service
        .install_memory_signer(&format!("arn:{tenant}:ec"), signer)
        .await;
}

async fn get(router: &axum::Router, host: &str, path: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn publish_rotation_candidate(service: &TenantKeyService, tenant: &str, seed: u8) {
    let signer = MemorySigner::from_seed([seed; 32]);
    let ec = signer.public_jwks().await.unwrap().remove(0);
    let rsa = signer.public_rsa_jwks().await.unwrap().remove(0);
    let operation = format!("rotate-{tenant}");
    let registry = memory_registry(service);
    let mut record = registry.get(tenant).await.unwrap().unwrap();
    let expected_revision = record.revision;
    record.begin_rotation(&operation, 10).unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Es256,
            format!("arn:{tenant}:ec:2"),
            11,
        )
        .unwrap();
    record
        .record_verified_ec(
            &operation,
            EcPublicJwk {
                x: ec.x,
                y: ec.y,
                kid: ec.kid,
            },
            12,
        )
        .unwrap();
    record
        .record_created_key(
            &operation,
            TenantKeyAlgorithm::Rs256,
            format!("arn:{tenant}:rsa:2"),
            13,
        )
        .unwrap();
    record
        .record_verified_rsa(
            &operation,
            RsaPublicJwk {
                n: rsa.n,
                e: rsa.e,
                kid: rsa.kid,
            },
            14,
        )
        .unwrap();
    record.publish_candidate(&operation, 15).unwrap();
    assert!(registry
        .compare_and_swap(expected_revision, record)
        .await
        .unwrap());
    service
        .install_memory_signer(&format!("arn:{tenant}:ec:2"), signer)
        .await;
}

async fn activate_rotation_candidate(service: &TenantKeyService, tenant: &str) {
    let operation = format!("rotate-{tenant}");
    let registry = memory_registry(service);
    let mut record = registry.get(tenant).await.unwrap().unwrap();
    let expected_revision = record.revision;
    record.activate_candidate(&operation, 1_000, 2_000).unwrap();
    assert!(registry
        .compare_and_swap(expected_revision, record)
        .await
        .unwrap());
}

async fn compact_es256_jws(signer: &SignerImpl, subject: &str) -> String {
    let kid = signer.active_kid().await.unwrap();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "ES256",
            "kid": kid,
            "typ": "at+jwt",
        }))
        .unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "sub": subject,
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = signer.sign_es256(signing_input.as_bytes()).await.unwrap();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn compact_rs256_jws(signer: &SignerImpl, subject: &str) -> String {
    let active_kid = signer.active_rsa_kid().await.unwrap();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "RS256",
            "kid": active_kid,
            "typ": "JWT",
        }))
        .unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "sub": subject,
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{payload}");
    let (signing_kid, signature) = signer.sign_rs256(signing_input.as_bytes()).await.unwrap();
    assert_eq!(signing_kid, active_kid);
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn compact_security_event_token(
    signer: &SignerImpl,
    tenant: &str,
    event_id: &str,
    issued_at: i64,
) -> String {
    let issuer = format!("https://{tenant}.aws.example.com");
    let event = SecurityEvent::new_at(
        event_id,
        issued_at - 1,
        tenant,
        SecurityActor::admin("admin:rotation"),
        Some(SecuritySubject::user("user:rotation")),
        SecurityEventCategory::UserLifecycle,
        "user.disable",
        SecurityEventOutcome::Success,
        SecurityEventCorrelation::default(),
    )
    .unwrap();
    let projection = project_security_event(&event, &issuer).unwrap();
    sign_projected_set(
        signer,
        &event,
        &projection,
        &SetSigningContext {
            issuer: &issuer,
            audience: "https://receiver.example.net/events",
            stream_id: "stream_rotation",
            stream_revision: u64::try_from(issued_at).unwrap(),
            issued_at,
        },
    )
    .await
    .unwrap()
    .compact_jws
}

fn jwk_map(jwks: &Value) -> BTreeMap<String, Value> {
    jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (key["kid"].as_str().unwrap().to_string(), key.clone()))
        .collect()
}

fn independent_thumbprint(key: &Value) -> String {
    let canonical = match key["kty"].as_str().unwrap() {
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            key["crv"].as_str().unwrap(),
            key["x"].as_str().unwrap(),
            key["y"].as_str().unwrap()
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            key["e"].as_str().unwrap(),
            key["n"].as_str().unwrap()
        ),
        other => panic!("unexpected signing key type {other}"),
    };
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn verifies_with_key(compact: &str, key: &Value) -> bool {
    let parts: Vec<&str> = compact.split('.').collect();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    match (
        token_header(compact)["alg"].as_str().unwrap(),
        key["kty"].as_str().unwrap(),
    ) {
        ("ES256", "EC") => {
            use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};

            let x = URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap();
            let y = URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap();
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
            let signature = Signature::from_slice(&signature).unwrap();
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok()
        }
        ("RS256", "RSA") => {
            use rsa::signature::Verifier as _;

            let n = rsa::BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD.decode(key["n"].as_str().unwrap()).unwrap(),
            );
            let e = rsa::BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD.decode(key["e"].as_str().unwrap()).unwrap(),
            );
            let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
            let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok()
        }
        _ => false,
    }
}

fn token_header(compact: &str) -> Value {
    let header = URL_SAFE_NO_PAD
        .decode(compact.split('.').next().unwrap())
        .unwrap();
    serde_json::from_slice(&header).unwrap()
}

fn token_kid(compact: &str) -> String {
    token_header(compact)["kid"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn saas_admission_and_jwks_require_complete_tenant_pairs() {
    let service = Arc::new(TenantKeyService::memory());
    let mut provisioning =
        TenantKeyRecord::begin_onboarding("provisioning", "onboard-provisioning", 1).unwrap();
    provisioning
        .record_created_key(
            "onboard-provisioning",
            TenantKeyAlgorithm::Es256,
            "arn:provisioning:ec",
            2,
        )
        .unwrap();
    assert!(memory_registry(&service)
        .create(provisioning)
        .await
        .unwrap());

    let mut failed = TenantKeyRecord::begin_onboarding("failed", "onboard-failed", 1).unwrap();
    failed
        .fail_operation("onboard-failed", "injected", 2)
        .unwrap();
    assert!(memory_registry(&service).create(failed).await.unwrap());

    install_ready(&service, "t1", 41).await;
    install_ready(&service, "t2", 42).await;

    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec![
        "t1".to_string(),
        "t2".to_string(),
        "empty".to_string(),
        "provisioning".to_string(),
        "failed".to_string(),
    ]);
    state.signer = Arc::new(SignerImpl::Unavailable);
    state.tenant_keys = service;
    let (router, _) = build_router(state);

    assert_eq!(
        get(&router, "unknown.aws.example.com", "/jwks.json")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for tenant in ["empty", "provisioning", "failed"] {
        assert_eq!(
            get(&router, &format!("{tenant}.aws.example.com"), "/jwks.json")
                .await
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    let (t1_status, t1) = get(&router, "t1.aws.example.com", "/jwks.json").await;
    let (t2_status, t2) = get(&router, "t2.aws.example.com", "/jwks.json").await;
    assert_eq!(t1_status, StatusCode::OK);
    assert_eq!(t2_status, StatusCode::OK);
    assert_eq!(t1["keys"].as_array().unwrap().len(), 2);
    assert_eq!(t2["keys"].as_array().unwrap().len(), 2);
    for jwks in [&t1, &t2] {
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(
            keys.iter()
                .filter(|key| key["kty"] == "EC" && key["alg"] == "ES256")
                .count(),
            1
        );
        assert_eq!(
            keys.iter()
                .filter(|key| key["kty"] == "RSA" && key["alg"] == "RS256")
                .count(),
            1
        );
    }
    let t1_kids: std::collections::HashSet<&str> = t1["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|key| key["kid"].as_str())
        .collect();
    let t2_kids: std::collections::HashSet<&str> = t2["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|key| key["kid"].as_str())
        .collect();
    assert!(t1_kids.is_disjoint(&t2_kids));
}

#[tokio::test]
async fn rotation_overlap_jwks_verifies_old_and_new_tokens_by_thumbprint_kid() {
    const TENANT: &str = "rotation";
    const HOST: &str = "rotation.aws.example.com";

    let service = Arc::new(TenantKeyService::memory());
    install_ready(&service, TENANT, 51).await;
    let ready = memory_registry(&service)
        .get(TENANT)
        .await
        .unwrap()
        .unwrap();
    let ready_snapshot = ready.ready_snapshot().unwrap();
    let old_ec_kid = ready_snapshot.ec.active.public_jwk.kid.clone();
    let old_rsa_kid = ready_snapshot.rsa.active.public_jwk.kid.clone();
    publish_rotation_candidate(&service, TENANT, 52).await;
    let publishing = memory_registry(&service)
        .get(TENANT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publishing.lifecycle, TenantKeyLifecycle::Publishing);
    let publishing_snapshot = publishing.ready_snapshot().unwrap();
    assert_eq!(publishing_snapshot.ec.active.public_jwk.kid, old_ec_kid);
    assert_eq!(publishing_snapshot.rsa.active.public_jwk.kid, old_rsa_kid);
    let new_ec_kid = publishing_snapshot
        .ec
        .published
        .iter()
        .find(|key| key.public_jwk.kid != old_ec_kid)
        .unwrap()
        .public_jwk
        .kid
        .clone();
    let new_rsa_kid = publishing_snapshot
        .rsa
        .published
        .iter()
        .find(|key| key.public_jwk.kid != old_rsa_kid)
        .unwrap()
        .public_jwk
        .kid
        .clone();

    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec![TENANT.to_string()]);
    state.signer = Arc::new(SignerImpl::Unavailable);
    state.tenant_keys = service.clone();
    let (router, _) = build_router(state);

    let old_signer = service.resolve(TENANT).await.unwrap();
    let old_ec_token = compact_es256_jws(old_signer.as_ref(), "old-ec-generation").await;
    let old_rsa_token = compact_rs256_jws(old_signer.as_ref(), "old-rsa-generation").await;
    let old_set =
        compact_security_event_token(old_signer.as_ref(), TENANT, "evt_old_rotation", 900).await;
    let (publishing_status, publishing_jwks) = get(&router, HOST, "/jwks.json").await;
    assert_eq!(publishing_status, StatusCode::OK);

    activate_rotation_candidate(&service, TENANT).await;
    let overlap = memory_registry(&service)
        .get(TENANT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(overlap.lifecycle, TenantKeyLifecycle::ActiveOverlap);
    let overlap_snapshot = overlap.ready_snapshot().unwrap();
    assert_eq!(overlap_snapshot.ec.active.public_jwk.kid, new_ec_kid);
    assert_eq!(overlap_snapshot.rsa.active.public_jwk.kid, new_rsa_kid);
    let new_signer = service.resolve(TENANT).await.unwrap();
    let new_ec_token = compact_es256_jws(new_signer.as_ref(), "new-ec-generation").await;
    let new_rsa_token = compact_rs256_jws(new_signer.as_ref(), "new-rsa-generation").await;
    let new_set =
        compact_security_event_token(new_signer.as_ref(), TENANT, "evt_new_rotation", 1_001).await;
    let (overlap_status, overlap_jwks) = get(&router, HOST, "/jwks.json").await;
    assert_eq!(overlap_status, StatusCode::OK);

    let publishing_keys = jwk_map(&publishing_jwks);
    let overlap_keys = jwk_map(&overlap_jwks);
    assert_eq!(publishing_keys.len(), 4);
    assert_eq!(publishing_keys, overlap_keys);
    assert_eq!(
        publishing_keys
            .values()
            .filter(|key| key["kty"] == "EC")
            .count(),
        2
    );
    assert_eq!(
        publishing_keys
            .values()
            .filter(|key| key["kty"] == "RSA")
            .count(),
        2
    );

    assert_eq!(token_kid(&old_ec_token), old_ec_kid);
    assert_eq!(token_kid(&old_rsa_token), old_rsa_kid);
    assert_eq!(token_kid(&new_ec_token), new_ec_kid);
    assert_eq!(token_kid(&new_rsa_token), new_rsa_kid);
    assert_eq!(token_kid(&old_set), old_ec_kid);
    assert_eq!(token_kid(&new_set), new_ec_kid);
    assert_eq!(token_header(&old_set)["typ"], "secevent+jwt");
    assert_eq!(token_header(&new_set)["typ"], "secevent+jwt");

    for keys in [&publishing_keys, &overlap_keys] {
        for key in keys.values() {
            assert_eq!(key["kid"].as_str().unwrap(), independent_thumbprint(key));
        }
        for token in [
            &old_ec_token,
            &old_rsa_token,
            &old_set,
            &new_ec_token,
            &new_rsa_token,
            &new_set,
        ] {
            let kid = token_kid(token);
            assert!(verifies_with_key(token, keys.get(&kid).unwrap()));
        }
        assert!(!verifies_with_key(
            &old_ec_token,
            keys.get(&new_ec_kid).unwrap()
        ));
        assert!(!verifies_with_key(
            &new_ec_token,
            keys.get(&old_ec_kid).unwrap()
        ));
        assert!(!verifies_with_key(
            &old_rsa_token,
            keys.get(&new_rsa_kid).unwrap()
        ));
        assert!(!verifies_with_key(
            &new_rsa_token,
            keys.get(&old_rsa_kid).unwrap()
        ));
    }

    let registry = memory_registry(&service);
    let mut retiring = registry.get(TENANT).await.unwrap().unwrap();
    let expected_revision = retiring.revision;
    assert_eq!(
        retiring.retire("rotate-rotation", 1_999),
        Err(TenantKeyStateError::OverlapNotElapsed)
    );
    retiring.retire("rotate-rotation", 2_000).unwrap();
    assert!(registry
        .compare_and_swap(expected_revision, retiring)
        .await
        .unwrap());

    let (retired_status, retired_jwks) = get(&router, HOST, "/jwks.json").await;
    assert_eq!(retired_status, StatusCode::OK);
    let retired_keys = jwk_map(&retired_jwks);
    assert_eq!(retired_keys.len(), 2);
    assert!(retired_keys.contains_key(&new_ec_kid));
    assert!(retired_keys.contains_key(&new_rsa_kid));
    assert!(!retired_keys.contains_key(&old_ec_kid));
    assert!(!retired_keys.contains_key(&old_rsa_kid));
    for token in [&new_ec_token, &new_rsa_token, &new_set] {
        assert!(verifies_with_key(
            token,
            retired_keys.get(&token_kid(token)).unwrap()
        ));
    }
    for token in [&old_ec_token, &old_rsa_token, &old_set] {
        assert!(retired_keys
            .values()
            .all(|key| !verifies_with_key(token, key)));
    }
}

#[tokio::test]
async fn emergency_revoke_zero_overlap_immediately_removes_old_pair_from_public_jwks() {
    const TENANT: &str = "emergency";
    const HOST: &str = "emergency.aws.example.com";
    const OPERATION: &str = "rotate-emergency";

    let service = Arc::new(TenantKeyService::memory());
    install_ready(&service, TENANT, 61).await;
    publish_rotation_candidate(&service, TENANT, 62).await;

    let old_signer = service.resolve(TENANT).await.unwrap();
    let old_ec_token = compact_es256_jws(old_signer.as_ref(), "old-ec-generation").await;
    let old_rsa_token = compact_rs256_jws(old_signer.as_ref(), "old-rsa-generation").await;
    let old_set =
        compact_security_event_token(old_signer.as_ref(), TENANT, "evt_old_emergency", 900).await;
    let old_ec_kid = token_kid(&old_ec_token);
    let old_rsa_kid = token_kid(&old_rsa_token);

    let registry = memory_registry(&service);
    let mut record = registry.get(TENANT).await.unwrap().unwrap();
    assert_eq!(record.lifecycle, TenantKeyLifecycle::Publishing);
    let expected_revision = record.revision;
    record.emergency_revoke(OPERATION, 16).unwrap();
    assert!(registry
        .compare_and_swap(expected_revision, record)
        .await
        .unwrap());

    let emergency = registry.get(TENANT).await.unwrap().unwrap();
    assert_eq!(emergency.lifecycle, TenantKeyLifecycle::Ready);
    assert_eq!(
        emergency.last_emergency_revoke_operation_id.as_deref(),
        Some(OPERATION)
    );
    assert_eq!(emergency.last_completed_outcome, None);
    assert_eq!(
        emergency.last_completed_operation_id.as_deref(),
        Some(OPERATION)
    );
    assert!(emergency.operation.is_none());
    assert_eq!(emergency.ready_snapshot().unwrap().ec.published.len(), 1);
    assert_eq!(emergency.ready_snapshot().unwrap().rsa.published.len(), 1);

    let mut state = AppState::dev("localhost");
    state.form = agent_auth_discovery::Form::Saas {
        zone: "aws.example.com".to_string(),
        control_host: "c.aws.example.com".to_string(),
    };
    state.tenant_partitioning = true;
    state.saas_tenants = Arc::new(vec![TENANT.to_string()]);
    state.signer = Arc::new(SignerImpl::Unavailable);
    state.tenant_keys = service.clone();
    let (router, _) = build_router(state);

    let new_signer = service.resolve(TENANT).await.unwrap();
    let new_ec_token = compact_es256_jws(new_signer.as_ref(), "new-ec-generation").await;
    let new_rsa_token = compact_rs256_jws(new_signer.as_ref(), "new-rsa-generation").await;
    let new_set =
        compact_security_event_token(new_signer.as_ref(), TENANT, "evt_new_emergency", 901).await;
    let (status, jwks) = get(&router, HOST, "/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    let keys = jwk_map(&jwks);
    assert_eq!(keys.len(), 2);
    assert!(!keys.contains_key(&old_ec_kid));
    assert!(!keys.contains_key(&old_rsa_kid));

    for token in [&new_ec_token, &new_rsa_token, &new_set] {
        assert!(verifies_with_key(
            token,
            keys.get(&token_kid(token)).unwrap()
        ));
    }
    for token in [&old_ec_token, &old_rsa_token, &old_set] {
        assert!(keys.values().all(|key| !verifies_with_key(token, key)));
    }
}
