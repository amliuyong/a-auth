#![cfg(feature = "postgres")]

use agent_auth_http::{
    adapters::mounted_signer::MountedSignerRing,
    ports::{Signer, SignerError},
    state::SignerImpl,
    tenant_keys::{
        TenantKeyCommand, TenantKeyCommandAction, TenantKeyCommandSink, TenantKeyRegistry,
        TenantKeyService,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Verifier as _, Signature, SigningKey, VerifyingKey},
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

struct Fixture {
    root: PathBuf,
}

fn rsa_keys() -> &'static [rsa::RsaPrivateKey; 2] {
    static KEYS: OnceLock<[rsa::RsaPrivateKey; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap(),
            rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap(),
        ]
    })
}

fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "a-auth-mounted-signer-{:032x}",
        rand::random::<u128>()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (id, scalar) in [("old", 37), ("new", 38)] {
        let ec = SigningKey::from_bytes(&[scalar; 32].into()).unwrap();
        std::fs::write(
            root.join(format!("{id}.ec.private.pem")),
            ec.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            root.join(format!("{id}.ec.public.pem")),
            ec.verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        let rsa = &rsa_keys()[usize::from(id == "new")];
        std::fs::write(
            root.join(format!("{id}.rsa.private.pem")),
            rsa.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(
            root.join(format!("{id}.rsa.public.pem")),
            rsa::RsaPublicKey::from(rsa)
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        for name in [
            format!("{id}.ec.private.pem"),
            format!("{id}.rsa.private.pem"),
        ] {
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        for name in [
            format!("{id}.ec.public.pem"),
            format!("{id}.rsa.public.pem"),
        ] {
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
    }
    Fixture { root }
}

fn manifest(root: &Path, generation: u64, active: &str, published: &[&str]) {
    let value = serde_json::json!({
        "schema": 1, "generation": generation,
        "es256_key": format!("{active}.ec.private.pem"),
        "rs256_key": format!("{active}.rsa.private.pem"),
        "ec_public_keys": published.iter().map(|id| format!("{id}.ec.public.pem")).collect::<Vec<_>>(),
        "rsa_public_keys": published.iter().map(|id| format!("{id}.rsa.public.pem")).collect::<Vec<_>>(),
    });
    std::fs::write(root.join("keys.json"), serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::set_permissions(
        root.join("keys.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

fn verify_ec(
    public: &[agent_auth_infra_core::EcJwk],
    kid: &str,
    input: &[u8],
    signature: &[u8],
) -> bool {
    let Some(jwk) = public.iter().find(|key| key.kid == kid) else {
        return false;
    };
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(&jwk.x).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap());
    VerifyingKey::from_sec1_bytes(&point)
        .unwrap()
        .verify(input, &Signature::from_slice(signature).unwrap())
        .is_ok()
}

fn verify_rsa(
    public: &[agent_auth_infra_core::RsaJwk],
    kid: &str,
    input: &[u8],
    signature: &[u8],
) -> bool {
    let Some(jwk) = public.iter().find(|key| key.kid == kid) else {
        return false;
    };
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.n).unwrap()),
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.e).unwrap()),
    )
    .unwrap();
    rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
        .verify(
            input,
            &rsa::pkcs1v15::Signature::try_from(signature).unwrap(),
        )
        .is_ok()
}

async fn independently_verify(signer: &impl Signer, input: &[u8]) -> (String, String) {
    let ec_kid = signer.active_kid().await.unwrap();
    let ec_signature = signer.sign_es256(input).await.unwrap();
    assert!(verify_ec(
        &signer.public_jwks().await.unwrap(),
        &ec_kid,
        input,
        &ec_signature,
    ));
    let rsa_kid = signer.active_rsa_kid().await.unwrap();
    let (actual_kid, signature) = signer.sign_rs256(input).await.unwrap();
    assert_eq!(actual_kid, rsa_kid);
    assert!(verify_rsa(
        &signer.public_rsa_jwks().await.unwrap(),
        &rsa_kid,
        input,
        &signature,
    ));
    (ec_kid, rsa_kid)
}

#[tokio::test]
async fn mounted_signer_rotates_complete_immutable_ec_rsa_snapshots() {
    let fixture = fixture();
    manifest(&fixture.root, 1, "old", &["old"]);
    let ring = MountedSignerRing::load(&fixture.root, "keys.json")
        .await
        .unwrap();
    let original = ring.snapshot().await.unwrap();
    assert_eq!(original.generation(), 1);
    let old = independently_verify(&original, b"header.old-payload").await;
    let old_input = b"header.old-token";
    let old_ec_signature = original.sign_es256(old_input).await.unwrap();
    let (_, old_rsa_signature) = original.sign_rs256(old_input).await.unwrap();
    assert!(!ring.reload().await.unwrap());

    manifest(&fixture.root, 2, "old", &["old", "new"]);
    assert!(ring.reload().await.unwrap());
    let overlap = ring.snapshot().await.unwrap();
    assert_eq!(overlap.public_jwks().await.unwrap().len(), 2);
    assert_eq!(overlap.public_rsa_jwks().await.unwrap().len(), 2);
    assert_eq!(
        independently_verify(&overlap, b"header.overlap-payload").await,
        old
    );
    manifest(&fixture.root, 3, "new", &["old", "new"]);
    assert!(ring.reload().await.unwrap());
    let active = ring.snapshot().await.unwrap();
    let new = independently_verify(&active, b"header.new-payload").await;
    assert_ne!(new.0, old.0);
    assert_ne!(new.1, old.1);
    assert!(verify_ec(
        &active.public_jwks().await.unwrap(),
        &old.0,
        old_input,
        &old_ec_signature,
    ));
    assert!(verify_rsa(
        &active.public_rsa_jwks().await.unwrap(),
        &old.1,
        old_input,
        &old_rsa_signature,
    ));
    assert!(!verify_ec(
        &active.public_jwks().await.unwrap(),
        &old.0,
        b"header.changed-token",
        &old_ec_signature,
    ));
    assert!(!verify_rsa(
        &active.public_rsa_jwks().await.unwrap(),
        &old.1,
        b"header.changed-token",
        &old_rsa_signature,
    ));
    // A request captured before activation retains one coherent key pair.
    assert_eq!(
        independently_verify(&original, b"header.captured-payload").await,
        old
    );
    manifest(&fixture.root, 4, "new", &["new"]);
    assert!(ring.reload().await.unwrap());
    let retired = ring.snapshot().await.unwrap();
    assert!(!verify_ec(
        &retired.public_jwks().await.unwrap(),
        &old.0,
        old_input,
        &old_ec_signature,
    ));
    assert!(!verify_rsa(
        &retired.public_rsa_jwks().await.unwrap(),
        &old.1,
        old_input,
        &old_rsa_signature,
    ));
    assert_eq!(
        independently_verify(&retired, b"header.retired-payload").await,
        new
    );
    assert!(!retired
        .public_jwks()
        .await
        .unwrap()
        .iter()
        .any(|key| key.kid == old.0));
    assert!(!retired
        .public_rsa_jwks()
        .await
        .unwrap()
        .iter()
        .any(|key| key.kid == old.1));
    std::fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn mounted_signer_rejects_unsafe_files_and_partial_reload_without_losing_authority() {
    let outside = fixture();
    let fixture = fixture();
    manifest(&fixture.root, 1, "old", &["old"]);
    let ring = MountedSignerRing::load(&fixture.root, "keys.json")
        .await
        .unwrap();
    let old = independently_verify(&ring.snapshot().await.unwrap(), b"header.initial").await;
    std::os::unix::fs::symlink(
        outside.root.join("old.ec.private.pem"),
        fixture.root.join("escape.pem"),
    )
    .unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(fixture.root.join("pipe.pem"))
        .status()
        .unwrap()
        .success());
    std::fs::create_dir(fixture.root.join("unsafe")).unwrap();
    std::fs::set_permissions(
        fixture.root.join("unsafe"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::copy(
        fixture.root.join("old.ec.private.pem"),
        fixture.root.join("unsafe/key.pem"),
    )
    .unwrap();
    std::fs::set_permissions(
        fixture.root.join("unsafe/key.pem"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        fixture.root.join("old.ec.private.pem"),
        fixture.root.join("unsafe/link.pem"),
    )
    .unwrap();
    for case in [
        "unknown_manifest_field",
        "duplicate_public_key",
        "unpublished_private_key",
        "relative_escape",
        "symlink_escape",
        "world_readable_private_key",
        "group_writable_manifest",
        "partial_manifest",
        "writable_root",
        "named_pipe",
        "writable_parent",
        "writable_symlink_parent",
    ] {
        manifest(&fixture.root, 2, "old", &["old", "new"]);
        let path = fixture.root.join("keys.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match case {
            "unknown_manifest_field" => value["unexpected"] = true.into(),
            "duplicate_public_key" => {
                value["ec_public_keys"] =
                    serde_json::json!(["old.ec.public.pem", "old.ec.public.pem"])
            }
            "unpublished_private_key" => {
                value["es256_key"] = "new.ec.private.pem".into();
                value["ec_public_keys"] = serde_json::json!(["old.ec.public.pem"]);
            }
            "relative_escape" => value["es256_key"] = "../old.ec.private.pem".into(),
            "symlink_escape" => value["es256_key"] = "escape.pem".into(),
            "named_pipe" => value["es256_key"] = "pipe.pem".into(),
            "writable_parent" => value["es256_key"] = "unsafe/key.pem".into(),
            "writable_symlink_parent" => value["es256_key"] = "unsafe/link.pem".into(),
            _ => {}
        }
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        match case {
            "world_readable_private_key" => std::fs::set_permissions(
                fixture.root.join("old.ec.private.pem"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            "group_writable_manifest" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap()
            }
            "partial_manifest" => std::fs::write(&path, b"{\"schema\":1,").unwrap(),
            "writable_root" => {
                std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o777))
                    .unwrap()
            }
            _ => {}
        }
        assert!(
            matches!(ring.reload().await, Err(SignerError::Permanent(_))),
            "{case}"
        );
        let snapshot = ring.snapshot().await.unwrap();
        assert_eq!(snapshot.generation(), 1, "{case}");
        assert_eq!(
            independently_verify(&snapshot, b"header.retained").await,
            old
        );
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            fixture.root.join("old.ec.private.pem"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    manifest(&fixture.root, 2, "old", &["old", "new"]);
    assert!(ring.reload().await.unwrap());
    let oversized = vec![0; 256 * 1024 + 1];
    let snapshot = ring.snapshot().await.unwrap();
    assert!(matches!(
        snapshot.sign_es256(&oversized).await,
        Err(SignerError::Permanent(_))
    ));
    assert!(matches!(
        snapshot.sign_rs256(&oversized).await,
        Err(SignerError::Permanent(_))
    ));
    std::fs::remove_dir_all(fixture.root).unwrap();
    std::fs::remove_dir_all(outside.root).unwrap();
}

#[tokio::test]
async fn mounted_signer_rejects_rebound_generation_and_unpublished_activation() {
    let fixture = fixture();
    manifest(&fixture.root, 1, "old", &["old"]);
    let ring = MountedSignerRing::load(&fixture.root, "keys.json")
        .await
        .unwrap();
    let old = independently_verify(&ring.snapshot().await.unwrap(), b"header.initial").await;
    for (generation, active, published) in [
        (1, "new", vec!["old", "new"]),
        (0, "old", vec!["old"]),
        (2, "new", vec!["new"]),
    ] {
        manifest(&fixture.root, generation, active, &published);
        assert!(matches!(
            ring.reload().await,
            Err(SignerError::Permanent(_))
        ));
        assert_eq!(
            independently_verify(&ring.snapshot().await.unwrap(), b"header.retained").await,
            old
        );
    }
    std::fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn mounted_tenant_service_resolves_each_request_without_a_memory_registry() {
    let fixture = fixture();
    manifest(&fixture.root, 1, "old", &["old"]);
    let ring = MountedSignerRing::load(&fixture.root, "keys.json")
        .await
        .unwrap();
    let service = TenantKeyService::mounted(ring.clone());
    assert!(service.registry().get("default").await.is_err());
    assert!(service
        .command_sink()
        .send(TenantKeyCommand {
            tenant_id: "default".into(),
            action: TenantKeyCommandAction::Ensure,
            operation_id: "disabled-saas-command".into(),
            requested_at: 100,
            governance_dispatch: None,
        })
        .await
        .is_err());
    let captured = service.resolve("default").await.unwrap();
    assert!(matches!(&*captured, SignerImpl::Mounted(_)));
    let old = independently_verify(&*captured, b"header.captured").await;
    manifest(&fixture.root, 2, "old", &["old", "new"]);
    ring.reload().await.unwrap();
    manifest(&fixture.root, 3, "new", &["old", "new"]);
    ring.reload().await.unwrap();
    let current = service.resolve("default").await.unwrap();
    assert_ne!(
        independently_verify(&*current, b"header.current").await,
        old
    );
    assert_eq!(
        independently_verify(&*captured, b"header.retained").await,
        old
    );
    std::fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn mounted_jwks_http_publishes_both_algorithms_from_the_current_generation() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::{collections::BTreeSet, sync::Arc};
    use tower::ServiceExt;

    let fixture = fixture();
    manifest(&fixture.root, 1, "old", &["old"]);
    let ring = MountedSignerRing::load(&fixture.root, "keys.json")
        .await
        .unwrap();
    let mut state = agent_auth_http::AppState::dev("issuer.example.test");
    state.signer = Arc::new(SignerImpl::Unavailable);
    state.tenant_keys = Arc::new(TenantKeyService::mounted(ring.clone()));
    let (router, _) = agent_auth_http::build_router(state);
    for (generation, active, published) in [
        (1, "old", vec!["old"]),
        (2, "old", vec!["old", "new"]),
        (3, "new", vec!["old", "new"]),
        (4, "new", vec!["new"]),
    ] {
        manifest(&fixture.root, generation, active, &published);
        ring.reload().await.unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/jwks.json")
                    .header("host", "issuer.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "max-age=300");
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let public: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = public["keys"].as_array().unwrap();
        assert_eq!(keys.len(), published.len() * 2);
        assert_eq!(
            keys.iter().filter(|key| key["alg"] == "ES256").count(),
            published.len()
        );
        assert_eq!(
            keys.iter().filter(|key| key["alg"] == "RS256").count(),
            published.len()
        );
        for key in keys {
            for private_field in ["d", "p", "q", "dp", "dq", "qi"] {
                assert!(key.get(private_field).is_none());
            }
        }
        let snapshot = ring.snapshot().await.unwrap();
        let mut expected: BTreeSet<String> = snapshot
            .public_jwks()
            .await
            .unwrap()
            .into_iter()
            .map(|key| key.kid)
            .collect();
        expected.extend(
            snapshot
                .public_rsa_jwks()
                .await
                .unwrap()
                .into_iter()
                .map(|key| key.kid),
        );
        let actual = keys
            .iter()
            .map(|key| key["kid"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }
    std::fs::remove_dir_all(fixture.root).unwrap();
}
