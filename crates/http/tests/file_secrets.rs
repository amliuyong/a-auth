#![cfg(feature = "postgres")]

use agent_auth_http::{
    adapters::file_secrets::FileSecretResolver,
    ports::{SecretResolver, StoreError},
    state::SecretResolverImpl,
};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
};

const REF: &str = "agent-auth/federation/default/example";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "a-auth-file-secrets-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        Self { root }
    }

    fn write(&self, name: &str, bytes: &[u8], permissions: u32) {
        std::fs::write(self.root.join(name), bytes).unwrap();
        mode(&self.root.join(name), permissions);
    }

    fn resolver(&self) -> FileSecretResolver {
        FileSecretResolver::new(&self.root, [(REF.to_owned(), "client-secret".to_owned())]).unwrap()
    }

    fn passed(self) {
        std::fs::remove_dir_all(self.root).unwrap();
    }
}

fn mode(path: &Path, permissions: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(permissions)).unwrap();
}

#[tokio::test]
async fn file_secrets_resolve_only_explicit_references_without_trimming() {
    let fixture = Fixture::new();
    fixture.write("client-secret", b"local-client-secret \n", 0o640);
    fixture.write(
        "unmapped",
        b"must-not-be-readable-through-the-resolver",
        0o600,
    );
    let resolver = SecretResolverImpl::File(fixture.resolver());
    assert_eq!(
        resolver.resolve(REF).await.unwrap().as_deref(),
        Some("local-client-secret \n")
    );
    for reference in [
        "unmapped",
        "client-secret",
        "/etc/passwd",
        "../client-secret",
        "agent-auth/federation/default/../example",
        "agent-auth/federation/other/example",
    ] {
        assert_eq!(resolver.resolve(reference).await.unwrap(), None);
    }
    std::fs::remove_file(fixture.root.join("client-secret")).unwrap();
    assert_eq!(resolver.resolve(REF).await.unwrap(), None);
    fixture.passed();
}

#[tokio::test]
async fn file_secrets_observe_kubernetes_projection_rotation_across_clones() {
    let fixture = Fixture::new();
    for (generation, value) in [
        ("generation-1", "first-value"),
        ("generation-2", "second-value"),
    ] {
        let directory = fixture.root.join(generation);
        std::fs::create_dir(&directory).unwrap();
        mode(&directory, 0o750);
        std::fs::write(directory.join("client-secret"), value).unwrap();
        mode(&directory.join("client-secret"), 0o640);
    }
    symlink("generation-1", fixture.root.join("..data")).unwrap();
    symlink("..data/client-secret", fixture.root.join("client-secret")).unwrap();
    let first = fixture.resolver();
    let second = first.clone();
    assert_eq!(
        first.resolve(REF).await.unwrap().as_deref(),
        Some("first-value")
    );
    symlink("generation-2", fixture.root.join("..next")).unwrap();
    std::fs::rename(fixture.root.join("..next"), fixture.root.join("..data")).unwrap();
    for resolver in [&first, &second] {
        assert_eq!(
            resolver.resolve(REF).await.unwrap().as_deref(),
            Some("second-value")
        );
    }
    fixture.passed();
}

#[tokio::test]
async fn file_secrets_reject_escapes_permissions_and_malformed_values_without_disclosure() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    outside.write("outside-secret", b"outside-value-must-not-leak", 0o600);
    symlink(
        outside.root.join("outside-secret"),
        fixture.root.join("client-secret"),
    )
    .unwrap();
    let resolver = fixture.resolver();
    let error = resolver.resolve(REF).await.unwrap_err();
    assert!(matches!(error, StoreError::Permanent(_)));
    let diagnostic = format!("{error:?}");
    for sensitive in [
        REF,
        outside.root.to_str().unwrap(),
        "outside-value-must-not-leak",
    ] {
        assert!(!diagnostic.contains(sensitive));
    }
    std::fs::remove_file(fixture.root.join("client-secret")).unwrap();
    for (value, permissions) in [
        (b"world-readable".as_slice(), 0o644),
        (b"group-writable".as_slice(), 0o660),
        (b"".as_slice(), 0o600),
        (b"invalid\0secret".as_slice(), 0o600),
        ([0xff].as_slice(), 0o600),
    ] {
        fixture.write("client-secret", value, permissions);
        assert!(matches!(
            resolver.resolve(REF).await,
            Err(StoreError::Permanent(_))
        ));
    }
    fixture.write("client-secret", &vec![b'x'; 65_537], 0o600);
    assert!(matches!(
        resolver.resolve(REF).await,
        Err(StoreError::Permanent(_))
    ));
    fixture.write("client-secret", b"repaired", 0o600);
    mode(&fixture.root, 0o770);
    assert!(matches!(
        resolver.resolve(REF).await,
        Err(StoreError::Permanent(_))
    ));
    mode(&fixture.root, 0o700);
    assert_eq!(
        resolver.resolve(REF).await.unwrap().as_deref(),
        Some("repaired")
    );
    fixture.passed();
    outside.passed();
}

#[test]
fn file_secrets_validate_binding_configuration_before_serving() {
    let fixture = Fixture::new();
    for name in [
        "../secret",
        "/secret",
        "nested/secret",
        "..",
        ".",
        "..data",
        "bad\nname",
    ] {
        assert!(FileSecretResolver::new(&fixture.root, [(REF.into(), name.into())]).is_err());
    }
    assert!(FileSecretResolver::new(
        &fixture.root,
        [(REF.into(), "one".into()), (REF.into(), "two".into())],
    )
    .is_err());
    assert!(FileSecretResolver::new(&fixture.root, [("bad ref".into(), "one".into())]).is_err());
    mode(&fixture.root, 0o777);
    assert!(FileSecretResolver::new(&fixture.root, [(REF.into(), "one".into())]).is_err());
    mode(&fixture.root, 0o700);
    fixture.passed();
}

#[tokio::test]
async fn file_secrets_never_block_on_nonregular_files() {
    let fixture = Fixture::new();
    let resolver = fixture.resolver();
    std::fs::create_dir(fixture.root.join("client-secret")).unwrap();
    assert!(matches!(
        resolver.resolve(REF).await,
        Err(StoreError::Permanent(_))
    ));
    std::fs::remove_dir(fixture.root.join("client-secret")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(fixture.root.join("client-secret"))
        .status()
        .unwrap()
        .success());
    mode(&fixture.root.join("client-secret"), 0o600);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), resolver.resolve(REF))
        .await
        .expect("a FIFO must not block a worker");
    assert!(matches!(result, Err(StoreError::Permanent(_))));
    fixture.passed();
}
