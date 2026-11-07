//! Immutable ES256/RS256 signing snapshots loaded from operator-mounted files.
//! A ring publishes complete generations; request signers never change keys
//! between reading a kid and signing its input.

use crate::ports::{Signer, SignerError};
use agent_auth_infra_core::{ec_kid, rsa_jwk_from_ne, EcJwk, RsaJwk};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Signer as _, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
};
use rsa::{
    pkcs8::DecodePublicKey,
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_KEYS: usize = 8;
const MAX_SIGNING_INPUT_BYTES: usize = 256 * 1024;
const SIGNING_SLOTS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    generation: u64,
    es256_key: String,
    rs256_key: String,
    ec_public_keys: Vec<String>,
    rsa_public_keys: Vec<String>,
}

struct Material {
    generation: u64,
    ec: SigningKey,
    rsa: rsa::RsaPrivateKey,
    ec_kid: String,
    rsa_kid: String,
    ec_public: Vec<EcJwk>,
    rsa_public: Vec<RsaJwk>,
}

/// One request's immutable private/public EC and RSA generation.
#[derive(Clone)]
pub struct MountedSigner {
    material: Arc<Material>,
    slots: Arc<Semaphore>,
}

struct Candidate {
    signer: MountedSigner,
    fingerprint: [u8; 32],
}

#[derive(Clone)]
pub struct MountedSignerRing {
    root: PathBuf,
    manifest: String,
    current: Arc<Mutex<Candidate>>,
    slots: Arc<Semaphore>,
}

fn invalid() -> SignerError {
    SignerError::Permanent("Mounted signing configuration invalid".into())
}

fn relative(name: &str) -> Result<(), SignerError> {
    if name.is_empty()
        || name.len() > 512
        || name.chars().any(char::is_control)
        || Path::new(name)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid());
    }
    Ok(())
}

fn read(root: &Path, name: &str, private: bool) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    relative(name)?;
    let requested = root.join(name);
    validate_parents(root, &requested)?;
    let path = requested.canonicalize().map_err(|_| invalid())?;
    if !path.starts_with(root) {
        return Err(invalid());
    }
    validate_parents(root, &path)?;
    let before = path.metadata().map_err(|_| invalid())?;
    if !before.is_file() || before.len() > MAX_FILE_BYTES as u64 {
        return Err(invalid());
    }
    let file = File::open(&path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.len() > MAX_FILE_BYTES as u64
        || before.dev() != metadata.dev()
        || before.ino() != metadata.ino()
        || mode & 0o022 != 0
        || (private && mode & 0o007 != 0)
    {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

fn ec_public(key: &p256::PublicKey) -> Result<EcJwk, SignerError> {
    let point = key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().ok_or_else(invalid)?);
    let y = URL_SAFE_NO_PAD.encode(point.y().ok_or_else(invalid)?);
    Ok(EcJwk {
        kty: "EC",
        crv: "P-256",
        kid: ec_kid("P-256", &x, &y),
        x,
        y,
        alg: "ES256",
        r#use: "sig",
    })
}

fn rsa_public(key: &rsa::RsaPublicKey) -> Result<RsaJwk, SignerError> {
    if !(2048..=8192).contains(&key.n().bits()) {
        return Err(invalid());
    }
    Ok(rsa_jwk_from_ne(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
    ))
}

fn text(bytes: &[u8]) -> Result<&str, SignerError> {
    std::str::from_utf8(bytes).map_err(|_| invalid())
}

fn validate_root(root: &Path) -> Result<(), SignerError> {
    let metadata = root.metadata().map_err(|_| invalid())?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid());
    }
    Ok(())
}

fn validate_parents(root: &Path, path: &Path) -> Result<(), SignerError> {
    for directory in path
        .parent()
        .ok_or_else(invalid)?
        .ancestors()
        .take_while(|directory| directory.starts_with(root))
    {
        validate_root(directory)?;
    }
    Ok(())
}

fn load(root: &Path, name: &str, slots: Arc<Semaphore>) -> Result<Candidate, SignerError> {
    validate_root(root)?;
    let bytes = read(root, name, false)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if manifest.schema != 1
        || manifest.generation == 0
        || !(1..=MAX_PUBLIC_KEYS).contains(&manifest.ec_public_keys.len())
        || !(1..=MAX_PUBLIC_KEYS).contains(&manifest.rsa_public_keys.len())
    {
        return Err(invalid());
    }
    let secret = p256::SecretKey::from_pkcs8_pem(text(&read(root, &manifest.es256_key, true)?)?)
        .map_err(|_| invalid())?;
    let own_ec = ec_public(&secret.public_key())?;
    let ec = SigningKey::from(secret);
    let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(text(&read(root, &manifest.rs256_key, true)?)?)
        .map_err(|_| invalid())?;
    rsa.validate().map_err(|_| invalid())?;
    let own_rsa = rsa_public(&rsa::RsaPublicKey::from(&rsa))?;
    let mut ec_keys = Vec::new();
    for path in &manifest.ec_public_keys {
        let key = p256::PublicKey::from_public_key_pem(text(&read(root, path, false)?)?)
            .map_err(|_| invalid())?;
        ec_keys.push(ec_public(&key)?);
    }
    let mut rsa_keys = Vec::new();
    for path in &manifest.rsa_public_keys {
        let key = rsa::RsaPublicKey::from_public_key_pem(text(&read(root, path, false)?)?)
            .map_err(|_| invalid())?;
        rsa_keys.push(rsa_public(&key)?);
    }
    ec_keys.sort_by(|left, right| left.kid.cmp(&right.kid));
    rsa_keys.sort_by(|left, right| left.kid.cmp(&right.kid));
    if !ec_keys.contains(&own_ec)
        || !rsa_keys.contains(&own_rsa)
        || ec_keys.windows(2).any(|pair| pair[0].kid == pair[1].kid)
        || rsa_keys.windows(2).any(|pair| pair[0].kid == pair[1].kid)
        || bytes.as_slice() != read(root, name, false)?.as_slice()
    {
        return Err(invalid());
    }
    validate_root(root)?;
    let mut fingerprint = Sha256::new();
    fingerprint.update(bytes.as_slice());
    fingerprint.update(
        serde_json::to_vec(&(
            &own_ec.kid,
            &own_rsa.kid,
            ec_keys.iter().map(|key| &key.kid).collect::<Vec<_>>(),
            rsa_keys.iter().map(|key| &key.kid).collect::<Vec<_>>(),
        ))
        .map_err(|_| invalid())?,
    );
    Ok(Candidate {
        fingerprint: fingerprint.finalize().into(),
        signer: MountedSigner {
            slots,
            material: Arc::new(Material {
                generation: manifest.generation,
                ec,
                rsa,
                ec_kid: own_ec.kid,
                rsa_kid: own_rsa.kid,
                ec_public: ec_keys,
                rsa_public: rsa_keys,
            }),
        },
    })
}

async fn load_async(
    root: PathBuf,
    name: String,
    slots: Arc<Semaphore>,
) -> Result<Candidate, SignerError> {
    tokio::task::spawn_blocking(move || load(&root, &name, slots))
        .await
        .map_err(|_| invalid())?
}

impl MountedSignerRing {
    pub async fn load(root: impl AsRef<Path>, manifest: &str) -> Result<Self, SignerError> {
        relative(manifest)?;
        let root = root.as_ref().canonicalize().map_err(|_| invalid())?;
        let slots = Arc::new(Semaphore::new(SIGNING_SLOTS));
        let current = load_async(root.clone(), manifest.into(), slots.clone()).await?;
        Ok(Self {
            root,
            manifest: manifest.into(),
            current: Arc::new(Mutex::new(current)),
            slots,
        })
    }

    pub fn private_root(&self) -> &Path {
        &self.root
    }

    pub async fn snapshot(&self) -> Result<MountedSigner, SignerError> {
        Ok(self.current.lock().await.signer.clone())
    }

    /// Publish-ahead precedes activation: the new active key must already be
    /// present in the previous generation's public set. Invalid or rebound
    /// configurations never replace the complete prior generation.
    pub async fn reload(&self) -> Result<bool, SignerError> {
        let candidate =
            load_async(self.root.clone(), self.manifest.clone(), self.slots.clone()).await?;
        let mut current = self.current.lock().await;
        if candidate.signer.generation() == current.signer.generation() {
            return if candidate.fingerprint == current.fingerprint {
                Ok(false)
            } else {
                Err(invalid())
            };
        }
        if candidate.signer.generation() < current.signer.generation()
            || !current
                .signer
                .material
                .ec_public
                .iter()
                .any(|key| key.kid == candidate.signer.material.ec_kid)
            || !current
                .signer
                .material
                .rsa_public
                .iter()
                .any(|key| key.kid == candidate.signer.material.rsa_kid)
        {
            return Err(invalid());
        }
        *current = candidate;
        Ok(true)
    }
}

impl MountedSigner {
    pub fn generation(&self) -> u64 {
        self.material.generation
    }

    fn input(input: &[u8]) -> Result<(), SignerError> {
        if input.len() > MAX_SIGNING_INPUT_BYTES {
            return Err(SignerError::Permanent(
                "Mounted signing input exceeds limit".into(),
            ));
        }
        Ok(())
    }
}

impl Signer for MountedSigner {
    async fn sign_es256(&self, input: &[u8]) -> Result<Vec<u8>, SignerError> {
        Self::input(input)?;
        let _permit = self
            .slots
            .try_acquire()
            .map_err(|_| SignerError::Transient("Mounted signing capacity exhausted".into()))?;
        let signature: Signature = self.material.ec.sign(input);
        Ok(signature.to_bytes().to_vec())
    }

    async fn public_jwks(&self) -> Result<Vec<EcJwk>, SignerError> {
        Ok(self.material.ec_public.clone())
    }

    async fn active_kid(&self) -> Result<String, SignerError> {
        Ok(self.material.ec_kid.clone())
    }

    async fn sign_rs256(&self, input: &[u8]) -> Result<(String, Vec<u8>), SignerError> {
        Self::input(input)?;
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| SignerError::Transient("Mounted signing capacity exhausted".into()))?;
        let material = self.material.clone();
        let input = input.to_vec();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(material.rsa.clone());
            let signature = key.sign_with_rng(&mut rand::rngs::OsRng, &input);
            (material.rsa_kid.clone(), signature.to_bytes().to_vec())
        })
        .await
        .map_err(|_| SignerError::Transient("Mounted signing worker failed".into()))
    }

    async fn public_rsa_jwks(&self) -> Result<Vec<RsaJwk>, SignerError> {
        Ok(self.material.rsa_public.clone())
    }

    async fn active_rsa_kid(&self) -> Result<String, SignerError> {
        Ok(self.material.rsa_kid.clone())
    }
}
