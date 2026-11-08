//! Explicit external encryption keys for portable durable secret state.
//! Keys never have a generated fallback and are never persisted in the database.

use crate::ports::StoreError;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::{collections::BTreeMap, io::Read, path::Path, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    active_kid: String,
    keys: Vec<FileKey>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileKey {
    kid: String,
    key_base64: String,
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

/// Immutable per-instance key snapshot. Keep old keys during rotation so
/// replicas with the new active key can still read previously encrypted rows.
/// Intentionally has no Debug or serialization implementation.
#[derive(Clone)]
pub struct EncryptionKeyring(Arc<Keyring>);

struct Keyring {
    active_kid: String,
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

pub(crate) struct SealedRecord {
    pub kid: String,
    pub key_nonce: [u8; 12],
    pub encrypted_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn invalid_keys() -> StoreError {
    StoreError::Permanent("Invalid external encryption key configuration".into())
}

fn crypto_error() -> StoreError {
    StoreError::Permanent("Encrypted record authentication failed".into())
}

impl EncryptionKeyring {
    pub fn new(
        active_kid: &str,
        mut supplied: Vec<(String, [u8; 32])>,
    ) -> Result<Self, StoreError> {
        let mut keys = BTreeMap::new();
        let mut invalid = supplied.is_empty() || supplied.len() > 64;
        for (kid, mut material) in supplied.drain(..) {
            let valid_kid = !kid.is_empty()
                && kid.len() <= 64
                && kid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            let key = Zeroizing::new(material);
            material.zeroize();
            invalid |=
                !valid_kid || key.iter().all(|byte| *byte == 0) || keys.insert(kid, key).is_some();
        }
        if invalid || !keys.contains_key(active_kid) {
            return Err(invalid_keys());
        }
        Ok(Self(Arc::new(Keyring {
            active_kid: active_kid.into(),
            keys,
        })))
    }

    /// Read a bounded JSON key file once, including Kubernetes projected Secret
    /// symlinks. The opened target must be a regular file with no world access
    /// or group write permission. The caller confines the mount path at startup.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let file = std::fs::File::open(path).map_err(|_| invalid_keys())?;
        let metadata = file.metadata().map_err(|_| invalid_keys())?;
        if !metadata.is_file() {
            return Err(invalid_keys());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o027 != 0 {
                return Err(invalid_keys());
            }
        }
        #[cfg(not(unix))]
        return Err(invalid_keys());
        let mut encoded = Zeroizing::new(Vec::new());
        file.take(65_537)
            .read_to_end(&mut encoded)
            .map_err(|_| invalid_keys())?;
        if encoded.len() > 65_536 {
            return Err(invalid_keys());
        }
        Self::from_json(&encoded)
    }

    /// The caller has already confined and protected the source file.
    pub(crate) fn from_json(encoded: &[u8]) -> Result<Self, StoreError> {
        use base64::Engine;
        if encoded.is_empty() || encoded.len() > 65_536 {
            return Err(invalid_keys());
        }
        let config: KeyFile = serde_json::from_slice(encoded).map_err(|_| invalid_keys())?;
        let mut supplied = Vec::new();
        let mut invalid = false;
        for entry in &config.keys {
            let decoded = base64::engine::general_purpose::STANDARD.decode(&entry.key_base64);
            let Ok(decoded) = decoded else {
                invalid = true;
                continue;
            };
            let decoded = Zeroizing::new(decoded);
            if decoded.len() != 32 {
                invalid = true;
                continue;
            }
            let mut material = [0; 32];
            material.copy_from_slice(&decoded);
            supplied.push((entry.kid.clone(), material));
            material.zeroize();
        }
        if invalid {
            for (_, key) in &mut supplied {
                key.zeroize();
            }
            return Err(invalid_keys());
        }
        Self::new(&config.active_kid, supplied)
    }

    pub(crate) fn seal(
        &self,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedRecord, StoreError> {
        let kid = &self.0.active_kid;
        let kek = self.0.keys.get(kid).ok_or_else(invalid_keys)?;
        let mut data_key = Zeroizing::new([0u8; 32]);
        let mut key_nonce = [0u8; 12];
        let mut nonce = [0u8; 12];
        for destination in [&mut data_key[..], &mut key_nonce[..], &mut nonce[..]] {
            OsRng.try_fill_bytes(destination).map_err(|_| {
                StoreError::Transient("Operating system entropy unavailable".into())
            })?;
        }
        let key_aad = aad(kid, context, b"data-key");
        let encrypted_key = Aes256Gcm::new_from_slice(&kek[..])
            .map_err(|_| invalid_keys())?
            .encrypt(
                Nonce::from_slice(&key_nonce),
                Payload {
                    msg: &data_key[..],
                    aad: &key_aad,
                },
            )
            .map_err(|_| crypto_error())?;
        let payload_aad = aad(kid, context, b"payload");
        let ciphertext = Aes256Gcm::new_from_slice(&data_key[..])
            .map_err(|_| crypto_error())?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &payload_aad,
                },
            )
            .map_err(|_| crypto_error())?;
        Ok(SealedRecord {
            kid: kid.clone(),
            key_nonce,
            encrypted_key,
            nonce,
            ciphertext,
        })
    }

    pub(crate) fn open(
        &self,
        context: &[u8],
        record: &SealedRecord,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let kek = self.0.keys.get(&record.kid).ok_or_else(crypto_error)?;
        let key_aad = aad(&record.kid, context, b"data-key");
        let data_key = Zeroizing::new(
            Aes256Gcm::new_from_slice(&kek[..])
                .map_err(|_| crypto_error())?
                .decrypt(
                    Nonce::from_slice(&record.key_nonce),
                    Payload {
                        msg: &record.encrypted_key,
                        aad: &key_aad,
                    },
                )
                .map_err(|_| crypto_error())?,
        );
        let payload_aad = aad(&record.kid, context, b"payload");
        Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| crypto_error())?
            .decrypt(
                Nonce::from_slice(&record.nonce),
                Payload {
                    msg: &record.ciphertext,
                    aad: &payload_aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| crypto_error())
    }
}

/// Length framing prevents ambiguous row/domain/key bindings.
fn aad(kid: &str, context: &[u8], purpose: &[u8]) -> Vec<u8> {
    let mut encoded = b"a-auth-envelope-v1".to_vec();
    for field in [kid.as_bytes(), context, purpose] {
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field);
    }
    encoded
}
