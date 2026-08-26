//! Local password policy and Argon2id hashing (spec 003 C9.8-C9.10).
//!
//! The PHC profile is deliberately fixed. Verification rejects any stored hash
//! that asks the process to exceed the reviewed memory/CPU budget.

use std::sync::LazyLock;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand_core::OsRng;
use serde::Deserialize;
use zeroize::Zeroize;

pub const MIN_PASSWORD_BYTES: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 128;
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_LANES: u32 = 1;
pub const ARGON2_OUTPUT_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    TooLong,
    InvalidHashProfile,
    HashFailure,
}

/// Password request value. Deliberately does not implement `Debug`, `Clone`, or
/// `Serialize`, so handler structs cannot accidentally log or return it.
pub struct PasswordValue(String);

impl PasswordValue {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for PasswordValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for PasswordValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

/// Validated PHC-encoded password hash. Deliberately does not implement
/// `Debug` or `Serialize`; persistence adapters must opt in via `expose()`.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedPasswordHash(String);

impl EncodedPasswordHash {
    pub fn from_storage(value: String) -> Result<Self, PasswordError> {
        let parsed = PasswordHash::new(&value).map_err(|_| PasswordError::InvalidHashProfile)?;
        validate_hash_profile(&parsed)?;
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|_| PasswordError::HashFailure)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    let len = password.len();
    if len < MIN_PASSWORD_BYTES {
        return Err(PasswordError::TooShort);
    }
    if len > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<EncodedPasswordHash, PasswordError> {
    validate_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| EncodedPasswordHash(hash.to_string()))
        .map_err(|_| PasswordError::HashFailure)
}

fn decimal_param(hash: &PasswordHash<'_>, name: &str) -> Option<u32> {
    hash.params.get(name)?.decimal().ok()
}

fn validate_hash_profile(hash: &PasswordHash<'_>) -> Result<(), PasswordError> {
    if hash.algorithm.as_str() != "argon2id"
        || hash.version != Some(Version::V0x13.into())
        || decimal_param(hash, "m") != Some(ARGON2_MEMORY_KIB)
        || decimal_param(hash, "t") != Some(ARGON2_ITERATIONS)
        || decimal_param(hash, "p") != Some(ARGON2_LANES)
        || hash.hash.as_ref().map(|v| v.len()) != Some(ARGON2_OUTPUT_BYTES)
        || hash.salt.as_ref().map(|v| v.as_str().len()).unwrap_or(0) < 22
    {
        return Err(PasswordError::InvalidHashProfile);
    }
    Ok(())
}

pub fn verify_password(
    password: &str,
    encoded_hash: &EncodedPasswordHash,
) -> Result<bool, PasswordError> {
    let parsed =
        PasswordHash::new(encoded_hash.expose()).map_err(|_| PasswordError::InvalidHashProfile)?;
    validate_hash_profile(&parsed)?;
    match argon2()?.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(PasswordError::HashFailure),
    }
}

/// Process-local dummy hash used for unknown users and users without passwords.
/// Every password request dereferences this before selecting the real/dummy hash,
/// so the one-time initialization cost does not depend on account existence.
pub fn dummy_hash() -> &'static EncodedPasswordHash {
    static HASH: LazyLock<EncodedPasswordHash> = LazyLock::new(|| {
        EncodedPasswordHash::from_storage(
            "$argon2id$v=19$m=19456,t=2,p=1$DyLZGf1JkluOc79Zpu8XqA$b4gSn1EyJ70SVXWldiR6s04ln6dCUMzOUQtGKmZwyQA"
                .to_string(),
        )
        .expect("the embedded dummy hash uses the reviewed Argon2 profile")
    });
    &HASH
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(
        PasswordValue:
            std::fmt::Debug,
            Clone,
            serde::Serialize
    );
    static_assertions::assert_not_impl_any!(
        EncodedPasswordHash:
            std::fmt::Debug,
            serde::Serialize
    );

    #[test]
    fn policy_uses_raw_utf8_bytes_without_trimming() {
        assert_eq!(validate_password("short"), Err(PasswordError::TooShort));
        assert!(validate_password(" twelve-byte").is_ok());
        assert_eq!(
            validate_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)),
            Err(PasswordError::TooLong)
        );
    }

    #[test]
    fn same_password_gets_distinct_salts_and_verifies() {
        let first = hash_password("correct horse battery staple").unwrap();
        let second = hash_password("correct horse battery staple").unwrap();
        assert!(first != second);
        assert!(verify_password("correct horse battery staple", &first).unwrap());
        assert!(!verify_password("wrong password", &first).unwrap());
    }

    #[test]
    fn rejects_non_reviewed_or_malformed_phc_profiles() {
        let valid = hash_password("correct horse battery staple").unwrap();
        let expensive = EncodedPasswordHash(valid.expose().replacen("m=19456", "m=65536", 1));
        assert_eq!(
            verify_password("correct horse battery staple", &expensive),
            Err(PasswordError::InvalidHashProfile)
        );
        let malformed = EncodedPasswordHash("not-a-phc".to_string());
        assert_eq!(
            verify_password("correct horse battery staple", &malformed),
            Err(PasswordError::InvalidHashProfile)
        );
    }

    #[test]
    fn dummy_hash_has_the_same_profile() {
        assert!(!verify_password("attacker guess", dummy_hash()).unwrap());
    }

    #[test]
    fn password_secret_wrappers_do_not_expose_debug_or_serialization_traits() {
        let source = include_str!("password.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .expect("test module follows password implementation")
            .0;
        let drop_body = production
            .split_once("impl Drop for PasswordValue")
            .expect("PasswordValue zeroizing Drop implementation")
            .1
            .split_once("impl<'de> Deserialize<'de> for PasswordValue")
            .expect("Deserialize follows PasswordValue Drop")
            .0;
        assert_eq!(drop_body.matches("self.0.zeroize()").count(), 1);
    }

    #[test]
    fn stored_hash_must_match_the_reviewed_profile() {
        let valid = hash_password("correct horse battery staple").unwrap();
        assert!(EncodedPasswordHash::from_storage(valid.expose().to_string()).is_ok());
        assert!(matches!(
            EncodedPasswordHash::from_storage(valid.expose().replacen("m=19456", "m=65536", 1)),
            Err(PasswordError::InvalidHashProfile)
        ));
    }
}
