use crate::{ParsedIdJag, SigningAlgorithm, VerifiedIdJag};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmaJwk {
    pub kid: Option<String>,
    pub kty: String,
    pub alg: Option<String>,
    pub crv: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdJagVerificationError {
    UnknownKid,
    NoCompatibleKey,
    AmbiguousKey,
    IncompatibleKey,
    BadKey,
    BadSignature,
}

pub fn verify_parsed_id_jag(
    parsed: ParsedIdJag,
    keys: &[EmaJwk],
) -> Result<VerifiedIdJag, IdJagVerificationError> {
    let algorithm = parsed.header().algorithm;
    let key = select_key(keys, parsed.header().kid.as_deref(), algorithm)?;
    let compact = format!(
        "{}.{}",
        std::str::from_utf8(parsed.signing_input())
            .map_err(|_| IdJagVerificationError::BadSignature)?,
        URL_SAFE_NO_PAD.encode(parsed.signature())
    );
    let expected_kid = parsed.header().kid.as_deref();

    match algorithm {
        SigningAlgorithm::Rs256 => {
            let n = key.n.as_deref().ok_or(IdJagVerificationError::BadKey)?;
            let e = key.e.as_deref().ok_or(IdJagVerificationError::BadKey)?;
            agent_auth_workload::verify_rs256(&compact, n, e, expected_kid)
                .map_err(map_rs256_error)?;
        }
        SigningAlgorithm::Es256 => {
            let x = key.x.as_deref().ok_or(IdJagVerificationError::BadKey)?;
            let y = key.y.as_deref().ok_or(IdJagVerificationError::BadKey)?;
            agent_auth_workload::verify_es256(&compact, x, y, expected_kid)
                .map_err(map_es256_error)?;
        }
    }

    Ok(VerifiedIdJag::from_verified(parsed))
}

fn select_key<'a>(
    keys: &'a [EmaJwk],
    kid: Option<&str>,
    algorithm: SigningAlgorithm,
) -> Result<&'a EmaJwk, IdJagVerificationError> {
    let candidates: Vec<_> = match kid {
        Some(kid) => {
            let matching_kid: Vec<_> = keys
                .iter()
                .filter(|key| key.kid.as_deref() == Some(kid))
                .collect();
            if matching_kid.is_empty() {
                return Err(IdJagVerificationError::UnknownKid);
            }
            let compatible: Vec<_> = matching_kid
                .into_iter()
                .filter(|key| key_is_compatible(key, algorithm))
                .collect();
            if compatible.is_empty() {
                return Err(IdJagVerificationError::IncompatibleKey);
            }
            compatible
        }
        None => keys
            .iter()
            .filter(|key| key_is_compatible(key, algorithm))
            .collect(),
    };

    match candidates.as_slice() {
        [key] => Ok(*key),
        [] => Err(IdJagVerificationError::NoCompatibleKey),
        _ => Err(IdJagVerificationError::AmbiguousKey),
    }
}

fn key_is_compatible(key: &EmaJwk, algorithm: SigningAlgorithm) -> bool {
    if key
        .alg
        .as_deref()
        .is_some_and(|declared| declared != algorithm.as_str())
    {
        return false;
    }
    match algorithm {
        SigningAlgorithm::Rs256 => {
            key.kty == "RSA"
                && key.n.as_deref().is_some_and(|value| !value.is_empty())
                && key.e.as_deref().is_some_and(|value| !value.is_empty())
        }
        SigningAlgorithm::Es256 => {
            key.kty == "EC"
                && key.crv.as_deref() == Some("P-256")
                && key.x.as_deref().is_some_and(|value| !value.is_empty())
                && key.y.as_deref().is_some_and(|value| !value.is_empty())
        }
    }
}

fn map_rs256_error(error: agent_auth_workload::Rs256Error) -> IdJagVerificationError {
    match error {
        agent_auth_workload::Rs256Error::BadKey => IdJagVerificationError::BadKey,
        agent_auth_workload::Rs256Error::BadSignature => IdJagVerificationError::BadSignature,
        agent_auth_workload::Rs256Error::Malformed
        | agent_auth_workload::Rs256Error::NotRs256
        | agent_auth_workload::Rs256Error::KidMismatch => IdJagVerificationError::BadSignature,
    }
}

fn map_es256_error(error: agent_auth_workload::Es256Error) -> IdJagVerificationError {
    match error {
        agent_auth_workload::Es256Error::BadKey => IdJagVerificationError::BadKey,
        agent_auth_workload::Es256Error::BadSignature => IdJagVerificationError::BadSignature,
        agent_auth_workload::Es256Error::Malformed
        | agent_auth_workload::Es256Error::NotEs256
        | agent_auth_workload::Es256Error::KidMismatch => IdJagVerificationError::BadSignature,
    }
}
