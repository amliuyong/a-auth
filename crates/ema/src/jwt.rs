use crate::SigningAlgorithm;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

const MAX_ASSERTION_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 4 * 1024;
const MAX_CLAIMS_BYTES: usize = 48 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024;
const MAX_KID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtParseError {
    TooLarge,
    Malformed,
    UnsupportedAlgorithm,
    InvalidType,
    CriticalHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagHeader {
    pub algorithm: SigningAlgorithm,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum StringListClaim {
    String(String),
    Array(Vec<String>),
}

impl StringListClaim {
    pub fn values(&self) -> &[String] {
        match self {
            Self::String(value) => std::slice::from_ref(value),
            Self::Array(values) => values,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdJagClaims {
    pub issuer: Option<String>,
    pub tenant: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<StringListClaim>,
    pub client_id: Option<String>,
    pub expires_at: Option<i64>,
    pub issued_at: Option<i64>,
    pub not_before: Option<i64>,
    pub jwt_id: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<StringListClaim>,
    pub authorization_details: Option<Value>,
    pub actor: Option<Value>,
    pub confirmation: Option<Value>,
    pub audience_tenant: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedIdJag {
    header: IdJagHeader,
    claims: IdJagClaims,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedIdJag(ParsedIdJag);

impl VerifiedIdJag {
    pub(crate) fn from_verified(parsed: ParsedIdJag) -> Self {
        Self(parsed)
    }

    pub fn header(&self) -> &IdJagHeader {
        self.0.header()
    }

    pub fn claims(&self) -> &IdJagClaims {
        self.0.claims()
    }

    #[cfg(test)]
    pub(crate) fn assume_verified_for_test(parsed: ParsedIdJag) -> Self {
        Self(parsed)
    }
}

impl ParsedIdJag {
    pub fn header(&self) -> &IdJagHeader {
        &self.header
    }

    pub fn claims(&self) -> &IdJagClaims {
        &self.claims
    }

    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Deserialize)]
struct RawHeader {
    alg: String,
    typ: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct RawClaims {
    #[serde(default, rename = "iss")]
    issuer: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default, rename = "sub")]
    subject: Option<String>,
    #[serde(default, rename = "aud")]
    audience: Option<StringListClaim>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default, rename = "exp")]
    expires_at: Option<i64>,
    #[serde(default, rename = "iat")]
    issued_at: Option<i64>,
    #[serde(default, rename = "nbf")]
    not_before: Option<i64>,
    #[serde(default, rename = "jti")]
    jwt_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<StringListClaim>,
    #[serde(default)]
    aud_tenant: Option<String>,
}

pub fn parse_compact_id_jag(assertion: &str) -> Result<ParsedIdJag, JwtParseError> {
    if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
        return Err(JwtParseError::TooLarge);
    }
    let mut parts = assertion.split('.');
    let (encoded_header, encoded_claims, encoded_signature) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(claims), Some(signature), None)
                if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
            {
                (header, claims, signature)
            }
            _ => return Err(JwtParseError::Malformed),
        };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| JwtParseError::Malformed)?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(encoded_claims)
        .map_err(|_| JwtParseError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| JwtParseError::Malformed)?;
    if header_bytes.len() > MAX_HEADER_BYTES
        || claims_bytes.len() > MAX_CLAIMS_BYTES
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(JwtParseError::TooLarge);
    }

    let header_value: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtParseError::Malformed)?;
    let header_object = header_value.as_object().ok_or(JwtParseError::Malformed)?;
    if header_object.contains_key("crit") {
        return Err(JwtParseError::CriticalHeader);
    }
    let raw_header: RawHeader =
        serde_json::from_value(header_value).map_err(|_| JwtParseError::Malformed)?;
    if raw_header.typ != "oauth-id-jag+jwt" {
        return Err(JwtParseError::InvalidType);
    }
    let algorithm = match raw_header.alg.as_str() {
        "RS256" => SigningAlgorithm::Rs256,
        "ES256" => SigningAlgorithm::Es256,
        _ => return Err(JwtParseError::UnsupportedAlgorithm),
    };
    if raw_header.kid.as_deref().is_some_and(|kid| {
        kid.is_empty()
            || kid.len() > MAX_KID_BYTES
            || kid.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(JwtParseError::Malformed);
    }

    let claims_value: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| JwtParseError::Malformed)?;
    let claims_object = claims_value.as_object().ok_or(JwtParseError::Malformed)?;
    reject_null_optional_claims(
        claims_object,
        &[
            "tenant",
            "nbf",
            "resource",
            "cnf",
            "aud_tenant",
            "authorization_details",
            "act",
        ],
    )?;
    let raw_claims: RawClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| JwtParseError::Malformed)?;
    let claims = IdJagClaims {
        issuer: raw_claims.issuer,
        tenant: raw_claims.tenant,
        subject: raw_claims.subject,
        audience: raw_claims.audience,
        client_id: raw_claims.client_id,
        expires_at: raw_claims.expires_at,
        issued_at: raw_claims.issued_at,
        not_before: raw_claims.not_before,
        jwt_id: raw_claims.jwt_id,
        scope: raw_claims.scope,
        resource: raw_claims.resource,
        authorization_details: claims_object.get("authorization_details").cloned(),
        actor: claims_object.get("act").cloned(),
        confirmation: claims_object.get("cnf").cloned(),
        audience_tenant: raw_claims.aud_tenant,
    };

    Ok(ParsedIdJag {
        header: IdJagHeader {
            algorithm,
            kid: raw_header.kid,
        },
        claims,
        signing_input: format!("{encoded_header}.{encoded_claims}").into_bytes(),
        signature,
    })
}

fn reject_null_optional_claims(
    claims: &serde_json::Map<String, Value>,
    names: &[&str],
) -> Result<(), JwtParseError> {
    if names
        .iter()
        .any(|name| claims.get(*name).is_some_and(Value::is_null))
    {
        return Err(JwtParseError::Malformed);
    }
    Ok(())
}
