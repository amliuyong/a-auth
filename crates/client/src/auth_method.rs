//! Registered-client authentication capability registry.
//!
//! A method can be known to the data model without being executable in the
//! current release. Admission and metadata use the executable projection;
//! update paths can still migrate an older known record away from a disabled
//! method.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredClientAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

pub const EXECUTABLE_REGISTERED_CLIENT_AUTH_METHODS: &[RegisteredClientAuthMethod] = &[
    RegisteredClientAuthMethod::None,
    RegisteredClientAuthMethod::ClientSecretBasic,
    RegisteredClientAuthMethod::ClientSecretPost,
    RegisteredClientAuthMethod::PrivateKeyJwt,
];

impl RegisteredClientAuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    pub fn parse_known(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "client_secret_basic" => Some(Self::ClientSecretBasic),
            "client_secret_post" => Some(Self::ClientSecretPost),
            "private_key_jwt" => Some(Self::PrivateKeyJwt),
            _ => None,
        }
    }

    pub fn parse_executable(value: &str) -> Option<Self> {
        let method = Self::parse_known(value)?;
        method.is_executable().then_some(method)
    }

    pub fn is_executable(self) -> bool {
        EXECUTABLE_REGISTERED_CLIENT_AUTH_METHODS.contains(&self)
    }

    pub const fn requires_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
}

pub fn executable_registered_client_auth_method_names() -> Vec<&'static str> {
    EXECUTABLE_REGISTERED_CLIENT_AUTH_METHODS
        .iter()
        .map(|method| method.as_str())
        .collect()
}

pub fn enabled_registered_client_auth_method_names(
    private_key_jwt_enabled: bool,
) -> Vec<&'static str> {
    EXECUTABLE_REGISTERED_CLIENT_AUTH_METHODS
        .iter()
        .copied()
        .filter(|method| {
            private_key_jwt_enabled || *method != RegisteredClientAuthMethod::PrivateKeyJwt
        })
        .map(RegisteredClientAuthMethod::as_str)
        .collect()
}

pub fn executable_private_key_jwt_signing_alg_names() -> Vec<&'static str> {
    if RegisteredClientAuthMethod::PrivateKeyJwt.is_executable() {
        vec!["RS256", "ES256"]
    } else {
        Vec::new()
    }
}

pub fn enabled_private_key_jwt_signing_alg_names(
    private_key_jwt_enabled: bool,
) -> Vec<&'static str> {
    if private_key_jwt_enabled {
        executable_private_key_jwt_signing_alg_names()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_projection_includes_private_key_jwt() {
        assert_eq!(
            executable_registered_client_auth_method_names(),
            vec![
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            ]
        );
        assert_eq!(
            RegisteredClientAuthMethod::parse_executable("private_key_jwt"),
            Some(RegisteredClientAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(
            executable_private_key_jwt_signing_alg_names(),
            vec!["RS256", "ES256"]
        );
        assert_eq!(
            enabled_registered_client_auth_method_names(false),
            vec!["none", "client_secret_basic", "client_secret_post"]
        );
        assert!(enabled_private_key_jwt_signing_alg_names(false).is_empty());
    }
}
