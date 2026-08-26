//! client 形态模型(spec 012 H1)——把"客户端形态"与"认证机制"解耦。
//!
//! `workload` **MUST** 由管理面显式设定,**MUST NOT** 靠 `token_endpoint_auth_method` 隐式判定
//! (避免"认证机制"耦合"客户端形态"导致误判)。public/confidential 未显式标时按 auth_method 推。

use serde::{Deserialize, Serialize};

/// 客户端形态(spec 012 / DESIGN §3.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// public:无凭证(`none` + PKCE)。
    Public,
    /// confidential:client_secret_* / private_key_jwt。
    Confidential,
    /// workload:机器身份(平台身份认证);**仅管理面显式设**。
    Workload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientTypeError {
    /// 未知的 token_endpoint_auth_method(无法推导默认类型)。
    UnknownAuthMethod(String),
}

impl ClientType {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientType::Public => "public",
            ClientType::Confidential => "confidential",
            ClientType::Workload => "workload",
        }
    }

    pub fn parse(s: &str) -> Option<ClientType> {
        match s {
            "public" => Some(ClientType::Public),
            "confidential" => Some(ClientType::Confidential),
            "workload" => Some(ClientType::Workload),
            _ => None,
        }
    }

    /// 是否 workload(识别一律走此,不看 auth_method 字符串)。
    pub fn is_workload(self) -> bool {
        matches!(self, ClientType::Workload)
    }

    /// 未显式标类型时,按 `token_endpoint_auth_method` 推默认(public/confidential)。
    /// **绝不推出 workload**——workload 只能管理面显式设(H1);未知方法 → 错误(fail-closed,不静默当 public)。
    pub fn default_from_auth_method(method: &str) -> Result<ClientType, ClientTypeError> {
        match method {
            "none" => Ok(ClientType::Public),
            "client_secret_basic" | "client_secret_post" | "private_key_jwt" => {
                Ok(ClientType::Confidential)
            }
            other => Err(ClientTypeError::UnknownAuthMethod(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_from_auth_method_never_yields_workload() {
        assert_eq!(
            ClientType::default_from_auth_method("none").unwrap(),
            ClientType::Public
        );
        assert_eq!(
            ClientType::default_from_auth_method("client_secret_basic").unwrap(),
            ClientType::Confidential
        );
        assert_eq!(
            ClientType::default_from_auth_method("private_key_jwt").unwrap(),
            ClientType::Confidential
        );
        // workload 三方法不是标准 token_endpoint_auth_method,推导应报未知(不静默当 public)。
        assert!(ClientType::default_from_auth_method("aws_sigv4_caller_identity").is_err());
        assert!(ClientType::default_from_auth_method("workload_oidc_jwt").is_err());
    }

    #[test]
    fn is_workload_only_for_explicit() {
        assert!(ClientType::Workload.is_workload());
        assert!(!ClientType::Public.is_workload());
        assert!(!ClientType::Confidential.is_workload());
    }

    #[test]
    fn parse_roundtrip() {
        for t in [
            ClientType::Public,
            ClientType::Confidential,
            ClientType::Workload,
        ] {
            assert_eq!(ClientType::parse(t.as_str()), Some(t));
        }
        assert_eq!(ClientType::parse("nonsense"), None);
    }
}
