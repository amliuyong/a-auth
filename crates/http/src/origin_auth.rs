use std::sync::Arc;

use agent_auth_discovery::Form;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::state::AppState;

pub const LEGACY_ORIGIN_AUTH_HEADER: &str = "x-agent-auth-origin-auth";
pub const PRIMARY_ORIGIN_AUTH_HEADER: &str = "x-agent-auth-origin-auth-primary";
pub const SECONDARY_ORIGIN_AUTH_HEADER: &str = "x-agent-auth-origin-auth-secondary";

#[derive(Clone)]
pub struct SaasOriginAuth {
    credentials: Option<OriginCredentials>,
}

#[derive(Clone)]
struct OriginCredentials {
    primary: Arc<Vec<u8>>,
    secondary: Arc<Vec<u8>>,
}

impl SaasOriginAuth {
    /// `AppState::dev` is also used as an integration-test fixture before tests
    /// replace its deployment form. Production construction cannot select this.
    pub(crate) fn development_bypass() -> Self {
        Self { credentials: None }
    }

    pub fn required(primary: String, secondary: String) -> Result<Self, String> {
        if primary.len() < 32 || secondary.len() < 32 {
            return Err("SaaS origin credentials must each contain at least 32 bytes".to_string());
        }
        if constant_time_eq(primary.as_bytes(), secondary.as_bytes()) {
            return Err("SaaS origin credentials must be distinct".to_string());
        }
        Ok(Self {
            credentials: Some(OriginCredentials {
                primary: Arc::new(primary.into_bytes()),
                secondary: Arc::new(secondary.into_bytes()),
            }),
        })
    }

    fn authenticates(&self, headers: &HeaderMap) -> bool {
        self.credentials.as_ref().is_none_or(|credentials| {
            header_matches(headers, PRIMARY_ORIGIN_AUTH_HEADER, &credentials.primary)
                || header_matches(headers, LEGACY_ORIGIN_AUTH_HEADER, &credentials.primary)
                || header_matches(
                    headers,
                    SECONDARY_ORIGIN_AUTH_HEADER,
                    &credentials.secondary,
                )
        })
    }
}

fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    expected.len() == presented.len() && bool::from(expected.ct_eq(presented))
}

fn header_matches(headers: &HeaderMap, name: &str, expected: &[u8]) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|presented| constant_time_eq(expected, presented.as_bytes()))
}

pub async fn saas_origin_auth_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(state.form, Form::Saas { .. })
        && !state.saas_origin_auth.authenticates(request.headers())
    {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "untrusted_origin",
                "error_description": "Request did not arrive through the managed SaaS edge"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::{
        SaasOriginAuth, LEGACY_ORIGIN_AUTH_HEADER, PRIMARY_ORIGIN_AUTH_HEADER,
        SECONDARY_ORIGIN_AUTH_HEADER,
    };
    use axum::http::{HeaderMap, HeaderValue};

    const PRIMARY: &str = "primary-origin-secret-at-least-32-bytes";
    const SECONDARY: &str = "secondary-origin-secret-at-least-32-bytes";

    #[test]
    fn either_rotation_slot_authenticates_and_wrong_slots_do_not() {
        let auth = SaasOriginAuth::required(PRIMARY.to_string(), SECONDARY.to_string()).unwrap();
        let mut headers = HeaderMap::new();
        assert!(!auth.authenticates(&headers));

        headers.insert(
            PRIMARY_ORIGIN_AUTH_HEADER,
            HeaderValue::from_static(PRIMARY),
        );
        assert!(auth.authenticates(&headers));

        headers.clear();
        headers.insert(
            SECONDARY_ORIGIN_AUTH_HEADER,
            HeaderValue::from_static(SECONDARY),
        );
        assert!(auth.authenticates(&headers));

        headers.clear();
        headers.insert(LEGACY_ORIGIN_AUTH_HEADER, HeaderValue::from_static(PRIMARY));
        assert!(auth.authenticates(&headers));

        headers.clear();
        headers.insert(
            PRIMARY_ORIGIN_AUTH_HEADER,
            HeaderValue::from_static(SECONDARY),
        );
        headers.insert(
            SECONDARY_ORIGIN_AUTH_HEADER,
            HeaderValue::from_static(PRIMARY),
        );
        assert!(!auth.authenticates(&headers));
    }

    #[test]
    fn required_credentials_are_long_and_distinct() {
        assert!(SaasOriginAuth::required("short".to_string(), SECONDARY.to_string()).is_err());
        assert!(SaasOriginAuth::required(PRIMARY.to_string(), "short".to_string()).is_err());
        assert!(SaasOriginAuth::required(PRIMARY.to_string(), PRIMARY.to_string()).is_err());
    }
}
