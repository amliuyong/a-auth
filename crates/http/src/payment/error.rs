//! Payment resource error responses.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Payment resource errors (`{"error", "error_description"}`, never cached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    NotFound,
    InvalidRequest(&'static str),
    InvalidToken(&'static str),
    InsufficientScope(&'static str),
    Forbidden(&'static str),
    Conflict(&'static str),
    Unavailable(&'static str),
}

impl IntoResponse for PaymentError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "payment intent not found",
            ),
            Self::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d),
            Self::InvalidToken(d) => (StatusCode::UNAUTHORIZED, "invalid_token", d),
            Self::InsufficientScope(d) => (StatusCode::FORBIDDEN, "insufficient_scope", d),
            Self::Forbidden(d) => (StatusCode::FORBIDDEN, "access_denied", d),
            Self::Conflict(d) => (StatusCode::CONFLICT, "conflict", d),
            Self::Unavailable(d) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                d,
            ),
        };
        let mut response = (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": error, "error_description": description})),
        )
            .into_response();
        match status {
            StatusCode::UNAUTHORIZED => {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
            StatusCode::FORBIDDEN if error == "insufficient_scope" => {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
                );
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            _ => {}
        }
        response
    }
}
