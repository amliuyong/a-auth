//! 公开 OpenAPI 文档下载端点。
//!
//! 文档直接由运行时 `OpenApiRouter` 汇聚，和 `export-openapi` 使用同一真相源。

use std::sync::OnceLock;

use axum::{
    http::{header, HeaderValue},
    response::IntoResponse,
    Json,
};
use serde_json::Value;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

static OPENAPI_DOCUMENT: OnceLock<Value> = OnceLock::new();

fn document() -> &'static Value {
    OPENAPI_DOCUMENT.get_or_init(|| {
        serde_json::to_value(crate::openapi_doc())
            .expect("OpenAPI document generated from static schemas must serialize")
    })
}

/// 下载完整 OpenAPI 3.1 文档。
#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "discovery",
    responses(
        (status = 200, description = "完整 OpenAPI 3.1 JSON 文档", body = serde_json::Value)
    )
)]
pub async fn openapi_document_handler() -> impl IntoResponse {
    (
        [(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"agent-auth-openapi.json\""),
        )],
        Json(document()),
    )
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(openapi_document_handler))
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_event_limit_schema_matches_runtime_validation() {
        let document =
            serde_json::to_value(crate::openapi_doc()).expect("OpenAPI document serializes");
        let parameters = document["paths"]["/admin/security-events"]["get"]["parameters"]
            .as_array()
            .expect("security event query parameters");
        let limit = parameters
            .iter()
            .find(|parameter| parameter["name"] == "limit")
            .expect("limit parameter");

        assert_eq!(limit["schema"]["minimum"], 1);
        assert_eq!(limit["schema"]["maximum"], 500);
    }

    #[test]
    fn security_event_subject_is_required_and_non_nullable() {
        let document =
            serde_json::to_value(crate::openapi_doc()).expect("OpenAPI document serializes");
        let schema = &document["components"]["schemas"]["SecurityEvent"];
        let required = schema["required"].as_array().expect("required properties");

        assert!(required.iter().any(|property| property == "subject"));
        assert_eq!(
            schema["properties"]["subject"]["$ref"],
            "#/components/schemas/SecuritySubject"
        );
    }
}
