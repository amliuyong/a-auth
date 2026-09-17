//! Explicit user consent for one registered workload on one resource.
//! Keeping this admission shared prevents direct consent and PAR continuations
//! from bypassing the authorization request checks.

use axum::{http::StatusCode, response::IntoResponse};

use crate::{ports::ClientStore, state::AppState};

pub(crate) async fn validate(
    state: &AppState,
    tenant: &str,
    actor: Option<&str>,
    resources: &[String],
) -> Result<(), axum::response::Response> {
    let Some(actor) = actor else {
        return Ok(());
    };
    if !state.phase.at_least(crate::Phase::P2)
        || actor.is_empty()
        || actor.len() > 256
        || actor
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '*')
        || resources.len() != 1
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_request: workload_actor requires P2, one exact client ID and one explicit resource",
        )
            .into_response());
    }
    match state.clients.get(tenant, actor).await {
        Ok(Some(client)) if client.is_workload() && !client.is_tombstoned() => Ok(()),
        Ok(_) => Err((
            StatusCode::BAD_REQUEST,
            "invalid_request: workload_actor must be an active registered workload in this tenant",
        )
            .into_response()),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable: workload registration unavailable",
        )
            .into_response()),
    }
}
