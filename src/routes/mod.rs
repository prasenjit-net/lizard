pub mod api;
#[cfg(test)]
mod tests;
pub mod ws;

use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::Router;

use crate::access_log;
use crate::acme;
use crate::state::SharedState;
use crate::static_assets;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/health", get(api::health))
        .route("/api/config", get(api::config))
        .route("/api/metrics", get(api::metrics))
        .route("/api/activity", get(api::list_activity))
        .route("/api/tasks", get(api::list_tasks).post(api::create_task))
        .route("/api/tasks/{id}", delete(api::delete_task))
        .route("/api/tasks/{id}/toggle", post(api::toggle_task))
        .route("/api/error-demo", get(api::error_demo))
        .route("/api/ca", get(api::ca_info))
        .route("/api/certificates", get(api::list_certificates))
        .route("/api/certificates/{id}", get(api::get_certificate))
        .route(
            "/api/certificates/{id}/revoke",
            post(api::revoke_certificate),
        )
        .route("/api/orders", get(api::list_orders))
        .route("/api/orders/{id}", get(api::get_order))
        .route("/api/accounts", get(api::list_accounts))
        .route("/ws", get(ws::handler))
        // The one URL an ACME client is expected to know in advance —
        // unauthenticated, unnested, so it stays reachable at the bare
        // base URL regardless of how /acme/* itself is laid out.
        .route("/directory", get(acme::directory::directory))
        .nest("/acme", acme::router(state.clone()))
        .fallback(static_assets::handler)
        .layer(from_fn_with_state(state.clone(), access_log::record))
        .with_state(state)
}
