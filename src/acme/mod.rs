pub mod account;
pub mod authz;
pub mod cert;
pub mod challenge;
pub mod directory;
pub mod error;
pub mod jws;
pub mod nonce;
pub mod order;
mod urls;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::state::SharedState;

/// Everything under `/acme/*` (the directory endpoint itself is exempt —
/// it's the one URL a client is expected to already know, so it's
/// unauthenticated and lives at the top level; see `routes::router`).
///
/// Deliberately left as `Router<SharedState>` rather than calling
/// `.with_state()` here — `routes::router` nests this into a still-stateful
/// outer router and erases state once for the whole assembled tree, which
/// is what lets both routers share a single `Arc<AppState>` clone.
pub fn router(state: SharedState) -> Router<SharedState> {
    Router::new()
        .route("/new-nonce", get(new_nonce))
        .route("/new-account", post(account::new_account))
        .route("/account/{id}", post(account::update_account))
        .route("/new-order", post(order::new_order))
        .route("/order/{id}", post(order::get_order))
        .route("/order/{id}/finalize", post(order::finalize_order))
        .route("/authz/{id}", post(authz::get_authz))
        .route("/challenge/{id}", post(challenge::respond_challenge))
        .route("/cert/{id}", post(cert::download_certificate))
        .route("/revoke-cert", post(cert::revoke_cert))
        // Without its own fallback, an unmatched /acme/* path falls
        // through to the outer router's fallback — the SPA/static-asset
        // handler — and an ACME client gets an HTML page (or a 503 "UI
        // not built" notice in dev) instead of a problem+json 404.
        .fallback(acme_not_found)
        .layer(middleware::from_fn_with_state(state, attach_replay_nonce))
}

async fn acme_not_found() -> error::AcmeError {
    error::AcmeError::not_found("no such ACME resource")
}

/// RFC 8555 §7.2 — a client without a nonce yet fetches one here. The
/// nonce itself comes from `attach_replay_nonce` below, same as on every
/// other `/acme/*` response; this handler only needs to exist so there's
/// something for that middleware to attach it to.
///
/// Must be 200, not 204 — the RFC's own example response for this
/// endpoint is `200 OK`, and at least one real client (`instant-acme`)
/// checks for exactly that status and errors out otherwise.
async fn new_nonce() -> StatusCode {
    StatusCode::OK
}

/// RFC 8555 §6.5 — every response from an ACME resource carries a fresh
/// `Replay-Nonce`, success or error alike, so a client always has one on
/// hand for its next request. Centralized here rather than in each
/// handler so nothing can forget it.
async fn attach_replay_nonce(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&state.nonces.issue()) {
        response.headers_mut().insert("Replay-Nonce", value);
    }
    response
}
