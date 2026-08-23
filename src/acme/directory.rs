use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::urls;
use crate::state::SharedState;

/// RFC 8555 §7.1.1 — the one endpoint a client is expected to know in
/// advance; every other URL is discovered from here. Unauthenticated GET,
/// served at the top-level `/directory` rather than nested under `/acme`.
pub async fn directory(State(state): State<SharedState>) -> Json<Value> {
    let base = &state.external_base_url;
    Json(json!({
        "newNonce": format!("{base}/acme/new-nonce"),
        "newAccount": urls::new_account(&state),
        "newOrder": urls::new_order(&state),
        "revokeCert": urls::revoke_cert(&state),
        "keyChange": format!("{base}/acme/key-change"),
    }))
}
