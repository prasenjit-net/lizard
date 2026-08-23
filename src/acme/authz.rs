use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::challenge;
use super::error::AcmeError;
use super::order::{self, Identifier};
use super::{account, jws};
use crate::db::Db;
use crate::state::SharedState;

pub struct AuthzRow {
    pub id: String,
    pub order_id: String,
    pub identifier: Identifier,
    pub status: String,
    pub wildcard: bool,
    pub expires: String,
}

pub(crate) fn find_authz(db: &Db, id: &str) -> Result<Option<AuthzRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, order_id, identifier_type, identifier_value, status, wildcard, expires \
         FROM authorizations WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(AuthzRow {
            id: row.get(0)?,
            order_id: row.get(1)?,
            identifier: Identifier {
                kind: row.get(2)?,
                value: row.get(3)?,
            },
            status: row.get(4)?,
            wildcard: row.get::<_, i64>(5)? != 0,
            expires: row.get(6)?,
        })),
        None => Ok(None),
    }
}

fn authz_response(state: &SharedState, authz: &AuthzRow) -> Result<Response, AcmeError> {
    let challenges = challenge::find_for_authorization(&state.db, &authz.id)?;
    let mut body = json!({
        "identifier": authz.identifier,
        "status": authz.status,
        "expires": authz.expires,
        "challenges": challenges
            .iter()
            .map(|c| challenge::challenge_json(state, c))
            .collect::<Vec<_>>(),
    });
    if authz.wildcard {
        body["wildcard"] = json!(true);
    }
    Ok((axum::http::StatusCode::OK, Json(body)).into_response())
}

/// POST-as-GET `/acme/authz/{id}` (RFC 8555 §7.5). Same not-found-over-
/// forbidden ownership policy as `order::get_order`.
pub async fn get_authz(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = super::urls::authz(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, _payload) = account::authenticate(&state, parsed)?;

    let authz =
        find_authz(&state.db, &id)?.ok_or_else(|| AcmeError::not_found("no such authorization"))?;
    let owner = order::order_account_id(&state.db, &authz.order_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned authorization"))?;
    if owner != account.id {
        return Err(AcmeError::not_found("no such authorization"));
    }

    authz_response(&state, &authz)
}
