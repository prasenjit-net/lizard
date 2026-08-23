use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use rusqlite::params;
use serde_json::{json, Value};
use uuid::Uuid;

use super::authz::{self, AuthzRow};
use super::error::AcmeError;
use super::{account, jws, order, urls};
use crate::db::Db;
use crate::state::SharedState;

pub struct ChallengeRow {
    pub id: String,
    pub authorization_id: String,
    pub kind: String,
    pub token: String,
    pub status: String,
    pub validated_at: Option<String>,
}

/// Inserts a `pending` http-01 challenge for a freshly created
/// authorization, inside the caller's transaction — the only challenge
/// type this server supports (dns-01/tls-alpn-01 are later extensions),
/// so `new_order` always creates exactly one per identifier.
pub(crate) fn insert_pending_http01(
    tx: &rusqlite::Transaction<'_>,
    authorization_id: &str,
) -> Result<(), AcmeError> {
    let id = Uuid::new_v4().to_string();
    let mut token_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);
    tx.execute(
        "INSERT INTO challenges (id, authorization_id, type, token, status) \
         VALUES (?1, ?2, 'http-01', ?3, 'pending')",
        params![id, authorization_id, token],
    )?;
    Ok(())
}

pub(crate) fn find_for_authorization(
    db: &Db,
    authorization_id: &str,
) -> Result<Vec<ChallengeRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, authorization_id, type, token, status, validated_at \
         FROM challenges WHERE authorization_id = ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map([authorization_id], |row| {
            Ok(ChallengeRow {
                id: row.get(0)?,
                authorization_id: row.get(1)?,
                kind: row.get(2)?,
                token: row.get(3)?,
                status: row.get(4)?,
                validated_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn find_challenge(db: &Db, id: &str) -> Result<Option<ChallengeRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, authorization_id, type, token, status, validated_at \
         FROM challenges WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(ChallengeRow {
            id: row.get(0)?,
            authorization_id: row.get(1)?,
            kind: row.get(2)?,
            token: row.get(3)?,
            status: row.get(4)?,
            validated_at: row.get(5)?,
        })),
        None => Ok(None),
    }
}

pub(crate) fn challenge_json(state: &SharedState, challenge: &ChallengeRow) -> Value {
    let mut body = json!({
        "type": challenge.kind,
        "url": urls::challenge(state, &challenge.id),
        "status": challenge.status,
        "token": challenge.token,
    });
    if let Some(validated_at) = &challenge.validated_at {
        body["validated"] = json!(validated_at);
    }
    body
}

/// `POST /acme/challenge/{id}` (RFC 8555 §7.5.1) — the client signals
/// it's ready to be checked. Real http-01 validation (an outbound fetch)
/// lands in a later milestone; for now this stands in with an
/// always-succeeds stub so the pending → valid → order-ready state
/// machine can be exercised end to end before that exists.
pub async fn respond_challenge(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::challenge(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, _payload) = account::authenticate(&state, parsed)?;

    let challenge =
        find_challenge(&state.db, &id)?.ok_or_else(|| AcmeError::not_found("no such challenge"))?;
    let authz = authz::find_authz(&state.db, &challenge.authorization_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned challenge"))?;
    let owner = order::order_account_id(&state.db, &authz.order_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned authorization"))?;
    if owner != account.id {
        return Err(AcmeError::not_found("no such challenge"));
    }

    if challenge.status == "pending" {
        validate_dev_stub(&state, &challenge, &authz)?;
    }

    let challenge = find_challenge(&state.db, &id)?
        .ok_or_else(|| AcmeError::server_internal("challenge vanished mid-request"))?;
    Ok((StatusCode::OK, Json(challenge_json(&state, &challenge))).into_response())
}

fn validate_dev_stub(
    state: &SharedState,
    challenge: &ChallengeRow,
    authz: &AuthzRow,
) -> Result<(), AcmeError> {
    let now = chrono::Utc::now().to_rfc3339();
    {
        let mut conn = state.db.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE challenges SET status = 'valid', validated_at = ?1 WHERE id = ?2",
            params![now, challenge.id],
        )?;
        tx.execute(
            "UPDATE authorizations SET status = 'valid' WHERE id = ?1",
            [&authz.id],
        )?;

        let still_pending: i64 = tx.query_row(
            "SELECT count(*) FROM authorizations WHERE order_id = ?1 AND status != 'valid'",
            [&authz.order_id],
            |row| row.get(0),
        )?;
        if still_pending == 0 {
            tx.execute(
                "UPDATE orders SET status = 'ready' WHERE id = ?1",
                [&authz.order_id],
            )?;
        }
        tx.commit()?;
    }

    state.activity(
        "certificate",
        format!(
            "authorization for \"{}\" validated (dev-mode stub)",
            authz.identifier.value
        ),
    );
    Ok(())
}
