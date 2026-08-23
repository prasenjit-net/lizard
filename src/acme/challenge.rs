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

#[derive(Clone)]
pub struct ChallengeRow {
    pub id: String,
    pub authorization_id: String,
    pub kind: String,
    pub token: String,
    pub status: String,
    pub validated_at: Option<String>,
    pub error_json: Option<String>,
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

const CHALLENGE_COLUMNS: &str =
    "id, authorization_id, type, token, status, validated_at, error_json";

fn row_to_challenge(row: &rusqlite::Row) -> rusqlite::Result<ChallengeRow> {
    Ok(ChallengeRow {
        id: row.get(0)?,
        authorization_id: row.get(1)?,
        kind: row.get(2)?,
        token: row.get(3)?,
        status: row.get(4)?,
        validated_at: row.get(5)?,
        error_json: row.get(6)?,
    })
}

pub(crate) fn find_for_authorization(
    db: &Db,
    authorization_id: &str,
) -> Result<Vec<ChallengeRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!(
        "SELECT {CHALLENGE_COLUMNS} FROM challenges WHERE authorization_id = ?1 ORDER BY id"
    ))?;
    let rows = stmt
        .query_map([authorization_id], row_to_challenge)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn find_challenge(db: &Db, id: &str) -> Result<Option<ChallengeRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!(
        "SELECT {CHALLENGE_COLUMNS} FROM challenges WHERE id = ?1"
    ))?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_challenge(row)?)),
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
    if let Some(error_json) = &challenge.error_json {
        if let Ok(error) = serde_json::from_str::<Value>(error_json) {
            body["error"] = error;
        }
    }
    body
}

/// `POST /acme/challenge/{id}` (RFC 8555 §7.5.1) — the client signals
/// it's ready to be checked. Responds immediately with the challenge
/// moved to `processing` and validates in the background (an outbound
/// HTTP fetch can take longer than we want to hold this request open
/// for); the client is expected to poll the authorization/order
/// afterward to see the final `valid`/`invalid` status. A second POST
/// while already `processing`, or after a terminal status, just returns
/// the current state without re-triggering validation.
pub async fn respond_challenge(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::challenge(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, _payload) = account::authenticate(&state, parsed)?;

    let mut challenge =
        find_challenge(&state.db, &id)?.ok_or_else(|| AcmeError::not_found("no such challenge"))?;
    let authz = authz::find_authz(&state.db, &challenge.authorization_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned challenge"))?;
    let owner = order::order_account_id(&state.db, &authz.order_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned authorization"))?;
    if owner != account.id {
        return Err(AcmeError::not_found("no such challenge"));
    }

    if challenge.status == "pending" {
        state.db.conn().execute(
            "UPDATE challenges SET status = 'processing' WHERE id = ?1",
            [&challenge.id],
        )?;
        challenge.status = "processing".to_string();

        let key_authorization = format!("{}.{}", challenge.token, account.jwk.thumbprint()?);
        state.activity(
            "challenge",
            format!(
                "started http-01 validation for \"{}\"",
                authz.identifier.value
            ),
        );
        spawn_validation(state.clone(), challenge.clone(), authz, key_authorization);
    }

    Ok((StatusCode::OK, Json(challenge_json(&state, &challenge))).into_response())
}

#[derive(Debug)]
enum ValidationFailure {
    /// Couldn't even complete the HTTP exchange — DNS/connect/timeout, or
    /// a non-2xx status.
    Connection(String),
    /// Got a response, but its body wasn't the expected key authorization.
    IncorrectResponse(String),
}

impl ValidationFailure {
    fn urn(&self) -> &'static str {
        match self {
            ValidationFailure::Connection(_) => "urn:ietf:params:acme:error:connection",
            ValidationFailure::IncorrectResponse(_) => {
                "urn:ietf:params:acme:error:incorrectResponse"
            }
        }
    }

    fn detail(&self) -> &str {
        match self {
            ValidationFailure::Connection(detail)
            | ValidationFailure::IncorrectResponse(detail) => detail,
        }
    }
}

const USER_AGENT: &str = concat!("lizard-acme/", env!("CARGO_PKG_VERSION"));

/// RFC 8555 §8.3 — fetches `http://{domain}/.well-known/acme-challenge/{token}`
/// and checks the body equals the expected key authorization exactly
/// (trimmed, since a well-behaved server serving a text file may add a
/// trailing newline).
///
/// Known limitation: `domain` comes straight from a client-submitted
/// identifier with no allow/deny-listing of the IP addresses it resolves
/// to. A real public CA has to guard this path against SSRF (a client
/// naming an internal/metadata address as its "domain"); an internal-only
/// CA is a smaller blast radius but the gap is still real and worth
/// hardening before this server is reachable from anything other than a
/// fully trusted network.
async fn validate_http01(
    client: &reqwest::Client,
    domain: &str,
    token: &str,
    expected_key_authorization: &str,
) -> Result<(), ValidationFailure> {
    let url = format!("http://{domain}/.well-known/acme-challenge/{token}");
    let response = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|err| ValidationFailure::Connection(err.to_string()))?;

    if !response.status().is_success() {
        return Err(ValidationFailure::Connection(format!(
            "unexpected HTTP status {}",
            response.status()
        )));
    }

    let body = response.text().await.map_err(|err| {
        ValidationFailure::Connection(format!("failed to read response body: {err}"))
    })?;

    if body.trim() != expected_key_authorization {
        return Err(ValidationFailure::IncorrectResponse(
            "response body did not match the expected key authorization".to_string(),
        ));
    }

    Ok(())
}

fn spawn_validation(
    state: SharedState,
    challenge: ChallengeRow,
    authz: AuthzRow,
    key_authorization: String,
) {
    tokio::spawn(async move {
        let outcome = validate_http01(
            &state.http_client,
            &authz.identifier.value,
            &challenge.token,
            &key_authorization,
        )
        .await;

        let record_result = match &outcome {
            Ok(()) => record_success(&state, &challenge.id, &authz),
            Err(failure) => record_failure(&state, &challenge.id, &authz, failure),
        };
        if let Err(err) = record_result {
            tracing::error!("failed to record http-01 validation outcome: {err:?}");
            return;
        }

        let message = match &outcome {
            Ok(()) => format!(
                "http-01 validation succeeded for \"{}\"",
                authz.identifier.value
            ),
            Err(failure) => format!(
                "http-01 validation failed for \"{}\": {}",
                authz.identifier.value,
                failure.detail()
            ),
        };
        state.activity("certificate", message);
    });
}

fn record_success(
    state: &SharedState,
    challenge_id: &str,
    authz: &AuthzRow,
) -> Result<(), AcmeError> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut conn = state.db.conn();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE challenges SET status = 'valid', validated_at = ?1 WHERE id = ?2",
        params![now, challenge_id],
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
    Ok(())
}

fn record_failure(
    state: &SharedState,
    challenge_id: &str,
    authz: &AuthzRow,
    failure: &ValidationFailure,
) -> Result<(), AcmeError> {
    let error_json = json!({ "type": failure.urn(), "detail": failure.detail() }).to_string();
    let mut conn = state.db.conn();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE challenges SET status = 'invalid', error_json = ?1 WHERE id = ?2",
        params![error_json, challenge_id],
    )?;
    tx.execute(
        "UPDATE authorizations SET status = 'invalid' WHERE id = ?1",
        [&authz.id],
    )?;
    tx.execute(
        "UPDATE orders SET status = 'invalid' WHERE id = ?1",
        [&authz.order_id],
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use axum::Router;

    use super::*;

    /// Spins up a real HTTP server on an OS-assigned local port serving
    /// `body` at the http-01 well-known path for `token`, and returns the
    /// "domain" (actually `127.0.0.1:port`) to validate against — this
    /// exercises the exact request `validate_http01` makes, over a real
    /// socket, without needing DNS or an actual external host.
    async fn spawn_challenge_server(token: String, body: &'static str) -> String {
        let path = format!("/.well-known/acme-challenge/{token}");
        let app = Router::new().route(&path, get(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn succeeds_when_the_response_body_matches() {
        let domain = spawn_challenge_server("tok-1".to_string(), "tok-1.thumbprint").await;
        let client = reqwest::Client::new();

        let result = validate_http01(&client, &domain, "tok-1", "tok-1.thumbprint").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fails_when_the_response_body_does_not_match() {
        let domain = spawn_challenge_server("tok-2".to_string(), "not-the-right-value").await;
        let client = reqwest::Client::new();

        let result = validate_http01(&client, &domain, "tok-2", "tok-2.thumbprint").await;

        match result.unwrap_err() {
            ValidationFailure::IncorrectResponse(_) => {}
            other => panic!("expected IncorrectResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fails_when_nothing_is_listening() {
        let client = reqwest::Client::new();

        // Port 1 is a reserved low port nothing binds to in test
        // environments, so this reliably fails to connect without
        // depending on any real network access.
        let result = validate_http01(&client, "127.0.0.1:1", "tok-3", "tok-3.thumbprint").await;

        match result.unwrap_err() {
            ValidationFailure::Connection(_) => {}
            other => panic!("expected Connection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_trailing_newline_in_the_response_body_is_tolerated() {
        let domain = spawn_challenge_server("tok-4".to_string(), "tok-4.thumbprint\n").await;
        let client = reqwest::Client::new();

        let result = validate_http01(&client, &domain, "tok-4", "tok-4.thumbprint").await;

        assert!(result.is_ok());
    }
}
