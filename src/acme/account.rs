use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::error::AcmeError;
use super::jws::{self, Jwk, KeyId, ParsedJws};
use super::urls;
use crate::db::Db;
use crate::state::SharedState;

pub struct AccountRow {
    pub id: String,
    pub jwk: Jwk,
    pub status: String,
    pub contact: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NewAccountPayload {
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AccountUpdate {
    contact: Option<Vec<String>>,
    status: Option<String>,
}

fn account_response(state: &SharedState, account: &AccountRow, status: StatusCode) -> Response {
    let url = urls::account(state, &account.id);
    let mut body = json!({
        "status": account.status,
        "orders": format!("{url}/orders"),
    });
    if let Some(contact) = &account.contact {
        body["contact"] = json!(contact);
    }
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&url).unwrap(),
    );
    response
}

fn row_from_query(
    id: String,
    jwk_json: String,
    status: String,
    contact_json: Option<String>,
) -> Result<AccountRow, AcmeError> {
    let jwk: Jwk = serde_json::from_str(&jwk_json)
        .map_err(|_| AcmeError::server_internal("corrupt account record"))?;
    let contact = contact_json
        .map(|c| serde_json::from_str(&c))
        .transpose()
        .map_err(|_| AcmeError::server_internal("corrupt account record"))?;
    Ok(AccountRow {
        id,
        jwk,
        status,
        contact,
    })
}

fn find_by_thumbprint(db: &Db, thumbprint: &str) -> Result<Option<AccountRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, jwk_json, status, contact_json FROM accounts WHERE jwk_thumbprint = ?1",
    )?;
    let mut rows = stmt.query([thumbprint])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_from_query(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
        )?)),
        None => Ok(None),
    }
}

fn find_by_id(db: &Db, id: &str) -> Result<Option<AccountRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt =
        conn.prepare("SELECT id, jwk_json, status, contact_json FROM accounts WHERE id = ?1")?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_from_query(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
        )?)),
        None => Ok(None),
    }
}

/// Resolves a `kid`-authenticated JWS to the account it claims to be from,
/// verifies the signature against that account's *stored* key (never a
/// key the request itself supplied), and checks the account is still
/// `valid`. The building block every authenticated ACME endpoint beyond
/// account creation uses — orders, authorizations, challenges, finalize,
/// and revocation all authenticate the exact same way.
pub fn authenticate(
    state: &SharedState,
    parsed: ParsedJws,
) -> Result<(AccountRow, Vec<u8>), AcmeError> {
    let KeyId::Kid(kid) = &parsed.key_id else {
        return Err(AcmeError::malformed(
            "this request must be authenticated with kid, not an embedded jwk",
        ));
    };
    let prefix = format!("{}/acme/account/", state.external_base_url);
    let id = kid
        .strip_prefix(&prefix)
        .ok_or_else(|| AcmeError::malformed("unrecognized kid"))?;

    let account = find_by_id(&state.db, id)?.ok_or_else(AcmeError::account_does_not_exist)?;
    if account.status != "valid" {
        return Err(AcmeError::unauthorized("account is not valid"));
    }

    let key = account.jwk.clone();
    let payload = parsed.verify_signature(&key)?;
    Ok((account, payload))
}

/// `POST /acme/new-account` (RFC 8555 §7.3).
pub async fn new_account(
    State(state): State<SharedState>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::new_account(&state);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;

    let KeyId::Jwk(jwk) = parsed.key_id.clone() else {
        return Err(AcmeError::malformed(
            "new-account requires an embedded jwk, not kid",
        ));
    };
    let payload = parsed.verify_signature(&jwk)?;
    let payload: NewAccountPayload = if payload.is_empty() {
        NewAccountPayload::default()
    } else {
        serde_json::from_slice(&payload)
            .map_err(|_| AcmeError::malformed("invalid request body"))?
    };

    let thumbprint = jwk.thumbprint()?;

    if let Some(existing) = find_by_thumbprint(&state.db, &thumbprint)? {
        return Ok(account_response(&state, &existing, StatusCode::OK));
    }

    if payload.only_return_existing.unwrap_or(false) {
        return Err(AcmeError::account_does_not_exist());
    }

    let id = Uuid::new_v4().to_string();
    let jwk_json = serde_json::to_string(&jwk)
        .map_err(|_| AcmeError::server_internal("failed to serialize jwk"))?;
    let contact_json = payload
        .contact
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| AcmeError::server_internal("failed to serialize contact"))?;
    let created_at = chrono::Utc::now().to_rfc3339();
    let tos_agreed = payload.terms_of_service_agreed.unwrap_or(false);

    state.db.conn().execute(
        "INSERT INTO accounts (id, jwk_thumbprint, jwk_json, status, contact_json, tos_agreed, created_at) \
         VALUES (?1, ?2, ?3, 'valid', ?4, ?5, ?6)",
        params![id, thumbprint, jwk_json, contact_json, tos_agreed, created_at],
    )?;

    let account = AccountRow {
        id,
        jwk,
        status: "valid".to_string(),
        contact: payload.contact,
    };
    state.audit("account", format!("created ACME account {}", account.id));
    Ok(account_response(&state, &account, StatusCode::CREATED))
}

/// `POST /acme/account/{id}` (RFC 8555 §7.3.2) — contact changes and
/// deactivation. `{id}` in the URL is only used to build the expected JWS
/// `url`; the account actually acted on is whichever one `kid` resolves
/// to, and the two are required to match so a request signed by account A
/// can never modify account B's resource just because its URL says so.
pub async fn update_account(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::account(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (mut account, payload) = authenticate(&state, parsed)?;
    if account.id != id {
        return Err(AcmeError::malformed(
            "kid does not match the account this request was sent to",
        ));
    }

    let update: AccountUpdate = if payload.is_empty() {
        AccountUpdate::default()
    } else {
        serde_json::from_slice(&payload)
            .map_err(|_| AcmeError::malformed("invalid request body"))?
    };

    let mut changes = Vec::new();
    if let Some(status) = &update.status {
        if status != "deactivated" {
            return Err(AcmeError::malformed(
                "status can only be set to deactivated",
            ));
        }
        state.db.conn().execute(
            "UPDATE accounts SET status = 'deactivated' WHERE id = ?1",
            [&account.id],
        )?;
        account.status = "deactivated".to_string();
        changes.push("deactivated".to_string());
    }

    if let Some(contact) = update.contact {
        let contact_json = serde_json::to_string(&contact)
            .map_err(|_| AcmeError::server_internal("failed to serialize contact"))?;
        state.db.conn().execute(
            "UPDATE accounts SET contact_json = ?1 WHERE id = ?2",
            params![contact_json, &account.id],
        )?;
        account.contact = Some(contact);
        changes.push("updated contact".to_string());
    }

    if !changes.is_empty() {
        state.audit(
            "account",
            format!("{} account {}", changes.join(" and "), account.id),
        );
    }

    Ok(account_response(&state, &account, StatusCode::OK))
}
