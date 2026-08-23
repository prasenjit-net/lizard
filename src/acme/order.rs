use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::challenge;
use super::error::AcmeError;
use super::urls;
use super::{account, jws};
use crate::db::Db;
use crate::state::SharedState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

pub struct OrderRow {
    pub id: String,
    pub account_id: String,
    pub status: String,
    pub identifiers: Vec<Identifier>,
    pub expires: String,
    pub certificate_id: Option<String>,
    pub authorization_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NewOrderPayload {
    identifiers: Vec<Identifier>,
}

fn order_response(state: &SharedState, order: &OrderRow, status: StatusCode) -> Response {
    let url = urls::order(state, &order.id);
    let authorizations: Vec<String> = order
        .authorization_ids
        .iter()
        .map(|id| urls::authz(state, id))
        .collect();

    let mut body = json!({
        "status": order.status,
        "expires": order.expires,
        "identifiers": order.identifiers,
        "authorizations": authorizations,
        "finalize": urls::order_finalize(state, &order.id),
    });
    if let Some(certificate_id) = &order.certificate_id {
        body["certificate"] = json!(urls::certificate(state, certificate_id));
    }

    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&url).unwrap(),
    );
    response
}

pub(crate) fn find_order(db: &Db, id: &str) -> Result<Option<OrderRow>, AcmeError> {
    let conn = db.conn();

    let base = {
        let mut stmt = conn.prepare(
            "SELECT id, account_id, status, identifiers_json, expires, certificate_id \
             FROM orders WHERE id = ?1",
        )?;
        let mut rows = stmt.query([id])?;
        match rows.next()? {
            Some(row) => Some((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            )),
            None => None,
        }
    };
    let Some((order_id, account_id, status, identifiers_json, expires, certificate_id)) = base
    else {
        return Ok(None);
    };

    let authorization_ids: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT id FROM authorizations WHERE order_id = ?1 ORDER BY id")?;
        let ids = stmt
            .query_map([&order_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        ids
    };

    let identifiers: Vec<Identifier> = serde_json::from_str(&identifiers_json)
        .map_err(|_| AcmeError::server_internal("corrupt order record"))?;

    Ok(Some(OrderRow {
        id: order_id,
        account_id,
        status,
        identifiers,
        expires,
        certificate_id,
        authorization_ids,
    }))
}

/// Just the owning account id, for the ownership checks authz/challenge
/// handlers need without pulling in the rest of the order.
pub(crate) fn order_account_id(db: &Db, order_id: &str) -> Result<Option<String>, AcmeError> {
    let conn = db.conn();
    Ok(conn
        .query_row(
            "SELECT account_id FROM orders WHERE id = ?1",
            [order_id],
            |row| row.get(0),
        )
        .ok())
}

/// `POST /acme/new-order` (RFC 8555 §7.4). Only `dns` identifiers are
/// accepted, and wildcards are rejected outright — they're only valid
/// with dns-01, which this server doesn't implement yet (http-01 can't
/// prove control of an entire subdomain space), so accepting one here
/// would create an order that can never be validated.
pub async fn new_order(
    State(state): State<SharedState>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::new_order(&state);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, payload) = account::authenticate(&state, parsed)?;

    let payload: NewOrderPayload = serde_json::from_slice(&payload)
        .map_err(|_| AcmeError::malformed("invalid request body"))?;

    if payload.identifiers.is_empty() {
        return Err(AcmeError::malformed("at least one identifier is required"));
    }
    for identifier in &payload.identifiers {
        if identifier.kind != "dns" {
            return Err(AcmeError::rejected_identifier(format!(
                "unsupported identifier type: {}",
                identifier.kind
            )));
        }
        if identifier.value.starts_with("*.") {
            return Err(AcmeError::rejected_identifier(
                "wildcard identifiers require dns-01, which this server does not support yet",
            ));
        }
    }

    let order_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let expires = (now + chrono::Duration::hours(24)).to_rfc3339();
    let identifiers_json = serde_json::to_string(&payload.identifiers)
        .map_err(|_| AcmeError::server_internal("failed to serialize identifiers"))?;

    {
        let mut conn = state.db.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO orders (id, account_id, status, identifiers_json, expires, created_at) \
             VALUES (?1, ?2, 'pending', ?3, ?4, ?5)",
            params![
                order_id,
                account.id,
                identifiers_json,
                expires,
                now.to_rfc3339()
            ],
        )?;
        for identifier in &payload.identifiers {
            let authz_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO authorizations \
                 (id, order_id, identifier_type, identifier_value, status, wildcard, expires) \
                 VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5)",
                params![
                    authz_id,
                    order_id,
                    identifier.kind,
                    identifier.value,
                    expires
                ],
            )?;
            challenge::insert_pending_http01(&tx, &authz_id)?;
        }
        tx.commit()?;
    }

    let order = find_order(&state.db, &order_id)?
        .ok_or_else(|| AcmeError::server_internal("order vanished immediately after insert"))?;
    Ok(order_response(&state, &order, StatusCode::CREATED))
}

/// POST-as-GET `/acme/order/{id}` (RFC 8555 §7.1.3 / §7.5). An order not
/// owned by the authenticated account is reported as not-found rather
/// than forbidden, so a client can't use this to probe which order ids
/// belong to someone else.
pub async fn get_order(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::order(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, _payload) = account::authenticate(&state, parsed)?;

    let order = find_order(&state.db, &id)?.ok_or_else(|| AcmeError::not_found("no such order"))?;
    if order.account_id != account.id {
        return Err(AcmeError::not_found("no such order"));
    }

    Ok(order_response(&state, &order, StatusCode::OK))
}
