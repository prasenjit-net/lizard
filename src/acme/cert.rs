use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::error::AcmeError;
use super::{account, jws, order, urls};
use crate::state::SharedState;

struct CertificateRow {
    order_id: String,
    pem_chain: String,
}

fn find_certificate(db: &crate::db::Db, id: &str) -> Result<Option<CertificateRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare("SELECT order_id, pem_chain FROM certificates WHERE id = ?1")?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(CertificateRow {
            order_id: row.get(0)?,
            pem_chain: row.get(1)?,
        })),
        None => Ok(None),
    }
}

/// POST-as-GET `/acme/cert/{id}` (RFC 8555 §7.4.2). This server signs
/// directly off its root with no intermediate (see `crate::ca`), so the
/// "chain" here is just the one leaf certificate — nothing else to
/// concatenate onto it.
pub async fn download_certificate(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::certificate(&state, &id);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, _payload) = account::authenticate(&state, parsed)?;

    let certificate = find_certificate(&state.db, &id)?
        .ok_or_else(|| AcmeError::not_found("no such certificate"))?;
    let owner = order::order_account_id(&state.db, &certificate.order_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned certificate"))?;
    if owner != account.id {
        return Err(AcmeError::not_found("no such certificate"));
    }

    let mut response = (StatusCode::OK, certificate.pem_chain).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    Ok(response)
}
