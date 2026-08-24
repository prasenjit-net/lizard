use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::params;
use serde::Deserialize;

use super::error::AcmeError;
use super::{account, jws, order, urls};
use crate::db::Db;
use crate::state::SharedState;

struct CertificateRow {
    id: String,
    order_id: String,
    pem_chain: String,
    revoked_at: Option<String>,
}

const CERTIFICATE_COLUMNS: &str = "id, order_id, pem_chain, revoked_at";

fn row_to_certificate(row: &rusqlite::Row) -> rusqlite::Result<CertificateRow> {
    Ok(CertificateRow {
        id: row.get(0)?,
        order_id: row.get(1)?,
        pem_chain: row.get(2)?,
        revoked_at: row.get(3)?,
    })
}

fn find_certificate(db: &Db, id: &str) -> Result<Option<CertificateRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!(
        "SELECT {CERTIFICATE_COLUMNS} FROM certificates WHERE id = ?1"
    ))?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_certificate(row)?)),
        None => Ok(None),
    }
}

/// Revocation identifies a certificate by its own DER bytes, not by any
/// id of ours — this is how that request gets matched back to a row.
fn find_certificate_by_der_hash(
    db: &Db,
    der_sha256: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!(
        "SELECT {CERTIFICATE_COLUMNS} FROM certificates WHERE der_sha256 = ?1"
    ))?;
    let mut rows = stmt.query([der_sha256])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_certificate(row)?)),
        None => Ok(None),
    }
}

/// POST-as-GET `/acme/cert/{id}` (RFC 8555 §7.4.2). This server signs
/// directly off its root with no intermediate (see `crate::ca`), so the
/// "chain" here is just the one leaf certificate — nothing else to
/// concatenate onto it. Served regardless of revocation status: the
/// certificate still exists and was legitimately issued, revocation just
/// means relying parties shouldn't trust it going forward (which this
/// server has no CRL/OCSP endpoint to communicate yet).
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

#[derive(Debug, Deserialize)]
struct RevokePayload {
    /// Base64url-encoded DER of the certificate to revoke.
    certificate: String,
    /// CRL reason code (RFC 5280 §5.3.1); optional, not validated against
    /// the enum of defined codes in v1.
    reason: Option<i64>,
}

/// `POST /acme/revoke-cert` (RFC 8555 §7.6). Account-key-authenticated
/// only for v1: the caller must be the account that requested the
/// certificate. RFC 8555 also allows revocation authenticated by the
/// certificate's own key (proving possession without needing an ACME
/// account at all) — deferred; a real gap for the "lost my account but
/// still have the key" case, but not one this server closes yet.
pub async fn revoke_cert(
    State(state): State<SharedState>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = urls::revoke_cert(&state);
    let parsed = jws::parse_and_check_nonce(&body, &url, &state.nonces)?;
    let (account, payload) = account::authenticate(&state, parsed)?;

    let payload: RevokePayload = serde_json::from_slice(&payload)
        .map_err(|_| AcmeError::malformed("invalid request body"))?;
    let cert_der = URL_SAFE_NO_PAD
        .decode(&payload.certificate)
        .map_err(|_| AcmeError::malformed("certificate is not valid base64url"))?;
    let der_sha256 = URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, &cert_der));

    let certificate = find_certificate_by_der_hash(&state.db, &der_sha256)?
        .ok_or_else(|| AcmeError::malformed("unrecognized certificate"))?;
    let owner = order::order_account_id(&state.db, &certificate.order_id)?
        .ok_or_else(|| AcmeError::server_internal("orphaned certificate"))?;
    if owner != account.id {
        // Per RFC 8555 §7.6, a client not authorized to revoke this
        // specific certificate gets `unauthorized` — unlike the
        // not-found-over-forbidden policy on reads elsewhere in this
        // module, there's no enumeration concern to hide here: reaching
        // this point already required possessing the certificate's own
        // DER bytes, which isn't something a random client would have.
        return Err(AcmeError::unauthorized(
            "this account is not authorized to revoke this certificate",
        ));
    }
    if certificate.revoked_at.is_some() {
        return Err(AcmeError::malformed("certificate has already been revoked"));
    }

    let now = chrono::Utc::now().to_rfc3339();
    state.db.conn().execute(
        "UPDATE certificates SET revoked_at = ?1, revocation_reason = ?2 WHERE id = ?3",
        params![now, payload.reason, certificate.id],
    )?;

    state.audit(
        "certificate",
        format!("revoked certificate {}", certificate.id),
    );

    Ok(StatusCode::OK.into_response())
}
