use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// ACME's own error envelope (RFC 8555 §6.7 / RFC 7807
/// `application/problem+json`) — deliberately not `crate::error::AppError`.
/// The two envelopes have different shapes (`type`/`detail`/`status` here
/// vs `error.code`/`error.message` there), and forcing ACME errors through
/// the rest of the app's envelope would corrupt one or the other.
#[derive(Debug)]
pub struct AcmeError {
    status: StatusCode,
    kind: &'static str,
    detail: String,
}

impl AcmeError {
    fn new(status: StatusCode, kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            detail: detail.into(),
        }
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "malformed", detail)
    }

    pub fn bad_nonce() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "badNonce",
            "the request's nonce was missing, unknown, or already used",
        )
    }

    pub fn bad_signature_algorithm() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "badSignatureAlgorithm",
            "unsupported JWS algorithm — only ES256 and RS256 are accepted",
        )
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "unauthorized", detail)
    }

    pub fn account_does_not_exist() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "accountDoesNotExist",
            "no account exists for this key",
        )
    }

    /// RFC 8555 doesn't define an error `type` for "no such resource" the
    /// way it does for the others — `malformed` is the closest fit and
    /// what other implementations use for an unrecognized path.
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "malformed", detail)
    }

    // order_not_ready / bad_csr / rejected_identifier land with the
    // order/authz/finalize handlers in a later milestone — added here
    // early they'd just be unused `pub fn`s (this is a binary crate, so
    // `dead_code` fires on those same as anything private).

    pub fn server_internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "serverInternal", detail)
    }
}

impl From<crate::error::AppError> for AcmeError {
    fn from(err: crate::error::AppError) -> Self {
        tracing::error!("acme request failed: {err}");
        Self::server_internal("an internal error occurred")
    }
}

impl From<rusqlite::Error> for AcmeError {
    fn from(err: rusqlite::Error) -> Self {
        tracing::error!("acme request failed: {err}");
        Self::server_internal("an internal error occurred")
    }
}

impl IntoResponse for AcmeError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(kind = self.kind, "acme request failed: {}", self.detail);
        } else {
            tracing::debug!(kind = self.kind, "acme request rejected: {}", self.detail);
        }
        let body = json!({
            "type": format!("urn:ietf:params:acme:error:{}", self.kind),
            "detail": self.detail,
            "status": self.status.as_u16(),
        });
        let mut response = (self.status, Json(body)).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
