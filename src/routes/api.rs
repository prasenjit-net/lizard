use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};

use crate::acme::order::Identifier;
use crate::error::{AppError, AppResult};
use crate::services::metrics::MetricsSnapshot;
use crate::services::tasks::{NewTask, Task};
use crate::state::SharedState;

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// Bootstrap configuration for the SPA, sourced from config.toml.
pub async fn config(State(state): State<SharedState>) -> Json<Value> {
    Json(json!({
        "ui": state.config.ui,
        "version": env!("CARGO_PKG_VERSION"),
        "startedAtMs": state.started_at_ms,
    }))
}

pub async fn metrics(State(state): State<SharedState>) -> AppResult<Json<MetricsSnapshot>> {
    state
        .latest_metrics
        .read()
        .await
        .clone()
        .map(Json)
        .ok_or_else(|| AppError::Internal("metrics are not available yet".into()))
}

pub async fn list_tasks(State(state): State<SharedState>) -> Json<Vec<Task>> {
    Json(state.tasks.list().await)
}

pub async fn create_task(
    State(state): State<SharedState>,
    Json(body): Json<NewTask>,
) -> AppResult<(StatusCode, Json<Task>)> {
    let task = state.tasks.create(&body.title).await?;
    state.activity("task", format!("Task \"{}\" created", task.title));
    Ok((StatusCode::CREATED, Json(task)))
}

pub async fn toggle_task(
    State(state): State<SharedState>,
    Path(id): Path<u64>,
) -> AppResult<Json<Task>> {
    let task = state.tasks.toggle(id).await?;
    let verb = if task.done { "completed" } else { "reopened" };
    state.activity("task", format!("Task \"{}\" {verb}", task.title));
    Ok(Json(task))
}

pub async fn delete_task(
    State(state): State<SharedState>,
    Path(id): Path<u64>,
) -> AppResult<StatusCode> {
    let task = state.tasks.delete(id).await?;
    state.activity("task", format!("Task \"{}\" deleted", task.title));
    Ok(StatusCode::NO_CONTENT)
}

/// Always fails — lets the UI demonstrate the whole error pipeline.
/// `?kind=bad-request|not-found|internal` picks the failure mode.
pub async fn error_demo(Query(params): Query<HashMap<String, String>>) -> AppResult<Json<Value>> {
    let kind = params.get("kind").map(String::as_str).unwrap_or("internal");
    Err(match kind {
        "bad-request" => {
            AppError::BadRequest("the request payload failed validation (demo)".into())
        }
        "not-found" => AppError::NotFound("the demo resource does not exist (demo)".into()),
        _ => AppError::Internal("something exploded deep inside the server (demo)".into()),
    })
}

/// The CA's root certificate, for the admin UI to display/download for
/// installation into trust stores.
pub async fn ca_info(State(state): State<SharedState>) -> Json<Value> {
    Json(json!({ "rootCertPem": state.ca.root_cert_pem() }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummary {
    id: String,
    order_id: String,
    identifiers: Vec<String>,
    serial: String,
    status: &'static str,
    issued_at: String,
    revoked_at: Option<String>,
}

/// Every certificate this server has issued, newest first — the admin
/// UI's certificate table. Plain `/api/*` shape (this envelope, not ACME's
/// problem+json), since this is operator tooling, not an ACME endpoint.
pub async fn list_certificates(
    State(state): State<SharedState>,
) -> AppResult<Json<Vec<CertificateSummary>>> {
    let conn = state.db.conn();
    let mut stmt = conn.prepare(
        "SELECT certificates.id, certificates.order_id, orders.identifiers_json, \
                certificates.serial, certificates.issued_at, certificates.revoked_at \
         FROM certificates JOIN orders ON orders.id = certificates.order_id \
         ORDER BY certificates.issued_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let certificates = rows
        .into_iter()
        .map(
            |(id, order_id, identifiers_json, serial, issued_at, revoked_at)| {
                let identifiers: Vec<Identifier> =
                    serde_json::from_str(&identifiers_json).unwrap_or_default();
                CertificateSummary {
                    id,
                    order_id,
                    identifiers: identifiers.into_iter().map(|i| i.value).collect(),
                    serial,
                    status: if revoked_at.is_some() {
                        "revoked"
                    } else {
                        "valid"
                    },
                    issued_at,
                    revoked_at,
                }
            },
        )
        .collect();

    Ok(Json(certificates))
}

/// Operator-triggered revocation from the admin UI — distinct from
/// `acme::cert::revoke_cert`, which requires a JWS-signed ACME request an
/// operator sitting at a browser doesn't have. This talks to the database
/// directly; it's trusted the same way the rest of `/api/*` already is
/// (no auth on this app's admin surface at all yet).
pub async fn revoke_certificate(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let conn = state.db.conn();
    let revoked_at: Option<Option<String>> = conn
        .query_row(
            "SELECT revoked_at FROM certificates WHERE id = ?1",
            [&id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(revoked_at) = revoked_at else {
        return Err(AppError::NotFound(format!(
            "certificate {id} does not exist"
        )));
    };
    if revoked_at.is_some() {
        return Err(AppError::BadRequest(
            "certificate is already revoked".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE certificates SET revoked_at = ?1 WHERE id = ?2",
        params![now, id],
    )?;

    state.activity("certificate", format!("certificate {id} revoked via admin"));
    Ok(StatusCode::NO_CONTENT)
}
