use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

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
        "ca": {
            "certValidityDays": state.config.ca.cert_validity_days,
            "rootValidityYears": state.config.ca.root_validity_years,
        },
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityLogEntry {
    id: i64,
    kind: String,
    summary: String,
    created_at: String,
    timestamp_ms: i64,
}

pub async fn list_activity(
    State(state): State<SharedState>,
) -> AppResult<Json<Vec<ActivityLogEntry>>> {
    let conn = state.db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, kind, summary, created_at, timestamp_ms \
         FROM activity_log ORDER BY timestamp_ms DESC, id DESC LIMIT 250",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ActivityLogEntry {
                id: row.get(0)?,
                kind: row.get(1)?,
                summary: row.get(2)?,
                created_at: row.get(3)?,
                timestamp_ms: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
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
    Json(json!({
        "rootCertPem": state.ca.root_cert_pem(),
        "attributes": parse_cert_attributes(state.ca.root_cert_pem()),
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertExtensionInfo {
    oid: String,
    name: String,
    critical: bool,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertAttributes {
    version: String,
    serial: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    signature_algorithm: String,
    public_key_algorithm: String,
    subject_alt_names: Vec<String>,
    parsed_extensions: ParsedCertExtensions,
    extensions: Vec<CertExtensionInfo>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedCertExtensions {
    authority_key_identifier: Option<AuthorityKeyIdentifierInfo>,
    subject_alternative_name: Option<SubjectAlternativeNameInfo>,
    key_usage: Option<KeyUsageInfo>,
    extended_key_usage: Option<ExtendedKeyUsageInfo>,
    subject_key_identifier: Option<String>,
    basic_constraints: Option<BasicConstraintsInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityKeyIdentifierInfo {
    key_identifier: Option<String>,
    authority_cert_issuer: Vec<String>,
    authority_cert_serial: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectAlternativeNameInfo {
    names: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyUsageInfo {
    flags: Vec<String>,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedKeyUsageInfo {
    usages: Vec<String>,
    any: bool,
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    email_protection: bool,
    time_stamping: bool,
    ocsp_signing: bool,
    other: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicConstraintsInfo {
    ca: bool,
    path_len_constraint: Option<u32>,
}

fn parse_cert_attributes(cert_pem: &str) -> Option<CertAttributes> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
    let parsed_extensions = parse_common_extensions(&cert);
    let subject_alt_names = parsed_extensions
        .subject_alternative_name
        .as_ref()
        .map(|san| san.names.clone())
        .unwrap_or_default();
    let extensions = cert
        .extensions()
        .iter()
        .map(|ext| CertExtensionInfo {
            oid: ext.oid.to_id_string(),
            name: ext.oid.to_string(),
            critical: ext.critical,
            value: format!("{:?}", ext.parsed_extension()),
        })
        .collect();

    Some(CertAttributes {
        version: format!("{:?}", cert.version()),
        serial: cert.raw_serial_as_string(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert
            .validity()
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|_| cert.validity().not_before.to_string()),
        not_after: cert
            .validity()
            .not_after
            .to_rfc2822()
            .unwrap_or_else(|_| cert.validity().not_after.to_string()),
        signature_algorithm: cert.signature_algorithm.algorithm.to_id_string(),
        public_key_algorithm: cert.public_key().algorithm.algorithm.to_id_string(),
        subject_alt_names,
        parsed_extensions,
        extensions,
    })
}

fn parse_common_extensions(cert: &X509Certificate<'_>) -> ParsedCertExtensions {
    let mut parsed = ParsedCertExtensions::default();
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(value) => {
                parsed.authority_key_identifier = Some(AuthorityKeyIdentifierInfo {
                    key_identifier: value.key_identifier.as_ref().map(|id| hex_bytes(id.0)),
                    authority_cert_issuer: value
                        .authority_cert_issuer
                        .as_ref()
                        .map(|names| names.iter().map(format_general_name).collect())
                        .unwrap_or_default(),
                    authority_cert_serial: value.authority_cert_serial.map(hex_bytes),
                });
            }
            ParsedExtension::SubjectAlternativeName(value) => {
                parsed.subject_alternative_name = Some(SubjectAlternativeNameInfo {
                    names: value
                        .general_names
                        .iter()
                        .map(format_general_name)
                        .collect(),
                });
            }
            ParsedExtension::KeyUsage(value) => {
                let flags = key_usage_flags(value);
                parsed.key_usage = Some(KeyUsageInfo {
                    flags,
                    digital_signature: value.digital_signature(),
                    non_repudiation: value.non_repudiation(),
                    key_encipherment: value.key_encipherment(),
                    data_encipherment: value.data_encipherment(),
                    key_agreement: value.key_agreement(),
                    key_cert_sign: value.key_cert_sign(),
                    crl_sign: value.crl_sign(),
                    encipher_only: value.encipher_only(),
                    decipher_only: value.decipher_only(),
                });
            }
            ParsedExtension::ExtendedKeyUsage(value) => {
                let mut usages = Vec::new();
                if value.any {
                    usages.push("Any".to_string());
                }
                if value.server_auth {
                    usages.push("TLS Web Server Authentication".to_string());
                }
                if value.client_auth {
                    usages.push("TLS Web Client Authentication".to_string());
                }
                if value.code_signing {
                    usages.push("Code Signing".to_string());
                }
                if value.email_protection {
                    usages.push("Email Protection".to_string());
                }
                if value.time_stamping {
                    usages.push("Time Stamping".to_string());
                }
                if value.ocsp_signing {
                    usages.push("OCSP Signing".to_string());
                }
                let other = value
                    .other
                    .iter()
                    .map(|oid| oid.to_id_string())
                    .collect::<Vec<_>>();
                usages.extend(other.iter().cloned());
                parsed.extended_key_usage = Some(ExtendedKeyUsageInfo {
                    usages,
                    any: value.any,
                    server_auth: value.server_auth,
                    client_auth: value.client_auth,
                    code_signing: value.code_signing,
                    email_protection: value.email_protection,
                    time_stamping: value.time_stamping,
                    ocsp_signing: value.ocsp_signing,
                    other,
                });
            }
            ParsedExtension::SubjectKeyIdentifier(value) => {
                parsed.subject_key_identifier = Some(hex_bytes(value.0));
            }
            ParsedExtension::BasicConstraints(value) => {
                parsed.basic_constraints = Some(BasicConstraintsInfo {
                    ca: value.ca,
                    path_len_constraint: value.path_len_constraint,
                });
            }
            _ => {}
        }
    }
    parsed
}

fn key_usage_flags(value: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    [
        (value.digital_signature(), "Digital Signature"),
        (value.non_repudiation(), "Non Repudiation"),
        (value.key_encipherment(), "Key Encipherment"),
        (value.data_encipherment(), "Data Encipherment"),
        (value.key_agreement(), "Key Agreement"),
        (value.key_cert_sign(), "Certificate Signing"),
        (value.crl_sign(), "CRL Signing"),
        (value.encipher_only(), "Encipher Only"),
        (value.decipher_only(), "Decipher Only"),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, label)| label.to_string())
    .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_general_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(value) => format!("DNS:{value}"),
        GeneralName::IPAddress(value) => format!(
            "IP:{}",
            value
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(".")
        ),
        GeneralName::RFC822Name(value) => format!("email:{value}"),
        GeneralName::URI(value) => format!("URI:{value}"),
        _ => format!("{name:?}"),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummary {
    id: String,
    order_id: String,
    account_id: String,
    identifiers: Vec<String>,
    serial: String,
    status: &'static str,
    issued_at: String,
    not_after: String,
    revoked_at: Option<String>,
    revocation_reason: Option<i64>,
}

/// Every certificate this server has issued, newest first — the admin
/// UI's certificate table. Plain `/api/*` shape (this envelope, not ACME's
/// problem+json), since this is operator tooling, not an ACME endpoint.
pub async fn list_certificates(
    State(state): State<SharedState>,
) -> AppResult<Json<Vec<CertificateSummary>>> {
    let conn = state.db.conn();
    let mut stmt = conn.prepare(
        "SELECT certificates.id, certificates.order_id, orders.account_id, orders.identifiers_json, \
                certificates.serial, certificates.issued_at, certificates.not_after, \
                certificates.revoked_at, certificates.revocation_reason \
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
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let certificates = rows
        .into_iter()
        .map(
            |(
                id,
                order_id,
                account_id,
                identifiers_json,
                serial,
                issued_at,
                not_after,
                revoked_at,
                revocation_reason,
            )| {
                let identifiers: Vec<Identifier> =
                    serde_json::from_str(&identifiers_json).unwrap_or_default();
                CertificateSummary {
                    id,
                    order_id,
                    account_id,
                    identifiers: identifiers.into_iter().map(|i| i.value).collect(),
                    serial,
                    status: if revoked_at.is_some() {
                        "revoked"
                    } else {
                        "valid"
                    },
                    issued_at,
                    not_after,
                    revoked_at,
                    revocation_reason,
                }
            },
        )
        .collect();

    Ok(Json(certificates))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateDetail {
    id: String,
    order_id: String,
    account_id: String,
    identifiers: Vec<String>,
    serial: String,
    status: &'static str,
    not_before: String,
    not_after: String,
    issued_at: String,
    revoked_at: Option<String>,
    revocation_reason: Option<i64>,
    pem_chain: String,
    attributes: Option<CertAttributes>,
}

/// One certificate's full detail — everything `list_certificates` leaves
/// out to keep the list cheap: the validity window, revocation reason, the
/// owning account, and the PEM itself.
pub async fn get_certificate(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> AppResult<Json<CertificateDetail>> {
    let conn = state.db.conn();
    let detail = conn
        .query_row(
            "SELECT certificates.order_id, orders.account_id, orders.identifiers_json, \
                    certificates.serial, certificates.not_before, certificates.not_after, \
                    certificates.issued_at, certificates.revoked_at, \
                    certificates.revocation_reason, certificates.pem_chain \
             FROM certificates JOIN orders ON orders.id = certificates.order_id \
             WHERE certificates.id = ?1",
            [&id],
            |row| {
                let order_id: String = row.get(0)?;
                let account_id: String = row.get(1)?;
                let identifiers_json: String = row.get(2)?;
                let serial: String = row.get(3)?;
                let not_before: String = row.get(4)?;
                let not_after: String = row.get(5)?;
                let issued_at: String = row.get(6)?;
                let revoked_at: Option<String> = row.get(7)?;
                let revocation_reason: Option<i64> = row.get(8)?;
                let pem_chain: String = row.get(9)?;

                let identifiers: Vec<Identifier> =
                    serde_json::from_str(&identifiers_json).unwrap_or_default();

                let attributes = parse_cert_attributes(&pem_chain);

                Ok(CertificateDetail {
                    id: id.clone(),
                    order_id,
                    account_id,
                    identifiers: identifiers.into_iter().map(|i| i.value).collect(),
                    serial,
                    status: if revoked_at.is_some() {
                        "revoked"
                    } else {
                        "valid"
                    },
                    not_before,
                    not_after,
                    issued_at,
                    revoked_at,
                    revocation_reason,
                    pem_chain,
                    attributes,
                })
            },
        )
        .optional()?;

    detail
        .ok_or_else(|| AppError::NotFound(format!("certificate {id} does not exist")))
        .map(Json)
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
    drop(conn);

    state.audit("certificate", format!("certificate {id} revoked via admin"));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderSummary {
    id: String,
    account_id: String,
    status: String,
    identifiers: Vec<String>,
    expires: String,
    created_at: String,
    certificate_id: Option<String>,
}

/// Every order regardless of status, newest first — unlike the
/// certificates list, this includes orders that never finished
/// (`pending`/`invalid`), since those are exactly the ones an operator
/// needs to see to debug a stuck ACME client.
pub async fn list_orders(State(state): State<SharedState>) -> AppResult<Json<Vec<OrderSummary>>> {
    let conn = state.db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, account_id, status, identifiers_json, expires, created_at, certificate_id \
         FROM orders ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let orders = rows
        .into_iter()
        .map(
            |(id, account_id, status, identifiers_json, expires, created_at, certificate_id)| {
                let identifiers: Vec<Identifier> =
                    serde_json::from_str(&identifiers_json).unwrap_or_default();
                OrderSummary {
                    id,
                    account_id,
                    status,
                    identifiers: identifiers.into_iter().map(|i| i.value).collect(),
                    expires,
                    created_at,
                    certificate_id,
                }
            },
        )
        .collect();

    Ok(Json(orders))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeInfo {
    id: String,
    r#type: String,
    status: String,
    validated_at: Option<String>,
    error: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationInfo {
    id: String,
    identifier: String,
    status: String,
    expires: String,
    challenges: Vec<ChallengeInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetail {
    id: String,
    account_id: String,
    status: String,
    identifiers: Vec<String>,
    expires: String,
    created_at: String,
    certificate_id: Option<String>,
    error: Option<Value>,
    authorizations: Vec<AuthorizationInfo>,
}

/// An order's full detail, including each identifier's authorization and
/// challenge status/error — this is what makes a stuck order ("client says
/// it's waiting, nothing happens") debuggable from the UI instead of the
/// access log.
pub async fn get_order(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> AppResult<Json<OrderDetail>> {
    let conn = state.db.conn();

    let order_row = conn
        .query_row(
            "SELECT account_id, status, identifiers_json, expires, created_at, \
                    certificate_id, error_json \
             FROM orders WHERE id = ?1",
            [&id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;

    let Some((
        account_id,
        status,
        identifiers_json,
        expires,
        created_at,
        certificate_id,
        error_json,
    )) = order_row
    else {
        return Err(AppError::NotFound(format!("order {id} does not exist")));
    };

    let identifiers: Vec<Identifier> = serde_json::from_str(&identifiers_json).unwrap_or_default();

    let mut authz_stmt = conn.prepare(
        "SELECT id, identifier_value, status, expires FROM authorizations \
         WHERE order_id = ?1 ORDER BY id",
    )?;
    let authz_rows = authz_stmt
        .query_map([&id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(authz_stmt);

    let mut chal_stmt = conn.prepare(
        "SELECT id, type, status, validated_at, error_json FROM challenges \
         WHERE authorization_id = ?1 ORDER BY id",
    )?;
    let mut authorizations = Vec::with_capacity(authz_rows.len());
    for (authz_id, identifier, authz_status, authz_expires) in authz_rows {
        let challenges = chal_stmt
            .query_map([&authz_id], |row| {
                let error_json: Option<String> = row.get(4)?;
                Ok(ChallengeInfo {
                    id: row.get(0)?,
                    r#type: row.get(1)?,
                    status: row.get(2)?,
                    validated_at: row.get(3)?,
                    error: error_json.and_then(|s| serde_json::from_str(&s).ok()),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        authorizations.push(AuthorizationInfo {
            id: authz_id,
            identifier,
            status: authz_status,
            expires: authz_expires,
            challenges,
        });
    }

    Ok(Json(OrderDetail {
        id,
        account_id,
        status,
        identifiers: identifiers.into_iter().map(|i| i.value).collect(),
        expires,
        created_at,
        certificate_id,
        error: error_json.and_then(|s| serde_json::from_str(&s).ok()),
        authorizations,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSummary {
    id: String,
    jwk_thumbprint: String,
    status: String,
    contact: Vec<String>,
    tos_agreed: bool,
    created_at: String,
}

/// Every ACME account, newest first.
pub async fn list_accounts(
    State(state): State<SharedState>,
) -> AppResult<Json<Vec<AccountSummary>>> {
    let conn = state.db.conn();
    let mut stmt = conn.prepare(
        "SELECT id, jwk_thumbprint, status, contact_json, tos_agreed, created_at \
         FROM accounts ORDER BY created_at DESC",
    )?;
    let accounts = stmt
        .query_map([], |row| {
            let contact_json: Option<String> = row.get(3)?;
            let tos_agreed: i64 = row.get(4)?;
            Ok(AccountSummary {
                id: row.get(0)?,
                jwk_thumbprint: row.get(1)?,
                status: row.get(2)?,
                contact: contact_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                tos_agreed: tos_agreed != 0,
                created_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(accounts))
}
