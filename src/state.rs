use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::time::Instant;

use rusqlite::params;
use tokio::sync::{broadcast, RwLock};

use crate::access_log::AccessLog;
use crate::acme::nonce::NonceStore;
use crate::ca::Ca;
use crate::config::AppConfig;
use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::services::events::Event;
use crate::services::metrics::MetricsSnapshot;
use crate::services::tasks::TaskStore;
use crate::tls::{self, ServerCert};

pub struct AppState {
    pub config: AppConfig,
    /// The externally-visible base URL ACME URLs are built from —
    /// `config.server.base_url` if set, else derived from `host`/`port`.
    /// Computed once here since it depends on whatever the CLI may have
    /// overridden `host`/`port` to, not just the config file's values.
    pub external_base_url: String,
    /// Fan-out channel feeding every connected WebSocket client.
    pub events: broadcast::Sender<Event>,
    pub tasks: TaskStore,
    pub nonces: NonceStore,
    /// Shared client for outbound http-01 challenge validation requests —
    /// built once so validations reuse its connection pool rather than
    /// paying a fresh TLS/TCP handshake per check.
    pub http_client: reqwest::Client,
    pub ca: Ca,
    /// The certificate currently served over HTTPS — `None` when
    /// `[tls].enabled` is off. Behind a lock because the renewal task
    /// swaps it out while the server is running.
    pub server_tls: Option<std::sync::RwLock<ServerCert>>,
    /// The SAN set the server certificate is (re)issued for, resolved
    /// once at startup from config + CLI overrides.
    pub tls_sans: Vec<String>,
    pub db: Db,
    pub latest_metrics: RwLock<Option<MetricsSnapshot>>,
    pub requests_total: AtomicU64,
    pub ws_clients: AtomicUsize,
    pub started: Instant,
    pub started_at_ms: i64,
    pub access_log: AccessLog,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub async fn new(config: AppConfig) -> AppResult<Self> {
        let (events, _) = broadcast::channel(64);
        let access_log = AccessLog::open(config.logging.access_log.as_deref()).await;
        let ca = Ca::load_or_generate(&config.ca)?;
        let generated_root = ca.generated_root();
        let db = Db::open(&config.ca.db_path)?;
        let scheme = if config.tls.enabled { "https" } else { "http" };
        let external_base_url =
            config.server.base_url.clone().unwrap_or_else(|| {
                format!("{scheme}://{}:{}", config.server.host, config.server.port)
            });
        let (server_tls, tls_sans, tls_reissue_reason) = if config.tls.enabled {
            if tls_validity_days(&config) < 1 {
                return Err(AppError::Config(
                    "[tls].validity_days must be at least 1".into(),
                ));
            }
            let sans = tls::desired_sans(&config)?;
            let (cert, reason) = tls::load_or_issue(
                &ca,
                &config.tls.cert_path,
                &config.tls.key_path,
                &sans,
                tls_validity_days(&config),
            )?;
            (Some(std::sync::RwLock::new(cert)), sans, reason)
        } else {
            (None, Vec::new(), None)
        };
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let state = Self {
            external_base_url,
            events,
            tasks: TaskStore::with_examples(),
            nonces: NonceStore::new(),
            http_client,
            ca,
            server_tls,
            tls_sans,
            db,
            latest_metrics: RwLock::new(None),
            requests_total: AtomicU64::new(0),
            ws_clients: AtomicUsize::new(0),
            started: Instant::now(),
            started_at_ms: chrono::Utc::now().timestamp_millis(),
            access_log,
            config,
        };
        if generated_root {
            state.audit("ca", "generated CA root certificate");
        }
        if let Some(reason) = tls_reissue_reason {
            state.audit(
                "tls",
                format!(
                    "issued server TLS certificate for {} ({reason})",
                    state.tls_sans.join(", ")
                ),
            );
        }
        Ok(state)
    }

    /// Lifetime of the server TLS certificate: `[tls].validity_days`, else
    /// the CA-wide `[ca].cert_validity_days`.
    pub fn tls_validity_days(&self) -> i64 {
        tls_validity_days(&self.config)
    }

    pub fn broadcast(&self, event: Event) {
        // send() only fails when no client is subscribed — not an error.
        let _ = self.events.send(event);
    }

    pub fn activity(&self, kind: &str, message: impl Into<String>) {
        self.broadcast_activity(kind, message.into());
    }

    /// Persist a human-readable mutation summary and push it to live clients.
    pub fn audit(&self, kind: &str, message: impl Into<String>) {
        let now = chrono::Utc::now();
        let timestamp_ms = now.timestamp_millis();
        let message = message.into();
        let created_at = now.to_rfc3339();
        if let Err(err) = self.db.conn().execute(
            "INSERT INTO activity_log (kind, summary, created_at, timestamp_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![kind, &message, &created_at, timestamp_ms],
        ) {
            tracing::error!("failed to write activity log entry: {err:?}");
            #[cfg(test)]
            panic!("failed to write activity log entry: {err:?}");
        }
        self.broadcast(Event::Activity {
            kind: kind.to_string(),
            message,
            timestamp_ms,
        });
    }

    fn broadcast_activity(&self, kind: &str, message: String) {
        self.broadcast(Event::Activity {
            kind: kind.to_string(),
            message,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });
    }
}

fn tls_validity_days(config: &AppConfig) -> i64 {
    config
        .tls
        .validity_days
        .unwrap_or(config.ca.cert_validity_days)
}
