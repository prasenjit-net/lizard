use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, RwLock};

use crate::access_log::AccessLog;
use crate::acme::nonce::NonceStore;
use crate::ca::Ca;
use crate::config::AppConfig;
use crate::db::Db;
use crate::error::AppResult;
use crate::services::events::Event;
use crate::services::metrics::MetricsSnapshot;
use crate::services::tasks::TaskStore;

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
    // Not read anywhere yet — the ACME handlers that sign certificates
    // land in a later milestone. See the module doc comment on `crate::ca`.
    #[allow(dead_code)]
    pub ca: Ca,
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
        let db = Db::open(&config.ca.db_path)?;
        let external_base_url = config
            .server
            .base_url
            .clone()
            .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port));
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            external_base_url,
            events,
            tasks: TaskStore::with_examples(),
            nonces: NonceStore::new(),
            http_client,
            ca,
            db,
            latest_metrics: RwLock::new(None),
            requests_total: AtomicU64::new(0),
            ws_clients: AtomicUsize::new(0),
            started: Instant::now(),
            started_at_ms: chrono::Utc::now().timestamp_millis(),
            access_log,
            config,
        })
    }

    pub fn broadcast(&self, event: Event) {
        // send() only fails when no client is subscribed — not an error.
        let _ = self.events.send(event);
    }

    /// Push a human-readable entry to every client's activity feed.
    pub fn activity(&self, kind: &str, message: impl Into<String>) {
        self.broadcast(Event::Activity {
            kind: kind.to_string(),
            message: message.into(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });
    }
}
