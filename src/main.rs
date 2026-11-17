mod access_log;
mod acme;
mod ca;
mod config;
mod db;
mod error;
mod routes;
mod services;
mod state;
mod static_assets;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::state::AppState;

/// Lizard: an ACME server that issues SSL/TLS certificates from its own private CA.
///
/// Configuration is read from a TOML file; every flag below overrides
/// the corresponding value from that file.
#[derive(Parser, Debug)]
#[command(name = "lizard", version, about)]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Override [server].host
    #[arg(long)]
    host: Option<String>,

    /// Override [server].port
    #[arg(short, long)]
    port: Option<u16>,

    /// Override [logging].level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Override [logging].access_log file path
    #[arg(long)]
    access_log: Option<PathBuf>,

    /// Disable the access log file entirely
    #[arg(long)]
    no_access_log: bool,

    /// Serve HTTPS (only) with a certificate issued by this server's own CA
    #[arg(long, conflicts_with = "no_tls")]
    tls: bool,

    /// Serve plain HTTP even if [tls].enabled is set
    #[arg(long)]
    no_tls: bool,

    /// Add an extra SAN to the server certificate (repeatable); appended to
    /// [tls].external_hostnames
    #[arg(long = "tls-hostname", value_name = "NAME")]
    tls_hostnames: Vec<String>,
}

impl Cli {
    fn apply(&self, config: &mut AppConfig) {
        if let Some(host) = &self.host {
            config.server.host = host.clone();
        }
        if let Some(port) = self.port {
            config.server.port = port;
        }
        if let Some(level) = &self.log_level {
            config.logging.level = level.clone();
        }
        if let Some(path) = &self.access_log {
            config.logging.access_log = Some(path.clone());
        }
        if self.no_access_log {
            config.logging.access_log = None;
        }
        if self.tls {
            config.tls.enabled = true;
        }
        if self.no_tls {
            config.tls.enabled = false;
        }
        config
            .tls
            .external_hostnames
            .extend(self.tls_hostnames.iter().cloned());
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut config = match AppConfig::load(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    cli.apply(&mut config);

    let filter =
        EnvFilter::try_new(&config.logging.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(err) = run(config).await {
        tracing::error!("fatal: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run(config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let tls_enabled = config.tls.enabled;
    if tls_enabled {
        tls::install_crypto_provider();
    }
    let state = Arc::new(AppState::new(config).await?);
    services::metrics::spawn(state.clone());

    let app = routes::router(state.clone());
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };

    if tls_enabled {
        // HTTPS only: there is intentionally no plain-HTTP listener (and
        // so no redirect) when TLS is on.
        let rustls = tls::rustls_config(&state).await?;
        tls::spawn_renewal(state.clone(), rustls.clone());
        let listener = std::net::TcpListener::bind(&addr)?;
        tracing::info!(
            sans = %state.tls_sans.join(","),
            "listening on https://{addr}"
        );
        tls::serve(listener, app, rustls, shutdown).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("listening on http://{addr}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
    }

    Ok(())
}
