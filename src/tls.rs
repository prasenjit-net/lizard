//! In-process HTTPS, using a server certificate issued by this server's
//! own CA.
//!
//! There is deliberately no way to serve an externally-issued certificate:
//! on startup the cached certificate at `[tls].cert_path`/`key_path` is
//! only reused if it still checks out against *this* CA (see
//! [`inspect`]); otherwise a fresh one is issued from the root. While
//! running, [`spawn_renewal`] reissues it once it's two-thirds of the way
//! through its lifetime and hot-swaps it into the listener, so no restart
//! is ever needed.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{KeyPair, PublicKeyData};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;

use crate::ca::Ca;
use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;

/// How often the renewal task re-checks the live certificate. Cheap (no
/// I/O unless renewal is actually due), so this only needs to be small
/// relative to the renewal window — a third of the certificate lifetime.
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long in-flight requests get to finish on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// The server certificate currently being served.
#[derive(Debug, Clone)]
pub struct ServerCert {
    /// Leaf followed by the root, as served in the TLS handshake.
    pub chain_pem: String,
    pub key_pem: String,
    /// Normalized SAN set actually embedded in the leaf.
    pub sans: Vec<String>,
    pub serial: String,
    /// Unix timestamps (seconds) of the leaf's validity window.
    pub not_before: i64,
    pub not_after: i64,
}

impl ServerCert {
    /// True once less than a third of the certificate's lifetime remains
    /// (the same "renew at 2/3" rule of thumb ACME clients use).
    pub fn renewal_due(&self, now: i64) -> bool {
        let lifetime = (self.not_after - self.not_before).max(0);
        now >= self.not_after - lifetime / 3
    }
}

/// Installs the process-wide rustls crypto provider. Safe to call more
/// than once. Done explicitly because rustls panics on first use if it
/// can't unambiguously pick a provider on its own.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// The SAN set the server certificate should carry: `localhost` and the
/// loopback IPs, `[server].host` (unless it's a wildcard bind address),
/// the host of `[server].base_url` if set, plus every
/// `[tls].external_hostnames` entry. Normalized, de-duplicated, and
/// sorted so it can be compared against an existing certificate's SANs.
pub fn desired_sans(config: &AppConfig) -> AppResult<Vec<String>> {
    let mut sans = BTreeSet::new();
    for automatic in ["localhost", "127.0.0.1", "::1"] {
        sans.insert(automatic.to_string());
    }

    let host = config.server.host.trim();
    let host_unspecified = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified());
    if !host.is_empty() && !host_unspecified {
        sans.insert(
            normalize_san(host)
                .map_err(|err| AppError::Config(format!("[server].host {host:?}: {err}")))?,
        );
    }

    if let Some(base_url) = &config.server.base_url {
        let url = reqwest::Url::parse(base_url)
            .map_err(|err| AppError::Config(format!("[server].base_url {base_url:?}: {err}")))?;
        let host = match url.host() {
            Some(url::Host::Domain(domain)) => domain.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => {
                return Err(AppError::Config(format!(
                    "[server].base_url {base_url:?} has no host"
                )))
            }
        };
        sans.insert(
            normalize_san(&host).map_err(|err| {
                AppError::Config(format!("[server].base_url {base_url:?}: {err}"))
            })?,
        );
    }

    for raw in &config.tls.external_hostnames {
        sans.insert(normalize_san(raw).map_err(|err| {
            AppError::Config(format!("[tls].external_hostnames entry {raw:?}: {err}"))
        })?);
    }

    Ok(sans.into_iter().collect())
}

/// Validates and canonicalizes one SAN entry: IP literals (optionally
/// bracketed) become their canonical textual form; anything else must be
/// a plain DNS hostname, lowercased with any trailing dot dropped.
/// Wildcards are rejected, matching the ACME side's policy of never
/// issuing them.
fn normalize_san(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty name".into());
    }
    let unbracketed = trimmed.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if trimmed.contains('*') {
        return Err("wildcard names are not supported".into());
    }
    let name = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return Err("not a valid DNS name (length)".into());
    }
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(format!("not a valid DNS name (label {label:?})"));
        }
    }
    Ok(name)
}

/// Loads the cached server certificate if it is still good for `sans`
/// under `ca`, or issues (and caches) a fresh one. Returns the reason a
/// new certificate was issued, if one was, for the audit log.
pub fn load_or_issue(
    ca: &Ca,
    cert_path: &Path,
    key_path: &Path,
    sans: &[String],
    validity_days: i64,
) -> AppResult<(ServerCert, Option<String>)> {
    let now = chrono::Utc::now().timestamp();
    let reason = if cert_path.exists() && key_path.exists() {
        let chain_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;
        match inspect(&chain_pem, &key_pem, ca.root_cert_pem(), sans) {
            Ok(cert) if !cert.renewal_due(now) => return Ok((cert, None)),
            Ok(_) => "existing certificate is due for renewal".to_string(),
            Err(reason) => reason,
        }
    } else {
        "no cached certificate".to_string()
    };

    let cert = issue(ca, sans, validity_days)?;
    write_cert(cert_path, key_path, &cert)?;
    Ok((cert, Some(reason)))
}

/// Issues a fresh server certificate (without touching disk).
fn issue(ca: &Ca, sans: &[String], validity_days: i64) -> AppResult<ServerCert> {
    let (issued, key_pem) = ca.issue_server_cert(sans, validity_days)?;
    let mut chain_pem = issued.pem;
    if !chain_pem.ends_with('\n') {
        chain_pem.push('\n');
    }
    chain_pem.push_str(ca.root_cert_pem());
    inspect(&chain_pem, &key_pem, ca.root_cert_pem(), sans)
        .map_err(|reason| AppError::Internal(format!("freshly issued server cert: {reason}")))
}

/// Checks a cached chain + key against the current root and desired SAN
/// set, returning the parsed certificate if it's usable, or a
/// human-readable reason it isn't. Expiry/renewal is checked separately
/// (via [`ServerCert::renewal_due`]) so callers can tell the two apart.
fn inspect(
    chain_pem: &str,
    key_pem: &str,
    root_pem: &str,
    sans: &[String],
) -> Result<ServerCert, String> {
    let leaf_pem = Pem::iter_from_buffer(chain_pem.as_bytes())
        .next()
        .ok_or("cached certificate file has no certificate")?
        .map_err(|err| format!("cached certificate is not valid PEM: {err}"))?;
    let leaf = leaf_pem
        .parse_x509()
        .map_err(|err| format!("cached certificate does not parse: {err}"))?;
    let root_pem = Pem::iter_from_buffer(root_pem.as_bytes())
        .next()
        .ok_or("CA root has no certificate")?
        .map_err(|err| format!("CA root is not valid PEM: {err}"))?;
    let root = root_pem
        .parse_x509()
        .map_err(|err| format!("CA root does not parse: {err}"))?;

    if leaf.issuer() != root.subject() || leaf.verify_signature(Some(root.public_key())).is_err() {
        return Err("cached certificate was not issued by the current CA root".into());
    }

    let key_pair =
        KeyPair::from_pem(key_pem).map_err(|err| format!("cached key does not parse: {err}"))?;
    if key_pair.subject_public_key_info() != leaf.public_key().raw {
        return Err("cached key does not match the cached certificate".into());
    }

    let mut actual = BTreeSet::new();
    if let Ok(Some(san)) = leaf.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    actual.insert(dns.to_ascii_lowercase());
                }
                GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap()),
                        16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap()),
                        _ => continue,
                    };
                    actual.insert(ip.to_string());
                }
                _ => {}
            }
        }
    }
    let desired: BTreeSet<String> = sans.iter().cloned().collect();
    if actual != desired {
        return Err("cached certificate's SANs differ from the configured set".into());
    }

    Ok(ServerCert {
        chain_pem: chain_pem.to_string(),
        key_pem: key_pem.to_string(),
        sans: actual.into_iter().collect(),
        serial: leaf.raw_serial_as_string(),
        not_before: leaf.validity().not_before.timestamp(),
        not_after: leaf.validity().not_after.timestamp(),
    })
}

fn write_cert(cert_path: &Path, key_path: &Path, cert: &ServerCert) -> AppResult<()> {
    for path in [cert_path, key_path] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(cert_path, &cert.chain_pem)?;

    // Create the key file with owner-only permissions from the start,
    // rather than writing it world-readable and tightening afterwards.
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(key_path)?;
    file.write_all(cert.key_pem.as_bytes())?;
    #[cfg(unix)]
    {
        // `mode` only applies on creation; an existing file keeps its old
        // permissions unless reset explicitly.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Builds the rustls server config for the certificate currently in
/// `state`.
pub async fn rustls_config(state: &SharedState) -> AppResult<RustlsConfig> {
    let cert = current(state)?;
    RustlsConfig::from_pem(cert.chain_pem.into_bytes(), cert.key_pem.into_bytes())
        .await
        .map_err(AppError::from)
}

fn current(state: &SharedState) -> AppResult<ServerCert> {
    let lock = state
        .server_tls
        .as_ref()
        .ok_or_else(|| AppError::Internal("TLS is not enabled".into()))?;
    Ok(lock.read().unwrap().clone())
}

/// Background task: reissues the server certificate once renewal is due
/// and hot-swaps it into `rustls`, so new handshakes pick it up without a
/// restart (existing connections keep the old certificate).
pub fn spawn_renewal(state: SharedState, rustls: RustlsConfig) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RENEWAL_CHECK_INTERVAL);
        interval.tick().await; // the first tick fires immediately
        loop {
            interval.tick().await;
            if let Err(err) = renew_if_due(&state, &rustls).await {
                tracing::error!("server TLS certificate renewal failed: {err}");
            }
        }
    });
}

async fn renew_if_due(state: &SharedState, rustls: &RustlsConfig) -> AppResult<bool> {
    let now = chrono::Utc::now().timestamp();
    if !current(state)?.renewal_due(now) {
        return Ok(false);
    }
    let tls = &state.config.tls;
    let cert = issue(&state.ca, &state.tls_sans, state.tls_validity_days())?;
    write_cert(&tls.cert_path, &tls.key_path, &cert)?;
    rustls
        .reload_from_pem(
            cert.chain_pem.clone().into_bytes(),
            cert.key_pem.clone().into_bytes(),
        )
        .await?;
    let serial = cert.serial.clone();
    if let Some(lock) = &state.server_tls {
        *lock.write().unwrap() = cert;
    }
    state.audit(
        "tls",
        format!("renewed server TLS certificate (serial {serial})"),
    );
    Ok(true)
}

/// Serves `app` over HTTPS only on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: std::net::TcpListener,
    app: Router,
    rustls: RustlsConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let handle = axum_server::Handle::<SocketAddr>::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
    });
    axum_server::from_tcp_rustls(listener, rustls)?
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::config::CaConfig;
    use crate::state::AppState;

    fn ca_config(dir: &TempDir) -> CaConfig {
        CaConfig {
            root_cert_path: dir.path().join("root-cert.pem"),
            root_key_path: dir.path().join("root-key.pem"),
            db_path: dir.path().join("lizard.db"),
            ..CaConfig::default()
        }
    }

    fn sans(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn automatic_sans_cover_loopback_and_skip_wildcard_bind_addresses() {
        let mut config = AppConfig::default();
        config.server.host = "0.0.0.0".into();
        assert_eq!(
            desired_sans(&config).unwrap(),
            sans(&["127.0.0.1", "::1", "localhost"])
        );
    }

    #[test]
    fn sans_merge_host_base_url_and_external_hostnames() {
        let mut config = AppConfig::default();
        config.server.host = "Lizard.Internal".into();
        config.server.base_url = Some("https://ca.example.com:8443".into());
        config.tls.external_hostnames = vec![
            "Alt.Example.com.".into(),
            "10.0.0.5".into(),
            "[fe80::1]".into(),
            "ca.example.com".into(), // duplicate of base_url host
        ];
        assert_eq!(
            desired_sans(&config).unwrap(),
            sans(&[
                "10.0.0.5",
                "127.0.0.1",
                "::1",
                "alt.example.com",
                "ca.example.com",
                "fe80::1",
                "lizard.internal",
                "localhost",
            ])
        );
    }

    #[test]
    fn invalid_external_hostnames_are_rejected() {
        for bad in [
            "*.example.com",
            "",
            "under_score.example",
            "-bad.example",
            "a..b",
        ] {
            let mut config = AppConfig::default();
            config.tls.external_hostnames = vec![bad.into()];
            assert!(
                matches!(desired_sans(&config), Err(AppError::Config(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn renewal_is_due_in_the_last_third_of_the_lifetime() {
        let cert = ServerCert {
            chain_pem: String::new(),
            key_pem: String::new(),
            sans: vec![],
            serial: String::new(),
            not_before: 0,
            not_after: 90,
        };
        assert!(!cert.renewal_due(59));
        assert!(cert.renewal_due(60));
        assert!(cert.renewal_due(1000));
    }

    #[test]
    fn issues_once_then_reuses_the_cached_certificate() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&ca_config(&dir)).unwrap();
        let (cert_path, key_path) = (dir.path().join("tls/c.pem"), dir.path().join("tls/k.pem"));
        let wanted = sans(&["127.0.0.1", "localhost"]);

        let (first, reason) = load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        assert_eq!(reason.as_deref(), Some("no cached certificate"));
        assert!(first.chain_pem.ends_with(ca.root_cert_pem()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let (second, reason) = load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        assert_eq!(reason, None);
        assert_eq!(second.serial, first.serial);
    }

    #[test]
    fn reissues_when_sans_change() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&ca_config(&dir)).unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));

        let (first, _) =
            load_or_issue(&ca, &cert_path, &key_path, &sans(&["localhost"]), 90).unwrap();
        let (second, reason) = load_or_issue(
            &ca,
            &cert_path,
            &key_path,
            &sans(&["ca.example.com", "localhost"]),
            90,
        )
        .unwrap();
        assert!(reason.unwrap().contains("SANs differ"));
        assert_ne!(second.serial, first.serial);
        assert_eq!(second.sans, sans(&["ca.example.com", "localhost"]));
    }

    #[test]
    fn reissues_when_the_root_changes() {
        let dir = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&ca_config(&dir)).unwrap();
        let other_ca = Ca::load_or_generate(&ca_config(&other)).unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let wanted = sans(&["localhost"]);

        load_or_issue(&other_ca, &cert_path, &key_path, &wanted, 90).unwrap();
        let (cert, reason) = load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        assert!(reason
            .unwrap()
            .contains("not issued by the current CA root"));
        assert!(cert.chain_pem.ends_with(ca.root_cert_pem()));
    }

    #[test]
    fn reissues_when_the_cached_key_does_not_match() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&ca_config(&dir)).unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let wanted = sans(&["localhost"]);

        load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        fs::write(&key_path, KeyPair::generate().unwrap().serialize_pem()).unwrap();
        let (_, reason) = load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        assert!(reason.unwrap().contains("key does not match"));
    }

    #[test]
    fn reissues_when_the_cached_certificate_is_due_for_renewal() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&ca_config(&dir)).unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let wanted = sans(&["localhost"]);

        // A zero-day certificate is already inside its renewal window.
        load_or_issue(&ca, &cert_path, &key_path, &wanted, 0).unwrap();
        let (_, reason) = load_or_issue(&ca, &cert_path, &key_path, &wanted, 90).unwrap();
        assert!(reason.unwrap().contains("due for renewal"));
    }

    /// End to end: a real HTTPS listener, hit by a client that trusts only
    /// this CA's root — proving the served chain actually validates for
    /// the SAN the client connects with, and that ACME URLs are `https://`.
    #[tokio::test]
    async fn serves_https_that_validates_against_the_ca_root() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut config = AppConfig {
            ca: ca_config(&dir),
            ..AppConfig::default()
        };
        config.server.port = port;
        config.tls.enabled = true;
        config.tls.cert_path = dir.path().join("tls/cert.pem");
        config.tls.key_path = dir.path().join("tls/key.pem");
        let state = Arc::new(AppState::new(config).await.unwrap());
        assert_eq!(state.external_base_url, format!("https://127.0.0.1:{port}"));

        let rustls = rustls_config(&state).await.unwrap();
        let app = crate::routes::router(state.clone());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, app, rustls, async {
            let _ = stop_rx.await;
        }));

        let root = reqwest::Certificate::from_pem(state.ca.root_cert_pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .tls_certs_only([root])
            .build()
            .unwrap();
        for host in ["localhost", "127.0.0.1"] {
            let res = client
                .get(format!("https://{host}:{port}/api/health"))
                .send()
                .await
                .unwrap_or_else(|err| panic!("https://{host} failed: {err:?}"));
            assert!(res.status().is_success());
        }
        let directory = client
            .get(format!("https://127.0.0.1:{port}/directory"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let directory: serde_json::Value = serde_json::from_str(&directory).unwrap();
        assert!(directory["newNonce"]
            .as_str()
            .unwrap()
            .starts_with(&format!("https://127.0.0.1:{port}/")));

        // A client that doesn't trust this CA must be refused.
        let untrusting = reqwest::Client::builder()
            .tls_certs_only([])
            .build()
            .unwrap();
        assert!(untrusting
            .get(format!("https://127.0.0.1:{port}/api/health"))
            .send()
            .await
            .is_err());

        let _ = stop_tx.send(());
        server.await.unwrap().unwrap();
    }
}
