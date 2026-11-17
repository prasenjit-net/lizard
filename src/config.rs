use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    pub ui: UiConfig,
    pub ca: CaConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// The externally-visible base URL ACME directory/resource URLs are
    /// built from, e.g. `https://ca.example.com`. Unset by default,
    /// falling back to `http://{host}:{port}` — set this explicitly once
    /// this server sits behind a reverse proxy doing TLS termination,
    /// since `host`/`port` alone can't describe that.
    pub base_url: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8080,
            base_url: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: String,
    pub access_log: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            access_log: None,
        }
    }
}

/// The `[ui]` section is exposed verbatim to the SPA through
/// `GET /api/config` (serialized in camelCase for the frontend).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all(serialize = "camelCase"))]
pub struct UiConfig {
    pub app_name: String,
    pub tagline: String,
    pub default_theme: String,
    pub repo_url: Option<String>,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            app_name: "Lizard".into(),
            tagline: "Single-binary fullstack starter".into(),
            default_theme: "auto".into(),
            repo_url: None,
        }
    }
}

/// The CA's own root keypair/certificate and the leaf certificates it
/// issues. `root_cert_path`/`root_key_path` are generated on first run if
/// absent (see `crate::ca::Ca::load_or_generate`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaConfig {
    pub root_cert_path: PathBuf,
    pub root_key_path: PathBuf,
    pub root_validity_years: i64,
    pub cert_validity_days: i64,
    pub db_path: PathBuf,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            root_cert_path: PathBuf::from("data/ca/root-cert.pem"),
            root_key_path: PathBuf::from("data/ca/root-key.pem"),
            root_validity_years: 10,
            cert_validity_days: 90,
            db_path: PathBuf::from("data/lizard.db"),
        }
    }
}

/// In-process HTTPS. When `enabled`, the server listens for HTTPS *only*
/// (no plain-HTTP listener at all) using a leaf certificate issued by this
/// server's own CA — there is deliberately no way to plug in an externally
/// issued certificate. `cert_path`/`key_path` are just where that
/// self-issued certificate is cached between restarts; it's (re)issued
/// automatically whenever it's missing, no longer chains to the current
/// root, has a stale SAN set, or is due for renewal (see `crate::tls`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Extra SAN entries (DNS names or IP addresses) on top of the ones
    /// derived automatically from `localhost`, `[server].host`, and
    /// `[server].base_url` — typically the hostname clients actually use
    /// to reach this server.
    pub external_hostnames: Vec<String>,
    /// Lifetime of the server certificate. Falls back to
    /// `[ca].cert_validity_days` when unset.
    pub validity_days: Option<i64>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: PathBuf::from("data/tls/server-cert.pem"),
            key_path: PathBuf::from("data/tls/server-key.pem"),
            external_hostnames: Vec::new(),
            validity_days: None,
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        if !path.exists() {
            eprintln!(
                "warning: config file {} not found, using built-in defaults",
                path.display()
            );
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|err| AppError::Config(format!("failed to read {}: {err}", path.display())))?;
        toml::from_str(&raw)
            .map_err(|err| AppError::Config(format!("invalid config {}: {err}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let config = AppConfig::load(Path::new("/nonexistent/definitely-not-here.toml")).unwrap();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.ui.default_theme, "auto");
    }

    #[test]
    fn parses_a_full_config_file() {
        let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 9000

            [logging]
            level = "debug"
            access_log = "access.log"

            [ui]
            app_name = "Test App"
            tagline = "Testing"
            default_theme = "dark"
            repo_url = "https://example.com/repo"
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.access_log, Some(PathBuf::from("access.log")));
        assert_eq!(config.ui.app_name, "Test App");
        assert_eq!(
            config.ui.repo_url.as_deref(),
            Some("https://example.com/repo")
        );
    }

    #[test]
    fn missing_sections_fall_back_to_defaults() {
        let config: AppConfig = toml::from_str("[server]\nport = 1234\n").unwrap();
        assert_eq!(config.server.port, 1234);
        assert_eq!(config.server.host, "127.0.0.1"); // untouched field defaults
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.ui.app_name, "Lizard");
        assert_eq!(
            config.ca.root_cert_path,
            PathBuf::from("data/ca/root-cert.pem")
        );
        assert_eq!(config.ca.cert_validity_days, 90);
    }

    #[test]
    fn ca_section_overrides_defaults() {
        let toml = r#"
            [ca]
            root_cert_path = "ca/root.pem"
            root_key_path = "ca/root.key"
            root_validity_years = 5
            cert_validity_days = 30
            db_path = "state.db"
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.ca.root_cert_path, PathBuf::from("ca/root.pem"));
        assert_eq!(config.ca.root_key_path, PathBuf::from("ca/root.key"));
        assert_eq!(config.ca.root_validity_years, 5);
        assert_eq!(config.ca.cert_validity_days, 30);
        assert_eq!(config.ca.db_path, PathBuf::from("state.db"));
    }

    #[test]
    fn tls_is_disabled_by_default() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.tls.enabled);
        assert_eq!(
            config.tls.cert_path,
            PathBuf::from("data/tls/server-cert.pem")
        );
        assert!(config.tls.external_hostnames.is_empty());
        assert_eq!(config.tls.validity_days, None);
    }

    #[test]
    fn tls_section_overrides_defaults() {
        let toml = r#"
            [tls]
            enabled = true
            cert_path = "tls/cert.pem"
            key_path = "tls/key.pem"
            external_hostnames = ["ca.example.com", "10.0.0.5"]
            validity_days = 30
        "#;
        let config: AppConfig = toml::from_str(toml).unwrap();
        assert!(config.tls.enabled);
        assert_eq!(config.tls.cert_path, PathBuf::from("tls/cert.pem"));
        assert_eq!(config.tls.key_path, PathBuf::from("tls/key.pem"));
        assert_eq!(
            config.tls.external_hostnames,
            vec!["ca.example.com".to_string(), "10.0.0.5".to_string()]
        );
        assert_eq!(config.tls.validity_days, Some(30));
    }

    #[test]
    fn tls_section_rejects_external_cert_options() {
        // There is no way to point at an externally-issued certificate;
        // an attempt to configure one should fail loudly, not be ignored.
        let result: Result<AppConfig, _> =
            toml::from_str("[tls]\nenabled = true\nca_bundle = \"x.pem\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml = "[server]\nport = 1234\ntypo_field = true\n";
        let result: Result<AppConfig, _> = toml::from_str(toml);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject typo_field"
        );
    }

    #[test]
    fn ui_config_serializes_camel_case_for_the_frontend() {
        let ui = UiConfig {
            app_name: "X".into(),
            tagline: "Y".into(),
            default_theme: "auto".into(),
            repo_url: None,
        };
        let value = serde_json::to_value(&ui).unwrap();
        assert!(value.get("appName").is_some());
        assert!(value.get("defaultTheme").is_some());
        assert!(value.get("app_name").is_none());
    }
}
