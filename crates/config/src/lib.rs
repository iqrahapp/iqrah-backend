//! Configuration module for Iqrah backend.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use secrecy::SecretString;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingVar(String),
    #[error("Invalid value for {0}: {1}")]
    InvalidValue(String, String),
}

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// PostgreSQL connection URL
    pub database_url: String,
    /// JWT secret for token signing
    pub jwt_secret: SecretString,
    /// Path to pack storage directory
    pub pack_storage_path: PathBuf,
    /// Google OAuth client ID
    pub google_client_id: String,
    /// Address to bind the server to
    pub bind_address: SocketAddr,
    /// Bind port extracted from bind_address.
    pub port: u16,
    /// Base URL for API (used in download URLs)
    pub base_url: String,
    /// Shared admin key for observability endpoints. Empty disables admin endpoints.
    pub admin_api_key: String,
    /// Allowlisted OAuth subjects that should receive admin role in API JWTs.
    pub admin_oauth_sub_allowlist: Vec<String>,
}

impl AppConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let database_url = env_var("DATABASE_URL")?;
        if !database_url.starts_with("postgres://") && !database_url.starts_with("postgresql://") {
            return Err(ConfigError::InvalidValue(
                "DATABASE_URL".to_string(),
                "must start with postgres:// or postgresql://".to_string(),
            ));
        }

        let bind_address_raw = env_var_or("BIND_ADDRESS", "0.0.0.0:8080");
        let bind_address = bind_address_raw.parse::<SocketAddr>().map_err(|e| {
            ConfigError::InvalidValue(
                "BIND_ADDRESS".to_string(),
                format!("failed to parse socket address: {e}"),
            )
        })?;

        Ok(Self {
            database_url,
            jwt_secret: SecretString::new(env_var("JWT_SECRET")?.into()),
            pack_storage_path: PathBuf::from(env_var_or("PACK_STORAGE_PATH", "./packs")),
            google_client_id: env_var_or("GOOGLE_CLIENT_ID", ""),
            port: bind_address.port(),
            bind_address,
            base_url: env_var_or("BASE_URL", "http://localhost:8080"),
            admin_api_key: env_var_or("ADMIN_API_KEY", ""),
            admin_oauth_sub_allowlist: parse_csv_env("ADMIN_OAUTH_SUB_ALLOWLIST"),
        })
    }
}

fn env_var(name: &str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingVar(name.to_string()))
}

fn env_var_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_csv_env(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env(vars: &[(&str, Option<&str>)], test: impl FnOnce()) {
        let _guard = env_lock().lock().expect("env lock should not be poisoned");
        let keys = [
            "DATABASE_URL",
            "JWT_SECRET",
            "PACK_STORAGE_PATH",
            "GOOGLE_CLIENT_ID",
            "BIND_ADDRESS",
            "BASE_URL",
            "ADMIN_API_KEY",
            "ADMIN_OAUTH_SUB_ALLOWLIST",
        ];

        let original: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|key| ((*key).to_string(), std::env::var(key).ok()))
            .collect();

        for key in keys {
            // SAFETY: tests are serialized via env_lock.
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            if let Some(value) = value {
                // SAFETY: tests are serialized via env_lock.
                unsafe { std::env::set_var(key, value) };
            }
        }

        test();

        for (key, value) in original {
            if let Some(value) = value {
                // SAFETY: tests are serialized via env_lock.
                unsafe { std::env::set_var(key, value) };
            } else {
                // SAFETY: tests are serialized via env_lock.
                unsafe { std::env::remove_var(key) };
            }
        }
    }

    #[test]
    fn test_env_var_or_uses_default() {
        let val = env_var_or("NON_EXISTENT_VAR_12345", "default_value");
        assert_eq!(val, "default_value");
    }

    #[test]
    fn from_env_loads_valid_config() {
        with_env(
            &[
                ("DATABASE_URL", Some("postgres://localhost:5432/iqrah")),
                ("JWT_SECRET", Some("secret")),
                ("PACK_STORAGE_PATH", Some("/tmp/packs")),
                ("GOOGLE_CLIENT_ID", Some("google-client-id")),
                ("BIND_ADDRESS", Some("127.0.0.1:9000")),
                ("BASE_URL", Some("https://api.example.com")),
                ("ADMIN_API_KEY", Some("admin-key")),
                (
                    "ADMIN_OAUTH_SUB_ALLOWLIST",
                    Some("google-sub-1, google-sub-2, ,google-sub-3"),
                ),
            ],
            || {
                let config = AppConfig::from_env().expect("valid env should parse");
                assert_eq!(config.database_url, "postgres://localhost:5432/iqrah");
                assert_eq!(config.pack_storage_path, PathBuf::from("/tmp/packs"));
                assert_eq!(config.google_client_id, "google-client-id");
                assert_eq!(config.bind_address.to_string(), "127.0.0.1:9000");
                assert_eq!(config.port, 9000);
                assert_eq!(config.base_url, "https://api.example.com");
                assert_eq!(config.admin_api_key, "admin-key");
                assert_eq!(
                    config.admin_oauth_sub_allowlist,
                    vec!["google-sub-1", "google-sub-2", "google-sub-3"]
                );
            },
        );
    }

    #[test]
    fn from_env_errors_when_required_database_url_is_missing() {
        with_env(
            &[("JWT_SECRET", Some("secret"))],
            || match AppConfig::from_env() {
                Err(ConfigError::MissingVar(name)) => assert_eq!(name, "DATABASE_URL"),
                other => panic!("expected missing DATABASE_URL error, got: {other:?}"),
            },
        );
    }

    #[test]
    fn from_env_errors_when_required_jwt_secret_is_missing() {
        with_env(
            &[("DATABASE_URL", Some("postgres://localhost:5432/iqrah"))],
            || match AppConfig::from_env() {
                Err(ConfigError::MissingVar(name)) => assert_eq!(name, "JWT_SECRET"),
                other => panic!("expected missing JWT_SECRET error, got: {other:?}"),
            },
        );
    }

    #[test]
    fn from_env_rejects_invalid_bind_address_value() {
        with_env(
            &[
                ("DATABASE_URL", Some("postgres://localhost:5432/iqrah")),
                ("JWT_SECRET", Some("secret")),
                ("BIND_ADDRESS", Some("127.0.0.1:99999")),
            ],
            || match AppConfig::from_env() {
                Err(ConfigError::InvalidValue(name, message)) => {
                    assert_eq!(name, "BIND_ADDRESS");
                    assert!(message.contains("failed to parse socket address"));
                }
                other => panic!("expected invalid BIND_ADDRESS error, got: {other:?}"),
            },
        );
    }

    #[test]
    fn from_env_rejects_db_url_without_postgres_prefix() {
        with_env(
            &[
                ("DATABASE_URL", Some("mysql://localhost:3306/iqrah")),
                ("JWT_SECRET", Some("secret")),
            ],
            || match AppConfig::from_env() {
                Err(ConfigError::InvalidValue(name, message)) => {
                    assert_eq!(name, "DATABASE_URL");
                    assert!(message.contains("postgres:// or postgresql://"));
                }
                other => panic!("expected invalid DATABASE_URL error, got: {other:?}"),
            },
        );
    }
}
