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
        })
    }
}

fn env_var(name: &str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingVar(name.to_string()))
}

fn env_var_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_var_or_uses_default() {
        let val = env_var_or("NON_EXISTENT_VAR_12345", "default_value");
        assert_eq!(val, "default_value");
    }
}
