//! Google JWT verification with cached JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use iqrah_backend_domain::JwtSubject;

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct GoogleJwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct GoogleIdTokenClaims {
    sub: String,
}

/// Trait boundary for Google ID token verification.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait JwtVerifier: Send + Sync {
    /// Verifies an ID token and returns the JWT subject.
    async fn verify_google_id_token(&self, id_token: &str) -> anyhow::Result<JwtSubject>;
}

/// JWKS-backed Google ID token verifier.
#[derive(Clone)]
pub struct GoogleJwtVerifier {
    client: Client,
    google_client_id: String,
    jwks_by_kid: Arc<RwLock<HashMap<String, GoogleJwk>>>,
}

impl GoogleJwtVerifier {
    /// Creates a verifier and fetches JWKS immediately.
    pub async fn new(client: Client, google_client_id: String) -> anyhow::Result<Self> {
        let verifier = Self {
            client,
            google_client_id,
            jwks_by_kid: Arc::new(RwLock::new(HashMap::new())),
        };
        verifier.refresh_jwks().await?;
        Ok(verifier)
    }

    /// Starts a background JWKS refresh loop.
    pub fn spawn_refresh_task(self: Arc<Self>, period: Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            loop {
                interval.tick().await;
                if let Err(error) = self.refresh_jwks().await {
                    tracing::warn!(error = %error, "Failed to refresh Google JWKS cache");
                }
            }
        });
    }

    async fn refresh_jwks(&self) -> anyhow::Result<()> {
        let response = self
            .client
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<GoogleJwks>().await?;

        let mut map = HashMap::with_capacity(body.keys.len());
        for key in body.keys {
            map.insert(key.kid.clone(), key);
        }

        let mut cache = self.jwks_by_kid.write().await;
        *cache = map;
        Ok(())
    }
}

#[async_trait]
impl JwtVerifier for GoogleJwtVerifier {
    async fn verify_google_id_token(&self, id_token: &str) -> anyhow::Result<JwtSubject> {
        let header = decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("Google ID token missing `kid` header"))?;

        let key = {
            let cache = self.jwks_by_kid.read().await;
            cache.get(&kid).cloned()
        }
        .ok_or_else(|| anyhow::anyhow!("No matching Google JWKS key for kid `{kid}`"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.google_client_id.as_str()]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)?;
        let token = decode::<GoogleIdTokenClaims>(id_token, &decoding_key, &validation)?;

        if token.claims.sub.trim().is_empty() {
            return Err(anyhow::anyhow!("Google ID token subject is empty"));
        }

        Ok(JwtSubject(token.claims.sub))
    }
}
