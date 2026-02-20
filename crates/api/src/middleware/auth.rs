//! Auth middleware for JWT verification.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{DecodingKey, Validation, decode};
use secrecy::ExposeSecret;
use uuid::Uuid;

use iqrah_backend_domain::{Claims, DomainError, UserId};

use crate::AppState;

/// Extracts and verifies user id from Authorization header.
pub fn auth_middleware(headers: &HeaderMap, jwt_secret: &str) -> Result<UserId, StatusCode> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "JWT verification failed");
        StatusCode::UNAUTHORIZED
    })?;

    let user_id = token_data
        .claims
        .sub
        .as_ref()
        .parse::<Uuid>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(UserId(user_id))
}

/// Axum extractor that validates JWT and provides authenticated user id.
pub struct AuthUser(pub UserId);

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = DomainError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user_id = auth_middleware(&parts.headers, state.config.jwt_secret.expose_secret())
            .map_err(|_| DomainError::Unauthorized("Invalid or missing token".to_string()))?;
        Ok(AuthUser(user_id))
    }
}

/// Extractor that enforces admin key for observability endpoints.
pub struct AdminApiKey;

impl FromRequestParts<Arc<AppState>> for AdminApiKey {
    type Rejection = DomainError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.config.admin_api_key.as_str();
        if expected.is_empty() {
            return Err(DomainError::Forbidden(
                "Admin observability endpoint is disabled".to_string(),
            ));
        }

        let provided = parts
            .headers
            .get("x-admin-key")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| DomainError::Unauthorized("Missing admin key".to_string()))?;

        if provided != expected {
            return Err(DomainError::Forbidden("Invalid admin key".to_string()));
        }

        Ok(Self)
    }
}
