//! Auth handlers.

use std::sync::Arc;

use axum::{Json, extract::State};
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::ExposeSecret;

use iqrah_backend_domain::{
    AuthResponse, Claims, DomainError, GoogleAuthRequest, JwtSubject, UserProfile,
};

use crate::AppState;
use crate::middleware::auth::AuthUser;

/// Google OAuth login handler.
pub async fn google_auth(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GoogleAuthRequest>,
) -> Result<Json<AuthResponse>, DomainError> {
    if req.id_token.trim().is_empty() {
        return Err(DomainError::Validation(
            "ID token cannot be empty".to_string(),
        ));
    }

    if state.config.google_client_id.trim().is_empty() {
        tracing::error!("GOOGLE_CLIENT_ID is not configured");
        return Err(DomainError::Internal(anyhow::anyhow!(
            "Google OAuth is not configured"
        )));
    }

    let oauth_sub = state
        .jwt_verifier
        .verify_google_id_token(&req.id_token)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "Google token verification failed");
            DomainError::Unauthorized("Invalid Google ID token".to_string())
        })?;

    let user = state
        .auth_repo
        .find_or_create(oauth_sub.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find/create user");
            DomainError::Database(e.to_string())
        })?;

    let expires_in = 3600u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            DomainError::Internal(anyhow::anyhow!(
                "System clock is before UNIX_EPOCH: {error}"
            ))
        })?
        .as_secs();

    let claims = Claims {
        sub: JwtSubject(user.id.to_string()),
        exp: now + expires_in,
        iat: now,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.expose_secret().as_bytes()),
    )
    .map_err(|error| {
        tracing::error!(error = %error, "Failed to encode JWT");
        DomainError::Internal(anyhow::anyhow!("Failed to generate access token: {error}"))
    })?;

    Ok(Json(AuthResponse {
        access_token: token,
        user_id: user.id,
        expires_in,
    }))
}

/// Returns current user profile from JWT context.
pub async fn get_me(
    State(state): State<Arc<AppState>>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<UserProfile>, DomainError> {
    let user = state
        .auth_repo
        .get_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = %user_id, "Failed to fetch user profile");
            DomainError::Database(e.to_string())
        })?
        .ok_or_else(|| DomainError::NotFound(format!("User {user_id} not found")))?;

    Ok(Json(UserProfile {
        id: user.id,
        created_at: user.created_at,
        last_seen_at: user.last_seen_at,
    }))
}
