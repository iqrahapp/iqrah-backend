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
#[derive(Debug)]
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
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::FromRequestParts;
    use axum::http::{Request, StatusCode, header};
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;
    use crate::test_support::{base_config, build_default_state, build_state};
    use iqrah_backend_domain::{Claims, JwtSubject};

    fn make_jwt(secret: &str, sub: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_secs();

        encode(
            &Header::default(),
            &Claims {
                sub: JwtSubject(sub.to_string()),
                exp: now + 3600,
                iat: now,
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token should encode")
    }

    #[test]
    fn auth_middleware_rejects_missing_authorization_header() {
        let headers = HeaderMap::new();
        let result = auth_middleware(&headers, "secret");
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn auth_middleware_rejects_invalid_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Token abc".parse().expect("valid header"),
        );
        let result = auth_middleware(&headers, "secret");
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn auth_middleware_accepts_valid_token_and_returns_user_id() {
        let user_id = uuid::Uuid::new_v4();
        let token = make_jwt("test-secret", &user_id.to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("valid header"),
        );

        let result = auth_middleware(&headers, "test-secret").expect("token should validate");
        assert_eq!(result.0, user_id);
    }

    #[test]
    fn auth_middleware_rejects_invalid_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer not-a-jwt".parse().expect("valid header"),
        );
        let result = auth_middleware(&headers, "secret");
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn auth_user_extractor_returns_unauthorized_error_for_missing_token() {
        let state = build_default_state();
        let (mut parts, _) = Request::builder()
            .uri("/v1/users/me")
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AuthUser::from_request_parts(&mut parts, &state)
            .await
            .expect_err("extractor should fail");

        assert!(matches!(err, DomainError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn admin_api_key_extractor_accepts_matching_key() {
        let state = build_default_state();
        let (mut parts, _) = Request::builder()
            .uri("/v1/admin/packs")
            .header("x-admin-key", "admin-secret")
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect("admin key should pass");
    }

    #[tokio::test]
    async fn admin_api_key_extractor_rejects_missing_key() {
        let state = build_default_state();
        let (mut parts, _) = Request::builder()
            .uri("/v1/admin/packs")
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect_err("missing key should fail");
        assert!(matches!(err, DomainError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn admin_api_key_extractor_rejects_invalid_key() {
        let state = build_default_state();
        let (mut parts, _) = Request::builder()
            .uri("/v1/admin/packs")
            .header("x-admin-key", "wrong-key")
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect_err("invalid key should fail");
        assert!(matches!(err, DomainError::Forbidden(_)));
    }

    #[tokio::test]
    async fn admin_api_key_extractor_rejects_when_admin_is_disabled() {
        let mut config = base_config();
        config.admin_api_key.clear();
        let state = build_state(
            Arc::new(crate::test_support::NoopPackRepository),
            Arc::new(crate::test_support::NoopAuthRepository),
            Arc::new(crate::test_support::NoopSyncRepository),
            Arc::new(crate::test_support::NoopJwtVerifier),
            Arc::new(crate::test_support::NoopPackAssetStore),
            config,
        );
        let (mut parts, _) = Request::builder()
            .uri("/v1/admin/packs")
            .header("x-admin-key", "ignored")
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect_err("disabled admin endpoint should fail");
        assert!(matches!(err, DomainError::Forbidden(_)));
    }
}
