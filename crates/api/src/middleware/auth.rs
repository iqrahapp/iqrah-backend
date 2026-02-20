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

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn decode_claims(headers: &HeaderMap, jwt_secret: &str) -> Result<Claims, StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|token_data| token_data.claims)
    .map_err(|e| {
        tracing::warn!(error = %e, "JWT verification failed");
        StatusCode::UNAUTHORIZED
    })
}

/// Extracts and verifies user id from Authorization header.
pub fn auth_middleware(headers: &HeaderMap, jwt_secret: &str) -> Result<UserId, StatusCode> {
    let claims = decode_claims(headers, jwt_secret)?;

    let user_id = claims
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
        let expected_key = state.config.admin_api_key.as_str();

        if let Some(provided_key) = parts
            .headers
            .get("x-admin-key")
            .and_then(|value| value.to_str().ok())
        {
            if expected_key.is_empty() {
                return Err(DomainError::Forbidden(
                    "Admin key authentication is disabled".to_string(),
                ));
            }

            if provided_key != expected_key {
                return Err(DomainError::Forbidden("Invalid admin key".to_string()));
            }

            return Ok(Self);
        }

        let allowlist = &state.config.admin_oauth_sub_allowlist;
        if allowlist.is_empty() {
            return Err(DomainError::Unauthorized(
                "Missing admin credentials".to_string(),
            ));
        }

        let claims = decode_claims(&parts.headers, state.config.jwt_secret.expose_secret())
            .map_err(|_| DomainError::Unauthorized("Missing admin credentials".to_string()))?;

        if claims.role.as_deref() != Some("admin") {
            return Err(DomainError::Forbidden("Admin role required".to_string()));
        }

        let oauth_sub = claims
            .oauth_sub
            .ok_or_else(|| DomainError::Forbidden("Admin OAuth subject missing".to_string()))?;

        if !allowlist
            .iter()
            .any(|allowed_sub| allowed_sub == &oauth_sub)
        {
            return Err(DomainError::Forbidden(
                "Admin subject not allowlisted".to_string(),
            ));
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
                role: None,
                oauth_sub: None,
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token should encode")
    }

    fn make_admin_jwt(secret: &str, sub: &str, oauth_sub: &str) -> String {
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
                role: Some("admin".to_string()),
                oauth_sub: Some(oauth_sub.to_string()),
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

    #[tokio::test]
    async fn admin_api_key_extractor_accepts_allowlisted_admin_jwt() {
        let mut config = base_config();
        config.admin_api_key.clear();
        config.admin_oauth_sub_allowlist = vec!["oauth-admin".to_string()];
        let token = make_admin_jwt("test-secret", &Uuid::new_v4().to_string(), "oauth-admin");
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
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect("allowlisted admin token should pass");
    }

    #[tokio::test]
    async fn admin_api_key_extractor_rejects_non_admin_jwt() {
        let mut config = base_config();
        config.admin_api_key.clear();
        config.admin_oauth_sub_allowlist = vec!["oauth-admin".to_string()];
        let token = make_jwt("test-secret", &Uuid::new_v4().to_string());
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
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect_err("non-admin token should fail");
        assert!(matches!(err, DomainError::Forbidden(_)));
    }

    #[tokio::test]
    async fn admin_api_key_extractor_rejects_non_allowlisted_admin_jwt() {
        let mut config = base_config();
        config.admin_api_key.clear();
        config.admin_oauth_sub_allowlist = vec!["oauth-admin".to_string()];
        let token = make_admin_jwt("test-secret", &Uuid::new_v4().to_string(), "oauth-other");
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
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request should build")
            .into_parts();

        let err = AdminApiKey::from_request_parts(&mut parts, &state)
            .await
            .expect_err("non-allowlisted admin token should fail");
        assert!(matches!(err, DomainError::Forbidden(_)));
    }
}
