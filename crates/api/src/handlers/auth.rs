//! Auth handlers.

use std::sync::Arc;

use axum::{Json, extract::State};
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::ExposeSecret;

use iqrah_backend_domain::{
    ApiError, AuthResponse, Claims, DomainError, GoogleAuthRequest, JwtSubject, UserProfile,
};

use crate::AppState;
use crate::middleware::auth::AuthUser;

/// Google OAuth login handler.
#[utoipa::path(
    post,
    path = "/v1/auth/google",
    tag = "auth",
    request_body = GoogleAuthRequest,
    responses(
        (status = 200, description = "Authenticated", body = AuthResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
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
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current user profile", body = UserProfile),
        (status = 401, description = "Unauthorized", body = ApiError),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("bearer_auth" = []))
)]
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use chrono::Utc;
    use iqrah_backend_domain::UserId;
    use iqrah_backend_storage::{AuthRepository, StorageError, UserRecord};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::jwt_verifier::MockJwtVerifier;
    use crate::build_router;
    use crate::test_support::{
        NoopPackAssetStore, NoopPackRepository, NoopSyncRepository, base_config, build_state,
    };

    mockall::mock! {
        pub AuthRepo {}

        #[async_trait]
        impl AuthRepository for AuthRepo {
            async fn find_or_create(&self, oauth_sub: &str) -> Result<UserRecord, StorageError>;
            async fn get_by_id(&self, id: UserId) -> Result<Option<UserRecord>, StorageError>;
        }
    }

    fn sample_user() -> UserRecord {
        UserRecord {
            id: UserId(Uuid::new_v4()),
            oauth_sub: "oauth-sub-1".to_string(),
            created_at: Utc::now(),
            last_seen_at: Some(Utc::now()),
        }
    }

    #[tokio::test]
    async fn google_auth_happy_path_returns_access_token_and_user() {
        let user = sample_user();

        let mut verifier = MockJwtVerifier::new();
        verifier
            .expect_verify_google_id_token()
            .times(1)
            .with(mockall::predicate::eq("google-token"))
            .returning(|_| Ok(JwtSubject("oauth-sub-1".to_string())));

        let mut auth_repo = MockAuthRepo::new();
        let user_for_mock = user.clone();
        auth_repo
            .expect_find_or_create()
            .times(1)
            .with(mockall::predicate::eq("oauth-sub-1"))
            .returning(move |_| Ok(user_for_mock.clone()));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let response = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "google-token".to_string(),
            }),
        )
        .await
        .expect("google auth should succeed");

        assert_eq!(response.0.user_id, user.id);
        assert_eq!(response.0.expires_in, 3600);
        assert!(!response.0.access_token.is_empty());
    }

    #[tokio::test]
    async fn google_auth_returns_400_for_empty_id_token() {
        let mut verifier = MockJwtVerifier::new();
        verifier.expect_verify_google_id_token().times(0);

        let mut auth_repo = MockAuthRepo::new();
        auth_repo.expect_find_or_create().times(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "   ".to_string(),
            }),
        )
        .await
        .expect_err("empty token should fail");

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn google_auth_returns_401_when_verifier_rejects_token() {
        let mut verifier = MockJwtVerifier::new();
        verifier
            .expect_verify_google_id_token()
            .times(1)
            .returning(|_| Err(anyhow::anyhow!("invalid token")));

        let mut auth_repo = MockAuthRepo::new();
        auth_repo.expect_find_or_create().times(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "bad-token".to_string(),
            }),
        )
        .await
        .expect_err("invalid token should fail");

        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn google_auth_returns_500_when_storage_fails() {
        let mut verifier = MockJwtVerifier::new();
        verifier
            .expect_verify_google_id_token()
            .times(1)
            .returning(|_| Ok(JwtSubject("oauth-sub-1".to_string())));

        let mut auth_repo = MockAuthRepo::new();
        auth_repo
            .expect_find_or_create()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db down".to_string())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "valid-token".to_string(),
            }),
        )
        .await
        .expect_err("storage error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn google_auth_returns_500_when_google_client_id_not_configured() {
        let mut verifier = MockJwtVerifier::new();
        verifier.expect_verify_google_id_token().times(0);

        let mut auth_repo = MockAuthRepo::new();
        auth_repo.expect_find_or_create().times(0);

        let mut config = base_config();
        config.google_client_id.clear();

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            config,
        );

        let err = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "valid-token".to_string(),
            }),
        )
        .await
        .expect_err("missing google config should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_me_happy_path_returns_profile() {
        let user = sample_user();

        let mut auth_repo = MockAuthRepo::new();
        let user_for_mock = user.clone();
        auth_repo
            .expect_get_by_id()
            .times(1)
            .with(mockall::predicate::eq(user.id))
            .returning(move |_| Ok(Some(user_for_mock.clone())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let response = get_me(axum::extract::State(state), AuthUser(user.id))
            .await
            .expect("get_me should succeed");

        assert_eq!(response.0.id, user.id);
    }

    #[tokio::test]
    async fn get_me_returns_404_when_user_is_missing() {
        let user_id = UserId(Uuid::new_v4());
        let mut auth_repo = MockAuthRepo::new();
        auth_repo
            .expect_get_by_id()
            .times(1)
            .returning(|_| Ok(None));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = get_me(axum::extract::State(state), AuthUser(user_id))
            .await
            .expect_err("missing user should fail");

        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_me_returns_500_when_repository_errors() {
        let mut auth_repo = MockAuthRepo::new();
        auth_repo
            .expect_get_by_id()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db timeout".to_string())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = get_me(
            axum::extract::State(state),
            AuthUser(UserId(Uuid::new_v4())),
        )
        .await
        .expect_err("repository error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_me_endpoint_returns_401_without_authorization_header() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(MockAuthRepo::new()),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/users/me")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn google_auth_error_maps_to_500_response() {
        let mut verifier = MockJwtVerifier::new();
        verifier
            .expect_verify_google_id_token()
            .times(1)
            .returning(|_| Ok(JwtSubject("oauth-sub-1".to_string())));

        let mut auth_repo = MockAuthRepo::new();
        auth_repo
            .expect_find_or_create()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db down".to_string())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(auth_repo),
            Arc::new(NoopSyncRepository),
            Arc::new(verifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let error = google_auth(
            axum::extract::State(state),
            Json(GoogleAuthRequest {
                id_token: "valid".to_string(),
            }),
        )
        .await
        .expect_err("request should fail");

        assert_eq!(
            error.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
