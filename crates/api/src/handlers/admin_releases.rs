//! Admin release management handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::AppState;
use crate::middleware::auth::AdminApiKey;
use iqrah_backend_domain::{
    ApiError, ArtifactRole, DatasetRelease, DatasetReleaseArtifact, DomainError, ReleaseId,
    ReleaseValidationReport,
};
use iqrah_backend_storage::StorageError;

/// Request to create a draft dataset release.
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateReleaseRequest {
    #[validate(length(min = 1, max = 128))]
    #[schema(example = "2026.02.20.1")]
    pub version: String,
    #[validate(length(max = 2000))]
    #[schema(example = "First production release slice")]
    pub notes: Option<String>,
    #[validate(length(min = 1, max = 255))]
    #[schema(example = "admin@iqrah")]
    pub created_by: String,
}

/// Response for draft release creation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateReleaseResponse {
    pub release: DatasetRelease,
}

/// Request to attach an artifact to an existing release.
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct AttachReleaseArtifactRequest {
    #[validate(length(min = 1, max = 255))]
    #[schema(example = "translation.en")]
    pub package_id: String,
    pub artifact_role: ArtifactRole,
    pub required: bool,
}

/// Response for artifact attachment.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AttachReleaseArtifactResponse {
    pub artifact: DatasetReleaseArtifact,
}

/// Validation response for a release.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ValidateReleaseResponse {
    pub report: ReleaseValidationReport,
}

/// Publish response for a release.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublishReleaseResponse {
    pub published: bool,
    pub release: DatasetRelease,
}

/// Deprecate response for a release.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeprecateReleaseResponse {
    pub deprecated: bool,
    pub release: DatasetRelease,
}

/// Creates a draft release.
#[utoipa::path(
    post,
    path = "/v1/admin/releases",
    tag = "admin",
    request_body = CreateReleaseRequest,
    responses(
        (status = 201, description = "Draft release created", body = CreateReleaseResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
pub async fn create_release(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Json(req): Json<CreateReleaseRequest>,
) -> Result<(StatusCode, Json<CreateReleaseResponse>), DomainError> {
    req.validate()
        .map_err(DomainError::from_validation_errors)?;

    let release = state
        .release_repo
        .create_draft_release(req.version, req.notes, req.created_by)
        .await
        .map_err(map_release_repo_error)?;

    Ok((StatusCode::CREATED, Json(CreateReleaseResponse { release })))
}

/// Attaches an artifact package to a release.
#[utoipa::path(
    post,
    path = "/v1/admin/releases/{id}/artifacts",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Release ID (UUID)")
    ),
    request_body = AttachReleaseArtifactRequest,
    responses(
        (status = 201, description = "Artifact attached", body = AttachReleaseArtifactResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 404, description = "Release not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
pub async fn attach_release_artifact(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Path(release_id): Path<Uuid>,
    Json(req): Json<AttachReleaseArtifactRequest>,
) -> Result<(StatusCode, Json<AttachReleaseArtifactResponse>), DomainError> {
    req.validate()
        .map_err(DomainError::from_validation_errors)?;

    let artifact = state
        .release_repo
        .attach_artifact(
            ReleaseId(release_id),
            req.package_id,
            req.artifact_role,
            req.required,
        )
        .await
        .map_err(map_release_repo_error)?;

    Ok((
        StatusCode::CREATED,
        Json(AttachReleaseArtifactResponse { artifact }),
    ))
}

/// Validates release publish constraints.
#[utoipa::path(
    post,
    path = "/v1/admin/releases/{id}/validate",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Release ID (UUID)")
    ),
    responses(
        (status = 200, description = "Validation result", body = ValidateReleaseResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 404, description = "Release not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
pub async fn validate_release(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Path(release_id): Path<Uuid>,
) -> Result<Json<ValidateReleaseResponse>, DomainError> {
    let report = state
        .release_repo
        .validate_release(ReleaseId(release_id))
        .await
        .map_err(map_release_repo_error)?;

    Ok(Json(ValidateReleaseResponse { report }))
}

/// Publishes a release after validation.
#[utoipa::path(
    post,
    path = "/v1/admin/releases/{id}/publish",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Release ID (UUID)")
    ),
    responses(
        (status = 200, description = "Release published", body = PublishReleaseResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 404, description = "Release not found", body = ApiError),
        (status = 422, description = "Release validation failed", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
pub async fn publish_release(
    State(state): State<Arc<AppState>>,
    admin: AdminApiKey,
    Path(release_id): Path<Uuid>,
) -> Result<Json<PublishReleaseResponse>, DomainError> {
    let release = state
        .release_repo
        .publish_release(ReleaseId(release_id), admin.actor)
        .await
        .map_err(map_release_repo_error)?;

    Ok(Json(PublishReleaseResponse {
        published: true,
        release,
    }))
}

/// Deprecates a published release.
#[utoipa::path(
    post,
    path = "/v1/admin/releases/{id}/deprecate",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Release ID (UUID)")
    ),
    responses(
        (status = 200, description = "Release deprecated", body = DeprecateReleaseResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 404, description = "Release not found", body = ApiError),
        (status = 409, description = "Release cannot be deprecated from current status", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
pub async fn deprecate_release(
    State(state): State<Arc<AppState>>,
    admin: AdminApiKey,
    Path(release_id): Path<Uuid>,
) -> Result<Json<DeprecateReleaseResponse>, DomainError> {
    let release = state
        .release_repo
        .deprecate_release(ReleaseId(release_id), admin.actor)
        .await
        .map_err(map_release_repo_error)?;

    Ok(Json(DeprecateReleaseResponse {
        deprecated: true,
        release,
    }))
}

fn map_release_repo_error(error: StorageError) -> DomainError {
    match error {
        StorageError::Unexpected(message) if message.starts_with("release_not_found:") => {
            DomainError::NotFound(format!(
                "Release '{}' not found",
                message.trim_start_matches("release_not_found:")
            ))
        }
        StorageError::Unexpected(message) if message.starts_with("release_validation_failed:") => {
            DomainError::BusinessLogic(format!(
                "Release validation failed: {}",
                message.trim_start_matches("release_validation_failed:")
            ))
        }
        StorageError::Unexpected(message) if message.starts_with("release_not_publishable:") => {
            DomainError::Conflict(format!(
                "Release cannot be published from status '{}'",
                message.trim_start_matches("release_not_publishable:")
            ))
        }
        StorageError::Unexpected(message) if message.starts_with("release_not_deprecatable:") => {
            DomainError::Conflict(format!(
                "Release cannot be deprecated from status '{}'",
                message.trim_start_matches("release_not_deprecatable:")
            ))
        }
        other => DomainError::Database(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::{
        Json,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use chrono::Utc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::assets::pack_asset_store::FsPackAssetStore;
    use crate::auth::jwt_verifier::MockJwtVerifier;
    use crate::build_router;
    use crate::test_support::{
        NoopAuthRepository, NoopPackRepository, NoopSyncRepository, base_config, build_state,
        build_state_with_release_repo,
    };
    use iqrah_backend_storage::{ReleaseManifestRecord, ReleaseRepository};

    mockall::mock! {
        pub ReleaseRepo {}

        #[async_trait]
        impl ReleaseRepository for ReleaseRepo {
            async fn create_draft_release(
                &self,
                version: String,
                notes: Option<String>,
                created_by: String,
            ) -> Result<DatasetRelease, StorageError>;

            async fn attach_artifact(
                &self,
                release_id: ReleaseId,
                package_id: String,
                artifact_role: ArtifactRole,
                required: bool,
            ) -> Result<DatasetReleaseArtifact, StorageError>;

            async fn validate_release(
                &self,
                release_id: ReleaseId,
            ) -> Result<ReleaseValidationReport, StorageError>;

            async fn publish_release(
                &self,
                release_id: ReleaseId,
                actor: String,
            ) -> Result<DatasetRelease, StorageError>;

            async fn deprecate_release(
                &self,
                release_id: ReleaseId,
                actor: String,
            ) -> Result<DatasetRelease, StorageError>;

            async fn get_latest_release(&self) -> Result<Option<DatasetRelease>, StorageError>;

            async fn get_release_manifest(
                &self,
                release_id: ReleaseId,
            ) -> Result<Option<ReleaseManifestRecord>, StorageError>;
        }
    }

    fn make_release() -> DatasetRelease {
        DatasetRelease {
            id: ReleaseId(Uuid::new_v4()),
            version: "2026.02.20.1".to_string(),
            status: iqrah_backend_domain::DatasetReleaseStatus::Draft,
            notes: Some("notes".to_string()),
            created_by: "admin@iqrah".to_string(),
            created_at: Utc::now(),
            published_at: None,
        }
    }

    fn build_admin_state(repo: MockReleaseRepo) -> Arc<AppState> {
        build_state_with_release_repo(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        )
    }

    fn admin_auth() -> AdminApiKey {
        AdminApiKey {
            actor: "test-admin".to_string(),
        }
    }

    #[tokio::test]
    async fn create_release_happy_path_returns_created() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release()
            .times(1)
            .with(
                mockall::predicate::eq("2026.02.20.1".to_string()),
                mockall::predicate::eq(Some("notes".to_string())),
                mockall::predicate::eq("admin@iqrah".to_string()),
            )
            .returning(|_, _, _| Ok(make_release()));
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let (status, Json(response)) = create_release(
            axum::extract::State(state),
            admin_auth(),
            Json(CreateReleaseRequest {
                version: "2026.02.20.1".to_string(),
                notes: Some("notes".to_string()),
                created_by: "admin@iqrah".to_string(),
            }),
        )
        .await
        .expect("create should succeed");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.release.version, "2026.02.20.1");
    }

    #[tokio::test]
    async fn create_release_validation_fail_returns_400() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = create_release(
            axum::extract::State(state),
            admin_auth(),
            Json(CreateReleaseRequest {
                version: "".to_string(),
                notes: None,
                created_by: "".to_string(),
            }),
        )
        .await
        .expect_err("invalid request should fail");

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_release_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release()
            .times(1)
            .returning(|_, _, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = create_release(
            axum::extract::State(state),
            admin_auth(),
            Json(CreateReleaseRequest {
                version: "2026.02.20.1".to_string(),
                notes: None,
                created_by: "admin@iqrah".to_string(),
            }),
        )
        .await
        .expect_err("repo error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn create_release_route_auth_fail_returns_401() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let app = build_router(build_admin_state(repo));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/releases")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "version": "2026.02.20.1",
                            "created_by": "admin@iqrah"
                        }))
                        .expect("payload should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn attach_release_artifact_happy_path_returns_created() {
        let mut repo = MockReleaseRepo::new();
        let release_id = ReleaseId(Uuid::new_v4());
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact()
            .times(1)
            .with(
                mockall::predicate::eq(release_id),
                mockall::predicate::eq("translation.en".to_string()),
                mockall::predicate::eq(ArtifactRole::CoreContentDb),
                mockall::predicate::eq(true),
            )
            .returning(move |release_id, package_id, artifact_role, required| {
                Ok(DatasetReleaseArtifact {
                    release_id,
                    package_id: package_id.into(),
                    artifact_role,
                    required,
                    created_at: Utc::now(),
                })
            });
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let (status, Json(response)) = attach_release_artifact(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(release_id.0),
            Json(AttachReleaseArtifactRequest {
                package_id: "translation.en".to_string(),
                artifact_role: ArtifactRole::CoreContentDb,
                required: true,
            }),
        )
        .await
        .expect("attach should succeed");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.artifact.release_id, release_id);
    }

    #[tokio::test]
    async fn attach_release_artifact_validation_fail_returns_400() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = attach_release_artifact(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
            Json(AttachReleaseArtifactRequest {
                package_id: "".to_string(),
                artifact_role: ArtifactRole::OptionalPack,
                required: false,
            }),
        )
        .await
        .expect_err("invalid request should fail");

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attach_release_artifact_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact()
            .times(1)
            .returning(|_, _, _, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = attach_release_artifact(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
            Json(AttachReleaseArtifactRequest {
                package_id: "translation.en".to_string(),
                artifact_role: ArtifactRole::OptionalPack,
                required: false,
            }),
        )
        .await
        .expect_err("repo error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn attach_release_artifact_route_auth_fail_returns_401() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let app = build_router(build_admin_state(repo));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admin/releases/{}/artifacts", Uuid::new_v4()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "package_id": "translation.en",
                            "artifact_role": "core_content_db",
                            "required": true
                        }))
                        .expect("payload should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_release_happy_path_returns_report() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(1).returning(|_| {
            Ok(ReleaseValidationReport {
                valid: true,
                failures: Vec::new(),
                warnings: Vec::new(),
            })
        });
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let Json(response) = validate_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
        )
        .await
        .expect("validation should succeed");

        assert!(response.report.valid);
    }

    #[tokio::test]
    async fn validate_release_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = validate_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
        )
        .await
        .expect_err("repo error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn validate_release_route_validation_fail_returns_400() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/releases/not-a-uuid/validate")
                    .header("x-admin-key", "admin-secret")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn validate_release_route_auth_fail_returns_401() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admin/releases/{}/validate", Uuid::new_v4()))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn publish_release_happy_path_returns_published_true() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release()
            .times(1)
            .with(
                mockall::predicate::eq(ReleaseId(Uuid::nil())),
                mockall::predicate::eq("test-admin".to_string()),
            )
            .returning(|_, _| Ok(make_release()));
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let release_id = Uuid::nil();
        let state = build_admin_state(repo);
        let Json(response) = publish_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(release_id),
        )
        .await
        .expect("publish should succeed");

        assert!(response.published);
    }

    #[tokio::test]
    async fn publish_release_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release()
            .times(1)
            .returning(|_, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_deprecate_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = publish_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
        )
        .await
        .expect_err("repo error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn publish_release_route_validation_fail_returns_400() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/releases/not-a-uuid/publish")
                    .header("x-admin-key", "admin-secret")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_release_route_auth_fail_returns_401() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admin/releases/{}/publish", Uuid::new_v4()))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deprecate_release_happy_path_returns_deprecated_true() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release()
            .times(1)
            .with(
                mockall::predicate::eq(ReleaseId(Uuid::nil())),
                mockall::predicate::eq("test-admin".to_string()),
            )
            .returning(|_, _| Ok(make_release()));
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let release_id = Uuid::nil();
        let state = build_admin_state(repo);
        let Json(response) = deprecate_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(release_id),
        )
        .await
        .expect("deprecate should succeed");

        assert!(response.deprecated);
    }

    #[tokio::test]
    async fn deprecate_release_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_deprecate_release()
            .times(1)
            .returning(|_, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest().times(0);

        let state = build_admin_state(repo);
        let err = deprecate_release(
            axum::extract::State(state),
            admin_auth(),
            axum::extract::Path(Uuid::new_v4()),
        )
        .await
        .expect_err("repo error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn deprecate_release_route_validation_fail_returns_400() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/releases/not-a-uuid/deprecate")
                    .header("x-admin-key", "admin-secret")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deprecate_release_route_auth_fail_returns_401() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admin/releases/{}/deprecate", Uuid::new_v4()))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
