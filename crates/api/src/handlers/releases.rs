//! Public release handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use uuid::Uuid;

use crate::AppState;
use iqrah_backend_domain::{
    ApiError, DomainError, LatestReleaseResponse, PackId, ReleaseArtifactManifestEntry, ReleaseId,
    ReleaseManifestResponse,
};
use iqrah_backend_storage::{ReleaseManifestArtifactRecord, ReleaseManifestRecord, StorageError};

/// Returns the latest published release and required artifacts.
#[utoipa::path(
    get,
    path = "/v1/releases/latest",
    tag = "releases",
    responses(
        (status = 200, description = "Latest published release", body = LatestReleaseResponse),
        (status = 404, description = "No published release found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_latest_release(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LatestReleaseResponse>, DomainError> {
    let latest = state
        .release_repo
        .get_latest_release()
        .await
        .map_err(map_release_repo_error)?
        .ok_or_else(|| DomainError::NotFound("No published release found".to_string()))?;

    let manifest = state
        .release_repo
        .get_release_manifest(latest.id)
        .await
        .map_err(map_release_repo_error)?
        .ok_or_else(|| DomainError::NotFound(format!("Release '{}' not found", latest.id)))?;

    let required_artifacts = build_manifest_entries(&manifest, &state.config.base_url)
        .into_iter()
        .filter(|artifact| artifact.required)
        .collect();

    Ok(Json(LatestReleaseResponse {
        release: manifest.release,
        required_artifacts,
    }))
}

/// Returns the full artifact manifest for one published release.
#[utoipa::path(
    get,
    path = "/v1/releases/{id}/manifest",
    tag = "releases",
    params(
        ("id" = String, Path, description = "Release ID (UUID)")
    ),
    responses(
        (status = 200, description = "Release manifest", body = ReleaseManifestResponse),
        (status = 400, description = "Invalid release id", body = ApiError),
        (status = 404, description = "Release not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_release_manifest(
    State(state): State<Arc<AppState>>,
    Path(release_id): Path<Uuid>,
) -> Result<Json<ReleaseManifestResponse>, DomainError> {
    let manifest = state
        .release_repo
        .get_release_manifest(ReleaseId(release_id))
        .await
        .map_err(map_release_repo_error)?
        .ok_or_else(|| DomainError::NotFound(format!("Release '{}' not found", release_id)))?;
    let artifacts = build_manifest_entries(&manifest, &state.config.base_url);

    Ok(Json(ReleaseManifestResponse {
        release: manifest.release,
        artifacts,
    }))
}

fn build_manifest_entries(
    manifest: &ReleaseManifestRecord,
    base_url: &str,
) -> Vec<ReleaseArtifactManifestEntry> {
    manifest
        .artifacts
        .iter()
        .map(|artifact| to_manifest_entry(artifact, base_url))
        .collect()
}

fn to_manifest_entry(
    artifact: &ReleaseManifestArtifactRecord,
    base_url: &str,
) -> ReleaseArtifactManifestEntry {
    ReleaseArtifactManifestEntry {
        package_id: PackId(artifact.package_id.clone()),
        required: artifact.required,
        artifact_role: artifact.artifact_role,
        version: artifact.version.clone(),
        sha256: artifact.sha256.clone(),
        file_size_bytes: artifact.file_size_bytes,
        download_url: format!("{}/v1/packs/{}/download", base_url, artifact.package_id),
    }
}

fn map_release_repo_error(error: StorageError) -> DomainError {
    match error {
        StorageError::Unexpected(message) if message.starts_with("release_not_found:") => {
            DomainError::NotFound(format!(
                "Release '{}' not found",
                message.trim_start_matches("release_not_found:")
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
        body::Body,
        http::{Request, StatusCode},
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
    use iqrah_backend_domain::{ArtifactRole, DatasetRelease, DatasetReleaseStatus};
    use iqrah_backend_storage::ReleaseRepository;

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
            ) -> Result<iqrah_backend_domain::DatasetReleaseArtifact, StorageError>;

            async fn validate_release(
                &self,
                release_id: ReleaseId,
            ) -> Result<iqrah_backend_domain::ReleaseValidationReport, StorageError>;

            async fn publish_release(
                &self,
                release_id: ReleaseId,
            ) -> Result<DatasetRelease, StorageError>;

            async fn get_latest_release(&self) -> Result<Option<DatasetRelease>, StorageError>;

            async fn get_release_manifest(
                &self,
                release_id: ReleaseId,
            ) -> Result<Option<ReleaseManifestRecord>, StorageError>;
        }
    }

    fn build_public_state(repo: MockReleaseRepo) -> Arc<AppState> {
        let mut config = base_config();
        config.base_url = "https://api.example.com".to_string();

        build_state_with_release_repo(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmpdir").path(),
            )),
            config,
        )
    }

    fn sample_release(id: ReleaseId) -> DatasetRelease {
        DatasetRelease {
            id,
            version: "2026.02.20.1".to_string(),
            status: DatasetReleaseStatus::Published,
            notes: Some("notes".to_string()),
            created_by: "admin@iqrah".to_string(),
            created_at: Utc::now(),
            published_at: Some(Utc::now()),
        }
    }

    fn sample_manifest(id: ReleaseId) -> ReleaseManifestRecord {
        ReleaseManifestRecord {
            release: sample_release(id),
            artifacts: vec![
                ReleaseManifestArtifactRecord {
                    package_id: "core-content-pack".to_string(),
                    required: true,
                    artifact_role: ArtifactRole::CoreContentDb,
                    version: "1.0.0".to_string(),
                    sha256: "a".repeat(64),
                    file_size_bytes: 1024,
                },
                ReleaseManifestArtifactRecord {
                    package_id: "optional-audio-pack".to_string(),
                    required: false,
                    artifact_role: ArtifactRole::AudioCatalog,
                    version: "2.0.0".to_string(),
                    sha256: "b".repeat(64),
                    file_size_bytes: 2048,
                },
            ],
        }
    }

    #[tokio::test]
    async fn get_latest_release_happy_path_returns_required_artifacts() {
        let release_id = ReleaseId(Uuid::new_v4());
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_get_latest_release()
            .times(1)
            .returning(move || Ok(Some(sample_release(release_id))));
        repo.expect_get_release_manifest()
            .times(1)
            .with(mockall::predicate::eq(release_id))
            .returning(move |_| Ok(Some(sample_manifest(release_id))));

        let state = build_public_state(repo);
        let Json(response) = get_latest_release(axum::extract::State(state))
            .await
            .expect("latest should load");

        assert_eq!(response.release.id, release_id);
        assert_eq!(response.required_artifacts.len(), 1);
        assert_eq!(
            response.required_artifacts[0].package_id.0,
            "core-content-pack"
        );
        assert_eq!(
            response.required_artifacts[0].download_url,
            "https://api.example.com/v1/packs/core-content-pack/download"
        );
    }

    #[tokio::test]
    async fn get_latest_release_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_get_latest_release()
            .times(1)
            .returning(|| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_get_release_manifest().times(0);

        let state = build_public_state(repo);
        let err = get_latest_release(axum::extract::State(state))
            .await
            .expect_err("repo failure should bubble");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_release_manifest_happy_path_returns_full_manifest() {
        let release_id = ReleaseId(Uuid::new_v4());
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest()
            .times(1)
            .with(mockall::predicate::eq(release_id))
            .returning(move |_| Ok(Some(sample_manifest(release_id))));

        let state = build_public_state(repo);
        let Json(response) = get_release_manifest(
            axum::extract::State(state),
            axum::extract::Path(release_id.0),
        )
        .await
        .expect("manifest should load");

        assert_eq!(response.release.id, release_id);
        assert_eq!(response.artifacts.len(), 2);
    }

    #[tokio::test]
    async fn get_release_manifest_repo_fail_returns_500() {
        let mut repo = MockReleaseRepo::new();
        repo.expect_create_draft_release().times(0);
        repo.expect_attach_artifact().times(0);
        repo.expect_validate_release().times(0);
        repo.expect_publish_release().times(0);
        repo.expect_get_latest_release().times(0);
        repo.expect_get_release_manifest()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db down".to_string())));

        let state = build_public_state(repo);
        let err = get_release_manifest(
            axum::extract::State(state),
            axum::extract::Path(Uuid::new_v4()),
        )
        .await
        .expect_err("repo failure should bubble");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_release_manifest_route_validation_fail_returns_400() {
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
                    .method("GET")
                    .uri("/v1/releases/not-a-uuid/manifest")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
