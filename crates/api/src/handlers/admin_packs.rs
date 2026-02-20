//! Admin pack management handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Multipart, Path, State},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::AppState;
use crate::middleware::auth::AdminApiKey;
use iqrah_backend_domain::{
    ApiError, DomainError, PackId, PackManifestEntry, PackManifestResponse, PackType,
};

/// Request to register a new pack.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterPackRequest {
    #[schema(example = "English Translation")]
    pub name: String,
    #[schema(example = "English translation pack for mobile clients")]
    pub description: String,
    #[schema(example = "translation")]
    pub pack_type: PackType,
}

/// Response for pack registration.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegisterPackResponse {
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: String,
}

/// Multipart payload for adding a pack version.
#[derive(Debug, utoipa::ToSchema)]
pub struct AddVersionMultipartBody {
    #[schema(example = "1.0.0")]
    pub version: String,
    #[schema(value_type = String, format = Binary)]
    pub file: String,
}

/// Response for adding a pack version.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AddVersionResponse {
    #[schema(example = "1.0.0")]
    pub version: String,
    #[schema(example = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    pub sha256: String,
    #[schema(example = 1024)]
    pub file_size_bytes: u64,
}

/// Response for publishing a pack.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublishPackResponse {
    pub published: bool,
}

/// Registers a new pack.
#[utoipa::path(
    post,
    path = "/v1/admin/packs",
    tag = "admin",
    request_body = RegisterPackRequest,
    responses(
        (status = 201, description = "Pack registered", body = RegisterPackResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []))
)]
pub async fn register_pack(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Json(req): Json<RegisterPackRequest>,
) -> Result<(axum::http::StatusCode, Json<RegisterPackResponse>), DomainError> {
    let package_id = Uuid::new_v4().to_string();
    let pack_type = serde_json::to_string(&req.pack_type)
        .map_err(|e| DomainError::Internal(anyhow::anyhow!(e)))?
        .trim_matches('"')
        .to_string();

    state
        .pack_repo
        .register_pack(
            package_id.clone(),
            pack_type,
            "und".to_string(),
            req.name,
            Some(req.description),
        )
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(RegisterPackResponse { id: package_id }),
    ))
}

/// Uploads a new version file for an existing pack.
#[utoipa::path(
    post,
    path = "/v1/admin/packs/{id}/versions",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Pack ID")
    ),
    request_body(
        content = AddVersionMultipartBody,
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 201, description = "Version uploaded", body = AddVersionResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []))
)]
pub async fn add_version(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Path(package_id): Path<String>,
    mut multipart: Multipart,
) -> Result<(axum::http::StatusCode, Json<AddVersionResponse>), DomainError> {
    let mut version: Option<String> = None;
    let mut filename = "pack.bin".to_string();
    let mut relative_path: Option<String> = None;
    let mut file_size: u64 = 0;
    let mut hasher = Sha256::new();
    let mut file_handle: Option<tokio::fs::File> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| DomainError::Validation(format!("Invalid multipart payload: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if name == "version" {
            version = Some(
                field
                    .text()
                    .await
                    .map_err(|e| DomainError::Validation(format!("Invalid version field: {e}")))?,
            );
            continue;
        }

        if name == "file" {
            if let Some(given) = field.file_name() {
                filename = given.to_string();
            }

            let version_value = version.clone().ok_or_else(|| {
                DomainError::Validation(
                    "Multipart field `version` must be provided before `file`".to_string(),
                )
            })?;

            let relative = format!("{package_id}/{version_value}/{filename}");
            state
                .pack_asset_store
                .ensure_parent_dirs(&relative)
                .await
                .map_err(|e| {
                    DomainError::Internal(anyhow::anyhow!("Failed to create upload directory: {e}"))
                })?;

            let mut out = state
                .pack_asset_store
                .create_for_write(&relative)
                .await
                .map_err(|e| {
                    DomainError::Internal(anyhow::anyhow!("Failed to create uploaded file: {e}"))
                })?;

            let mut upload_field = field;
            while let Some(chunk) = upload_field
                .chunk()
                .await
                .map_err(|e| DomainError::Validation(format!("Invalid file upload chunk: {e}")))?
            {
                hasher.update(&chunk);
                file_size += chunk.len() as u64;
                out.write_all(&chunk).await.map_err(|e| {
                    DomainError::Internal(anyhow::anyhow!("Failed to write uploaded file: {e}"))
                })?;
            }

            file_handle = Some(out);
            relative_path = Some(relative);
        }
    }

    if let Some(file) = file_handle.as_mut() {
        file.flush().await.map_err(|e| {
            DomainError::Internal(anyhow::anyhow!("Failed to flush uploaded file: {e}"))
        })?;
    }

    let version =
        version.ok_or_else(|| DomainError::Validation("Missing `version` field".to_string()))?;
    let relative_path =
        relative_path.ok_or_else(|| DomainError::Validation("Missing `file` field".to_string()))?;
    let sha256 = format!("{:x}", hasher.finalize());

    state
        .add_pack_version(
            &package_id,
            &version,
            &relative_path,
            i64::try_from(file_size).map_err(|e| DomainError::Internal(anyhow::anyhow!(e)))?,
            &sha256,
            None,
        )
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(AddVersionResponse {
            version,
            sha256,
            file_size_bytes: file_size,
        }),
    ))
}

/// Publishes an existing pack.
#[utoipa::path(
    post,
    path = "/v1/admin/packs/{id}/publish",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Pack ID")
    ),
    responses(
        (status = 200, description = "Pack published", body = PublishPackResponse),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []))
)]
pub async fn publish_pack(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Path(package_id): Path<String>,
) -> Result<Json<PublishPackResponse>, DomainError> {
    state
        .pack_repo
        .publish_pack(package_id)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok(Json(PublishPackResponse { published: true }))
}

/// Lists all packs and their latest versions for admin tooling.
#[utoipa::path(
    get,
    path = "/v1/admin/packs",
    tag = "admin",
    responses(
        (status = 200, description = "All packs", body = PackManifestResponse),
        (status = 401, description = "Missing admin key", body = ApiError),
        (status = 403, description = "Invalid/disabled admin key", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    ),
    security(("admin_api_key" = []))
)]
pub async fn list_all_packs(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
) -> Result<Json<PackManifestResponse>, DomainError> {
    let packs = state
        .pack_repo
        .list_all_packs()
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let base_url = &state.config.base_url;
    let entries = packs
        .into_iter()
        .map(|pack| PackManifestEntry {
            id: PackId(pack.id.clone()),
            name: pack.name,
            description: pack.description,
            pack_type: pack.pack_type,
            version: pack.version,
            sha256: pack.sha256,
            file_size_bytes: pack.file_size_bytes,
            created_at: pack.created_at,
            download_url: format!("{}/v1/packs/{}/download", base_url, pack.id),
        })
        .collect();

    Ok(Json(PackManifestResponse { packs: entries }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use chrono::Utc;
    use iqrah_backend_storage::{PackInfo, PackRepository, PackVersionInfo, StorageError};
    use tower::ServiceExt;

    use super::*;
    use crate::assets::pack_asset_store::FsPackAssetStore;
    use crate::auth::jwt_verifier::MockJwtVerifier;
    use crate::build_router;
    use crate::test_support::{NoopAuthRepository, NoopSyncRepository, base_config, build_state};

    mockall::mock! {
        pub PackRepo {}

        #[async_trait]
        impl PackRepository for PackRepo {
            async fn list_available(
                &self,
                pack_type: Option<String>,
                language: Option<String>,
            ) -> Result<Vec<PackInfo>, StorageError>;

            async fn get_pack(&self, package_id: String) -> Result<Option<PackInfo>, StorageError>;
            async fn list_active_pack_versions(&self) -> Result<Vec<PackVersionInfo>, StorageError>;
            async fn list_all_packs(&self) -> Result<Vec<PackVersionInfo>, StorageError>;
            async fn get_active_version_id(&self, package_id: String) -> Result<Option<i32>, StorageError>;
            async fn register_pack(
                &self,
                package_id: String,
                pack_type: String,
                language: String,
                name: String,
                description: Option<String>,
            ) -> Result<(), StorageError>;
            async fn add_version(
                &self,
                package_id: String,
                version: String,
                file_path: String,
                size_bytes: i64,
                sha256: String,
                min_app_version: Option<String>,
            ) -> Result<(), StorageError>;
            async fn publish_pack(&self, package_id: String) -> Result<(), StorageError>;
        }
    }

    fn multipart_body(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
        let boundary = "----iqrah-test-boundary";
        let mut body = Vec::new();
        for (name, filename, value) in parts {
            match filename {
                Some(filename) => {
                    body.extend_from_slice(
                        format!(
                            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(value);
                    body.extend_from_slice(b"\r\n");
                }
                None => {
                    body.extend_from_slice(
                        format!(
                            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(value);
                    body.extend_from_slice(b"\r\n");
                }
            }
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (boundary.to_string(), body)
    }

    #[tokio::test]
    async fn register_pack_happy_path_returns_created_and_pack_id() {
        let mut repo = MockPackRepo::new();
        repo.expect_register_pack()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmp").path(),
            )),
            base_config(),
        );

        let (status, Json(body)) = register_pack(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
            Json(RegisterPackRequest {
                name: "English Pack".to_string(),
                description: "desc".to_string(),
                pack_type: PackType::Translation,
            }),
        )
        .await
        .expect("register should succeed");

        assert_eq!(status, StatusCode::CREATED);
        assert!(Uuid::parse_str(&body.id).is_ok());
    }

    #[tokio::test]
    async fn register_pack_returns_500_on_repository_error() {
        let mut repo = MockPackRepo::new();
        repo.expect_register_pack()
            .times(1)
            .returning(|_, _, _, _, _| Err(StorageError::Unexpected("db".to_string())));
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmp").path(),
            )),
            base_config(),
        );

        let err = register_pack(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
            Json(RegisterPackRequest {
                name: "English Pack".to_string(),
                description: "desc".to_string(),
                pack_type: PackType::Translation,
            }),
        )
        .await
        .expect_err("register should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn publish_pack_happy_path_returns_published_true() {
        let mut repo = MockPackRepo::new();
        repo.expect_publish_pack().times(1).returning(|_| Ok(()));
        repo.expect_register_pack().times(0);
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_add_version().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmp").path(),
            )),
            base_config(),
        );

        let Json(response) = publish_pack(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
            axum::extract::Path("pack-1".to_string()),
        )
        .await
        .expect("publish should succeed");

        assert!(response.published);
    }

    #[tokio::test]
    async fn list_all_packs_happy_path_maps_entries() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_all_packs().times(1).returning(|| {
            Ok(vec![PackVersionInfo {
                id: "pack-1".to_string(),
                name: "English".to_string(),
                description: Some("desc".to_string()),
                pack_type: "translation".to_string(),
                version: "1.0.0".to_string(),
                sha256: "abc".repeat(21) + "a",
                file_size_bytes: 100,
                created_at: Utc::now(),
            }])
        });
        repo.expect_publish_pack().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_add_version().times(0);

        let mut config = base_config();
        config.base_url = "https://api.example.com".to_string();

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmp").path(),
            )),
            config,
        );

        let Json(response) = list_all_packs(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
        )
        .await
        .expect("list should succeed");

        assert_eq!(response.packs.len(), 1);
        assert_eq!(
            response.packs[0].download_url,
            "https://api.example.com/v1/packs/pack-1/download"
        );
    }

    #[tokio::test]
    async fn add_version_route_returns_400_when_version_missing() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        let mut repo = MockPackRepo::new();
        repo.expect_get_active_version_id().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(temp_dir.path())),
            base_config(),
        );
        let app = build_router(state);

        let (boundary, body) = multipart_body(&[("file", Some("pack.bin"), b"abc")]);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/packs/pack-1/versions")
                    .header("x-admin-key", "admin-secret")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_version_route_happy_path_writes_file_and_returns_sha() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        let mut repo = MockPackRepo::new();
        repo.expect_get_active_version_id()
            .times(1)
            .with(mockall::predicate::eq("pack-2".to_string()))
            .returning(|_| Ok(None));
        repo.expect_add_version()
            .times(1)
            .withf(
                |package_id, version, file_path, size_bytes, sha256, min_app_version| {
                    package_id == "pack-2"
                        && version == "1.0.0"
                        && file_path == "pack-2/1.0.0/pack.bin"
                        && *size_bytes == 3
                        && sha256
                            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        && min_app_version.is_none()
                },
            )
            .returning(|_, _, _, _, _, _| Ok(()));
        repo.expect_publish_pack().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(temp_dir.path())),
            base_config(),
        );
        let app = build_router(state);

        let (boundary, body) = multipart_body(&[
            ("version", None, b"1.0.0"),
            ("file", Some("pack.bin"), b"abc"),
        ]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/packs/pack-2/versions")
                    .header("x-admin-key", "admin-secret")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn admin_route_returns_401_when_admin_key_missing() {
        let state = build_state(
            Arc::new(MockPackRepo::new()),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(FsPackAssetStore::new(
                tempfile::tempdir().expect("tmp").path(),
            )),
            base_config(),
        );
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/packs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "English Pack",
                            "description": "desc",
                            "pack_type": "translation"
                        }))
                        .expect("payload should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
