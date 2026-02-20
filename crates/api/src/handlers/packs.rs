//! Pack API handlers.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Path, Query as AxumQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use validator::Validate;

use iqrah_backend_domain::{
    ApiError, DomainError, PackId, PackManifestEntry, PackManifestResponse,
};
use iqrah_backend_storage::PackInfo;

use crate::AppState;
use crate::assets::pack_asset_store::PackAssetStore;
use crate::cache::pack_verification_cache::PackVerificationCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeParseError {
    Invalid,
    Unsatisfiable,
}

/// Query parameters for pack listing.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ListPacksQuery {
    #[serde(rename = "type")]
    #[schema(example = "translation")]
    pub pack_type: Option<String>,
    #[schema(example = "en")]
    pub language: Option<String>,
}

/// Pack info response DTO.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PackDto {
    #[schema(example = "translation.en")]
    pub package_id: String,
    #[schema(example = "translation")]
    pub package_type: String,
    #[schema(example = "1.0.0")]
    pub version: String,
    #[schema(example = "en")]
    pub language_code: String,
    #[schema(example = "English Translation")]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[schema(example = 1_024_i64)]
    pub size_bytes: i64,
    #[schema(example = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    pub sha256: String,
    #[schema(example = "https://api.example.com/v1/packs/translation.en/download")]
    pub download_url: String,
}

impl PackDto {
    fn from_info(info: PackInfo, base_url: &str) -> Self {
        Self {
            package_id: info.package_id.clone(),
            package_type: info.pack_type,
            version: info.version,
            language_code: info.language,
            name: info.name,
            description: info.description,
            size_bytes: info.size_bytes,
            sha256: info.sha256,
            download_url: format!("{}/v1/packs/{}/download", base_url, info.package_id),
        }
    }
}

/// List packs response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListPacksResponse {
    pub packs: Vec<PackDto>,
}

/// Installed pack version reported by a client.
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct InstalledPackVersion {
    #[validate(length(min = 1, max = 255))]
    #[schema(example = "translation.en")]
    pub package_id: String,
    #[validate(length(min = 1, max = 128))]
    #[schema(example = "1.0.0")]
    pub version: String,
}

/// Request payload for checking available pack updates.
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct PackUpdatesRequest {
    #[validate(nested)]
    pub installed: Vec<InstalledPackVersion>,
}

/// Update info for one installed package.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PackUpdateDto {
    #[schema(example = "translation.en")]
    pub package_id: String,
    #[schema(example = "1.1.0")]
    pub version: String,
    #[schema(example = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    pub sha256: String,
    #[schema(example = 1_024_i64)]
    pub size_bytes: i64,
    #[schema(example = "https://api.example.com/v1/packs/translation.en/download")]
    pub download_url: String,
}

/// Response payload for available updates.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PackUpdatesResponse {
    pub updates: Vec<PackUpdateDto>,
}

/// Response payload for a pack checksum lookup.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PackChecksumResponse {
    #[schema(example = "translation.en")]
    pub package_id: String,
    #[schema(example = "1.1.0")]
    pub version: String,
    #[schema(example = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    pub sha256: String,
}

/// Lists available published packs.
#[utoipa::path(
    get,
    path = "/v1/packs/available",
    tag = "packs",
    params(
        ("type" = Option<String>, Query, description = "Filter by pack type"),
        ("language" = Option<String>, Query, description = "Filter by language code")
    ),
    responses(
        (status = 200, description = "Available packs", body = ListPacksResponse),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn list_packs(
    State(state): State<Arc<AppState>>,
    AxumQuery(query): AxumQuery<ListPacksQuery>,
) -> Result<Json<ListPacksResponse>, DomainError> {
    let packs = state
        .pack_repo
        .list_available(query.pack_type, query.language)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let base_url = &state.config.base_url;
    let dtos = packs
        .into_iter()
        .map(|pack| PackDto::from_info(pack, base_url))
        .collect();

    Ok(Json(ListPacksResponse { packs: dtos }))
}

/// Returns only installed packs that have a newer published version available.
#[utoipa::path(
    post,
    path = "/v1/packs/updates",
    tag = "packs",
    request_body = PackUpdatesRequest,
    responses(
        (status = 200, description = "Available updates", body = PackUpdatesResponse),
        (status = 400, description = "Invalid input", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_pack_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PackUpdatesRequest>,
) -> Result<Json<PackUpdatesResponse>, DomainError> {
    req.validate()
        .map_err(iqrah_backend_domain::DomainError::from_validation_errors)?;

    let installed_versions: HashMap<String, String> = req
        .installed
        .into_iter()
        .map(|installed| (installed.package_id, installed.version))
        .collect();

    let packs = state
        .pack_repo
        .list_available(None, None)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let base_url = &state.config.base_url;
    let updates = packs
        .into_iter()
        .filter_map(|pack| {
            let installed = installed_versions.get(&pack.package_id)?;
            if is_newer_version(installed, &pack.version) {
                Some(PackUpdateDto {
                    package_id: pack.package_id.clone(),
                    version: pack.version,
                    sha256: pack.sha256,
                    size_bytes: pack.size_bytes,
                    download_url: format!("{}/v1/packs/{}/download", base_url, pack.package_id),
                })
            } else {
                None
            }
        })
        .collect();

    Ok(Json(PackUpdatesResponse { updates }))
}

/// Gets manifest for all published active packs.
#[utoipa::path(
    get,
    path = "/v1/packs/manifest",
    tag = "packs",
    responses(
        (status = 200, description = "Global pack manifest", body = PackManifestResponse),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_global_manifest(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PackManifestResponse>, DomainError> {
    let packs = state
        .pack_repo
        .list_active_pack_versions()
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let base_url = &state.config.base_url;
    let manifest_entries = packs
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

    Ok(Json(PackManifestResponse {
        packs: manifest_entries,
    }))
}

/// Streams a pack file with range support.
#[utoipa::path(
    get,
    path = "/v1/packs/{id}/download",
    tag = "packs",
    params(
        ("id" = String, Path, description = "Pack ID")
    ),
    responses(
        (status = 200, description = "Full pack file", content_type = "application/octet-stream"),
        (status = 206, description = "Partial content", content_type = "application/octet-stream"),
        (status = 404, description = "Pack not found", body = ApiError),
        (status = 416, description = "Unsatisfiable range", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn download_pack(
    State(state): State<Arc<AppState>>,
    Path(package_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, DomainError> {
    let pack = state
        .pack_repo
        .get_pack(package_id.clone())
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?
        .ok_or_else(|| DomainError::NotFound(format!("Pack '{package_id}' not found")))?;

    if !state
        .pack_asset_store
        .exists(&pack.file_path)
        .await
        .map_err(|e| DomainError::Internal(anyhow::anyhow!("Failed to check pack file: {e}")))?
    {
        return Err(DomainError::NotFound(format!(
            "Pack file not found: {package_id}"
        )));
    }

    if let Err(response) = verify_pack_integrity(
        state.pack_asset_store.as_ref(),
        &pack.file_path,
        &package_id,
        pack.version_id,
        &pack.sha256,
        &state.pack_cache,
    )
    .await
    {
        return Ok(response);
    }

    let file = state
        .pack_asset_store
        .open_for_read(&pack.file_path)
        .await
        .map_err(|e| DomainError::Internal(anyhow::anyhow!("Failed to open pack file: {e}")))?;

    let file_size = file
        .metadata()
        .await
        .map_err(|e| DomainError::Internal(anyhow::anyhow!("Failed to stat pack file: {e}")))?
        .len();

    build_download_response(file, file_size, &pack.sha256, &headers, &package_id).await
}

async fn verify_pack_integrity(
    store: &dyn PackAssetStore,
    relative_path: &str,
    package_id: &str,
    version_id: i32,
    expected_sha256: &str,
    pack_cache: &PackVerificationCache,
) -> Result<(), Response> {
    if pack_cache.is_verified(version_id) {
        return Ok(());
    }

    let computed_hash = compute_pack_sha256(store, relative_path)
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: error.to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?;

    if !computed_hash.eq_ignore_ascii_case(expected_sha256) {
        tracing::error!(
            package_id = %package_id,
            version_id,
            expected_sha256 = %expected_sha256,
            actual_sha256 = %computed_hash,
            "Pack integrity check failed"
        );

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: "Pack integrity check failed".to_string(),
                details: None,
            }),
        )
            .into_response());
    }

    pack_cache.mark_verified(version_id);
    Ok(())
}

async fn compute_pack_sha256(
    store: &dyn PackAssetStore,
    relative_path: &str,
) -> Result<String, DomainError> {
    let mut file = store
        .open_for_read(relative_path)
        .await
        .map_err(|e| DomainError::Internal(anyhow::anyhow!("Failed to open pack file: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer).await.map_err(|e| {
            DomainError::Internal(anyhow::anyhow!("Failed to read pack file for hashing: {e}"))
        })?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

async fn build_download_response(
    mut file: tokio::fs::File,
    file_size: u64,
    sha256: &str,
    headers: &HeaderMap,
    package_id: &str,
) -> Result<Response, DomainError> {
    let parsed_range = match parse_range_header(headers, file_size) {
        Ok(range) => range,
        Err(RangeParseError::Invalid | RangeParseError::Unsatisfiable) => {
            let response = Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{file_size}"))
                .header(header::ACCEPT_RANGES, "bytes")
                .header("X-Pack-SHA256", sha256)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&ApiError {
                        error: "Unsatisfiable range".to_string(),
                        details: None,
                    })
                    .map_err(|e| {
                        DomainError::Internal(anyhow::anyhow!(
                            "Failed to serialize range error response: {e}"
                        ))
                    })?,
                ))
                .map_err(|e| {
                    DomainError::Internal(anyhow::anyhow!("Failed to build 416 response: {e}"))
                })?;
            return Ok(response);
        }
    };

    let (start, end) = parsed_range.unwrap_or_else(|| {
        if file_size == 0 {
            (0, 0)
        } else {
            (0, file_size - 1)
        }
    });
    let content_length = if file_size == 0 { 0 } else { end - start + 1 };

    if content_length > 0 && start > 0 {
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| {
                DomainError::Internal(anyhow::anyhow!("Failed to seek in pack file: {e}"))
            })?;
    }

    let limited = tokio::io::AsyncReadExt::take(file, content_length);
    let stream = ReaderStream::new(limited);
    let body = Body::from_stream(stream);

    let mut response = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::ACCEPT_RANGES, "bytes")
        .header("X-Pack-SHA256", sha256);

    if content_length > 0 && (start > 0 || end < file_size - 1) {
        response = response.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{file_size}"),
        );
        tracing::info!(
            package_id = %package_id,
            range = %format!("bytes {start}-{end}/{file_size}"),
            "Serving partial content"
        );
    } else {
        response = response.status(StatusCode::OK);
        tracing::info!(package_id = %package_id, size = file_size, "Serving full pack");
    }

    response
        .body(body)
        .map_err(|e| DomainError::Internal(anyhow::anyhow!("Failed to build response: {e}")))
}

fn parse_range_header(
    headers: &HeaderMap,
    file_size: u64,
) -> Result<Option<(u64, u64)>, RangeParseError> {
    let Some(raw_range) = headers.get(header::RANGE) else {
        return Ok(None);
    };

    let range_str = raw_range.to_str().map_err(|_| RangeParseError::Invalid)?;
    let bytes_range = range_str
        .strip_prefix("bytes=")
        .ok_or(RangeParseError::Invalid)?;

    if bytes_range.contains(',') {
        return Err(RangeParseError::Invalid);
    }

    let (start_str, end_str) = bytes_range
        .split_once('-')
        .ok_or(RangeParseError::Invalid)?;

    let range = match (start_str.is_empty(), end_str.is_empty()) {
        (false, false) => {
            let start = start_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::Invalid)?;
            let end = end_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::Invalid)?;

            if start > end {
                return Err(RangeParseError::Invalid);
            }
            if start >= file_size {
                return Err(RangeParseError::Unsatisfiable);
            }

            (start, end.min(file_size.saturating_sub(1)))
        }
        (false, true) => {
            let start = start_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::Invalid)?;
            if start >= file_size {
                return Err(RangeParseError::Unsatisfiable);
            }

            (start, file_size.saturating_sub(1))
        }
        (true, false) => {
            let suffix_len = end_str
                .parse::<u64>()
                .map_err(|_| RangeParseError::Invalid)?;
            if suffix_len == 0 || file_size == 0 {
                return Err(RangeParseError::Unsatisfiable);
            }

            let len = suffix_len.min(file_size);
            (file_size - len, file_size - 1)
        }
        (true, true) => return Err(RangeParseError::Invalid),
    };

    Ok(Some(range))
}

fn is_newer_version(installed: &str, available: &str) -> bool {
    if installed == available {
        return false;
    }

    match (parse_semver(installed), parse_semver(available)) {
        (Some(installed_version), Some(available_version)) => available_version > installed_version,
        _ => available.cmp(installed) == Ordering::Greater,
    }
}

fn parse_semver(version: &str) -> Option<semver::Version> {
    let normalized = version.trim().strip_prefix('v').unwrap_or(version.trim());
    semver::Version::parse(normalized).ok()
}

/// Gets pack metadata without downloading the file.
#[utoipa::path(
    get,
    path = "/v1/packs/{id}/manifest",
    tag = "packs",
    params(
        ("id" = String, Path, description = "Pack ID")
    ),
    responses(
        (status = 200, description = "Pack manifest entry", body = PackDto),
        (status = 404, description = "Pack not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path(package_id): Path<String>,
) -> Result<Json<PackDto>, DomainError> {
    let pack = state
        .pack_repo
        .get_pack(package_id.clone())
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?
        .ok_or_else(|| DomainError::NotFound(format!("Pack '{package_id}' not found")))?;

    let base_url = &state.config.base_url;
    Ok(Json(PackDto::from_info(pack, base_url)))
}

/// Returns checksum metadata for the currently active pack version.
#[utoipa::path(
    get,
    path = "/v1/packs/{id}/checksum",
    tag = "packs",
    params(
        ("id" = String, Path, description = "Pack ID")
    ),
    responses(
        (status = 200, description = "Active pack checksum", body = PackChecksumResponse),
        (status = 404, description = "Pack not found", body = ApiError),
        (status = 500, description = "Internal error", body = ApiError)
    )
)]
pub async fn get_checksum(
    State(state): State<Arc<AppState>>,
    Path(package_id): Path<String>,
) -> Result<Json<PackChecksumResponse>, DomainError> {
    let pack = state
        .pack_repo
        .get_pack(package_id.clone())
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?
        .ok_or_else(|| DomainError::NotFound(format!("Pack '{package_id}' not found")))?;

    Ok(Json(PackChecksumResponse {
        package_id: pack.package_id,
        version: pack.version,
        sha256: pack.sha256,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::assets::pack_asset_store::FsPackAssetStore;
    use crate::assets::pack_asset_store::MockPackAssetStore;
    use crate::auth::jwt_verifier::MockJwtVerifier;
    use crate::test_support::{NoopAuthRepository, NoopSyncRepository, base_config, build_state};
    use async_trait::async_trait;
    use axum::http::HeaderValue;
    use chrono::Utc;
    use iqrah_backend_storage::{PackInfo, PackRepository, PackVersionInfo, StorageError};
    use tokio::io::AsyncWriteExt;

    fn headers_with_range(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn parse_range_supports_standard_forms() {
        let headers = headers_with_range("bytes=10-20");
        assert_eq!(parse_range_header(&headers, 100), Ok(Some((10, 20))));

        let headers = headers_with_range("bytes=10-");
        assert_eq!(parse_range_header(&headers, 100), Ok(Some((10, 99))));

        let headers = headers_with_range("bytes=-15");
        assert_eq!(parse_range_header(&headers, 100), Ok(Some((85, 99))));
    }

    #[test]
    fn parse_range_caps_end_to_file_size() {
        let headers = headers_with_range("bytes=90-150");
        assert_eq!(parse_range_header(&headers, 100), Ok(Some((90, 99))));
    }

    #[test]
    fn parse_range_rejects_invalid_and_unsatisfiable_ranges() {
        assert_eq!(
            parse_range_header(&headers_with_range("bytes=20-10"), 100),
            Err(RangeParseError::Invalid)
        );
        assert_eq!(
            parse_range_header(&headers_with_range("bytes=100-120"), 100),
            Err(RangeParseError::Unsatisfiable)
        );
        assert_eq!(
            parse_range_header(&headers_with_range("bytes=-0"), 100),
            Err(RangeParseError::Unsatisfiable)
        );
        assert_eq!(
            parse_range_header(&headers_with_range("bytes=0-1,4-5"), 100),
            Err(RangeParseError::Invalid)
        );
    }

    #[test]
    fn parse_range_without_header_is_none() {
        assert_eq!(parse_range_header(&HeaderMap::new(), 100), Ok(None));
    }

    #[test]
    fn is_newer_version_compares_numeric_versions() {
        assert!(is_newer_version("1.0.0", "1.0.1"));
        assert!(is_newer_version("1.0", "1.0.0"));
        assert!(is_newer_version("v1.2.2", "1.2.3"));
        assert!(is_newer_version("1.2.3-alpha.1", "1.2.3"));
        assert!(!is_newer_version("2.0.0", "1.9.9"));
        assert!(!is_newer_version("1.2.3", "1.2.3-alpha.1"));
    }

    #[test]
    fn is_newer_version_falls_back_for_non_numeric_versions() {
        assert!(is_newer_version("v1-alpha", "v2-alpha"));
        assert!(!is_newer_version("same", "same"));
    }

    async fn write_temp_pack(content: &[u8]) -> (tempfile::TempDir, FsPackAssetStore, String) {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FsPackAssetStore::new(temp_dir.path());
        let relative = "pkg/v1/pack.bin".to_string();

        store.ensure_parent_dirs(&relative).await.unwrap();
        let mut file = store.create_for_write(&relative).await.unwrap();
        file.write_all(content).await.unwrap();
        file.flush().await.unwrap();

        (temp_dir, store, relative)
    }

    #[tokio::test]
    async fn verify_pack_integrity_accepts_matching_hash() {
        let (_temp, store, relative) = write_temp_pack(b"abc").await;
        let cache = PackVerificationCache::new();

        let result = verify_pack_integrity(
            &store,
            &relative,
            "pkg",
            1,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            &cache,
        )
        .await;

        assert!(result.is_ok());
        assert!(cache.is_verified(1));
    }

    #[tokio::test]
    async fn verify_pack_integrity_rejects_tampered_file() {
        let (_temp, store, relative) = write_temp_pack(b"abc").await;
        let cache = PackVerificationCache::new();

        let response = verify_pack_integrity(
            &store,
            &relative,
            "pkg",
            2,
            "0000000000000000000000000000000000000000000000000000000000000000",
            &cache,
        )
        .await
        .unwrap_err();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn verify_pack_integrity_uses_cache_on_second_request() {
        let (_temp, store, relative) = write_temp_pack(b"abc").await;
        let cache = PackVerificationCache::new();

        verify_pack_integrity(
            &store,
            &relative,
            "pkg",
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            &cache,
        )
        .await
        .unwrap();

        tokio::fs::write(store.resolve_path(&relative), b"mutated")
            .await
            .unwrap();

        let second = verify_pack_integrity(
            &store,
            &relative,
            "pkg",
            3,
            "0000000000000000000000000000000000000000000000000000000000000000",
            &cache,
        )
        .await;

        assert!(second.is_ok());
        assert!(cache.is_verified(3));
    }

    #[tokio::test]
    async fn download_response_full_request_returns_200_with_full_body() {
        let (_temp, store, relative) = write_temp_pack(b"abcdefghijklmnopqrstuvwxyz").await;
        let file = store.open_for_read(&relative).await.unwrap();

        let response = build_download_response(file, 26, "abc123", &HeaderMap::new(), "pkg")
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(response.headers()["X-Pack-SHA256"], "abc123");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"abcdefghijklmnopqrstuvwxyz");
    }

    #[tokio::test]
    async fn download_response_zero_length_file_is_safe() {
        let (_temp, store, relative) = write_temp_pack(b"").await;
        let file = store.open_for_read(&relative).await.unwrap();

        let response = build_download_response(file, 0, "abc123", &HeaderMap::new(), "pkg")
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "0");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn download_response_partial_request_returns_206() {
        let (_temp, store, relative) = write_temp_pack(b"abcdefghijklmnopqrstuvwxyz").await;
        let file = store.open_for_read(&relative).await.unwrap();

        let response =
            build_download_response(file, 26, "abc123", &headers_with_range("bytes=5-9"), "pkg")
                .await
                .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 5-9/26");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"fghij");
    }

    #[tokio::test]
    async fn download_response_invalid_range_returns_416() {
        let (_temp, store, relative) = write_temp_pack(b"abcdefghijklmnopqrstuvwxyz").await;
        let file = store.open_for_read(&relative).await.unwrap();

        let response = build_download_response(
            file,
            26,
            "abc123",
            &headers_with_range("bytes=30-35"),
            "pkg",
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */26");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: ApiError = serde_json::from_slice(&body).expect("416 body should be api error");
        assert_eq!(error.error, "Unsatisfiable range");
        assert!(error.details.is_none());
    }

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
            async fn disable_pack(&self, package_id: String) -> Result<bool, StorageError>;
        }
    }

    #[tokio::test]
    async fn list_packs_happy_path_maps_download_url() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_available()
            .times(1)
            .with(
                mockall::predicate::eq(Some("translation".to_string())),
                mockall::predicate::eq(Some("en".to_string())),
            )
            .returning(|_, _| {
                Ok(vec![PackInfo {
                    version_id: 1,
                    package_id: "pack-en".to_string(),
                    pack_type: "translation".to_string(),
                    version: "1.0.0".to_string(),
                    language: "en".to_string(),
                    name: "English".to_string(),
                    description: Some("desc".to_string()),
                    size_bytes: 10,
                    sha256: "abc".repeat(21) + "a",
                    file_path: "pack-en/1.0.0/pack.bin".to_string(),
                }])
            });
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let mut config = base_config();
        config.base_url = "https://api.example.com".to_string();
        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            config,
        );

        let Json(response) = list_packs(
            axum::extract::State(state),
            axum::extract::Query(ListPacksQuery {
                pack_type: Some("translation".to_string()),
                language: Some("en".to_string()),
            }),
        )
        .await
        .expect("list should succeed");

        assert_eq!(response.packs.len(), 1);
        assert_eq!(
            response.packs[0].download_url,
            "https://api.example.com/v1/packs/pack-en/download"
        );
    }

    #[tokio::test]
    async fn list_packs_returns_500_on_repository_error() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_available()
            .times(1)
            .returning(|_, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = list_packs(
            axum::extract::State(state),
            axum::extract::Query(ListPacksQuery {
                pack_type: None,
                language: None,
            }),
        )
        .await
        .expect_err("storage error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_pack_updates_happy_path_returns_only_outdated_installed_packs() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_available().times(1).returning(|_, _| {
            Ok(vec![
                PackInfo {
                    version_id: 1,
                    package_id: "pack-en".to_string(),
                    pack_type: "translation".to_string(),
                    version: "1.2.0".to_string(),
                    language: "en".to_string(),
                    name: "English".to_string(),
                    description: None,
                    size_bytes: 120,
                    sha256: "abc".repeat(21) + "a",
                    file_path: "pack-en/1.2.0/pack.bin".to_string(),
                },
                PackInfo {
                    version_id: 2,
                    package_id: "pack-ar".to_string(),
                    pack_type: "translation".to_string(),
                    version: "1.0.0".to_string(),
                    language: "ar".to_string(),
                    name: "Arabic".to_string(),
                    description: None,
                    size_bytes: 130,
                    sha256: "bcd".repeat(21) + "b",
                    file_path: "pack-ar/1.0.0/pack.bin".to_string(),
                },
            ])
        });
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let mut config = base_config();
        config.base_url = "https://api.example.com".to_string();
        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            config,
        );

        let Json(response) = get_pack_updates(
            axum::extract::State(state),
            Json(PackUpdatesRequest {
                installed: vec![
                    InstalledPackVersion {
                        package_id: "pack-en".to_string(),
                        version: "1.0.0".to_string(),
                    },
                    InstalledPackVersion {
                        package_id: "pack-ar".to_string(),
                        version: "1.0.0".to_string(),
                    },
                ],
            }),
        )
        .await
        .expect("updates should succeed");

        assert_eq!(response.updates.len(), 1);
        assert_eq!(response.updates[0].package_id, "pack-en");
        assert_eq!(
            response.updates[0].download_url,
            "https://api.example.com/v1/packs/pack-en/download"
        );
    }

    #[tokio::test]
    async fn get_pack_updates_returns_400_for_invalid_payload() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = get_pack_updates(
            axum::extract::State(state),
            Json(PackUpdatesRequest {
                installed: vec![InstalledPackVersion {
                    package_id: "".to_string(),
                    version: "1.0.0".to_string(),
                }],
            }),
        )
        .await
        .expect_err("invalid payload should fail");

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_pack_updates_returns_500_on_repository_error() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_available()
            .times(1)
            .returning(|_, _| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_get_pack().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = get_pack_updates(
            axum::extract::State(state),
            Json(PackUpdatesRequest { installed: vec![] }),
        )
        .await
        .expect_err("repository error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn global_manifest_happy_path_maps_manifest_entries() {
        let mut repo = MockPackRepo::new();
        repo.expect_list_active_pack_versions()
            .times(1)
            .returning(|| {
                Ok(vec![PackVersionInfo {
                    id: "pack-1".to_string(),
                    name: "English".to_string(),
                    description: Some("desc".to_string()),
                    pack_type: "translation".to_string(),
                    version: "1.0.0".to_string(),
                    sha256: "abc".repeat(21) + "a",
                    file_size_bytes: 10,
                    created_at: Utc::now(),
                }])
            });
        repo.expect_list_available().times(0);
        repo.expect_get_pack().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let Json(response) = get_global_manifest(axum::extract::State(state))
            .await
            .expect("manifest should succeed");

        assert_eq!(response.packs.len(), 1);
        assert_eq!(response.packs[0].id, PackId("pack-1".to_string()));
    }

    #[tokio::test]
    async fn get_manifest_returns_404_when_pack_missing() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack().times(1).returning(|_| Ok(None));
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = get_manifest(
            axum::extract::State(state),
            axum::extract::Path("missing".to_string()),
        )
        .await
        .expect_err("missing pack should fail");

        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_checksum_happy_path_returns_active_pack_checksum() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack().times(1).returning(|_| {
            Ok(Some(PackInfo {
                version_id: 7,
                package_id: "pack-1".to_string(),
                pack_type: "translation".to_string(),
                version: "1.0.0".to_string(),
                language: "en".to_string(),
                name: "English".to_string(),
                description: None,
                size_bytes: 10,
                sha256: "abc".repeat(21) + "a",
                file_path: "pack-1/1.0.0/pack.bin".to_string(),
            }))
        });
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let Json(response) = get_checksum(
            axum::extract::State(state),
            axum::extract::Path("pack-1".to_string()),
        )
        .await
        .expect("checksum should succeed");

        assert_eq!(response.package_id, "pack-1");
        assert_eq!(response.version, "1.0.0");
    }

    #[tokio::test]
    async fn get_checksum_returns_404_when_pack_missing() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack().times(1).returning(|_| Ok(None));
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = get_checksum(
            axum::extract::State(state),
            axum::extract::Path("missing".to_string()),
        )
        .await
        .expect_err("missing pack should fail");

        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_checksum_returns_500_on_repository_error() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack()
            .times(1)
            .returning(|_| Err(StorageError::Unexpected("db down".to_string())));
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let err = get_checksum(
            axum::extract::State(state),
            axum::extract::Path("pack-1".to_string()),
        )
        .await
        .expect_err("storage error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn download_pack_returns_404_when_repository_has_no_pack() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack().times(1).returning(|_| Ok(None));
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(MockPackAssetStore::new()),
            base_config(),
        );

        let result = download_pack(
            axum::extract::State(state),
            axum::extract::Path("missing".to_string()),
            HeaderMap::new(),
        )
        .await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("missing pack should fail"),
        };

        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn download_pack_returns_404_when_file_does_not_exist() {
        let mut repo = MockPackRepo::new();
        repo.expect_get_pack().times(1).returning(|_| {
            Ok(Some(PackInfo {
                version_id: 5,
                package_id: "pack-1".to_string(),
                pack_type: "translation".to_string(),
                version: "1.0.0".to_string(),
                language: "en".to_string(),
                name: "English".to_string(),
                description: None,
                size_bytes: 10,
                sha256: "abc".repeat(21) + "a",
                file_path: "pack-1/1.0.0/pack.bin".to_string(),
            }))
        });
        repo.expect_list_available().times(0);
        repo.expect_list_active_pack_versions().times(0);
        repo.expect_list_all_packs().times(0);
        repo.expect_get_active_version_id().times(0);
        repo.expect_register_pack().times(0);
        repo.expect_add_version().times(0);
        repo.expect_publish_pack().times(0);
        repo.expect_disable_pack().times(0);

        let mut store = MockPackAssetStore::new();
        store.expect_exists().times(1).returning(|_| Ok(false));
        store.expect_open_for_read().times(0);
        store.expect_create_for_write().times(0);
        store.expect_ensure_parent_dirs().times(0);
        store.expect_resolve_path().times(0);

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(store),
            base_config(),
        );

        let result = download_pack(
            axum::extract::State(state),
            axum::extract::Path("pack-1".to_string()),
            HeaderMap::new(),
        )
        .await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("missing file should fail"),
        };

        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }
}
