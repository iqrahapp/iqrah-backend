#![cfg(feature = "postgres-tests")]

use std::{sync::Arc, time::Instant};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use iqrah_backend_api::assets::pack_asset_store::FsPackAssetStore;
use iqrah_backend_api::auth::jwt_verifier::JwtVerifier;
use iqrah_backend_api::cache::pack_verification_cache::PackVerificationCache;
use iqrah_backend_api::{AppState, build_router};
use iqrah_backend_config::AppConfig;
use iqrah_backend_domain::JwtSubject;
use iqrah_backend_storage::{PgAuthRepository, PgPackRepository, PgSyncRepository};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

#[derive(Clone)]
struct FakeVerifier;

#[async_trait::async_trait]
impl JwtVerifier for FakeVerifier {
    async fn verify_google_id_token(&self, _: &str) -> anyhow::Result<JwtSubject> {
        Ok(JwtSubject("subject".to_string()))
    }
}

fn test_state(pool: PgPool, pack_dir: String, admin_api_key: &str) -> Arc<AppState> {
    Arc::new(AppState {
        pool: pool.clone(),
        pack_repo: Arc::new(PgPackRepository::new(pool.clone())),
        auth_repo: Arc::new(PgAuthRepository::new(pool.clone())),
        sync_repo: Arc::new(PgSyncRepository::new(pool)),
        jwt_verifier: Arc::new(FakeVerifier),
        pack_asset_store: Arc::new(FsPackAssetStore::new(&pack_dir)),
        pack_cache: PackVerificationCache::new(),
        config: AppConfig {
            database_url: "postgres://unused".to_string(),
            jwt_secret: SecretString::new("test-secret".to_string().into()),
            pack_storage_path: pack_dir.into(),
            google_client_id: "test-client-id".to_string(),
            bind_address: "127.0.0.1:0".parse().expect("valid socket address"),
            port: 0,
            base_url: "http://localhost:8080".to_string(),
            admin_api_key: admin_api_key.to_string(),
        },
        start_time: Instant::now(),
    })
}

fn multipart_body(version: &str, filename: &str, file: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----iqrah-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n{version}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (boundary.to_string(), body)
}

#[sqlx::test(migrations = "../../migrations")]
async fn register_pack_requires_admin_key(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
        "secret-admin",
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "name": "English Quran",
                    "description": "desc",
                    "pack_type": "translation"
                }))?))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn register_pack_valid_body_returns_201_and_id(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
        "secret-admin",
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header("x-admin-key", "secret-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "name": "English Quran",
                    "description": "desc",
                    "pack_type": "translation"
                }))?))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    assert!(body["id"].as_str().is_some());
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn register_pack_missing_fields_returns_422(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
        "secret-admin",
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header("x-admin-key", "secret-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"name": "Only Name"}),
                )?))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn upload_version_returns_sha256_for_uploaded_file(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let app = build_router(test_state(
        pool,
        tmp.path().display().to_string(),
        "secret-admin",
    ));

    let register = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header("x-admin-key", "secret-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "name": "Upload Pack",
                    "description": "upload",
                    "pack_type": "translation"
                }))?))?,
        )
        .await?;

    let register_json: Value =
        serde_json::from_slice(&to_bytes(register.into_body(), 1024 * 1024).await?)?;
    let pack_id = register_json["id"].as_str().unwrap();

    let payload = b"pack-bytes";
    let expected_sha = format!("{:x}", Sha256::digest(payload));
    let (boundary, multipart) = multipart_body("1.2.0", "pack.bin", payload);

    let upload = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/packs/{pack_id}/versions"))
                .header("x-admin-key", "secret-admin")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart))?,
        )
        .await?;

    assert_eq!(upload.status(), StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&to_bytes(upload.into_body(), 1024 * 1024).await?)?;
    assert_eq!(body["sha256"], expected_sha);
    assert_eq!(body["file_size_bytes"], payload.len() as u64);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn publish_then_available_includes_pack(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
        "secret-admin",
    ));

    let register = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header("x-admin-key", "secret-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "name": "Lifecycle",
                    "description": "desc",
                    "pack_type": "translation"
                }))?))?,
        )
        .await?;
    let register_json: Value =
        serde_json::from_slice(&to_bytes(register.into_body(), 1024 * 1024).await?)?;
    let pack_id = register_json["id"].as_str().unwrap();

    let (boundary, multipart) = multipart_body("1.0.0", "file.pack", b"lifecycle-bytes");
    let upload = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/packs/{pack_id}/versions"))
                .header("x-admin-key", "secret-admin")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart))?,
        )
        .await?;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let publish = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/packs/{pack_id}/publish"))
                .header("x-admin-key", "secret-admin")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(publish.status(), StatusCode::OK);

    let available = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/available")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(available.status(), StatusCode::OK);
    let available_json: Value =
        serde_json::from_slice(&to_bytes(available.into_body(), 1024 * 1024).await?)?;
    assert_eq!(available_json["packs"].as_array().unwrap().len(), 1);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn full_lifecycle_publish_makes_pack_visible_in_manifest(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
        "secret-admin",
    ));

    let register = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/packs")
                .header("x-admin-key", "secret-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "name": "Manifest Pack",
                    "description": "desc",
                    "pack_type": "translation"
                }))?))?,
        )
        .await?;
    let register_json: Value =
        serde_json::from_slice(&to_bytes(register.into_body(), 1024 * 1024).await?)?;
    let pack_id = register_json["id"].as_str().unwrap();

    let (boundary, multipart) = multipart_body("2.0.0", "manifest.pack", b"manifest-bytes");
    let upload = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/packs/{pack_id}/versions"))
                .header("x-admin-key", "secret-admin")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart))?,
        )
        .await?;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let publish = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/packs/{pack_id}/publish"))
                .header("x-admin-key", "secret-admin")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(publish.status(), StatusCode::OK);

    let manifest = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/manifest")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(manifest.status(), StatusCode::OK);
    let manifest_json: Value =
        serde_json::from_slice(&to_bytes(manifest.into_body(), 1024 * 1024).await?)?;
    assert_eq!(manifest_json["packs"].as_array().unwrap().len(), 1);
    assert_eq!(manifest_json["packs"][0]["id"], pack_id);

    Ok(())
}
