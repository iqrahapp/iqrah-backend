#![cfg(feature = "postgres-tests")]

use std::{str::from_utf8, sync::Arc, time::Instant};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use iqrah_backend_api::assets::pack_asset_store::FsPackAssetStore;
use iqrah_backend_api::auth::jwt_verifier::JwtVerifier;
use iqrah_backend_api::cache::pack_verification_cache::PackVerificationCache;
use iqrah_backend_api::{AppState, build_router};
use iqrah_backend_config::AppConfig;
use iqrah_backend_domain::{Claims, JwtSubject};
use iqrah_backend_storage::{
    PgAuthRepository, PgPackRepository, PgReleaseRepository, PgSyncRepository,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct FakeVerifier;

#[async_trait::async_trait]
impl JwtVerifier for FakeVerifier {
    async fn verify_google_id_token(&self, id_token: &str) -> anyhow::Result<JwtSubject> {
        if id_token == "valid-google-token" {
            Ok(JwtSubject("google-subject-1".to_string()))
        } else {
            Err(anyhow::anyhow!("invalid token"))
        }
    }
}

fn test_state(pool: PgPool, pack_dir: String) -> Arc<AppState> {
    let pack_cache = PackVerificationCache::new();

    Arc::new(AppState {
        pool: pool.clone(),
        pack_repo: Arc::new(PgPackRepository::new(pool.clone())),
        auth_repo: Arc::new(PgAuthRepository::new(pool.clone())),
        sync_repo: Arc::new(PgSyncRepository::new(pool.clone())),
        release_repo: Arc::new(PgReleaseRepository::new(pool)),
        jwt_verifier: Arc::new(FakeVerifier),
        pack_asset_store: Arc::new(FsPackAssetStore::new(&pack_dir)),
        pack_cache,
        config: AppConfig {
            database_url: "postgres://unused".to_string(),
            jwt_secret: SecretString::new("test-secret".to_string().into()),
            pack_storage_path: pack_dir.into(),
            google_client_id: "test-client-id".to_string(),
            bind_address: "127.0.0.1:0".parse().expect("valid socket address"),
            port: 0,
            base_url: "http://localhost:8080".to_string(),
            admin_api_key: "".to_string(),
            admin_oauth_sub_allowlist: Vec::new(),
        },
        start_time: Instant::now(),
    })
}

fn auth_header(user_id: Uuid) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs();
    let token = encode(
        &Header::default(),
        &Claims {
            sub: JwtSubject(user_id.to_string()),
            exp: now + 3600,
            iat: now,
            role: None,
            oauth_sub: None,
        },
        &EncodingKey::from_secret(b"test-secret"),
    )
    .unwrap();

    format!("Bearer {token}")
}

#[sqlx::test(migrations = "../../migrations")]
async fn auth_pack_sync_and_error_paths(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    tokio::fs::write(tmp.path().join("quran-en-v1.pack"), b"abcdefghij").await?;

    let app = build_router(test_state(pool.clone(), tmp.path().display().to_string()));

    sqlx::query!(
        "INSERT INTO packs (package_id, pack_type, language, name, description, status, legacy_version) VALUES ($1,$2,$3,$4,$5,'published','legacy-test')",
        "quran-en",
        "quran",
        "en",
        "English Quran",
        "test pack"
    )
    .execute(&pool)
    .await?;

    sqlx::query!(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES ($1,$2,$3,$4,$5,true)",
        "quran-en",
        "1.0.0",
        "quran-en-v1.pack",
        10_i64,
        "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"
    )
    .execute(&pool)
    .await?;

    tokio::fs::write(tmp.path().join("quran-ar-v1.pack"), b"mismatch-content").await?;

    sqlx::query!(
        "INSERT INTO packs (package_id, pack_type, language, name, description, status, legacy_version) VALUES ($1,$2,$3,$4,$5,'published','legacy-test')",
        "quran-ar",
        "quran",
        "ar",
        "Arabic Quran",
        "tampered pack"
    )
    .execute(&pool)
    .await?;

    sqlx::query!(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES ($1,$2,$3,$4,$5,true)",
        "quran-ar",
        "1.0.0",
        "quran-ar-v1.pack",
        16_i64,
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    .execute(&pool)
    .await?;

    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/google")
        .header("x-forwarded-for", "198.51.100.1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(
            &json!({"id_token":"valid-google-token"}),
        )?))?;
    let auth_resp = app.clone().oneshot(auth_req).await?;
    let auth_status = auth_resp.status();
    let auth_bytes = to_bytes(auth_resp.into_body(), 1024 * 1024).await?;
    assert_eq!(
        auth_status,
        StatusCode::OK,
        "auth response body: {}",
        String::from_utf8_lossy(&auth_bytes)
    );
    let auth_body: Value = serde_json::from_slice(&auth_bytes)?;
    let user_id = Uuid::parse_str(auth_body["user_id"].as_str().unwrap())?;
    let access_token = auth_body["access_token"].as_str().unwrap().to_string();

    let me_req = Request::builder()
        .uri("/v1/users/me")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())?;
    let me_resp = app.clone().oneshot(me_req).await?;
    assert_eq!(me_resp.status(), StatusCode::OK);

    let unauthorized_req = Request::builder().uri("/v1/users/me").body(Body::empty())?;
    let unauthorized_resp = app.clone().oneshot(unauthorized_req).await?;
    assert_eq!(unauthorized_resp.status(), StatusCode::UNAUTHORIZED);

    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/available?type=quran&language=en")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json: Value =
        serde_json::from_slice(&to_bytes(list_resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(list_json["packs"].as_array().unwrap().len(), 1);

    let full_download = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/quran-en/download")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(full_download.status(), StatusCode::OK);
    assert_eq!(full_download.headers()[header::CONTENT_LENGTH], "10");
    let full_bytes = to_bytes(full_download.into_body(), 1024 * 1024).await?;
    assert_eq!(from_utf8(&full_bytes)?, "abcdefghij");

    tokio::fs::write(tmp.path().join("quran-en-v1.pack"), b"XXXXXXXXXX").await?;

    let cached_download = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/quran-en/download")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(cached_download.status(), StatusCode::OK);

    let cached_bytes = to_bytes(cached_download.into_body(), 1024 * 1024).await?;
    assert_eq!(from_utf8(&cached_bytes)?, "XXXXXXXXXX");

    let range_download = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/quran-en/download")
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(range_download.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range_download.headers()[header::CONTENT_RANGE],
        "bytes 2-5/10"
    );
    let range_bytes = to_bytes(range_download.into_body(), 1024 * 1024).await?;
    assert_eq!(from_utf8(&range_bytes)?, "XXXX");

    let tampered_pack = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/quran-ar/download")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(tampered_pack.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let tampered_json: Value =
        serde_json::from_slice(&to_bytes(tampered_pack.into_body(), 1024 * 1024).await?)?;
    assert_eq!(tampered_json["error"], "Pack integrity check failed");

    let missing_pack = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs/missing/download")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(missing_pack.status(), StatusCode::NOT_FOUND);

    let push_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("x-forwarded-for", "198.51.100.1")
                .header(header::AUTHORIZATION, auth_header(user_id))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "device_id": Uuid::new_v4(),
                    "changes": {"settings": [{"key": "theme", "value": "dark", "client_updated_at": 1}]},
                    "device_os": "android",
                    "device_model": "pixel",
                    "app_version": "1.0.0"
                }))?))?,
        )
        .await?;
    assert_eq!(push_resp.status(), StatusCode::OK);

    let pull_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/pull")
                .header(header::AUTHORIZATION, auth_header(user_id))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"device_id": Uuid::new_v4(), "since": 0, "limit": 50}),
                )?))?,
        )
        .await?;
    assert_eq!(pull_resp.status(), StatusCode::OK);
    let pull_json: Value =
        serde_json::from_slice(&to_bytes(pull_resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(
        pull_json["changes"]["settings"].as_array().unwrap().len(),
        1
    );

    let invalid_pull = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/pull")
                .header(header::AUTHORIZATION, auth_header(user_id))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"device_id": Uuid::new_v4(), "since": 0, "limit": 0}),
                )?))?,
        )
        .await?;
    assert_eq!(invalid_pull.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn global_manifest_returns_200_and_expected_shape(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool.clone(),
        tempfile::tempdir()?.path().display().to_string(),
    ));

    sqlx::query!(
        "INSERT INTO packs (package_id, pack_type, language, name, description, status, legacy_version) VALUES ($1,$2,$3,$4,$5,'published','legacy-test')",
        "quran-fr",
        "quran",
        "fr",
        "French Quran",
        "French translation"
    )
    .execute(&pool)
    .await?;

    sqlx::query!(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES ($1,$2,$3,$4,$5,true)",
        "quran-fr",
        "1.5.0",
        "quran-fr-v1.pack",
        777_i64,
        "sha-fr"
    )
    .execute(&pool)
    .await?;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/manifest")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(&to_bytes(resp.into_body(), 1024 * 1024).await?)?;
    let packs = body["packs"].as_array().expect("packs should be array");
    assert_eq!(packs.len(), 1);

    let pack = &packs[0];
    assert_eq!(pack["id"], "quran-fr");
    assert_eq!(pack["name"], "French Quran");
    assert_eq!(pack["pack_type"], "quran");
    assert_eq!(pack["version"], "1.5.0");
    assert_eq!(pack["sha256"], "sha-fr");
    assert_eq!(pack["file_size_bytes"], 777);
    assert!(pack["created_at"].is_string());
    assert_eq!(
        pack["download_url"],
        "http://localhost:8080/v1/packs/quran-fr/download"
    );

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn global_manifest_returns_empty_array_when_no_packs(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
    ));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/manifest")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&to_bytes(resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(body, json!({"packs": []}));

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn global_manifest_download_url_uses_pack_download_route(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool.clone(),
        tempfile::tempdir()?.path().display().to_string(),
    ));

    sqlx::query!(
        "INSERT INTO packs (package_id, pack_type, language, name, description, status, legacy_version) VALUES ($1,$2,$3,$4,$5,'published','legacy-test')",
        "recitation-ar",
        "recitation",
        "ar",
        "Arabic Recitation",
        "recitation pack"
    )
    .execute(&pool)
    .await?;

    sqlx::query!(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES ($1,$2,$3,$4,$5,true)",
        "recitation-ar",
        "3.0.0",
        "recitation-ar-v3.pack",
        123_i64,
        "sha-rec"
    )
    .execute(&pool)
    .await?;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/manifest")
                .body(Body::empty())?,
        )
        .await?;

    let body: Value = serde_json::from_slice(&to_bytes(resp.into_body(), 1024 * 1024).await?)?;
    assert_eq!(
        body["packs"][0]["download_url"],
        "http://localhost:8080/v1/packs/recitation-ar/download"
    );

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn auth_google_is_rate_limited_on_11th_request(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
    ));

    for _ in 0..10 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/google")
                    .header("x-forwarded-for", "203.0.113.8")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &json!({"id_token": "valid-google-token"}),
                    )?))?,
            )
            .await?;
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    let throttled = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/google")
                .header("x-forwarded-for", "203.0.113.8")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"id_token": "valid-google-token"}),
                )?))?,
        )
        .await?;

    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn sync_push_body_above_1mb_returns_413(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool.clone(),
        tempfile::tempdir()?.path().display().to_string(),
    ));

    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/google")
                .header("x-forwarded-for", "198.51.100.10")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"id_token":"valid-google-token"}),
                )?))?,
        )
        .await?;
    let auth_status = auth_resp.status();
    let auth_bytes = to_bytes(auth_resp.into_body(), 1024 * 1024).await?;
    assert_eq!(
        auth_status,
        StatusCode::OK,
        "auth response body: {}",
        String::from_utf8_lossy(&auth_bytes)
    );
    let auth_body: Value = serde_json::from_slice(&auth_bytes)?;
    let token = auth_body["access_token"].as_str().unwrap();

    let oversized = "x".repeat(1_100_000);
    let req_body = json!({
        "device_id": Uuid::new_v4(),
        "changes": {
            "settings": [{"key": "blob", "value": oversized, "client_updated_at": 1}],
            "memory_states": [],
            "sessions": [],
            "session_items": []
        }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("x-forwarded-for", "198.51.100.10")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&req_body)?))?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn sync_push_body_under_1mb_is_accepted(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(test_state(
        pool,
        tempfile::tempdir()?.path().display().to_string(),
    ));

    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/google")
                .header("x-forwarded-for", "198.51.100.11")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(
                    &json!({"id_token":"valid-google-token"}),
                )?))?,
        )
        .await?;
    let auth_status = auth_resp.status();
    let auth_bytes = to_bytes(auth_resp.into_body(), 1024 * 1024).await?;
    assert_eq!(
        auth_status,
        StatusCode::OK,
        "auth response body: {}",
        String::from_utf8_lossy(&auth_bytes)
    );
    let auth_body: Value = serde_json::from_slice(&auth_bytes)?;
    let token = auth_body["access_token"].as_str().unwrap();

    let ok_value = "x".repeat(100_000);
    let req_body = json!({
        "device_id": Uuid::new_v4(),
        "changes": {
            "settings": [{"key": "blob", "value": ok_value, "client_updated_at": 1}],
            "memory_states": [],
            "sessions": [],
            "session_items": []
        }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("x-forwarded-for", "198.51.100.11")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&req_body)?))?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
