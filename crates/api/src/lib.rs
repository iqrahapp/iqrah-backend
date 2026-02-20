//! Iqrah backend HTTP server library.

pub mod assets;
pub mod auth;
pub mod cache;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;

use std::sync::Arc;
use std::time::Instant;

use axum::{Json, Router, extract::State, http::header, routing::get};
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use iqrah_backend_config::AppConfig;
use iqrah_backend_domain::{HealthResponse, ReadyResponse};
use iqrah_backend_storage::{
    AuthRepository, PackRepository, ReleaseRepository, StorageError, SyncRepository,
    check_connection,
};
use sqlx::PgPool;

use crate::assets::pack_asset_store::PackAssetStore;
use crate::auth::jwt_verifier::JwtVerifier;
use crate::cache::pack_verification_cache::PackVerificationCache;
use crate::middleware::auth::AdminApiKey;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub pack_repo: Arc<dyn PackRepository>,
    pub auth_repo: Arc<dyn AuthRepository>,
    pub sync_repo: Arc<dyn SyncRepository>,
    pub release_repo: Arc<dyn ReleaseRepository>,
    pub jwt_verifier: Arc<dyn JwtVerifier>,
    pub pack_asset_store: Arc<dyn PackAssetStore>,
    pub pack_cache: PackVerificationCache,
    pub config: AppConfig,
    pub start_time: Instant,
}

impl AppState {
    /// Invalidates pack integrity cache for a version.
    pub fn invalidate_pack_cache(&self, pack_version_id: i32) {
        self.pack_cache.invalidate(pack_version_id);
    }

    /// Adds a new pack version and invalidates cache for prior active version.
    pub async fn add_pack_version(
        &self,
        package_id: &str,
        version: &str,
        file_path: &str,
        size_bytes: i64,
        sha256: &str,
        min_app_version: Option<&str>,
    ) -> Result<(), StorageError> {
        if let Some(active_version_id) = self
            .pack_repo
            .get_active_version_id(package_id.to_string())
            .await?
        {
            self.invalidate_pack_cache(active_version_id);
        }

        self.pack_repo
            .add_version(
                package_id.to_string(),
                version.to_string(),
                file_path.to_string(),
                size_bytes,
                sha256.to_string(),
                min_app_version.map(ToString::to_string),
            )
            .await
    }
}

/// Builds the complete Axum router.
pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/v1/metrics", get(metrics))
        .merge(routes::auth::router(state.clone()))
        .merge(routes::packs::router(state.clone()))
        .merge(routes::sync::router(state.clone()))
        .merge(routes::releases::router(state.clone()))
        .merge(routes::admin::router(state.clone()))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    #[cfg(feature = "swagger-ui")]
    let router = {
        use crate::openapi::ApiDoc;
        use utoipa::OpenApi;

        router.merge(
            utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
    };

    router
}

/// Health check endpoint.
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let uptime = state.start_time.elapsed().as_secs();

    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_sha: option_env!("BUILD_SHA").unwrap_or("dev").to_string(),
        uptime_seconds: uptime,
    })
}

/// Readiness check endpoint.
async fn ready(State(state): State<Arc<AppState>>) -> Json<ReadyResponse> {
    let db_status = match check_connection(&state.pool).await {
        Ok(()) => "connected",
        Err(_) => "disconnected",
    };

    Json(ReadyResponse {
        status: if db_status == "connected" {
            "ok"
        } else {
            "degraded"
        }
        .to_string(),
        database: db_status.to_string(),
    })
}

/// Prometheus-style metrics endpoint for basic service observability.
#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "admin",
    responses(
        (status = 200, description = "Prometheus metrics", body = String, content_type = "text/plain"),
        (status = 401, description = "Missing admin credentials", body = iqrah_backend_domain::ApiError),
        (status = 403, description = "Insufficient admin credentials", body = iqrah_backend_domain::ApiError)
    ),
    security(("admin_api_key" = []), ("bearer_auth" = []))
)]
async fn metrics(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
) -> ([(header::HeaderName, &'static str); 1], String) {
    let uptime_seconds = state.start_time.elapsed().as_secs();
    let db_up = if check_connection(&state.pool).await.is_ok() {
        1
    } else {
        0
    };

    let body = format!(
        "# HELP iqrah_uptime_seconds Service uptime in seconds\n\
# TYPE iqrah_uptime_seconds gauge\n\
iqrah_uptime_seconds {uptime_seconds}\n\
# HELP iqrah_db_connected Database connectivity status\n\
# TYPE iqrah_db_connected gauge\n\
iqrah_db_connected {db_up}\n"
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use iqrah_backend_config::AppConfig;
    use iqrah_backend_domain::{
        DeviceId, JwtSubject, SyncChanges, SyncPullCursor, TimestampMs, UserId,
    };
    use iqrah_backend_storage::{
        AuthRepository, ConflictLogEntry, PackInfo, PackRepository, PackVersionInfo,
        ReleaseManifestRecord, ReleaseRepository, StorageError, SyncRepository, UserRecord,
    };
    use secrecy::SecretString;
    use sqlx::{PgPool, postgres::PgPoolOptions};

    use crate::AppState;
    use crate::assets::pack_asset_store::PackAssetStore;
    use crate::auth::jwt_verifier::JwtVerifier;
    use crate::cache::pack_verification_cache::PackVerificationCache;

    pub fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(25))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/iqrah")
            .expect("lazy pool should be created")
    }

    pub fn base_config() -> AppConfig {
        AppConfig {
            database_url: "postgres://unused".to_string(),
            jwt_secret: SecretString::new("test-secret".to_string().into()),
            pack_storage_path: PathBuf::from("./packs"),
            google_client_id: "test-google-client-id".to_string(),
            bind_address: "127.0.0.1:0".parse().expect("valid bind address"),
            port: 0,
            base_url: "http://localhost:8080".to_string(),
            admin_api_key: "admin-secret".to_string(),
            admin_oauth_sub_allowlist: Vec::new(),
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopPackRepository;

    #[async_trait]
    impl PackRepository for NoopPackRepository {
        async fn list_available(
            &self,
            _pack_type: Option<String>,
            _language: Option<String>,
        ) -> Result<Vec<PackInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_available_all_versions(
            &self,
            _pack_type: Option<String>,
            _language: Option<String>,
        ) -> Result<Vec<PackInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_pack(&self, _package_id: String) -> Result<Option<PackInfo>, StorageError> {
            Ok(None)
        }

        async fn list_active_pack_versions(&self) -> Result<Vec<PackVersionInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_all_packs(&self) -> Result<Vec<PackVersionInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_active_version_id(
            &self,
            _package_id: String,
        ) -> Result<Option<i32>, StorageError> {
            Ok(None)
        }

        async fn register_pack(
            &self,
            _package_id: String,
            _pack_type: String,
            _language: String,
            _name: String,
            _description: Option<String>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn add_version(
            &self,
            _package_id: String,
            _version: String,
            _file_path: String,
            _size_bytes: i64,
            _sha256: String,
            _min_app_version: Option<String>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn publish_pack(&self, _package_id: String) -> Result<(), StorageError> {
            Ok(())
        }

        async fn disable_pack(&self, _package_id: String) -> Result<bool, StorageError> {
            Ok(false)
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopAuthRepository;

    #[async_trait]
    impl AuthRepository for NoopAuthRepository {
        async fn find_or_create(&self, _oauth_sub: &str) -> Result<UserRecord, StorageError> {
            Err(StorageError::Unexpected(
                "NoopAuthRepository::find_or_create".to_string(),
            ))
        }

        async fn get_by_id(&self, _id: UserId) -> Result<Option<UserRecord>, StorageError> {
            Ok(None)
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopSyncRepository;

    #[async_trait]
    impl SyncRepository for NoopSyncRepository {
        async fn touch_device(
            &self,
            _user_id: UserId,
            _device_id: DeviceId,
            _device_os: Option<String>,
            _device_model: Option<String>,
            _app_version: Option<String>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn apply_changes(
            &self,
            _user_id: UserId,
            _device_id: DeviceId,
            _changes: SyncChanges,
        ) -> Result<(u64, u64), StorageError> {
            Ok((0, 0))
        }

        async fn list_recent_conflicts(
            &self,
            _user_id: UserId,
            _limit: usize,
        ) -> Result<Vec<ConflictLogEntry>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_changes_since(
            &self,
            _user_id: UserId,
            _since: TimestampMs,
            _limit: usize,
            _cursor: Option<SyncPullCursor>,
        ) -> Result<(SyncChanges, bool, Option<SyncPullCursor>), StorageError> {
            Ok((SyncChanges::default(), false, None))
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopReleaseRepository;

    #[async_trait]
    impl ReleaseRepository for NoopReleaseRepository {
        async fn create_draft_release(
            &self,
            _version: String,
            _notes: Option<String>,
            _created_by: String,
        ) -> Result<iqrah_backend_domain::DatasetRelease, StorageError> {
            Err(StorageError::Unexpected(
                "NoopReleaseRepository::create_draft_release".to_string(),
            ))
        }

        async fn attach_artifact(
            &self,
            _release_id: iqrah_backend_domain::ReleaseId,
            _package_id: String,
            _artifact_role: iqrah_backend_domain::ArtifactRole,
            _required: bool,
        ) -> Result<iqrah_backend_domain::DatasetReleaseArtifact, StorageError> {
            Err(StorageError::Unexpected(
                "NoopReleaseRepository::attach_artifact".to_string(),
            ))
        }

        async fn validate_release(
            &self,
            _release_id: iqrah_backend_domain::ReleaseId,
        ) -> Result<iqrah_backend_domain::ReleaseValidationReport, StorageError> {
            Err(StorageError::Unexpected(
                "NoopReleaseRepository::validate_release".to_string(),
            ))
        }

        async fn publish_release(
            &self,
            _release_id: iqrah_backend_domain::ReleaseId,
        ) -> Result<iqrah_backend_domain::DatasetRelease, StorageError> {
            Err(StorageError::Unexpected(
                "NoopReleaseRepository::publish_release".to_string(),
            ))
        }

        async fn get_latest_release(
            &self,
        ) -> Result<Option<iqrah_backend_domain::DatasetRelease>, StorageError> {
            Ok(None)
        }

        async fn get_release_manifest(
            &self,
            _release_id: iqrah_backend_domain::ReleaseId,
        ) -> Result<Option<ReleaseManifestRecord>, StorageError> {
            Ok(None)
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopJwtVerifier;

    #[async_trait]
    impl JwtVerifier for NoopJwtVerifier {
        async fn verify_google_id_token(&self, _id_token: &str) -> anyhow::Result<JwtSubject> {
            Err(anyhow::anyhow!("NoopJwtVerifier"))
        }
    }

    #[derive(Clone, Default)]
    pub struct NoopPackAssetStore;

    #[async_trait]
    impl PackAssetStore for NoopPackAssetStore {
        fn resolve_path(&self, relative_path: &str) -> PathBuf {
            PathBuf::from(relative_path)
        }

        async fn exists(&self, _relative_path: &str) -> std::io::Result<bool> {
            Ok(false)
        }

        async fn open_for_read(&self, relative_path: &str) -> std::io::Result<tokio::fs::File> {
            tokio::fs::File::open(relative_path).await
        }

        async fn create_for_write(&self, relative_path: &str) -> std::io::Result<tokio::fs::File> {
            tokio::fs::File::create(relative_path).await
        }

        async fn ensure_parent_dirs(&self, _relative_path: &str) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn build_state(
        pack_repo: Arc<dyn PackRepository>,
        auth_repo: Arc<dyn AuthRepository>,
        sync_repo: Arc<dyn SyncRepository>,
        jwt_verifier: Arc<dyn JwtVerifier>,
        pack_asset_store: Arc<dyn PackAssetStore>,
        config: AppConfig,
    ) -> Arc<AppState> {
        build_state_with_release_repo(
            pack_repo,
            auth_repo,
            sync_repo,
            Arc::new(NoopReleaseRepository),
            jwt_verifier,
            pack_asset_store,
            config,
        )
    }

    pub fn build_state_with_release_repo(
        pack_repo: Arc<dyn PackRepository>,
        auth_repo: Arc<dyn AuthRepository>,
        sync_repo: Arc<dyn SyncRepository>,
        release_repo: Arc<dyn ReleaseRepository>,
        jwt_verifier: Arc<dyn JwtVerifier>,
        pack_asset_store: Arc<dyn PackAssetStore>,
        config: AppConfig,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            pool: unreachable_pool(),
            pack_repo,
            auth_repo,
            sync_repo,
            release_repo,
            jwt_verifier,
            pack_asset_store,
            pack_cache: PackVerificationCache::new(),
            config,
            start_time: Instant::now(),
        })
    }

    pub fn build_default_state() -> Arc<AppState> {
        build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(NoopJwtVerifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode, header};
    use iqrah_backend_storage::{PackInfo, PackRepository, StorageError};
    use tower::ServiceExt;

    use super::*;
    use crate::test_support::{
        NoopAuthRepository, NoopJwtVerifier, NoopPackAssetStore, NoopSyncRepository, base_config,
        build_default_state, build_state,
    };

    #[derive(Clone, Default)]
    struct RecordingPackRepository {
        active_version_id: Option<i32>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl PackRepository for RecordingPackRepository {
        async fn list_available(
            &self,
            _pack_type: Option<String>,
            _language: Option<String>,
        ) -> Result<Vec<PackInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_available_all_versions(
            &self,
            _pack_type: Option<String>,
            _language: Option<String>,
        ) -> Result<Vec<PackInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_pack(&self, _package_id: String) -> Result<Option<PackInfo>, StorageError> {
            Ok(None)
        }

        async fn list_active_pack_versions(
            &self,
        ) -> Result<Vec<iqrah_backend_storage::PackVersionInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn list_all_packs(
            &self,
        ) -> Result<Vec<iqrah_backend_storage::PackVersionInfo>, StorageError> {
            Ok(Vec::new())
        }

        async fn get_active_version_id(
            &self,
            package_id: String,
        ) -> Result<Option<i32>, StorageError> {
            self.calls
                .lock()
                .expect("call lock should be available")
                .push(format!("active:{package_id}"));
            Ok(self.active_version_id)
        }

        async fn register_pack(
            &self,
            _package_id: String,
            _pack_type: String,
            _language: String,
            _name: String,
            _description: Option<String>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn add_version(
            &self,
            package_id: String,
            version: String,
            _file_path: String,
            _size_bytes: i64,
            _sha256: String,
            _min_app_version: Option<String>,
        ) -> Result<(), StorageError> {
            self.calls
                .lock()
                .expect("call lock should be available")
                .push(format!("add:{package_id}:{version}"));
            Ok(())
        }

        async fn publish_pack(&self, _package_id: String) -> Result<(), StorageError> {
            Ok(())
        }

        async fn disable_pack(&self, _package_id: String) -> Result<bool, StorageError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn add_pack_version_invalidates_existing_cache_entry() {
        let repo = RecordingPackRepository {
            active_version_id: Some(42),
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let calls = repo.calls.clone();

        let state = build_state(
            Arc::new(repo),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(NoopJwtVerifier),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );
        state.pack_cache.mark_verified(42);

        state
            .add_pack_version("pack-id", "1.0.0", "pack.bin", 10, "abc", None)
            .await
            .expect("add version should succeed");

        assert!(!state.pack_cache.is_verified(42));
        assert_eq!(
            calls
                .lock()
                .expect("call lock should be available")
                .as_slice(),
            ["active:pack-id", "add:pack-id:1.0.0"]
        );
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok_payload() {
        let app = build_router(build_default_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("health request should run");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["status"], "ok");
        assert!(json["uptime_seconds"].is_number());
    }

    #[tokio::test]
    async fn ready_endpoint_reports_degraded_when_database_unreachable() {
        let mut config = base_config();
        config.admin_api_key.clear();
        let app = build_router(build_state(
            Arc::new(test_support::NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(NoopSyncRepository),
            Arc::new(NoopJwtVerifier),
            Arc::new(NoopPackAssetStore),
            config,
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("ready request should run");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["database"], "disconnected");
    }

    #[tokio::test]
    async fn metrics_endpoint_requires_admin_credentials() {
        let app = build_router(build_default_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("metrics request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_payload_with_admin_key() {
        let app = build_router(build_default_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .header("x-admin-key", "admin-secret")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("metrics request should run");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("metrics body should be utf-8");
        assert!(body.contains("iqrah_uptime_seconds"));
        assert!(body.contains("iqrah_db_connected"));
    }
}
