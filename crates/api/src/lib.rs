//! Iqrah backend HTTP server library.

pub mod assets;
pub mod auth;
pub mod cache;
pub mod handlers;
pub mod middleware;
pub mod routes;

use std::sync::Arc;
use std::time::Instant;

use axum::{Json, Router, extract::State, routing::get};
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use iqrah_backend_config::AppConfig;
use iqrah_backend_domain::{HealthResponse, ReadyResponse};
use iqrah_backend_storage::{
    AuthRepository, PackRepository, StorageError, SyncRepository, check_connection,
};
use sqlx::PgPool;

use crate::assets::pack_asset_store::PackAssetStore;
use crate::auth::jwt_verifier::JwtVerifier;
use crate::cache::pack_verification_cache::PackVerificationCache;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub pack_repo: Arc<dyn PackRepository>,
    pub auth_repo: Arc<dyn AuthRepository>,
    pub sync_repo: Arc<dyn SyncRepository>,
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
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .merge(routes::auth::router(state.clone()))
        .merge(routes::packs::router(state.clone()))
        .merge(routes::sync::router(state.clone()))
        .merge(routes::admin::router(state.clone()))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
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
