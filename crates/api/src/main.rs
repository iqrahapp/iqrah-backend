//! Iqrah backend server entrypoint.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use iqrah_backend_api::assets::pack_asset_store::FsPackAssetStore;
use iqrah_backend_api::auth::jwt_verifier::{GoogleJwtVerifier, JwtVerifier};
use iqrah_backend_api::cache::pack_verification_cache::PackVerificationCache;
use iqrah_backend_api::{AppState, build_router};
use iqrah_backend_config::AppConfig;
use iqrah_backend_storage::{
    AuthRepository, PackRepository, PgAuthRepository, PgPackRepository, PgSyncRepository,
    SyncRepository, create_pool, run_migrations,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Iqrah backend server");

    let config = AppConfig::from_env()?;

    let pool = create_pool(&config.database_url).await?;
    run_migrations(&pool).await?;

    let pack_repo: Arc<dyn PackRepository> = Arc::new(PgPackRepository::new(pool.clone()));
    let auth_repo: Arc<dyn AuthRepository> = Arc::new(PgAuthRepository::new(pool.clone()));
    let sync_repo: Arc<dyn SyncRepository> = Arc::new(PgSyncRepository::new(pool.clone()));

    let google_jwt_verifier = Arc::new(
        GoogleJwtVerifier::new(reqwest::Client::new(), config.google_client_id.clone()).await?,
    );
    google_jwt_verifier
        .clone()
        .spawn_refresh_task(Duration::from_secs(6 * 60 * 60));
    let jwt_verifier: Arc<dyn JwtVerifier> = google_jwt_verifier;

    let pack_asset_store = Arc::new(FsPackAssetStore::new(&config.pack_storage_path));

    let state = Arc::new(AppState {
        pool,
        pack_repo,
        auth_repo,
        sync_repo,
        jwt_verifier,
        pack_asset_store,
        pack_cache: PackVerificationCache::new(),
        config: config.clone(),
        start_time: Instant::now(),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    tracing::info!(address = %config.bind_address, "Server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
