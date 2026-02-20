//! Storage layer for Iqrah backend.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub mod auth_repository;
pub mod error;
pub mod pack_repository;
pub mod sync_repository;

pub use auth_repository::{AuthRepository, PgAuthRepository, UserRecord};
pub use error::StorageError;
pub use pack_repository::{PackInfo, PackRepository, PackVersionInfo, PgPackRepository};
pub use sync_repository::{ConflictLogEntry, PgSyncRepository, SyncRepository};

/// Creates a PostgreSQL connection pool.
pub async fn create_pool(database_url: &str) -> Result<PgPool, StorageError> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(StorageError::Connection)
}

/// Runs all SQL migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), StorageError> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(StorageError::Migration)
}

/// Checks DB connectivity with a minimal query.
pub async fn check_connection(pool: &PgPool) -> Result<(), StorageError> {
    sqlx::query!("SELECT 1 AS one")
        .fetch_one(pool)
        .await
        .map_err(StorageError::Query)?;
    Ok(())
}
