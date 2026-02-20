//! Dataset release routes.

use std::sync::Arc;

use axum::{Router, routing::get};

use crate::AppState;
use crate::handlers::releases::{get_latest_release, get_release_manifest};

/// Builds public release routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/releases/latest", get(get_latest_release))
        .route("/v1/releases/{id}/manifest", get(get_release_manifest))
}
