//! Pack browsing routes.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;
use crate::handlers::packs::{
    download_pack, get_checksum, get_global_manifest, get_manifest, get_pack_updates, list_packs,
};

/// Builds pack routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/packs/available", get(list_packs))
        .route("/v1/packs/updates", post(get_pack_updates))
        .route("/v1/packs/manifest", get(get_global_manifest))
        .route("/v1/packs/{id}/download", get(download_pack))
        .route("/v1/packs/{id}/manifest", get(get_manifest))
        .route("/v1/packs/{id}/checksum", get(get_checksum))
}
