//! Admin routes.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;
use crate::handlers::admin_packs::{
    add_version, disable_pack, list_all_packs, publish_pack, register_pack, upload_pack,
};
use crate::handlers::admin_releases::{
    attach_release_artifact, create_release, publish_release, validate_release,
};
use crate::handlers::sync::{admin_recent_conflicts, admin_user_sync_status};

/// Builds admin routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/admin/packs", post(register_pack))
        .route("/v1/admin/packs/upload", post(upload_pack))
        .route("/v1/admin/packs", get(list_all_packs))
        .route("/v1/admin/packs/{id}/versions", post(add_version))
        .route("/v1/admin/packs/{id}/publish", post(publish_pack))
        .route("/v1/admin/packs/{id}/disable", post(disable_pack))
        .route("/v1/admin/releases", post(create_release))
        .route(
            "/v1/admin/releases/{id}/artifacts",
            post(attach_release_artifact),
        )
        .route("/v1/admin/releases/{id}/validate", post(validate_release))
        .route("/v1/admin/releases/{id}/publish", post(publish_release))
        .route(
            "/v1/admin/sync/conflicts/{user_id}",
            get(admin_recent_conflicts),
        )
        .route(
            "/v1/admin/users/{id}/sync_status",
            get(admin_user_sync_status),
        )
}
