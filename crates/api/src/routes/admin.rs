//! Admin routes.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;
use crate::handlers::admin_packs::{add_version, list_all_packs, publish_pack, register_pack};
use crate::handlers::sync::admin_recent_conflicts;

/// Builds admin routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/admin/packs", post(register_pack))
        .route("/v1/admin/packs", get(list_all_packs))
        .route("/v1/admin/packs/{id}/versions", post(add_version))
        .route("/v1/admin/packs/{id}/publish", post(publish_pack))
        .route(
            "/v1/admin/sync/conflicts/{user_id}",
            get(admin_recent_conflicts),
        )
}
