//! Sync routes.

use std::sync::Arc;
use std::time::Duration;

use axum::{Router, extract::DefaultBodyLimit, routing::post};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

use crate::AppState;
use crate::handlers::sync::{sync_pull, sync_push};

/// Builds sync routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    let sync_push_router = match GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .period(Duration::from_secs(60))
        .burst_size(30)
        .finish()
    {
        Some(config) => post(sync_push)
            .route_layer(DefaultBodyLimit::max(1024 * 1024))
            .route_layer(GovernorLayer::new(config)),
        None => {
            tracing::error!("Invalid sync rate-limit config; rate limit disabled");
            post(sync_push).route_layer(DefaultBodyLimit::max(1024 * 1024))
        }
    };

    Router::new()
        .route("/v1/sync/push", sync_push_router)
        .route("/v1/sync/pull", post(sync_pull))
}
