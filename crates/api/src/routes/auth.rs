//! Auth-related routes.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    routing::{get, post},
};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

use crate::AppState;
use crate::handlers;

/// Builds auth routes.
pub fn router(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    let auth_method_router = match GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .period(Duration::from_secs(60))
        .burst_size(10)
        .finish()
    {
        Some(config) => post(handlers::auth::google_auth).route_layer(GovernorLayer::new(config)),
        None => {
            tracing::error!("Invalid auth rate-limit config; rate limit disabled");
            post(handlers::auth::google_auth)
        }
    };

    Router::new()
        .route("/v1/auth/google", auth_method_router)
        .route("/v1/users/me", get(handlers::auth::get_me))
}
