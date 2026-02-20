//! Sync handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::Utc;
use validator::Validate;

use crate::AppState;
use crate::middleware::auth::{AdminApiKey, AuthUser};
use iqrah_backend_domain::{
    AdminConflictListResponse, AdminConflictRecord, DomainError, SyncPullRequest, SyncPullResponse,
    SyncPushRequest, SyncPushResponse, TimestampMs, UserId,
};

/// Pushes local device changes to the server.
pub async fn sync_push(
    State(state): State<Arc<AppState>>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<SyncPushRequest>,
) -> Result<Json<SyncPushResponse>, DomainError> {
    req.validate()
        .map_err(iqrah_backend_domain::DomainError::from_validation_errors)?;

    let device_id = req.device_id;
    let changes = req.changes;

    state
        .sync_repo
        .touch_device(
            user_id,
            device_id,
            req.device_os,
            req.device_model,
            req.app_version,
        )
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let (applied, skipped) = state
        .sync_repo
        .apply_changes(user_id, device_id, changes)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok(Json(SyncPushResponse {
        applied,
        skipped,
        server_time: TimestampMs(Utc::now().timestamp_millis()),
    }))
}

/// Pulls server-side changes since a cursor or initial timestamp.
pub async fn sync_pull(
    State(state): State<Arc<AppState>>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<SyncPullRequest>,
) -> Result<Json<SyncPullResponse>, DomainError> {
    req.validate()
        .map_err(iqrah_backend_domain::DomainError::from_validation_errors)?;

    let device_id = req.device_id;
    let since = req.since;
    let limit = req.limit.unwrap_or(1000);
    let cursor = req.cursor;

    state
        .sync_repo
        .touch_device(
            user_id,
            device_id,
            req.device_os,
            req.device_model,
            req.app_version,
        )
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    let (changes, has_more, next_cursor) = state
        .sync_repo
        .get_changes_since(user_id, since, limit, cursor)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok(Json(SyncPullResponse {
        server_time: TimestampMs(Utc::now().timestamp_millis()),
        changes,
        has_more,
        next_cursor,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct ConflictQuery {
    pub limit: Option<usize>,
}

/// Admin-only conflict inspection endpoint.
pub async fn admin_recent_conflicts(
    State(state): State<Arc<AppState>>,
    _admin: AdminApiKey,
    Path(user_id): Path<uuid::Uuid>,
    Query(query): Query<ConflictQuery>,
) -> Result<Json<AdminConflictListResponse>, DomainError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    let rows = state
        .sync_repo
        .list_recent_conflicts(UserId(user_id), limit)
        .await
        .map_err(|e| DomainError::Database(e.to_string()))?;

    Ok(Json(AdminConflictListResponse {
        conflicts: rows
            .into_iter()
            .map(|row| AdminConflictRecord {
                id: row.id,
                user_id: row.user_id,
                entity_type: row.entity_type,
                entity_key: row.entity_key,
                incoming_metadata: row.incoming_metadata,
                winning_metadata: row.winning_metadata,
                resolved_at: TimestampMs(row.resolved_at.timestamp_millis()),
            })
            .collect(),
    }))
}
