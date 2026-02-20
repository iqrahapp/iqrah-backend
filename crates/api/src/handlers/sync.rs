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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use chrono::Utc;
    use iqrah_backend_domain::{DeviceId, SyncChanges, SyncPullCursor, TimestampMs, UserId};
    use iqrah_backend_storage::{ConflictLogEntry, StorageError, SyncRepository};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::jwt_verifier::MockJwtVerifier;
    use crate::build_router;
    use crate::test_support::{
        NoopAuthRepository, NoopPackAssetStore, NoopPackRepository, base_config, build_state,
    };

    mockall::mock! {
        pub SyncRepo {}

        #[async_trait]
        impl SyncRepository for SyncRepo {
            async fn touch_device(
                &self,
                user_id: UserId,
                device_id: DeviceId,
                device_os: Option<String>,
                device_model: Option<String>,
                app_version: Option<String>,
            ) -> Result<(), StorageError>;

            async fn apply_changes(
                &self,
                user_id: UserId,
                device_id: DeviceId,
                changes: SyncChanges,
            ) -> Result<(u64, u64), StorageError>;

            async fn list_recent_conflicts(
                &self,
                user_id: UserId,
                limit: usize,
            ) -> Result<Vec<ConflictLogEntry>, StorageError>;

            async fn get_changes_since(
                &self,
                user_id: UserId,
                since: TimestampMs,
                limit: usize,
                cursor: Option<SyncPullCursor>,
            ) -> Result<(SyncChanges, bool, Option<SyncPullCursor>), StorageError>;
        }
    }

    fn valid_push_request(device_id: Uuid) -> SyncPushRequest {
        SyncPushRequest {
            device_id: DeviceId(device_id),
            changes: SyncChanges {
                settings: vec![iqrah_backend_domain::SettingChange {
                    key: "theme".to_string(),
                    value: serde_json::json!("dark"),
                    client_updated_at: TimestampMs(1),
                }],
                ..SyncChanges::default()
            },
            device_os: Some("Android 14".to_string()),
            device_model: Some("Pixel 8".to_string()),
            app_version: Some("1.0.0".to_string()),
        }
    }

    fn valid_pull_request(device_id: Uuid) -> SyncPullRequest {
        SyncPullRequest {
            device_id: DeviceId(device_id),
            since: TimestampMs(0),
            limit: Some(100),
            cursor: None,
            device_os: Some("Android 14".to_string()),
            device_model: Some("Pixel 8".to_string()),
            app_version: Some("1.0.0".to_string()),
        }
    }

    #[tokio::test]
    async fn sync_push_happy_path_returns_counts() {
        let user_id = UserId(Uuid::new_v4());
        let device_id = Uuid::new_v4();

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_touch_device()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        sync_repo
            .expect_apply_changes()
            .times(1)
            .returning(|_, _, _| Ok((3, 1)));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let response = sync_push(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(valid_push_request(device_id)),
        )
        .await
        .expect("push should succeed");

        assert_eq!(response.0.applied, 3);
        assert_eq!(response.0.skipped, 1);
    }

    #[tokio::test]
    async fn sync_push_returns_400_for_validation_errors() {
        let user_id = UserId(Uuid::new_v4());
        let device_id = Uuid::new_v4();

        let mut sync_repo = MockSyncRepo::new();
        sync_repo.expect_touch_device().times(0);
        sync_repo.expect_apply_changes().times(0);

        let mut request = valid_push_request(device_id);
        request.changes.settings[0].key = "".to_string();

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = sync_push(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(request),
        )
        .await
        .expect_err("invalid payload should fail");

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sync_push_returns_500_when_touch_device_fails() {
        let user_id = UserId(Uuid::new_v4());

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_touch_device()
            .times(1)
            .returning(|_, _, _, _, _| Err(StorageError::Unexpected("db down".to_string())));
        sync_repo.expect_apply_changes().times(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = sync_push(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(valid_push_request(Uuid::new_v4())),
        )
        .await
        .expect_err("touch_device error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sync_push_returns_500_when_apply_changes_fails() {
        let user_id = UserId(Uuid::new_v4());

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_touch_device()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        sync_repo
            .expect_apply_changes()
            .times(1)
            .returning(|_, _, _| Err(StorageError::Unexpected("write failed".to_string())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = sync_push(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(valid_push_request(Uuid::new_v4())),
        )
        .await
        .expect_err("apply_changes error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sync_pull_happy_path_returns_changes() {
        let user_id = UserId(Uuid::new_v4());
        let device_id = Uuid::new_v4();

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_touch_device()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        sync_repo
            .expect_get_changes_since()
            .times(1)
            .returning(|_, _, _, _| Ok((SyncChanges::default(), false, None)));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let response = sync_pull(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(valid_pull_request(device_id)),
        )
        .await
        .expect("pull should succeed");

        assert!(!response.0.has_more);
    }

    #[tokio::test]
    async fn sync_pull_returns_400_for_invalid_limit() {
        let user_id = UserId(Uuid::new_v4());

        let mut sync_repo = MockSyncRepo::new();
        sync_repo.expect_touch_device().times(0);
        sync_repo.expect_get_changes_since().times(0);

        let mut request = valid_pull_request(Uuid::new_v4());
        request.limit = Some(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = sync_pull(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(request),
        )
        .await
        .expect_err("invalid payload should fail");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sync_pull_returns_500_when_get_changes_fails() {
        let user_id = UserId(Uuid::new_v4());

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_touch_device()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        sync_repo
            .expect_get_changes_since()
            .times(1)
            .returning(|_, _, _, _| Err(StorageError::Unexpected("read failed".to_string())));

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = sync_pull(
            axum::extract::State(state),
            AuthUser(user_id),
            Json(valid_pull_request(Uuid::new_v4())),
        )
        .await
        .expect_err("get_changes error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn admin_recent_conflicts_clamps_limit_and_returns_rows() {
        let user_id = Uuid::new_v4();

        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_list_recent_conflicts()
            .times(1)
            .with(
                mockall::predicate::eq(UserId(user_id)),
                mockall::predicate::eq(200),
            )
            .returning(move |_, _| {
                Ok(vec![ConflictLogEntry {
                    id: 1,
                    user_id: UserId(user_id),
                    entity_type: "setting".to_string(),
                    entity_key: "theme".to_string(),
                    incoming_metadata: serde_json::json!({"value":"dark"}),
                    winning_metadata: serde_json::json!({"value":"light"}),
                    resolved_at: Utc::now(),
                }])
            });
        sync_repo.expect_touch_device().times(0);
        sync_repo.expect_apply_changes().times(0);
        sync_repo.expect_get_changes_since().times(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let response = admin_recent_conflicts(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
            axum::extract::Path(user_id),
            axum::extract::Query(ConflictQuery { limit: Some(9999) }),
        )
        .await
        .expect("conflicts should load");

        assert_eq!(response.0.conflicts.len(), 1);
        assert_eq!(response.0.conflicts[0].entity_key, "theme");
    }

    #[tokio::test]
    async fn admin_recent_conflicts_returns_500_when_repository_fails() {
        let mut sync_repo = MockSyncRepo::new();
        sync_repo
            .expect_list_recent_conflicts()
            .times(1)
            .returning(|_, _| Err(StorageError::Unexpected("db down".to_string())));
        sync_repo.expect_touch_device().times(0);
        sync_repo.expect_apply_changes().times(0);
        sync_repo.expect_get_changes_since().times(0);

        let state = build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(sync_repo),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        );

        let err = admin_recent_conflicts(
            axum::extract::State(state),
            crate::middleware::auth::AdminApiKey,
            axum::extract::Path(Uuid::new_v4()),
            axum::extract::Query(ConflictQuery { limit: None }),
        )
        .await
        .expect_err("storage error should fail");

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sync_push_route_returns_401_when_missing_auth_header() {
        let app = build_router(build_state(
            Arc::new(NoopPackRepository),
            Arc::new(NoopAuthRepository),
            Arc::new(MockSyncRepo::new()),
            Arc::new(MockJwtVerifier::new()),
            Arc::new(NoopPackAssetStore),
            base_config(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("x-forwarded-for", "198.51.100.1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id": Uuid::new_v4(),
                            "changes": {},
                        }))
                        .expect("payload should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should run");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
