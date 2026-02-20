//! Sync types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{DeviceId, GoalId, TimestampMs, UserId};

/// Sync push request.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SyncPushRequest {
    pub device_id: DeviceId,
    #[validate(nested)]
    pub changes: SyncChanges,
    /// Device OS (e.g., "Android 14", "iOS 17.2"). Max 50 characters.
    #[validate(length(max = 50))]
    pub device_os: Option<String>,
    /// Device model (e.g., "Pixel 8 Pro", "iPhone 15"). Max 100 characters.
    #[validate(length(max = 100))]
    pub device_model: Option<String>,
    /// App version (e.g., "1.2.3"). Max 20 characters.
    #[validate(length(max = 20))]
    pub app_version: Option<String>,
}

/// Sync pull request.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SyncPullRequest {
    pub device_id: DeviceId,
    /// Timestamp in milliseconds since epoch. Returns changes after this time.
    pub since: TimestampMs,
    /// Max records per batch across all entity types combined (global cap).
    ///
    /// The server merges changes from all categories and stops when the total
    /// payload reaches `limit`. Default: 1000, Maximum allowed: 10000.
    #[validate(range(min = 1, max = 10000))]
    #[serde(default = "default_limit")]
    pub limit: Option<usize>,
    /// Per-entity pagination cursor (optional).
    #[serde(default)]
    #[validate(nested)]
    pub cursor: Option<SyncPullCursor>,
    /// Device OS (e.g., "Android 14", "iOS 17.2"). Max 50 characters.
    #[validate(length(max = 50))]
    pub device_os: Option<String>,
    /// Device model (e.g., "Pixel 8 Pro", "iPhone 15"). Max 100 characters.
    #[validate(length(max = 100))]
    pub device_model: Option<String>,
    /// App version (e.g., "1.2.3"). Max 20 characters.
    #[validate(length(max = 20))]
    pub app_version: Option<String>,
}

fn default_limit() -> Option<usize> {
    Some(1000)
}

/// Per-entity cursor for paginated sync pulls.
#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct SyncPullCursor {
    #[serde(default)]
    #[validate(nested)]
    pub settings: Option<SyncCursorSetting>,
    #[serde(default)]
    #[validate(nested)]
    pub memory_states: Option<SyncCursorMemoryState>,
    #[serde(default)]
    #[validate(nested)]
    pub sessions: Option<SyncCursorSession>,
    #[serde(default)]
    #[validate(nested)]
    pub session_items: Option<SyncCursorSessionItem>,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct SyncCursorSetting {
    pub updated_at: TimestampMs,
    #[validate(length(min = 1, max = 255))]
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct SyncCursorMemoryState {
    pub updated_at: TimestampMs,
    pub node_id: i64,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct SyncCursorSession {
    pub updated_at: TimestampMs,
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct SyncCursorSessionItem {
    pub updated_at: TimestampMs,
    pub id: Uuid,
}

/// Collection of sync changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub struct SyncChanges {
    #[serde(default)]
    #[validate(nested)]
    pub settings: Vec<SettingChange>,
    #[serde(default)]
    #[validate(nested)]
    pub memory_states: Vec<MemoryStateChange>,
    #[serde(default)]
    #[validate(nested)]
    pub sessions: Vec<SessionChange>,
    #[serde(default)]
    #[validate(nested)]
    pub session_items: Vec<SessionItemChange>,
}

/// Setting change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SettingChange {
    #[validate(length(min = 1, max = 255))]
    pub key: String,
    pub value: serde_json::Value,
    pub client_updated_at: TimestampMs,
}

/// Memory state change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct MemoryStateChange {
    pub node_id: i64,
    #[validate(range(min = 0.0, max = 1.0))]
    pub energy: f32,
    #[validate(range(min = 0.0))]
    pub fsrs_stability: Option<f32>,
    #[validate(range(min = 0.0))]
    pub fsrs_difficulty: Option<f32>,
    pub last_reviewed_at: Option<TimestampMs>,
    pub next_review_at: Option<TimestampMs>,
    pub client_updated_at: TimestampMs,
}

/// Session change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SessionChange {
    pub id: Uuid,
    pub goal_id: Option<GoalId>,
    pub started_at: TimestampMs,
    pub completed_at: Option<TimestampMs>,
    #[validate(range(min = 0))]
    pub items_completed: i32,
    pub client_updated_at: TimestampMs,
}

/// Session item change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SessionItemChange {
    pub id: Uuid,
    pub session_id: Uuid,
    pub node_id: i64,
    #[validate(length(min = 1, max = 100))]
    pub exercise_type: String,
    #[validate(range(min = 0, max = 5))]
    pub grade: Option<i32>,
    #[validate(range(min = 0))]
    pub duration_ms: Option<i32>,
    pub client_updated_at: TimestampMs,
}

/// Admin conflict log record.
#[derive(Debug, Serialize)]
pub struct AdminConflictRecord {
    pub id: i64,
    pub user_id: UserId,
    pub entity_type: String,
    pub entity_key: String,
    pub incoming_metadata: serde_json::Value,
    pub winning_metadata: serde_json::Value,
    pub resolved_at: TimestampMs,
}

/// Admin conflict inspection response.
#[derive(Debug, Serialize)]
pub struct AdminConflictListResponse {
    pub conflicts: Vec<AdminConflictRecord>,
}

/// Sync push response.
#[derive(Debug, Serialize)]
pub struct SyncPushResponse {
    /// Number of changes accepted and written (LWW won).
    pub applied: u64,
    /// Number of changes silently rejected because the server had a newer version (LWW lost).
    pub skipped: u64,
    pub server_time: TimestampMs,
}

/// Sync pull response.
#[derive(Debug, Serialize)]
pub struct SyncPullResponse {
    pub server_time: TimestampMs,
    pub changes: SyncChanges,
    pub has_more: bool, // true if there are more records available
    pub next_cursor: Option<SyncPullCursor>,
}
