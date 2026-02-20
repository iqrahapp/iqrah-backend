//! Sync types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{DeviceId, GoalId, TimestampMs, UserId};

/// Sync push request.
#[derive(Debug, Clone, Deserialize, Validate, utoipa::ToSchema)]
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
#[derive(Debug, Clone, Deserialize, Validate, utoipa::ToSchema)]
pub struct SyncPullRequest {
    pub device_id: DeviceId,
    /// Timestamp in milliseconds since epoch. Returns changes after this time.
    #[schema(example = 1706000000000_i64)]
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
#[derive(Debug, Serialize, Deserialize, Validate, Clone, utoipa::ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, Validate, Clone, utoipa::ToSchema)]
pub struct SyncCursorSetting {
    #[schema(example = 1706000000000_i64)]
    pub updated_at: TimestampMs,
    #[validate(length(min = 1, max = 255))]
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone, utoipa::ToSchema)]
pub struct SyncCursorMemoryState {
    #[schema(example = 1706000000000_i64)]
    pub updated_at: TimestampMs,
    pub node_id: i64,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone, utoipa::ToSchema)]
pub struct SyncCursorSession {
    #[schema(example = 1706000000000_i64)]
    pub updated_at: TimestampMs,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone, utoipa::ToSchema)]
pub struct SyncCursorSessionItem {
    #[schema(example = 1706000000000_i64)]
    pub updated_at: TimestampMs,
    #[schema(example = "f47ac10b-58cc-4372-a567-0e02b2c3d479")]
    pub id: Uuid,
}

/// Collection of sync changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate, utoipa::ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
pub struct SettingChange {
    #[validate(length(min = 1, max = 255))]
    pub key: String,
    pub value: serde_json::Value,
    #[schema(example = 1706000000000_i64)]
    pub client_updated_at: TimestampMs,
}

/// Memory state change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
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
    #[schema(example = 1706000000000_i64)]
    pub client_updated_at: TimestampMs,
}

/// Session change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
pub struct SessionChange {
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    pub goal_id: Option<GoalId>,
    #[schema(example = 1706000000000_i64)]
    pub started_at: TimestampMs,
    pub completed_at: Option<TimestampMs>,
    #[validate(range(min = 0))]
    pub items_completed: i32,
    #[schema(example = 1706000000000_i64)]
    pub client_updated_at: TimestampMs,
}

/// Session item change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
pub struct SessionItemChange {
    #[schema(example = "f47ac10b-58cc-4372-a567-0e02b2c3d479")]
    pub id: Uuid,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub session_id: Uuid,
    pub node_id: i64,
    #[validate(length(min = 1, max = 100))]
    pub exercise_type: String,
    #[validate(range(min = 0, max = 5))]
    pub grade: Option<i32>,
    #[validate(range(min = 0))]
    pub duration_ms: Option<i32>,
    #[schema(example = 1706000000000_i64)]
    pub client_updated_at: TimestampMs,
}

/// Admin conflict log record.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminConflictRecord {
    pub id: i64,
    pub user_id: UserId,
    pub entity_type: String,
    pub entity_key: String,
    pub incoming_metadata: serde_json::Value,
    pub winning_metadata: serde_json::Value,
    #[schema(example = 1706000000000_i64)]
    pub resolved_at: TimestampMs,
}

/// Admin conflict inspection response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminConflictListResponse {
    pub conflicts: Vec<AdminConflictRecord>,
}

/// Sync push response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SyncPushResponse {
    /// Number of changes accepted and written (LWW won).
    pub applied: u64,
    /// Number of changes silently rejected because the server had a newer version (LWW lost).
    pub skipped: u64,
    #[schema(example = 1706000000000_i64)]
    pub server_time: TimestampMs,
}

/// Sync pull response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SyncPullResponse {
    #[schema(example = 1706000000000_i64)]
    pub server_time: TimestampMs,
    pub changes: SyncChanges,
    pub has_more: bool, // true if there are more records available
    pub next_cursor: Option<SyncPullCursor>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;
    use validator::Validate;

    use super::*;

    fn valid_sync_changes() -> SyncChanges {
        SyncChanges {
            settings: vec![SettingChange {
                key: "theme".to_string(),
                value: json!("dark"),
                client_updated_at: TimestampMs(1),
            }],
            memory_states: vec![MemoryStateChange {
                node_id: 11,
                energy: 0.4,
                fsrs_stability: Some(2.0),
                fsrs_difficulty: Some(3.0),
                last_reviewed_at: Some(TimestampMs(2)),
                next_review_at: Some(TimestampMs(3)),
                client_updated_at: TimestampMs(4),
            }],
            sessions: vec![SessionChange {
                id: Uuid::new_v4(),
                goal_id: Some(GoalId("goal-1".to_string())),
                started_at: TimestampMs(5),
                completed_at: Some(TimestampMs(6)),
                items_completed: 2,
                client_updated_at: TimestampMs(7),
            }],
            session_items: vec![SessionItemChange {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                node_id: 12,
                exercise_type: "review".to_string(),
                grade: Some(5),
                duration_ms: Some(1500),
                client_updated_at: TimestampMs(8),
            }],
        }
    }

    #[test]
    fn sync_push_request_validates_successfully_for_valid_payload() {
        let request = SyncPushRequest {
            device_id: DeviceId(Uuid::new_v4()),
            changes: valid_sync_changes(),
            device_os: Some("Android 14".to_string()),
            device_model: Some("Pixel 8 Pro".to_string()),
            app_version: Some("1.2.3".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn sync_push_request_rejects_invalid_nested_changes() {
        let request = SyncPushRequest {
            device_id: DeviceId(Uuid::new_v4()),
            changes: SyncChanges {
                settings: vec![SettingChange {
                    key: "".to_string(),
                    value: json!(null),
                    client_updated_at: TimestampMs(1),
                }],
                ..SyncChanges::default()
            },
            device_os: None,
            device_model: None,
            app_version: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn sync_pull_request_defaults_limit_to_1000() {
        let request: SyncPullRequest = serde_json::from_value(json!({
            "device_id": Uuid::new_v4(),
            "since": 0
        }))
        .expect("request should deserialize");

        assert_eq!(request.limit, Some(1000));
    }

    #[test]
    fn sync_pull_request_rejects_limit_below_range() {
        let request = SyncPullRequest {
            device_id: DeviceId(Uuid::new_v4()),
            since: TimestampMs(0),
            limit: Some(0),
            cursor: None,
            device_os: None,
            device_model: None,
            app_version: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn sync_pull_cursor_roundtrips_through_serde() {
        let cursor = SyncPullCursor {
            settings: Some(SyncCursorSetting {
                updated_at: TimestampMs(100),
                key: "setting-key".to_string(),
            }),
            memory_states: Some(SyncCursorMemoryState {
                updated_at: TimestampMs(101),
                node_id: 10,
            }),
            sessions: Some(SyncCursorSession {
                updated_at: TimestampMs(102),
                id: Uuid::new_v4(),
            }),
            session_items: Some(SyncCursorSessionItem {
                updated_at: TimestampMs(103),
                id: Uuid::new_v4(),
            }),
        };

        let json = serde_json::to_string(&cursor).expect("cursor should serialize");
        let restored: SyncPullCursor =
            serde_json::from_str(&json).expect("cursor should deserialize");

        assert_eq!(
            restored.settings.expect("settings cursor should exist").key,
            "setting-key"
        );
    }

    #[test]
    fn session_item_change_rejects_out_of_range_grade() {
        let item = SessionItemChange {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            node_id: 5,
            exercise_type: "listen".to_string(),
            grade: Some(6),
            duration_ms: Some(1000),
            client_updated_at: TimestampMs(99),
        };

        assert!(item.validate().is_err());
    }

    #[test]
    fn admin_conflict_and_sync_responses_serialize_expected_shape() {
        let conflict = AdminConflictRecord {
            id: 1,
            user_id: UserId(Uuid::new_v4()),
            entity_type: "setting".to_string(),
            entity_key: "theme".to_string(),
            incoming_metadata: json!({"value": "dark"}),
            winning_metadata: json!({"value": "light"}),
            resolved_at: TimestampMs(123),
        };

        let response = SyncPullResponse {
            server_time: TimestampMs(999),
            changes: valid_sync_changes(),
            has_more: false,
            next_cursor: None,
        };

        let conflict_json = serde_json::to_value(&conflict).expect("conflict should serialize");
        let response_json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(conflict_json["entity_key"], "theme");
        assert_eq!(response_json["server_time"], 999);
        assert!(response_json["changes"]["settings"].is_array());
    }
}
