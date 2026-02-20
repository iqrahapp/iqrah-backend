//! Postgres-only integration tests.
//!
//! Kept separate from the default SQLite suite so regular `cargo test`
//! stays sandbox-safe and deterministic.
#![cfg(feature = "postgres-tests")]

use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use iqrah_backend_domain::{
    GoalId, MemoryStateChange, SessionChange, SessionItemChange, SettingChange, SyncChanges,
    TimestampMs,
};
use iqrah_backend_storage::PgSyncRepository;

#[sqlx::test(migrations = "../../migrations")]
async fn sync_push_then_pull_returns_changes(pool: PgPool) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_id, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let changes = SyncChanges {
        settings: vec![SettingChange {
            key: "theme".to_string(),
            value: json!({ "mode": "dark" }),
            client_updated_at: TimestampMs(1_700_000_000_000),
        }],
        memory_states: vec![MemoryStateChange {
            node_id: 42,
            energy: 0.7,
            fsrs_stability: Some(2.5),
            fsrs_difficulty: Some(4.2),
            last_reviewed_at: Some(TimestampMs(1_700_000_000_000)),
            next_review_at: Some(TimestampMs(1_700_000_100_000)),
            client_updated_at: TimestampMs(1_700_000_120_000),
        }],
        sessions: vec![SessionChange {
            id: session_id,
            goal_id: Some(GoalId("goal-1".to_string())),
            started_at: TimestampMs(1_700_000_000_000),
            completed_at: Some(TimestampMs(1_700_000_120_000)),
            items_completed: 1,
            client_updated_at: TimestampMs(1_700_000_120_000),
        }],
        session_items: vec![SessionItemChange {
            id: item_id,
            session_id,
            node_id: 42,
            exercise_type: "translate".to_string(),
            grade: Some(3),
            duration_ms: Some(1200),
            client_updated_at: TimestampMs(1_700_000_120_000),
        }],
    };

    repo.apply_changes(user_id, device_id, &changes)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    let (pulled, has_more, next_cursor) = repo
        .get_changes_since(user_id, 0, 1000, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;

    assert_eq!(pulled.settings.len(), 1);
    assert_eq!(pulled.memory_states.len(), 1);
    assert_eq!(pulled.sessions.len(), 1);
    assert_eq!(pulled.session_items.len(), 1);
    assert!(!has_more);
    assert!(next_cursor.is_none());

    let setting = &pulled.settings[0];
    assert_eq!(setting.key, "theme");
    assert_eq!(setting.value, json!({ "mode": "dark" }));

    let state = &pulled.memory_states[0];
    assert_eq!(state.node_id, 42);
    assert!((state.energy - 0.7).abs() < f32::EPSILON);

    let session = &pulled.sessions[0];
    assert_eq!(session.id, session_id);
    assert_eq!(
        session.goal_id.as_ref().map(|goal| goal.0.as_str()),
        Some("goal-1")
    );
    assert_eq!(session.items_completed, 1);

    let item = &pulled.session_items[0];
    assert_eq!(item.id, item_id);
    assert_eq!(item.session_id, session_id);
    assert_eq!(item.exercise_type, "translate");

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn stale_client_timestamp_is_rejected_across_devices(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_a, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;
    repo.touch_device(user_id, device_b, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let first = SyncChanges {
        settings: vec![SettingChange {
            key: "mode".to_string(),
            value: json!("newer-but-arrived-first"),
            client_updated_at: TimestampMs(1_700_000_100_000),
        }],
        ..SyncChanges::default()
    };
    repo.apply_changes(user_id, device_a, &first)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    let second = SyncChanges {
        settings: vec![SettingChange {
            key: "mode".to_string(),
            value: json!("older-but-arrived-later"),
            client_updated_at: TimestampMs(1_700_000_000_000),
        }],
        ..SyncChanges::default()
    };
    let (applied, skipped) = repo
        .apply_changes(user_id, device_b, &second)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    assert_eq!(applied, 0);
    assert_eq!(skipped, 1);

    let value: serde_json::Value = sqlx::query_scalar!(
        r#"
        SELECT value
        FROM user_settings
        WHERE user_id = $1 AND key = $2
        "#,
        user_id,
        "mode"
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(value, json!("newer-but-arrived-first"));

    Ok(())
}

fn total_changes_count(changes: &SyncChanges) -> usize {
    changes.settings.len()
        + changes.memory_states.len()
        + changes.sessions.len()
        + changes.session_items.len()
}

#[sqlx::test(migrations = "../../migrations")]
async fn pull_limit_is_global_and_cursor_advances_precisely(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_id, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let session_ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let item_ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

    let changes = SyncChanges {
        settings: vec![
            SettingChange {
                key: "a".to_string(),
                value: json!(1),
                client_updated_at: TimestampMs(1),
            },
            SettingChange {
                key: "b".to_string(),
                value: json!(2),
                client_updated_at: TimestampMs(1),
            },
            SettingChange {
                key: "c".to_string(),
                value: json!(3),
                client_updated_at: TimestampMs(1),
            },
        ],
        memory_states: vec![
            MemoryStateChange {
                node_id: 10,
                energy: 0.2,
                fsrs_stability: None,
                fsrs_difficulty: None,
                last_reviewed_at: None,
                next_review_at: None,
                client_updated_at: TimestampMs(1),
            },
            MemoryStateChange {
                node_id: 20,
                energy: 0.3,
                fsrs_stability: None,
                fsrs_difficulty: None,
                last_reviewed_at: None,
                next_review_at: None,
                client_updated_at: TimestampMs(1),
            },
            MemoryStateChange {
                node_id: 30,
                energy: 0.4,
                fsrs_stability: None,
                fsrs_difficulty: None,
                last_reviewed_at: None,
                next_review_at: None,
                client_updated_at: TimestampMs(1),
            },
        ],
        sessions: vec![
            SessionChange {
                id: session_ids[0],
                goal_id: None,
                started_at: TimestampMs(1),
                completed_at: None,
                items_completed: 1,
                client_updated_at: TimestampMs(1),
            },
            SessionChange {
                id: session_ids[1],
                goal_id: None,
                started_at: TimestampMs(1),
                completed_at: None,
                items_completed: 1,
                client_updated_at: TimestampMs(1),
            },
            SessionChange {
                id: session_ids[2],
                goal_id: None,
                started_at: TimestampMs(1),
                completed_at: None,
                items_completed: 1,
                client_updated_at: TimestampMs(1),
            },
        ],
        session_items: vec![
            SessionItemChange {
                id: item_ids[0],
                session_id: session_ids[0],
                node_id: 10,
                exercise_type: "translate".to_string(),
                grade: Some(3),
                duration_ms: Some(1000),
                client_updated_at: TimestampMs(1),
            },
            SessionItemChange {
                id: item_ids[1],
                session_id: session_ids[1],
                node_id: 20,
                exercise_type: "translate".to_string(),
                grade: Some(3),
                duration_ms: Some(1000),
                client_updated_at: TimestampMs(1),
            },
            SessionItemChange {
                id: item_ids[2],
                session_id: session_ids[2],
                node_id: 30,
                exercise_type: "translate".to_string(),
                grade: Some(3),
                duration_ms: Some(1000),
                client_updated_at: TimestampMs(1),
            },
        ],
    };

    repo.apply_changes(user_id, device_id, &changes)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    let limit = 5;
    let (first_page, has_more, next_cursor) = repo
        .get_changes_since(user_id, 0, limit, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;

    assert!(has_more);
    assert!(total_changes_count(&first_page) <= limit);

    let cursor = next_cursor.expect("next cursor required for partial page");
    assert_eq!(cursor.settings.as_ref().map(|c| c.key.as_str()), Some("c"));
    assert_eq!(cursor.memory_states.as_ref().map(|c| c.node_id), Some(20));
    assert!(cursor.sessions.is_none());
    assert!(cursor.session_items.is_none());

    let (second_page, has_more, next_cursor) = repo
        .get_changes_since(user_id, 0, limit, Some(&cursor))
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;

    assert!(has_more);
    assert!(total_changes_count(&second_page) <= limit);

    let next_cursor = next_cursor.expect("next cursor required for remaining records");
    let (third_page, has_more, next_cursor) = repo
        .get_changes_since(user_id, 0, limit, Some(&next_cursor))
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;

    assert!(!has_more);
    assert!(next_cursor.is_none());
    assert!(total_changes_count(&third_page) <= limit);

    let total = total_changes_count(&first_page)
        + total_changes_count(&second_page)
        + total_changes_count(&third_page);
    assert_eq!(total, 12);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn pagination_cursor_returns_all_settings_without_duplicates(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_id, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let mut expected_keys = Vec::new();
    for idx in 0..15 {
        let key = format!("key-{idx:02}");
        expected_keys.push(key.clone());
        let changes = SyncChanges {
            settings: vec![SettingChange {
                key,
                value: json!(idx),
                client_updated_at: TimestampMs(1_700_000_000_000 + idx),
            }],
            ..SyncChanges::default()
        };
        repo.apply_changes(user_id, device_id, &changes)
            .await
            .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let mut collected = Vec::new();
    let mut cursor = None;
    loop {
        let (page, has_more, next_cursor) = repo
            .get_changes_since(user_id, 0, 4, cursor.as_ref())
            .await
            .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;
        collected.extend(page.settings.into_iter().map(|s| s.key));
        cursor = next_cursor;
        if !has_more {
            break;
        }
    }

    assert_eq!(collected.len(), expected_keys.len());
    assert_eq!(collected, expected_keys);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_changes_is_idempotent_for_repeated_payloads(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_id, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let session_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let changes = SyncChanges {
        settings: vec![SettingChange {
            key: "theme".to_string(),
            value: json!("dark"),
            client_updated_at: TimestampMs(10),
        }],
        sessions: vec![SessionChange {
            id: session_id,
            goal_id: Some(GoalId("goal-x".to_string())),
            started_at: TimestampMs(10),
            completed_at: Some(TimestampMs(11)),
            items_completed: 1,
            client_updated_at: TimestampMs(10),
        }],
        session_items: vec![SessionItemChange {
            id: item_id,
            session_id,
            node_id: 9,
            exercise_type: "translate".to_string(),
            grade: Some(4),
            duration_ms: Some(123),
            client_updated_at: TimestampMs(10),
        }],
        ..SyncChanges::default()
    };

    let (first_applied, first_skipped) = repo
        .apply_changes(user_id, device_id, &changes)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;
    let (second_applied, second_skipped) =
        repo.apply_changes(user_id, device_id, &changes)
            .await
            .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    assert_eq!((first_applied, first_skipped), (3, 0));
    assert_eq!((second_applied, second_skipped), (0, 3));

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn cursor_pagination_property_holds_for_multiple_limits(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO users (id, oauth_sub) VALUES ($1, $2)",
        user_id,
        format!("sub-{}", user_id)
    )
    .execute(&pool)
    .await?;

    let repo = PgSyncRepository::new(pool.clone());
    repo.touch_device(user_id, device_id, None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let source_keys: Vec<String> = (0..9).map(|n| format!("prop-{n}")).collect();
    for key in &source_keys {
        repo.apply_changes(
            user_id,
            device_id,
            &SyncChanges {
                settings: vec![SettingChange {
                    key: key.clone(),
                    value: json!(key),
                    client_updated_at: TimestampMs(42),
                }],
                ..SyncChanges::default()
            },
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    for limit in [1usize, 2, 3, 4, 5] {
        let mut cursor = None;
        let mut pulled = Vec::new();
        loop {
            let (page, has_more, next_cursor) = repo
                .get_changes_since(user_id, 0, limit, cursor.as_ref())
                .await
                .map_err(|e| sqlx::Error::Protocol(format!("get_changes_since failed: {e}")))?;
            pulled.extend(page.settings.into_iter().map(|s| s.key));
            cursor = next_cursor;
            if !has_more {
                break;
            }
        }

        assert_eq!(pulled, source_keys, "failed for limit={limit}");
    }

    Ok(())
}
