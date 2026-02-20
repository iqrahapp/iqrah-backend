#![cfg(feature = "postgres-tests")]

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use iqrah_backend_domain::{DeviceId, SettingChange, SyncChanges, TimestampMs, UserId};
use iqrah_backend_storage::PgSyncRepository;

#[sqlx::test(migrations = "../../migrations")]
async fn applied_changes_create_sync_events(pool: PgPool) -> Result<(), sqlx::Error> {
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
    repo.touch_device(UserId(user_id), DeviceId(device_id), None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let changes = SyncChanges {
        settings: vec![SettingChange {
            key: "language".to_string(),
            value: json!("ar"),
            client_updated_at: TimestampMs(1_700_000_000_500),
        }],
        ..SyncChanges::default()
    };

    let (applied, skipped) = repo
        .apply_changes(UserId(user_id), DeviceId(device_id), &changes)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;

    assert_eq!(applied, 1);
    assert_eq!(skipped, 0);

    let event_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*)::BIGINT as \"count!\" FROM sync_events WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(event_count, 1);

    let conflict_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*)::BIGINT as \"count!\" FROM conflict_logs WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(conflict_count, 0);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn skipped_changes_create_conflict_logs(pool: PgPool) -> Result<(), sqlx::Error> {
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
    repo.touch_device(UserId(user_id), DeviceId(device_a), None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;
    repo.touch_device(UserId(user_id), DeviceId(device_b), None, None, None)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("touch_device failed: {e}")))?;

    let newer = SyncChanges {
        settings: vec![SettingChange {
            key: "mode".to_string(),
            value: json!("new"),
            client_updated_at: TimestampMs(1_700_000_100_000),
        }],
        ..SyncChanges::default()
    };

    let older = SyncChanges {
        settings: vec![SettingChange {
            key: "mode".to_string(),
            value: json!("old"),
            client_updated_at: TimestampMs(1_700_000_000_000),
        }],
        ..SyncChanges::default()
    };

    let (applied_first, skipped_first) = repo
        .apply_changes(UserId(user_id), DeviceId(device_a), &newer)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;
    assert_eq!((applied_first, skipped_first), (1, 0));

    let (applied_second, skipped_second) = repo
        .apply_changes(UserId(user_id), DeviceId(device_b), &older)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("apply_changes failed: {e}")))?;
    assert_eq!((applied_second, skipped_second), (0, 1));

    let event_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*)::BIGINT as \"count!\" FROM sync_events WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(event_count, 1);

    let conflict_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*)::BIGINT as \"count!\" FROM conflict_logs WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(conflict_count, 1);

    Ok(())
}
