//! Sync repository for LWW sync operations.

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use iqrah_backend_domain::{
    DeviceId, GoalId, MemoryStateChange, SessionChange, SessionItemChange, SettingChange,
    SyncChanges, SyncCursorMemoryState, SyncCursorSession, SyncCursorSessionItem,
    SyncCursorSetting, SyncPullCursor, TimestampMs, UserId,
};
use sqlx::PgPool;

use crate::StorageError;

/// Conflict log record used by admin endpoints.
#[derive(Debug)]
pub struct ConflictLogEntry {
    pub id: i64,
    pub user_id: UserId,
    pub entity_type: String,
    pub entity_key: String,
    pub incoming_metadata: serde_json::Value,
    pub winning_metadata: serde_json::Value,
    pub resolved_at: DateTime<Utc>,
}

/// Sync repository boundary.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SyncRepository: Send + Sync {
    /// Registers or updates device metadata for the current user.
    async fn touch_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        device_os: Option<String>,
        device_model: Option<String>,
        app_version: Option<String>,
    ) -> Result<(), StorageError>;

    /// Applies client changes in one transaction using LWW semantics.
    async fn apply_changes(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        changes: SyncChanges,
    ) -> Result<(u64, u64), StorageError>;

    /// Lists recent sync conflicts for an admin view.
    async fn list_recent_conflicts(
        &self,
        user_id: UserId,
        limit: usize,
    ) -> Result<Vec<ConflictLogEntry>, StorageError>;

    /// Returns batched sync changes since a cursor or initial timestamp.
    async fn get_changes_since(
        &self,
        user_id: UserId,
        since: TimestampMs,
        limit: usize,
        cursor: Option<SyncPullCursor>,
    ) -> Result<(SyncChanges, bool, Option<SyncPullCursor>), StorageError>;
}

/// PostgreSQL implementation for [`SyncRepository`].
#[derive(Clone)]
pub struct PgSyncRepository {
    pool: PgPool,
}

impl PgSyncRepository {
    /// Creates a repository from a PostgreSQL pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Backward-compatible helper for call sites using borrowed metadata values.
    pub async fn touch_device<U, D>(
        &self,
        user_id: U,
        device_id: D,
        device_os: Option<&str>,
        device_model: Option<&str>,
        app_version: Option<&str>,
    ) -> Result<(), StorageError>
    where
        U: Into<UserId>,
        D: Into<DeviceId>,
    {
        <Self as SyncRepository>::touch_device(
            self,
            user_id.into(),
            device_id.into(),
            device_os.map(ToString::to_string),
            device_model.map(ToString::to_string),
            app_version.map(ToString::to_string),
        )
        .await
    }

    /// Backward-compatible helper for call sites borrowing sync changes.
    pub async fn apply_changes<U, D>(
        &self,
        user_id: U,
        device_id: D,
        changes: &SyncChanges,
    ) -> Result<(u64, u64), StorageError>
    where
        U: Into<UserId>,
        D: Into<DeviceId>,
    {
        <Self as SyncRepository>::apply_changes(
            self,
            user_id.into(),
            device_id.into(),
            changes.clone(),
        )
        .await
    }

    /// Backward-compatible helper for call sites borrowing cursor values.
    pub async fn get_changes_since<U, T>(
        &self,
        user_id: U,
        since: T,
        limit: usize,
        cursor: Option<&SyncPullCursor>,
    ) -> Result<(SyncChanges, bool, Option<SyncPullCursor>), StorageError>
    where
        U: Into<UserId>,
        T: Into<TimestampMs>,
    {
        <Self as SyncRepository>::get_changes_since(
            self,
            user_id.into(),
            since.into(),
            limit,
            cursor.cloned(),
        )
        .await
    }

    /// Backward-compatible helper for call sites using UUID user ids.
    pub async fn list_recent_conflicts<U>(
        &self,
        user_id: U,
        limit: usize,
    ) -> Result<Vec<ConflictLogEntry>, StorageError>
    where
        U: Into<UserId>,
    {
        <Self as SyncRepository>::list_recent_conflicts(self, user_id.into(), limit).await
    }

    async fn upsert_setting_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        device_id: DeviceId,
        setting: &SettingChange,
        now: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let incoming_updated_at =
            timestamp_from_millis(setting.client_updated_at, "setting.client_updated_at")?;

        let result = sqlx::query!(
            r#"
            INSERT INTO user_settings (user_id, key, value, updated_at, updated_by_device)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = EXCLUDED.updated_at,
                updated_by_device = EXCLUDED.updated_by_device
            WHERE user_settings.updated_at < EXCLUDED.updated_at
            "#,
            user_id.0,
            setting.key,
            setting.value,
            incoming_updated_at,
            device_id.0
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        if result.rows_affected() > 0 {
            self.log_sync_event_tx(
                tx,
                user_id,
                "setting",
                &setting.key,
                device_id,
                incoming_updated_at,
            )
            .await?;
            return Ok(result.rows_affected());
        }

        let winner = sqlx::query!(
            "SELECT updated_at, updated_by_device FROM user_settings WHERE user_id = $1 AND key = $2",
            user_id.0,
            setting.key
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        self.log_conflict_tx(
            tx,
            user_id,
            "setting",
            &setting.key,
            serde_json::json!({
                "client_updated_at": setting.client_updated_at,
                "device_id": device_id,
                "value_type": json_type_name(&setting.value),
            }),
            serde_json::json!({
                "updated_at": winner.updated_at.timestamp_millis(),
                "updated_by_device": winner.updated_by_device,
            }),
            now,
        )
        .await?;

        Ok(result.rows_affected())
    }

    async fn upsert_memory_state_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        device_id: DeviceId,
        state: &MemoryStateChange,
        now: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let last_reviewed = state
            .last_reviewed_at
            .map(|ts| timestamp_from_millis(ts, "memory_state.last_reviewed_at"))
            .transpose()?;
        let next_review = state
            .next_review_at
            .map(|ts| timestamp_from_millis(ts, "memory_state.next_review_at"))
            .transpose()?;
        let incoming_updated_at =
            timestamp_from_millis(state.client_updated_at, "memory_state.client_updated_at")?;

        let result = sqlx::query!(
            r#"
            INSERT INTO memory_states (user_id, node_id, energy, fsrs_stability, fsrs_difficulty,
                                       last_reviewed_at, next_review_at, updated_at, updated_by_device)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (user_id, node_id) DO UPDATE SET
                energy = EXCLUDED.energy,
                fsrs_stability = EXCLUDED.fsrs_stability,
                fsrs_difficulty = EXCLUDED.fsrs_difficulty,
                last_reviewed_at = EXCLUDED.last_reviewed_at,
                next_review_at = EXCLUDED.next_review_at,
                updated_at = EXCLUDED.updated_at,
                updated_by_device = EXCLUDED.updated_by_device
            WHERE memory_states.updated_at < EXCLUDED.updated_at
            "#,
            user_id.0,
            state.node_id,
            state.energy,
            state.fsrs_stability,
            state.fsrs_difficulty,
            last_reviewed,
            next_review,
            incoming_updated_at,
            device_id.0
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        if result.rows_affected() > 0 {
            self.log_sync_event_tx(
                tx,
                user_id,
                "memory_state",
                &state.node_id.to_string(),
                device_id,
                incoming_updated_at,
            )
            .await?;
            return Ok(result.rows_affected());
        }

        let winner = sqlx::query!(
            "SELECT updated_at, updated_by_device FROM memory_states WHERE user_id = $1 AND node_id = $2",
            user_id.0,
            state.node_id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        self.log_conflict_tx(
            tx,
            user_id,
            "memory_state",
            &state.node_id.to_string(),
            serde_json::json!({
                "client_updated_at": state.client_updated_at,
                "device_id": device_id,
                "energy": state.energy,
            }),
            serde_json::json!({
                "updated_at": winner.updated_at.timestamp_millis(),
                "updated_by_device": winner.updated_by_device,
            }),
            now,
        )
        .await?;

        Ok(result.rows_affected())
    }

    async fn upsert_session_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        device_id: DeviceId,
        session: &SessionChange,
        now: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let started = timestamp_from_millis(session.started_at, "session.started_at")?;
        let completed = session
            .completed_at
            .map(|ts| timestamp_from_millis(ts, "session.completed_at"))
            .transpose()?;
        let incoming_updated_at =
            timestamp_from_millis(session.client_updated_at, "session.client_updated_at")?;
        let goal_id = session.goal_id.as_ref().map(|value| value.0.as_str());

        let result = sqlx::query!(
            r#"
            INSERT INTO sessions (id, user_id, goal_id, started_at, completed_at, items_completed, updated_at, updated_by_device)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                items_completed = EXCLUDED.items_completed,
                updated_at = EXCLUDED.updated_at,
                updated_by_device = EXCLUDED.updated_by_device
            WHERE sessions.updated_at < EXCLUDED.updated_at
            "#,
            session.id,
            user_id.0,
            goal_id,
            started,
            completed,
            session.items_completed,
            incoming_updated_at,
            device_id.0
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        if result.rows_affected() > 0 {
            self.log_sync_event_tx(
                tx,
                user_id,
                "session",
                &session.id.to_string(),
                device_id,
                incoming_updated_at,
            )
            .await?;
            return Ok(result.rows_affected());
        }

        let winner = sqlx::query!(
            "SELECT updated_at, updated_by_device FROM sessions WHERE id = $1",
            session.id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        self.log_conflict_tx(
            tx,
            user_id,
            "session",
            &session.id.to_string(),
            serde_json::json!({
                "client_updated_at": session.client_updated_at,
                "device_id": device_id,
                "items_completed": session.items_completed,
            }),
            serde_json::json!({
                "updated_at": winner.updated_at.timestamp_millis(),
                "updated_by_device": winner.updated_by_device,
            }),
            now,
        )
        .await?;

        Ok(result.rows_affected())
    }

    async fn upsert_session_item_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        device_id: DeviceId,
        item: &SessionItemChange,
        now: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let incoming_updated_at =
            timestamp_from_millis(item.client_updated_at, "session_item.client_updated_at")?;

        let result = sqlx::query!(
            r#"
            INSERT INTO session_items (id, session_id, user_id, node_id, exercise_type, grade, duration_ms, updated_at, updated_by_device)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
                grade = EXCLUDED.grade,
                duration_ms = EXCLUDED.duration_ms,
                updated_at = EXCLUDED.updated_at,
                updated_by_device = EXCLUDED.updated_by_device
            WHERE session_items.updated_at < EXCLUDED.updated_at
            "#,
            item.id,
            item.session_id,
            user_id.0,
            item.node_id,
            item.exercise_type,
            item.grade,
            item.duration_ms,
            incoming_updated_at,
            device_id.0
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        if result.rows_affected() > 0 {
            self.log_sync_event_tx(
                tx,
                user_id,
                "session_item",
                &item.id.to_string(),
                device_id,
                incoming_updated_at,
            )
            .await?;
            return Ok(result.rows_affected());
        }

        let winner = sqlx::query!(
            "SELECT updated_at, updated_by_device FROM session_items WHERE id = $1",
            item.id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        self.log_conflict_tx(
            tx,
            user_id,
            "session_item",
            &item.id.to_string(),
            serde_json::json!({
                "client_updated_at": item.client_updated_at,
                "device_id": device_id,
                "grade": item.grade,
            }),
            serde_json::json!({
                "updated_at": winner.updated_at.timestamp_millis(),
                "updated_by_device": winner.updated_by_device,
            }),
            now,
        )
        .await?;

        Ok(result.rows_affected())
    }

    async fn log_sync_event_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        entity_type: &str,
        entity_key: &str,
        source_device_id: DeviceId,
        entity_updated_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO sync_events (user_id, entity_type, entity_key, source_device_id, entity_updated_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user_id.0,
            entity_type,
            entity_key,
            source_device_id.0,
            entity_updated_at
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn log_conflict_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        entity_type: &str,
        entity_key: &str,
        incoming_metadata: serde_json::Value,
        winning_metadata: serde_json::Value,
        resolved_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO conflict_logs (user_id, entity_type, entity_key, incoming_metadata, winning_metadata, resolved_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            user_id.0,
            entity_type,
            entity_key,
            incoming_metadata,
            winning_metadata,
            resolved_at
        )
        .execute(&mut **tx)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }
}

#[async_trait]
impl SyncRepository for PgSyncRepository {
    async fn touch_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        device_os: Option<String>,
        device_model: Option<String>,
        app_version: Option<String>,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO devices (id, user_id, os, device_model, app_version, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (id) DO UPDATE SET
                os = COALESCE(EXCLUDED.os, devices.os),
                device_model = COALESCE(EXCLUDED.device_model, devices.device_model),
                app_version = COALESCE(EXCLUDED.app_version, devices.app_version),
                last_seen_at = now()
            "#,
            device_id.0,
            user_id.0,
            device_os.as_deref(),
            device_model.as_deref(),
            app_version.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }

    async fn apply_changes(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        changes: SyncChanges,
    ) -> Result<(u64, u64), StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Query)?;
        let now = Utc::now();
        let mut applied: u64 = 0;
        let mut skipped: u64 = 0;

        for setting in &changes.settings {
            let rows = self
                .upsert_setting_tx(&mut tx, user_id, device_id, setting, now)
                .await?;
            if rows > 0 {
                applied += 1;
            } else {
                skipped += 1;
            }
        }

        for state in &changes.memory_states {
            let rows = self
                .upsert_memory_state_tx(&mut tx, user_id, device_id, state, now)
                .await?;
            if rows > 0 {
                applied += 1;
            } else {
                skipped += 1;
            }
        }

        for session in &changes.sessions {
            let rows = self
                .upsert_session_tx(&mut tx, user_id, device_id, session, now)
                .await?;
            if rows > 0 {
                applied += 1;
            } else {
                skipped += 1;
            }
        }

        for item in &changes.session_items {
            let rows = self
                .upsert_session_item_tx(&mut tx, user_id, device_id, item, now)
                .await?;
            if rows > 0 {
                applied += 1;
            } else {
                skipped += 1;
            }
        }

        tx.commit().await.map_err(StorageError::Query)?;
        Ok((applied, skipped))
    }

    async fn list_recent_conflicts(
        &self,
        user_id: UserId,
        limit: usize,
    ) -> Result<Vec<ConflictLogEntry>, StorageError> {
        let limit_i64 = i64::try_from(limit)
            .map_err(|_| StorageError::Unexpected(format!("conflict limit too large: {limit}")))?;

        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, entity_type, entity_key, incoming_metadata, winning_metadata, resolved_at
            FROM conflict_logs
            WHERE user_id = $1
            ORDER BY resolved_at DESC, id DESC
            LIMIT $2
            "#,
            user_id.0,
            limit_i64
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(rows
            .into_iter()
            .map(|row| ConflictLogEntry {
                id: row.id,
                user_id: UserId(row.user_id),
                entity_type: row.entity_type,
                entity_key: row.entity_key,
                incoming_metadata: row.incoming_metadata,
                winning_metadata: row.winning_metadata,
                resolved_at: row.resolved_at,
            })
            .collect())
    }

    async fn get_changes_since(
        &self,
        user_id: UserId,
        since: TimestampMs,
        limit: usize,
        cursor: Option<SyncPullCursor>,
    ) -> Result<(SyncChanges, bool, Option<SyncPullCursor>), StorageError> {
        let since = timestamp_from_millis(since, "sync_pull.since")?;
        let query_limit = i64::try_from(limit + 1)
            .map_err(|_| StorageError::Unexpected(format!("sync limit too large: {limit}")))?;
        let previous_cursor = cursor.clone();

        let settings_raw: Vec<SettingDbRow> =
            if let Some(cursor) = cursor.as_ref().and_then(|c| c.settings.as_ref()) {
                let cursor_time =
                    timestamp_from_millis(cursor.updated_at, "cursor.settings.updated_at")?;
                sqlx::query_as!(
                    SettingDbRow,
                    r#"
                SELECT key, value, updated_at
                FROM user_settings
                WHERE user_id = $1 AND (updated_at, key) > ($2, $3)
                ORDER BY updated_at, key
                LIMIT $4
                "#,
                    user_id.0,
                    cursor_time,
                    cursor.key,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            } else {
                sqlx::query_as!(
                    SettingDbRow,
                    r#"
                SELECT key, value, updated_at
                FROM user_settings
                WHERE user_id = $1 AND updated_at > $2
                ORDER BY updated_at, key
                LIMIT $3
                "#,
                    user_id.0,
                    since,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            };

        let mut remaining = limit;
        let settings_available = settings_raw.len();
        let settings_take = settings_available.min(remaining);
        remaining = remaining.saturating_sub(settings_take);

        let settings_cursor = if settings_take > 0 {
            settings_raw
                .get(settings_take - 1)
                .map(|row| SyncCursorSetting {
                    updated_at: TimestampMs(row.updated_at.timestamp_millis()),
                    key: row.key.clone(),
                })
        } else {
            None
        };
        let settings = settings_raw
            .into_iter()
            .take(settings_take)
            .map(|row| SettingChange {
                key: row.key,
                value: row.value,
                client_updated_at: TimestampMs(row.updated_at.timestamp_millis()),
            })
            .collect();

        let memory_states_raw: Vec<MemoryStateDbRow> = if let Some(cursor) =
            cursor.as_ref().and_then(|c| c.memory_states.as_ref())
        {
            let cursor_time =
                timestamp_from_millis(cursor.updated_at, "cursor.memory_states.updated_at")?;
            sqlx::query_as!(
                MemoryStateDbRow,
                r#"
                SELECT node_id, energy, fsrs_stability, fsrs_difficulty, last_reviewed_at, next_review_at, updated_at
                FROM memory_states
                WHERE user_id = $1 AND (updated_at, node_id) > ($2, $3)
                ORDER BY updated_at, node_id
                LIMIT $4
                "#,
                user_id.0,
                cursor_time,
                cursor.node_id,
                query_limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::Query)?
        } else {
            sqlx::query_as!(
                MemoryStateDbRow,
                r#"
                SELECT node_id, energy, fsrs_stability, fsrs_difficulty, last_reviewed_at, next_review_at, updated_at
                FROM memory_states
                WHERE user_id = $1 AND updated_at > $2
                ORDER BY updated_at, node_id
                LIMIT $3
                "#,
                user_id.0,
                since,
                query_limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::Query)?
        };

        let memory_states_available = memory_states_raw.len();
        let memory_states_take = memory_states_available.min(remaining);
        remaining = remaining.saturating_sub(memory_states_take);

        let memory_states_cursor = if memory_states_take > 0 {
            memory_states_raw
                .get(memory_states_take - 1)
                .map(|row| SyncCursorMemoryState {
                    updated_at: TimestampMs(row.updated_at.timestamp_millis()),
                    node_id: row.node_id,
                })
        } else {
            None
        };
        let memory_states = memory_states_raw
            .into_iter()
            .take(memory_states_take)
            .map(|row| MemoryStateChange {
                node_id: row.node_id,
                energy: row.energy,
                fsrs_stability: row.fsrs_stability,
                fsrs_difficulty: row.fsrs_difficulty,
                last_reviewed_at: row
                    .last_reviewed_at
                    .map(|value| TimestampMs(value.timestamp_millis())),
                next_review_at: row
                    .next_review_at
                    .map(|value| TimestampMs(value.timestamp_millis())),
                client_updated_at: TimestampMs(row.updated_at.timestamp_millis()),
            })
            .collect();

        let sessions_raw: Vec<SessionDbRow> =
            if let Some(cursor) = cursor.as_ref().and_then(|c| c.sessions.as_ref()) {
                let cursor_time =
                    timestamp_from_millis(cursor.updated_at, "cursor.sessions.updated_at")?;
                sqlx::query_as!(
                    SessionDbRow,
                    r#"
                SELECT id, goal_id, started_at, completed_at, items_completed, updated_at
                FROM sessions
                WHERE user_id = $1 AND (updated_at, id) > ($2, $3)
                ORDER BY updated_at, id
                LIMIT $4
                "#,
                    user_id.0,
                    cursor_time,
                    cursor.id,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            } else {
                sqlx::query_as!(
                    SessionDbRow,
                    r#"
                SELECT id, goal_id, started_at, completed_at, items_completed, updated_at
                FROM sessions
                WHERE user_id = $1 AND updated_at > $2
                ORDER BY updated_at, id
                LIMIT $3
                "#,
                    user_id.0,
                    since,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            };

        let sessions_available = sessions_raw.len();
        let sessions_take = sessions_available.min(remaining);
        remaining = remaining.saturating_sub(sessions_take);

        let sessions_cursor = if sessions_take > 0 {
            sessions_raw
                .get(sessions_take - 1)
                .map(|row| SyncCursorSession {
                    updated_at: TimestampMs(row.updated_at.timestamp_millis()),
                    id: row.id,
                })
        } else {
            None
        };
        let sessions = sessions_raw
            .into_iter()
            .take(sessions_take)
            .map(|row| SessionChange {
                id: row.id,
                goal_id: row.goal_id.map(GoalId),
                started_at: TimestampMs(row.started_at.timestamp_millis()),
                completed_at: row
                    .completed_at
                    .map(|value| TimestampMs(value.timestamp_millis())),
                items_completed: row.items_completed,
                client_updated_at: TimestampMs(row.updated_at.timestamp_millis()),
            })
            .collect();

        let session_items_raw: Vec<SessionItemDbRow> =
            if let Some(cursor) = cursor.as_ref().and_then(|c| c.session_items.as_ref()) {
                let cursor_time =
                    timestamp_from_millis(cursor.updated_at, "cursor.session_items.updated_at")?;
                sqlx::query_as!(
                    SessionItemDbRow,
                    r#"
                SELECT id, session_id, node_id, exercise_type, grade, duration_ms, updated_at
                FROM session_items
                WHERE user_id = $1 AND (updated_at, id) > ($2, $3)
                ORDER BY updated_at, id
                LIMIT $4
                "#,
                    user_id.0,
                    cursor_time,
                    cursor.id,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            } else {
                sqlx::query_as!(
                    SessionItemDbRow,
                    r#"
                SELECT id, session_id, node_id, exercise_type, grade, duration_ms, updated_at
                FROM session_items
                WHERE user_id = $1 AND updated_at > $2
                ORDER BY updated_at, id
                LIMIT $3
                "#,
                    user_id.0,
                    since,
                    query_limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::Query)?
            };

        let session_items_available = session_items_raw.len();
        let session_items_take = session_items_available.min(remaining);

        let session_items_cursor = if session_items_take > 0 {
            session_items_raw
                .get(session_items_take - 1)
                .map(|row| SyncCursorSessionItem {
                    updated_at: TimestampMs(row.updated_at.timestamp_millis()),
                    id: row.id,
                })
        } else {
            None
        };
        let session_items = session_items_raw
            .into_iter()
            .take(session_items_take)
            .map(|row| SessionItemChange {
                id: row.id,
                session_id: row.session_id,
                node_id: row.node_id,
                exercise_type: row.exercise_type,
                grade: row.grade,
                duration_ms: row.duration_ms,
                client_updated_at: TimestampMs(row.updated_at.timestamp_millis()),
            })
            .collect();

        let has_more = settings_available > settings_take
            || memory_states_available > memory_states_take
            || sessions_available > sessions_take
            || session_items_available > session_items_take;

        let next_cursor = if has_more {
            Some(SyncPullCursor {
                settings: settings_cursor.or_else(|| {
                    previous_cursor
                        .as_ref()
                        .and_then(|value| value.settings.clone())
                }),
                memory_states: memory_states_cursor.or_else(|| {
                    previous_cursor
                        .as_ref()
                        .and_then(|value| value.memory_states.clone())
                }),
                sessions: sessions_cursor.or_else(|| {
                    previous_cursor
                        .as_ref()
                        .and_then(|value| value.sessions.clone())
                }),
                session_items: session_items_cursor.or_else(|| {
                    previous_cursor
                        .as_ref()
                        .and_then(|value| value.session_items.clone())
                }),
            })
        } else {
            None
        };

        Ok((
            SyncChanges {
                settings,
                memory_states,
                sessions,
                session_items,
            },
            has_more,
            next_cursor,
        ))
    }
}

#[derive(Debug)]
struct SettingDbRow {
    key: String,
    value: serde_json::Value,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct MemoryStateDbRow {
    node_id: i64,
    energy: f32,
    fsrs_stability: Option<f32>,
    fsrs_difficulty: Option<f32>,
    last_reviewed_at: Option<DateTime<Utc>>,
    next_review_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct SessionDbRow {
    id: uuid::Uuid,
    goal_id: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    items_completed: i32,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct SessionItemDbRow {
    id: uuid::Uuid,
    session_id: uuid::Uuid,
    node_id: i64,
    exercise_type: String,
    grade: Option<i32>,
    duration_ms: Option<i32>,
    updated_at: DateTime<Utc>,
}

fn timestamp_from_millis(
    value: TimestampMs,
    field_name: &str,
) -> Result<DateTime<Utc>, StorageError> {
    Utc.timestamp_millis_opt(value.0).single().ok_or_else(|| {
        StorageError::Unexpected(format!(
            "invalid unix timestamp milliseconds for {field_name}: {}",
            value.0
        ))
    })
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    use uuid::Uuid;

    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/iqrah")
            .expect("lazy pool should be created")
    }

    #[tokio::test]
    async fn connectionless_repository_methods_surface_query_errors() {
        let repo = PgSyncRepository::new(unreachable_pool());
        let user_id = UserId(Uuid::new_v4());
        let device_id = DeviceId(Uuid::new_v4());

        assert!(matches!(
            repo.touch_device(user_id, device_id, None, None, None)
                .await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.list_recent_conflicts(user_id, 10).await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_changes_since(user_id, TimestampMs(0), 10, None)
                .await,
            Err(StorageError::Query(_))
        ));
    }

    #[tokio::test]
    async fn apply_changes_errors_for_each_change_group_without_database() {
        let repo = PgSyncRepository::new(unreachable_pool());
        let user_id = UserId(Uuid::new_v4());
        let device_id = DeviceId(Uuid::new_v4());

        let settings = SyncChanges {
            settings: vec![SettingChange {
                key: "k".to_string(),
                value: serde_json::json!("v"),
                client_updated_at: TimestampMs(1),
            }],
            ..SyncChanges::default()
        };

        assert!(matches!(
            repo.apply_changes(user_id, device_id, &settings).await,
            Err(StorageError::Query(_))
        ));
    }
}
