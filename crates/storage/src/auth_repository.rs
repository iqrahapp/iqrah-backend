//! Authentication repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use iqrah_backend_domain::UserId;
use sqlx::PgPool;
use uuid::Uuid;

use crate::StorageError;

/// User record used by authentication flows.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: UserId,
    pub oauth_sub: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Authentication repository boundary.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AuthRepository: Send + Sync {
    /// Finds a user by OAuth subject or creates a new one atomically.
    async fn find_or_create(&self, oauth_sub: &str) -> Result<UserRecord, StorageError>;

    /// Loads a user by id.
    async fn get_by_id(&self, id: UserId) -> Result<Option<UserRecord>, StorageError>;
}

/// PostgreSQL implementation for [`AuthRepository`].
#[derive(Clone)]
pub struct PgAuthRepository {
    pool: PgPool,
}

impl PgAuthRepository {
    /// Creates a repository from a PostgreSQL pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Backward-compatible helper for call sites using the concrete type.
    pub async fn find_or_create(&self, oauth_sub: &str) -> Result<UserRecord, StorageError> {
        <Self as AuthRepository>::find_or_create(self, oauth_sub).await
    }

    /// Backward-compatible helper for call sites using the concrete type.
    pub async fn get_by_id(&self, id: UserId) -> Result<Option<UserRecord>, StorageError> {
        <Self as AuthRepository>::get_by_id(self, id).await
    }
}

#[async_trait]
impl AuthRepository for PgAuthRepository {
    async fn find_or_create(&self, oauth_sub: &str) -> Result<UserRecord, StorageError> {
        let generated_id = Uuid::new_v4();
        let row = sqlx::query!(
            r#"
            INSERT INTO users (id, oauth_sub, last_seen_at)
            VALUES ($1, $2, now())
            ON CONFLICT (oauth_sub) DO UPDATE SET last_seen_at = now()
            RETURNING id, oauth_sub, created_at, last_seen_at
            "#,
            generated_id,
            oauth_sub
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(UserRecord {
            id: UserId(row.id),
            oauth_sub: row.oauth_sub,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
        })
    }

    async fn get_by_id(&self, id: UserId) -> Result<Option<UserRecord>, StorageError> {
        let row = sqlx::query!(
            "SELECT id, oauth_sub, created_at, last_seen_at FROM users WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(row.map(|value| UserRecord {
            id: UserId(value.id),
            oauth_sub: value.oauth_sub,
            created_at: value.created_at,
            last_seen_at: value.last_seen_at,
        }))
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
    async fn auth_repository_returns_query_errors_without_database() {
        let repo = PgAuthRepository::new(unreachable_pool());

        assert!(matches!(
            repo.find_or_create("sub-1").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_by_id(UserId(Uuid::new_v4())).await,
            Err(StorageError::Query(_))
        ));
    }
}
