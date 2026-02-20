//! Pack repository for storage layer.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::StorageError;

/// Combined pack info for API responses.
#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version_id: i32,
    pub package_id: String,
    pub pack_type: String,
    pub version: String,
    pub language: String,
    pub name: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub sha256: String,
    pub file_path: String,
}

/// Active pack version info for manifest responses.
#[derive(Debug, Clone)]
pub struct PackVersionInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub pack_type: String,
    pub version: String,
    pub sha256: String,
    pub file_size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

/// Pack repository boundary.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PackRepository: Send + Sync {
    /// Lists currently available packs with optional filters.
    async fn list_available(
        &self,
        pack_type: Option<String>,
        language: Option<String>,
    ) -> Result<Vec<PackInfo>, StorageError>;

    /// Lists all published pack versions (active and historical) with optional filters.
    async fn list_available_all_versions(
        &self,
        pack_type: Option<String>,
        language: Option<String>,
    ) -> Result<Vec<PackInfo>, StorageError>;

    /// Returns active version details for a published package id.
    async fn get_pack(&self, package_id: String) -> Result<Option<PackInfo>, StorageError>;

    /// Lists active versions for all published packs.
    async fn list_active_pack_versions(&self) -> Result<Vec<PackVersionInfo>, StorageError>;

    /// Lists latest versions for all packs regardless of publish state.
    async fn list_all_packs(&self) -> Result<Vec<PackVersionInfo>, StorageError>;

    /// Returns active version id for a package.
    async fn get_active_version_id(&self, package_id: String) -> Result<Option<i32>, StorageError>;

    /// Creates or updates a pack registration.
    async fn register_pack(
        &self,
        package_id: String,
        pack_type: String,
        language: String,
        name: String,
        description: Option<String>,
    ) -> Result<(), StorageError>;

    /// Adds a new pack version and makes it active.
    async fn add_version(
        &self,
        package_id: String,
        version: String,
        file_path: String,
        size_bytes: i64,
        sha256: String,
        min_app_version: Option<String>,
    ) -> Result<(), StorageError>;

    /// Publishes a pack.
    async fn publish_pack(&self, package_id: String) -> Result<(), StorageError>;

    /// Disables a pack so it is no longer listed or downloadable.
    ///
    /// Returns `true` when a pack row was updated, `false` when no pack matched the id.
    async fn disable_pack(&self, package_id: String) -> Result<bool, StorageError>;
}

/// PostgreSQL implementation for [`PackRepository`].
#[derive(Clone)]
pub struct PgPackRepository {
    pool: PgPool,
}

impl PgPackRepository {
    /// Creates a repository from a PostgreSQL pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Backward-compatible helper for call sites using borrowed filters.
    pub async fn list_available(
        &self,
        pack_type: Option<&str>,
        language: Option<&str>,
    ) -> Result<Vec<PackInfo>, StorageError> {
        <Self as PackRepository>::list_available(
            self,
            pack_type.map(ToString::to_string),
            language.map(ToString::to_string),
        )
        .await
    }

    /// Backward-compatible helper for call sites requesting all published versions.
    pub async fn list_available_all_versions(
        &self,
        pack_type: Option<&str>,
        language: Option<&str>,
    ) -> Result<Vec<PackInfo>, StorageError> {
        <Self as PackRepository>::list_available_all_versions(
            self,
            pack_type.map(ToString::to_string),
            language.map(ToString::to_string),
        )
        .await
    }

    /// Backward-compatible helper for call sites using borrowed ids.
    pub async fn get_pack(&self, package_id: &str) -> Result<Option<PackInfo>, StorageError> {
        <Self as PackRepository>::get_pack(self, package_id.to_string()).await
    }

    /// Backward-compatible helper for call sites using borrowed ids.
    pub async fn get_active_version_id(
        &self,
        package_id: &str,
    ) -> Result<Option<i32>, StorageError> {
        <Self as PackRepository>::get_active_version_id(self, package_id.to_string()).await
    }

    /// Backward-compatible helper for call sites using borrowed values.
    pub async fn register_pack(
        &self,
        package_id: &str,
        pack_type: &str,
        language: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), StorageError> {
        <Self as PackRepository>::register_pack(
            self,
            package_id.to_string(),
            pack_type.to_string(),
            language.to_string(),
            name.to_string(),
            description.map(ToString::to_string),
        )
        .await
    }

    /// Backward-compatible helper for call sites using borrowed values.
    pub async fn add_version(
        &self,
        package_id: &str,
        version: &str,
        file_path: &str,
        size_bytes: i64,
        sha256: &str,
        min_app_version: Option<&str>,
    ) -> Result<(), StorageError> {
        <Self as PackRepository>::add_version(
            self,
            package_id.to_string(),
            version.to_string(),
            file_path.to_string(),
            size_bytes,
            sha256.to_string(),
            min_app_version.map(ToString::to_string),
        )
        .await
    }

    /// Backward-compatible helper for call sites using borrowed ids.
    pub async fn publish_pack(&self, package_id: &str) -> Result<(), StorageError> {
        <Self as PackRepository>::publish_pack(self, package_id.to_string()).await
    }

    /// Backward-compatible helper for call sites using borrowed ids.
    pub async fn disable_pack(&self, package_id: &str) -> Result<bool, StorageError> {
        <Self as PackRepository>::disable_pack(self, package_id.to_string()).await
    }
}

#[async_trait]
impl PackRepository for PgPackRepository {
    async fn list_available(
        &self,
        pack_type: Option<String>,
        language: Option<String>,
    ) -> Result<Vec<PackInfo>, StorageError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                pv.id AS "version_id!",
                p.package_id,
                p.pack_type,
                pv.version,
                p.language,
                COALESCE(p.name, p.package_id) AS "name!",
                p.description,
                pv.size_bytes,
                pv.sha256,
                pv.file_path
            FROM packs p
            JOIN pack_versions pv ON p.package_id = pv.package_id AND pv.is_active = true
            WHERE p.status = 'published'
              AND ($1::text IS NULL OR p.pack_type = $1)
              AND ($2::text IS NULL OR p.language = $2)
            ORDER BY p.package_id
            "#,
            pack_type.as_deref(),
            language.as_deref()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(rows
            .into_iter()
            .map(|row| PackInfo {
                version_id: row.version_id,
                package_id: row.package_id,
                pack_type: row.pack_type,
                version: row.version,
                language: row.language,
                name: row.name,
                description: row.description,
                size_bytes: row.size_bytes,
                sha256: row.sha256,
                file_path: row.file_path,
            })
            .collect())
    }

    async fn list_available_all_versions(
        &self,
        pack_type: Option<String>,
        language: Option<String>,
    ) -> Result<Vec<PackInfo>, StorageError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                pv.id AS "version_id!",
                p.package_id,
                p.pack_type,
                pv.version,
                p.language,
                COALESCE(p.name, p.package_id) AS "name!",
                p.description,
                pv.size_bytes,
                pv.sha256,
                pv.file_path
            FROM packs p
            JOIN pack_versions pv ON p.package_id = pv.package_id
            WHERE p.status = 'published'
              AND ($1::text IS NULL OR p.pack_type = $1)
              AND ($2::text IS NULL OR p.language = $2)
            ORDER BY p.package_id, pv.published_at DESC, pv.id DESC
            "#,
            pack_type.as_deref(),
            language.as_deref()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(rows
            .into_iter()
            .map(|row| PackInfo {
                version_id: row.version_id,
                package_id: row.package_id,
                pack_type: row.pack_type,
                version: row.version,
                language: row.language,
                name: row.name,
                description: row.description,
                size_bytes: row.size_bytes,
                sha256: row.sha256,
                file_path: row.file_path,
            })
            .collect())
    }

    async fn get_pack(&self, package_id: String) -> Result<Option<PackInfo>, StorageError> {
        let row = sqlx::query!(
            r#"
            SELECT
                pv.id AS "version_id!",
                p.package_id,
                p.pack_type,
                pv.version,
                p.language,
                COALESCE(p.name, p.package_id) AS "name!",
                p.description,
                pv.size_bytes,
                pv.sha256,
                pv.file_path
            FROM packs p
            JOIN pack_versions pv ON p.package_id = pv.package_id AND pv.is_active = true
            WHERE p.package_id = $1
              AND p.status = 'published'
            "#,
            package_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(row.map(|value| PackInfo {
            version_id: value.version_id,
            package_id: value.package_id,
            pack_type: value.pack_type,
            version: value.version,
            language: value.language,
            name: value.name,
            description: value.description,
            size_bytes: value.size_bytes,
            sha256: value.sha256,
            file_path: value.file_path,
        }))
    }

    async fn list_active_pack_versions(&self) -> Result<Vec<PackVersionInfo>, StorageError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                p.package_id AS id,
                COALESCE(p.name, p.package_id) AS "name!",
                p.description,
                p.pack_type,
                pv.version,
                pv.sha256,
                pv.size_bytes AS file_size_bytes,
                pv.published_at AS created_at
            FROM packs p
            JOIN pack_versions pv ON p.package_id = pv.package_id
            WHERE p.status = 'published' AND pv.is_active = true
            ORDER BY p.package_id
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(rows
            .into_iter()
            .map(|row| PackVersionInfo {
                id: row.id,
                name: row.name,
                description: row.description,
                pack_type: row.pack_type,
                version: row.version,
                sha256: row.sha256,
                file_size_bytes: row.file_size_bytes,
                created_at: row.created_at,
            })
            .collect())
    }

    async fn list_all_packs(&self) -> Result<Vec<PackVersionInfo>, StorageError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                p.package_id AS id,
                COALESCE(p.name, p.package_id) AS "name!",
                p.description,
                p.pack_type,
                pv.version,
                pv.sha256,
                pv.size_bytes AS file_size_bytes,
                pv.published_at AS created_at
            FROM packs p
            JOIN LATERAL (
                SELECT version, sha256, size_bytes, published_at
                FROM pack_versions
                WHERE package_id = p.package_id
                ORDER BY published_at DESC, id DESC
                LIMIT 1
            ) pv ON true
            ORDER BY p.package_id
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(rows
            .into_iter()
            .map(|row| PackVersionInfo {
                id: row.id,
                name: row.name,
                description: row.description,
                pack_type: row.pack_type,
                version: row.version,
                sha256: row.sha256,
                file_size_bytes: row.file_size_bytes,
                created_at: row.created_at,
            })
            .collect())
    }

    async fn get_active_version_id(&self, package_id: String) -> Result<Option<i32>, StorageError> {
        sqlx::query_scalar!(
            "SELECT id FROM pack_versions WHERE package_id = $1 AND is_active = true LIMIT 1",
            package_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Query)
    }

    async fn register_pack(
        &self,
        package_id: String,
        pack_type: String,
        language: String,
        name: String,
        description: Option<String>,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO packs (
                package_id,
                pack_type,
                language,
                name,
                description,
                status,
                legacy_version,
                legacy_file_path,
                legacy_sha256
            )
            VALUES ($1, $2, $3, $4, $5, 'draft', 'legacy-placeholder', NULL, NULL)
            ON CONFLICT (package_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description
            "#,
            package_id,
            pack_type,
            language,
            name,
            description.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }

    async fn add_version(
        &self,
        package_id: String,
        version: String,
        file_path: String,
        size_bytes: i64,
        sha256: String,
        min_app_version: Option<String>,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE pack_versions SET is_active = false WHERE package_id = $1",
            package_id
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        sqlx::query!(
            r#"
            INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, min_app_version, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            "#,
            package_id,
            version,
            file_path,
            size_bytes,
            sha256,
            min_app_version.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }

    async fn publish_pack(&self, package_id: String) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE packs SET status = 'published' WHERE package_id = $1",
            package_id
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(())
    }

    async fn disable_pack(&self, package_id: String) -> Result<bool, StorageError> {
        let result = sqlx::query!(
            "UPDATE packs SET status = 'deprecated' WHERE package_id = $1",
            package_id
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/iqrah")
            .expect("lazy pool should be created")
    }

    #[tokio::test]
    async fn repository_methods_return_query_errors_without_database() {
        let repo = PgPackRepository::new(unreachable_pool());

        assert!(matches!(
            repo.list_available(None, None).await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_pack("pack").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.list_active_pack_versions().await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.list_all_packs().await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.list_available_all_versions(None, None).await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_active_version_id("pack").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.register_pack("pack", "type", "en", "name", None).await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.add_version("pack", "1.0.0", "file", 10, "sha", None)
                .await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.publish_pack("pack").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.disable_pack("pack").await,
            Err(StorageError::Query(_))
        ));
    }
}
