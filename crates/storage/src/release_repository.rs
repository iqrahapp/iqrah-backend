//! Dataset release repository.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use iqrah_backend_domain::{
    ArtifactRole, DatasetRelease, DatasetReleaseArtifact, DatasetReleaseStatus, ReleaseId,
    ReleaseValidationIssue, ReleaseValidationReport,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::StorageError;

#[derive(Debug, Clone)]
pub struct ReleaseManifestArtifactRecord {
    pub package_id: String,
    pub required: bool,
    pub artifact_role: ArtifactRole,
    pub version: String,
    pub sha256: String,
    pub file_size_bytes: i64,
}

#[derive(Debug, Clone)]
pub struct ReleaseManifestRecord {
    pub release: DatasetRelease,
    pub artifacts: Vec<ReleaseManifestArtifactRecord>,
}

#[derive(Debug)]
struct ReleaseRow {
    id: Uuid,
    version: String,
    status: String,
    notes: Option<String>,
    created_by: String,
    created_at: DateTime<Utc>,
    published_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct ReleaseArtifactRow {
    release_id: Uuid,
    package_id: String,
    required: bool,
    artifact_role: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug)]
struct ReleaseValidationRow {
    package_id: String,
    artifact_role: String,
    pack_status: Option<String>,
    sha256: Option<String>,
    size_bytes: Option<i64>,
    file_path: Option<String>,
}

#[derive(Debug)]
struct ManifestArtifactRow {
    package_id: String,
    required: bool,
    artifact_role: String,
    version: Option<String>,
    sha256: Option<String>,
    file_size_bytes: Option<i64>,
}

/// Release repository boundary.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ReleaseRepository: Send + Sync {
    async fn create_draft_release(
        &self,
        version: String,
        notes: Option<String>,
        created_by: String,
    ) -> Result<DatasetRelease, StorageError>;

    async fn attach_artifact(
        &self,
        release_id: ReleaseId,
        package_id: String,
        artifact_role: ArtifactRole,
        required: bool,
    ) -> Result<DatasetReleaseArtifact, StorageError>;

    async fn validate_release(
        &self,
        release_id: ReleaseId,
    ) -> Result<ReleaseValidationReport, StorageError>;

    async fn publish_release(
        &self,
        release_id: ReleaseId,
        actor: String,
    ) -> Result<DatasetRelease, StorageError>;

    async fn deprecate_release(
        &self,
        release_id: ReleaseId,
        actor: String,
    ) -> Result<DatasetRelease, StorageError>;

    async fn get_latest_release(&self) -> Result<Option<DatasetRelease>, StorageError>;

    async fn get_release_manifest(
        &self,
        release_id: ReleaseId,
    ) -> Result<Option<ReleaseManifestRecord>, StorageError>;
}

/// PostgreSQL implementation for [`ReleaseRepository`].
#[derive(Clone)]
pub struct PgReleaseRepository {
    pool: PgPool,
}

impl PgReleaseRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_draft_release(
        &self,
        version: &str,
        notes: Option<&str>,
        created_by: &str,
    ) -> Result<DatasetRelease, StorageError> {
        <Self as ReleaseRepository>::create_draft_release(
            self,
            version.to_string(),
            notes.map(ToString::to_string),
            created_by.to_string(),
        )
        .await
    }

    pub async fn attach_artifact(
        &self,
        release_id: ReleaseId,
        package_id: &str,
        artifact_role: ArtifactRole,
        required: bool,
    ) -> Result<DatasetReleaseArtifact, StorageError> {
        <Self as ReleaseRepository>::attach_artifact(
            self,
            release_id,
            package_id.to_string(),
            artifact_role,
            required,
        )
        .await
    }

    pub async fn validate_release(
        &self,
        release_id: ReleaseId,
    ) -> Result<ReleaseValidationReport, StorageError> {
        <Self as ReleaseRepository>::validate_release(self, release_id).await
    }

    pub async fn publish_release(
        &self,
        release_id: ReleaseId,
        actor: &str,
    ) -> Result<DatasetRelease, StorageError> {
        <Self as ReleaseRepository>::publish_release(self, release_id, actor.to_string()).await
    }

    pub async fn deprecate_release(
        &self,
        release_id: ReleaseId,
        actor: &str,
    ) -> Result<DatasetRelease, StorageError> {
        <Self as ReleaseRepository>::deprecate_release(self, release_id, actor.to_string()).await
    }

    pub async fn get_latest_release(&self) -> Result<Option<DatasetRelease>, StorageError> {
        <Self as ReleaseRepository>::get_latest_release(self).await
    }

    pub async fn get_release_manifest(
        &self,
        release_id: ReleaseId,
    ) -> Result<Option<ReleaseManifestRecord>, StorageError> {
        <Self as ReleaseRepository>::get_release_manifest(self, release_id).await
    }

    fn map_release_row(row: ReleaseRow) -> Result<DatasetRelease, StorageError> {
        Ok(DatasetRelease {
            id: ReleaseId(row.id),
            version: row.version,
            status: parse_release_status(&row.status)?,
            notes: row.notes,
            created_by: row.created_by,
            created_at: row.created_at,
            published_at: row.published_at,
        })
    }
}

#[async_trait]
impl ReleaseRepository for PgReleaseRepository {
    async fn create_draft_release(
        &self,
        version: String,
        notes: Option<String>,
        created_by: String,
    ) -> Result<DatasetRelease, StorageError> {
        let row = sqlx::query_as!(
            ReleaseRow,
            r#"
            INSERT INTO dataset_releases (version, status, notes, created_by)
            VALUES ($1, 'draft', $2, $3)
            RETURNING id, version, status, notes, created_by, created_at, published_at
            "#,
            version,
            notes.as_deref(),
            created_by
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Self::map_release_row(row)
    }

    async fn attach_artifact(
        &self,
        release_id: ReleaseId,
        package_id: String,
        artifact_role: ArtifactRole,
        required: bool,
    ) -> Result<DatasetReleaseArtifact, StorageError> {
        let release_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM dataset_releases WHERE id = $1) AS "exists!""#,
            release_id.0
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        if !release_exists {
            return Err(StorageError::Unexpected(format!(
                "release_not_found:{}",
                release_id
            )));
        }

        let row = sqlx::query_as!(
            ReleaseArtifactRow,
            r#"
            INSERT INTO dataset_release_artifacts (release_id, package_id, required, artifact_role)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (release_id, package_id) DO UPDATE SET
                required = EXCLUDED.required,
                artifact_role = EXCLUDED.artifact_role
            RETURNING release_id, package_id, required, artifact_role, created_at
            "#,
            release_id.0,
            package_id,
            required,
            artifact_role.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(DatasetReleaseArtifact {
            release_id: ReleaseId(row.release_id),
            package_id: row.package_id.into(),
            required: row.required,
            artifact_role: parse_artifact_role(&row.artifact_role)?,
            created_at: row.created_at,
        })
    }

    async fn validate_release(
        &self,
        release_id: ReleaseId,
    ) -> Result<ReleaseValidationReport, StorageError> {
        let release_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM dataset_releases WHERE id = $1) AS "exists!""#,
            release_id.0
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        if !release_exists {
            return Err(StorageError::Unexpected(format!(
                "release_not_found:{}",
                release_id
            )));
        }

        let rows = sqlx::query_as!(
            ReleaseValidationRow,
            r#"
            SELECT
                dra.package_id,
                dra.artifact_role,
                p.status AS "pack_status?",
                pv.sha256 AS "sha256?",
                pv.size_bytes AS "size_bytes?",
                pv.file_path AS "file_path?"
            FROM dataset_release_artifacts dra
            LEFT JOIN packs p
                ON p.package_id = dra.package_id
            LEFT JOIN pack_versions pv
                ON pv.package_id = dra.package_id
               AND pv.is_active = true
            WHERE dra.release_id = $1
            ORDER BY dra.package_id
            "#,
            release_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        Ok(build_validation_report(rows)?)
    }

    async fn publish_release(
        &self,
        release_id: ReleaseId,
        actor: String,
    ) -> Result<DatasetRelease, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Query)?;

        let release_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM dataset_releases WHERE id = $1) AS "exists!""#,
            release_id.0
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::Query)?;

        if !release_exists {
            tx.rollback().await.map_err(StorageError::Query)?;
            return Err(StorageError::Unexpected(format!(
                "release_not_found:{}",
                release_id
            )));
        }

        let validation_rows = sqlx::query_as!(
            ReleaseValidationRow,
            r#"
            SELECT
                dra.package_id,
                dra.artifact_role,
                p.status AS "pack_status?",
                pv.sha256 AS "sha256?",
                pv.size_bytes AS "size_bytes?",
                pv.file_path AS "file_path?"
            FROM dataset_release_artifacts dra
            LEFT JOIN packs p
                ON p.package_id = dra.package_id
            LEFT JOIN pack_versions pv
                ON pv.package_id = dra.package_id
               AND pv.is_active = true
            WHERE dra.release_id = $1
            ORDER BY dra.package_id
            "#,
            release_id.0
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::Query)?;

        let report = build_validation_report(validation_rows)?;
        if !report.valid {
            tx.rollback().await.map_err(StorageError::Query)?;
            let codes = report
                .failures
                .iter()
                .map(|failure| failure.code.as_str())
                .collect::<Vec<_>>()
                .join(",");
            return Err(StorageError::Unexpected(format!(
                "release_validation_failed:{codes}"
            )));
        }

        let row = sqlx::query_as!(
            ReleaseRow,
            r#"
            UPDATE dataset_releases
            SET status = 'published', published_at = now()
            WHERE id = $1
              AND status = 'draft'
            RETURNING id, version, status, notes, created_by, created_at, published_at
            "#,
            release_id.0
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::Query)?;

        let row = if let Some(row) = row {
            row
        } else {
            let status = sqlx::query_scalar!(
                "SELECT status FROM dataset_releases WHERE id = $1",
                release_id.0
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(StorageError::Query)?;

            tx.rollback().await.map_err(StorageError::Query)?;
            let status = status.unwrap_or_else(|| "missing".to_string());
            return Err(StorageError::Unexpected(format!(
                "release_not_publishable:{status}"
            )));
        };

        log_admin_release_action_tx(
            &mut tx,
            release_id,
            "publish",
            &actor,
            serde_json::json!({
                "release_status": row.status,
            }),
        )
        .await?;

        tx.commit().await.map_err(StorageError::Query)?;
        Self::map_release_row(row)
    }

    async fn deprecate_release(
        &self,
        release_id: ReleaseId,
        actor: String,
    ) -> Result<DatasetRelease, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::Query)?;

        let release_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM dataset_releases WHERE id = $1) AS "exists!""#,
            release_id.0
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::Query)?;

        if !release_exists {
            tx.rollback().await.map_err(StorageError::Query)?;
            return Err(StorageError::Unexpected(format!(
                "release_not_found:{}",
                release_id
            )));
        }

        let row = sqlx::query_as!(
            ReleaseRow,
            r#"
            UPDATE dataset_releases
            SET status = 'deprecated'
            WHERE id = $1
              AND status = 'published'
            RETURNING id, version, status, notes, created_by, created_at, published_at
            "#,
            release_id.0
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::Query)?;

        let row = if let Some(row) = row {
            row
        } else {
            let status = sqlx::query_scalar!(
                "SELECT status FROM dataset_releases WHERE id = $1",
                release_id.0
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(StorageError::Query)?;

            tx.rollback().await.map_err(StorageError::Query)?;
            let status = status.unwrap_or_else(|| "missing".to_string());
            return Err(StorageError::Unexpected(format!(
                "release_not_deprecatable:{status}"
            )));
        };

        log_admin_release_action_tx(
            &mut tx,
            release_id,
            "deprecate",
            &actor,
            serde_json::json!({
                "release_status": row.status,
            }),
        )
        .await?;

        tx.commit().await.map_err(StorageError::Query)?;
        Self::map_release_row(row)
    }

    async fn get_latest_release(&self) -> Result<Option<DatasetRelease>, StorageError> {
        let row = sqlx::query_as!(
            ReleaseRow,
            r#"
            SELECT
                id,
                version,
                status,
                notes,
                created_by,
                created_at,
                published_at
            FROM dataset_releases
            WHERE status = 'published'
            ORDER BY published_at DESC NULLS LAST, created_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        row.map(Self::map_release_row).transpose()
    }

    async fn get_release_manifest(
        &self,
        release_id: ReleaseId,
    ) -> Result<Option<ReleaseManifestRecord>, StorageError> {
        let row = sqlx::query_as!(
            ReleaseRow,
            r#"
            SELECT
                id,
                version,
                status,
                notes,
                created_by,
                created_at,
                published_at
            FROM dataset_releases
            WHERE id = $1
              AND status = 'published'
            "#,
            release_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        let Some(release_row) = row else {
            return Ok(None);
        };

        let artifacts = sqlx::query_as!(
            ManifestArtifactRow,
            r#"
            SELECT
                dra.package_id,
                dra.required,
                dra.artifact_role,
                pv.version AS "version?",
                pv.sha256 AS "sha256?",
                pv.size_bytes AS "file_size_bytes?"
            FROM dataset_release_artifacts dra
            LEFT JOIN pack_versions pv
                ON pv.package_id = dra.package_id
               AND pv.is_active = true
            WHERE dra.release_id = $1
            ORDER BY dra.required DESC, dra.artifact_role, dra.package_id
            "#,
            release_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Query)?;

        let mapped = artifacts
            .into_iter()
            .map(|row| {
                let version = row.version.ok_or_else(|| {
                    StorageError::Unexpected(format!(
                        "release_manifest_metadata_missing:{}",
                        row.package_id
                    ))
                })?;
                let sha256 = row.sha256.ok_or_else(|| {
                    StorageError::Unexpected(format!(
                        "release_manifest_metadata_missing:{}",
                        row.package_id
                    ))
                })?;
                let file_size_bytes = row.file_size_bytes.ok_or_else(|| {
                    StorageError::Unexpected(format!(
                        "release_manifest_metadata_missing:{}",
                        row.package_id
                    ))
                })?;

                Ok(ReleaseManifestArtifactRecord {
                    package_id: row.package_id,
                    required: row.required,
                    artifact_role: parse_artifact_role(&row.artifact_role)?,
                    version,
                    sha256,
                    file_size_bytes,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        Ok(Some(ReleaseManifestRecord {
            release: Self::map_release_row(release_row)?,
            artifacts: mapped,
        }))
    }
}

async fn log_admin_release_action_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    release_id: ReleaseId,
    action: &str,
    actor: &str,
    metadata: serde_json::Value,
) -> Result<(), StorageError> {
    sqlx::query!(
        r#"
        INSERT INTO release_admin_audit_logs (release_id, action, actor, metadata)
        VALUES ($1, $2, $3, $4)
        "#,
        release_id.0,
        action,
        actor,
        metadata
    )
    .execute(&mut **tx)
    .await
    .map_err(StorageError::Query)?;

    Ok(())
}

fn parse_release_status(value: &str) -> Result<DatasetReleaseStatus, StorageError> {
    match value {
        "draft" => Ok(DatasetReleaseStatus::Draft),
        "published" => Ok(DatasetReleaseStatus::Published),
        "deprecated" => Ok(DatasetReleaseStatus::Deprecated),
        _ => Err(StorageError::Unexpected(format!(
            "unsupported_release_status:{value}"
        ))),
    }
}

fn parse_artifact_role(value: &str) -> Result<ArtifactRole, StorageError> {
    value.parse().map_err(|error| {
        StorageError::Unexpected(format!("unsupported_artifact_role:{value}:{error}"))
    })
}

fn build_validation_report(
    rows: Vec<ReleaseValidationRow>,
) -> Result<ReleaseValidationReport, StorageError> {
    let mut failures = Vec::new();
    let mut seen = HashSet::new();
    let mut roles = HashSet::new();

    if rows.is_empty() {
        failures.push(ReleaseValidationIssue {
            code: "no_artifacts".to_string(),
            message: "Release must include at least one artifact".to_string(),
        });
    }

    for row in &rows {
        roles.insert(parse_artifact_role(&row.artifact_role)?);
    }

    let missing_roles = ArtifactRole::required_baseline_roles()
        .into_iter()
        .filter(|role| !roles.contains(role))
        .map(|role| role.as_str().to_string())
        .collect::<Vec<_>>();
    if !missing_roles.is_empty() {
        failures.push(ReleaseValidationIssue {
            code: "missing_required_roles".to_string(),
            message: format!(
                "Required artifact roles are missing: {}",
                missing_roles.join(", ")
            ),
        });
    }

    for row in rows {
        let pack_status = row.pack_status.as_deref().unwrap_or("missing");
        if pack_status != "published" {
            let key = format!("package_not_published:{}", row.package_id);
            if seen.insert(key) {
                failures.push(ReleaseValidationIssue {
                    code: "package_not_published".to_string(),
                    message: format!("Attached package '{}' is not published", row.package_id),
                });
            }
        }

        let missing_metadata = row
            .sha256
            .as_deref()
            .is_none_or(|sha| sha.trim().is_empty())
            || row.size_bytes.unwrap_or_default() <= 0
            || row
                .file_path
                .as_deref()
                .is_none_or(|path| path.trim().is_empty());

        if missing_metadata {
            let key = format!("package_metadata_missing:{}", row.package_id);
            if seen.insert(key) {
                failures.push(ReleaseValidationIssue {
                    code: "package_metadata_missing".to_string(),
                    message: format!(
                        "Attached package '{}' is missing checksum or size metadata",
                        row.package_id
                    ),
                });
            }
        }
    }

    Ok(ReleaseValidationReport {
        valid: failures.is_empty(),
        failures,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::postgres::PgPoolOptions;

    use super::*;

    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/iqrah")
            .expect("lazy pool should be created")
    }

    #[tokio::test]
    async fn release_repository_methods_return_query_errors_without_database() {
        let repo = PgReleaseRepository::new(unreachable_pool());
        let release_id = ReleaseId(Uuid::new_v4());

        assert!(matches!(
            repo.create_draft_release("2026.1.0", None, "admin").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.attach_artifact(release_id, "pack", ArtifactRole::CoreContentDb, true)
                .await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.validate_release(release_id).await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.publish_release(release_id, "admin@iqrah").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.deprecate_release(release_id, "admin@iqrah").await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_latest_release().await,
            Err(StorageError::Query(_))
        ));
        assert!(matches!(
            repo.get_release_manifest(release_id).await,
            Err(StorageError::Query(_))
        ));
    }
}
