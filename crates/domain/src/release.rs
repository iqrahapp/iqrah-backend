//! Release domain types.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{PackId, ReleaseId};

/// Dataset release lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(example = "draft")]
pub enum DatasetReleaseStatus {
    Draft,
    Published,
    Deprecated,
}

impl DatasetReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Deprecated => "deprecated",
        }
    }
}

impl Display for DatasetReleaseStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Artifact semantic role within a dataset release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(example = "core_content_db")]
pub enum ArtifactRole {
    CoreContentDb,
    KnowledgeGraph,
    Morphology,
    TranslationCatalog,
    AudioCatalog,
    OptionalPack,
}

impl ArtifactRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoreContentDb => "core_content_db",
            Self::KnowledgeGraph => "knowledge_graph",
            Self::Morphology => "morphology",
            Self::TranslationCatalog => "translation_catalog",
            Self::AudioCatalog => "audio_catalog",
            Self::OptionalPack => "optional_pack",
        }
    }

    pub fn required_baseline_roles() -> [Self; 2] {
        [Self::CoreContentDb, Self::KnowledgeGraph]
    }
}

impl Display for ArtifactRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Unsupported artifact role: {0}")]
pub struct ArtifactRoleParseError(pub String);

impl FromStr for ArtifactRole {
    type Err = ArtifactRoleParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "core_content_db" => Ok(Self::CoreContentDb),
            "knowledge_graph" => Ok(Self::KnowledgeGraph),
            "morphology" => Ok(Self::Morphology),
            "translation_catalog" => Ok(Self::TranslationCatalog),
            "audio_catalog" => Ok(Self::AudioCatalog),
            "optional_pack" => Ok(Self::OptionalPack),
            _ => Err(ArtifactRoleParseError(value.to_string())),
        }
    }
}

/// Dataset release entity.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DatasetRelease {
    pub id: ReleaseId,
    #[schema(example = "2026.02.20.1")]
    pub version: String,
    pub status: DatasetReleaseStatus,
    pub notes: Option<String>,
    pub created_by: String,
    #[schema(example = "2026-02-20T16:00:00Z")]
    pub created_at: DateTime<Utc>,
    #[schema(example = "2026-02-20T17:00:00Z")]
    pub published_at: Option<DateTime<Utc>>,
}

/// Artifact attached to a release.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DatasetReleaseArtifact {
    pub release_id: ReleaseId,
    pub package_id: PackId,
    pub required: bool,
    pub artifact_role: ArtifactRole,
    #[schema(example = "2026-02-20T16:05:00Z")]
    pub created_at: DateTime<Utc>,
}

/// Artifact manifest entry used by clients.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReleaseArtifactManifestEntry {
    pub package_id: PackId,
    pub required: bool,
    pub artifact_role: ArtifactRole,
    #[schema(example = "1.0.0")]
    pub version: String,
    #[schema(example = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    pub sha256: String,
    #[schema(example = 1024_i64)]
    pub file_size_bytes: i64,
    #[schema(example = "http://localhost:8080/v1/packs/translation.en/download")]
    pub download_url: String,
}

/// Full manifest for one release.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReleaseManifestResponse {
    pub release: DatasetRelease,
    pub artifacts: Vec<ReleaseArtifactManifestEntry>,
}

/// Latest published release with required artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LatestReleaseResponse {
    pub release: DatasetRelease,
    pub required_artifacts: Vec<ReleaseArtifactManifestEntry>,
}

/// One validation issue from release checks.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReleaseValidationIssue {
    #[schema(example = "missing_required_roles")]
    pub code: String,
    #[schema(example = "Required artifact roles are missing: knowledge_graph")]
    pub message: String,
}

/// Result of release validation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReleaseValidationReport {
    pub valid: bool,
    pub failures: Vec<ReleaseValidationIssue>,
    pub warnings: Vec<ReleaseValidationIssue>,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn release_status_and_role_serialize_as_snake_case() {
        let status = serde_json::to_string(&DatasetReleaseStatus::Published)
            .expect("status should serialize");
        let role =
            serde_json::to_string(&ArtifactRole::KnowledgeGraph).expect("role should serialize");

        assert_eq!(status, "\"published\"");
        assert_eq!(role, "\"knowledge_graph\"");
    }

    #[test]
    fn artifact_role_parses_known_values_and_rejects_unknown() {
        assert_eq!(
            ArtifactRole::from_str("core_content_db").expect("role should parse"),
            ArtifactRole::CoreContentDb
        );

        let err = ArtifactRole::from_str("unknown-role").expect_err("unknown role should fail");
        assert_eq!(err.to_string(), "Unsupported artifact role: unknown-role");
    }

    #[test]
    fn release_manifest_roundtrips_through_serde() {
        let release = DatasetRelease {
            id: ReleaseId(Uuid::new_v4()),
            version: "2026.02.20.1".to_string(),
            status: DatasetReleaseStatus::Published,
            notes: Some("stable set".to_string()),
            created_by: "admin@example.com".to_string(),
            created_at: Utc::now(),
            published_at: Some(Utc::now()),
        };

        let payload = ReleaseManifestResponse {
            release: release.clone(),
            artifacts: vec![ReleaseArtifactManifestEntry {
                package_id: PackId("translation.en".to_string()),
                required: true,
                artifact_role: ArtifactRole::CoreContentDb,
                version: "1.0.0".to_string(),
                sha256: "abc".repeat(21) + "a",
                file_size_bytes: 1024,
                download_url: "http://localhost:8080/v1/packs/translation.en/download".to_string(),
            }],
        };

        let json = serde_json::to_string(&payload).expect("payload should serialize");
        let restored: ReleaseManifestResponse =
            serde_json::from_str(&json).expect("payload should deserialize");

        assert_eq!(restored.release.id, release.id);
        assert_eq!(restored.artifacts.len(), 1);
        assert_eq!(
            restored.artifacts[0].artifact_role,
            ArtifactRole::CoreContentDb
        );
    }

    #[test]
    fn validation_report_roundtrips_through_serde() {
        let report = ReleaseValidationReport {
            valid: false,
            failures: vec![ReleaseValidationIssue {
                code: "missing_required_roles".to_string(),
                message: "Required artifact roles are missing: knowledge_graph".to_string(),
            }],
            warnings: Vec::new(),
        };

        let json = serde_json::to_string(&report).expect("report should serialize");
        let restored: ReleaseValidationReport =
            serde_json::from_str(&json).expect("report should deserialize");

        assert!(!restored.valid);
        assert_eq!(restored.failures[0].code, "missing_required_roles");
    }
}
