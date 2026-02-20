//! Domain types for Iqrah backend.

pub mod auth;
pub mod errors;
pub mod newtypes;
pub mod release;
pub mod sync;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use auth::*;
pub use errors::*;
pub use newtypes::*;
pub use release::*;
pub use sync::*;

/// User entity.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct User {
    pub id: UserId,
    pub oauth_sub: String,
    #[schema(example = "2026-02-20T16:00:00Z")]
    pub created_at: DateTime<Utc>,
}

/// Pack type (translation, recitation, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(example = "translation")]
pub enum PackType {
    Translation,
    Recitation,
    Tafsir,
}

/// Pack status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(example = "published")]
pub enum PackStatus {
    Draft,
    Published,
    Deprecated,
}

/// Content pack entity.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Pack {
    pub package_id: PackId,
    #[schema(example = "translation")]
    pub pack_type: PackType,
    pub version: String,
    pub language: String,
    pub status: PackStatus,
    pub file_path: Option<String>,
    pub sha256: Option<String>,
    #[schema(example = "2026-02-20T16:00:00Z")]
    pub created_at: DateTime<Utc>,
}

/// Global manifest entry for a published active pack.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PackManifestEntry {
    pub id: PackId,
    pub name: String,
    pub description: Option<String>,
    pub pack_type: String,
    pub version: String,
    pub sha256: String,
    pub file_size_bytes: i64,
    #[schema(example = "2026-02-20T16:00:00Z")]
    pub created_at: DateTime<Utc>,
    pub download_url: String,
}

/// Global pack manifest response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PackManifestResponse {
    pub packs: Vec<PackManifestEntry>,
}
/// Health check response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub build_sha: String,
    pub uptime_seconds: u64,
}

/// Ready check response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    pub status: String,
    pub database: String,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn pack_type_and_status_serialize_as_snake_case() {
        let pack_type =
            serde_json::to_string(&PackType::Translation).expect("pack type should serialize");
        let status =
            serde_json::to_string(&PackStatus::Published).expect("pack status should serialize");

        assert_eq!(pack_type, "\"translation\"");
        assert_eq!(status, "\"published\"");
    }

    #[test]
    fn user_roundtrips_through_serde() {
        let user = User {
            id: UserId(Uuid::new_v4()),
            oauth_sub: "oauth-sub-1".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&user).expect("user should serialize");
        let restored: User = serde_json::from_str(&json).expect("user should deserialize");

        assert_eq!(restored.id, user.id);
        assert_eq!(restored.oauth_sub, user.oauth_sub);
    }

    #[test]
    fn pack_roundtrips_through_serde() {
        let pack = Pack {
            package_id: PackId("translation.en".to_string()),
            pack_type: PackType::Translation,
            version: "1.2.3".to_string(),
            language: "en".to_string(),
            status: PackStatus::Published,
            file_path: Some("translation.en/1.2.3/pack.bin".to_string()),
            sha256: Some("abc".repeat(21) + "a"),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&pack).expect("pack should serialize");
        let restored: Pack = serde_json::from_str(&json).expect("pack should deserialize");

        assert_eq!(restored.package_id, pack.package_id);
        assert_eq!(restored.version, pack.version);
        assert_eq!(restored.language, pack.language);
    }

    #[test]
    fn manifest_response_roundtrips_through_serde() {
        let manifest = PackManifestResponse {
            packs: vec![PackManifestEntry {
                id: PackId("pack-1".to_string()),
                name: "English Pack".to_string(),
                description: Some("Description".to_string()),
                pack_type: "translation".to_string(),
                version: "1.0.0".to_string(),
                sha256: "abc".repeat(21) + "a",
                file_size_bytes: 1024,
                created_at: Utc::now(),
                download_url: "http://localhost:8080/v1/packs/pack-1/download".to_string(),
            }],
        };

        let json = serde_json::to_string(&manifest).expect("manifest should serialize");
        let restored: PackManifestResponse =
            serde_json::from_str(&json).expect("manifest should deserialize");

        assert_eq!(restored.packs.len(), 1);
        assert_eq!(restored.packs[0].id, PackId("pack-1".to_string()));
    }

    #[test]
    fn health_and_ready_responses_serialize_expected_shape() {
        let health = HealthResponse {
            status: "ok".to_string(),
            version: "1.0.0".to_string(),
            build_sha: "abc123".to_string(),
            uptime_seconds: 5,
        };
        let ready = ReadyResponse {
            status: "degraded".to_string(),
            database: "disconnected".to_string(),
        };

        let health_json = serde_json::to_value(&health).expect("health should serialize");
        let ready_json = serde_json::to_value(&ready).expect("ready should serialize");

        assert_eq!(health_json["status"], "ok");
        assert_eq!(health_json["build_sha"], "abc123");
        assert_eq!(ready_json["status"], "degraded");
        assert_eq!(ready_json["database"], "disconnected");
    }
}
