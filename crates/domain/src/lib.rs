//! Domain types for Iqrah backend.

pub mod auth;
pub mod errors;
pub mod newtypes;
pub mod sync;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use auth::*;
pub use errors::*;
pub use newtypes::*;
pub use sync::*;

/// User entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub oauth_sub: String,
    pub created_at: DateTime<Utc>,
}

/// Pack type (translation, recitation, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackType {
    Translation,
    Recitation,
    Tafsir,
}

/// Pack status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    Draft,
    Published,
    Deprecated,
}

/// Content pack entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pack {
    pub package_id: PackId,
    pub pack_type: PackType,
    pub version: String,
    pub language: String,
    pub status: PackStatus,
    pub file_path: Option<String>,
    pub sha256: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Global manifest entry for a published active pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifestEntry {
    pub id: PackId,
    pub name: String,
    pub description: Option<String>,
    pub pack_type: String,
    pub version: String,
    pub sha256: String,
    pub file_size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub download_url: String,
}

/// Global pack manifest response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifestResponse {
    pub packs: Vec<PackManifestEntry>,
}
/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub build_sha: String,
    pub uptime_seconds: u64,
}

/// Ready check response.
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: String,
    pub database: String,
}
