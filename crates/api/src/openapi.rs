use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Iqrah Backend API",
        version = env!("CARGO_PKG_VERSION"),
        description = "REST API for the Iqrah mobile app"
    ),
    paths(
        crate::metrics,
        crate::handlers::auth::google_auth,
        crate::handlers::auth::get_me,
        crate::handlers::packs::list_packs,
        crate::handlers::packs::get_pack_updates,
        crate::handlers::packs::get_global_manifest,
        crate::handlers::packs::download_pack,
        crate::handlers::packs::get_manifest,
        crate::handlers::packs::get_checksum,
        crate::handlers::sync::sync_push,
        crate::handlers::sync::sync_pull,
        crate::handlers::sync::admin_recent_conflicts,
        crate::handlers::sync::admin_user_sync_status,
        crate::handlers::admin_packs::register_pack,
        crate::handlers::admin_packs::upload_pack,
        crate::handlers::admin_packs::add_version,
        crate::handlers::admin_packs::publish_pack,
        crate::handlers::admin_packs::disable_pack,
        crate::handlers::admin_packs::list_all_packs,
        crate::handlers::admin_releases::create_release,
        crate::handlers::admin_releases::attach_release_artifact,
        crate::handlers::admin_releases::validate_release,
        crate::handlers::admin_releases::publish_release,
        crate::handlers::releases::get_latest_release,
        crate::handlers::releases::get_release_manifest
    ),
    components(
        schemas(
            iqrah_backend_domain::ApiError,
            iqrah_backend_domain::GoogleAuthRequest,
            iqrah_backend_domain::AuthResponse,
            iqrah_backend_domain::UserProfile,
            iqrah_backend_domain::UserId,
            iqrah_backend_domain::DeviceId,
            iqrah_backend_domain::ReleaseId,
            iqrah_backend_domain::PackId,
            iqrah_backend_domain::GoalId,
            iqrah_backend_domain::TimestampMs,
            iqrah_backend_domain::PackType,
            iqrah_backend_domain::PackStatus,
            iqrah_backend_domain::DatasetReleaseStatus,
            iqrah_backend_domain::ArtifactRole,
            iqrah_backend_domain::Pack,
            iqrah_backend_domain::PackManifestEntry,
            iqrah_backend_domain::PackManifestResponse,
            iqrah_backend_domain::DatasetRelease,
            iqrah_backend_domain::DatasetReleaseArtifact,
            iqrah_backend_domain::ReleaseArtifactManifestEntry,
            iqrah_backend_domain::ReleaseManifestResponse,
            iqrah_backend_domain::LatestReleaseResponse,
            iqrah_backend_domain::ReleaseValidationIssue,
            iqrah_backend_domain::ReleaseValidationReport,
            iqrah_backend_domain::SyncPushRequest,
            iqrah_backend_domain::SyncPushResponse,
            iqrah_backend_domain::SyncPullRequest,
            iqrah_backend_domain::SyncPullResponse,
            iqrah_backend_domain::SyncChanges,
            iqrah_backend_domain::SyncPullCursor,
            iqrah_backend_domain::SyncCursorSetting,
            iqrah_backend_domain::SyncCursorMemoryState,
            iqrah_backend_domain::SyncCursorSession,
            iqrah_backend_domain::SyncCursorSessionItem,
            iqrah_backend_domain::SettingChange,
            iqrah_backend_domain::MemoryStateChange,
            iqrah_backend_domain::SessionChange,
            iqrah_backend_domain::SessionItemChange,
            iqrah_backend_domain::AdminConflictRecord,
            iqrah_backend_domain::AdminConflictListResponse,
            iqrah_backend_domain::AdminUserSyncStatusResponse,
            crate::handlers::packs::PackDto,
            crate::handlers::packs::ListPacksResponse,
            crate::handlers::packs::InstalledPackVersion,
            crate::handlers::packs::PackUpdatesRequest,
            crate::handlers::packs::PackUpdateDto,
            crate::handlers::packs::PackUpdatesResponse,
            crate::handlers::packs::PackChecksumResponse,
            crate::handlers::admin_packs::RegisterPackRequest,
            crate::handlers::admin_packs::RegisterPackResponse,
            crate::handlers::admin_packs::UploadPackMultipartBody,
            crate::handlers::admin_packs::AddVersionMultipartBody,
            crate::handlers::admin_packs::AddVersionResponse,
            crate::handlers::admin_packs::PublishPackResponse,
            crate::handlers::admin_packs::DisablePackResponse,
            crate::handlers::admin_releases::CreateReleaseRequest,
            crate::handlers::admin_releases::CreateReleaseResponse,
            crate::handlers::admin_releases::AttachReleaseArtifactRequest,
            crate::handlers::admin_releases::AttachReleaseArtifactResponse,
            crate::handlers::admin_releases::ValidateReleaseResponse,
            crate::handlers::admin_releases::PublishReleaseResponse
        )
    ),
    modifiers(&SecuritySchemes),
    tags(
        (name = "auth", description = "Authentication and device registration"),
        (name = "packs", description = "Content pack management"),
        (name = "releases", description = "Dataset release discovery"),
        (name = "sync", description = "Client data synchronisation"),
        (name = "admin", description = "Admin-only operations")
    )
)]
pub struct ApiDoc;

struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "admin_api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-admin-key"))),
            );
        }
    }
}
