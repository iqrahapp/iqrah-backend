#![cfg(feature = "postgres-tests")]

use sqlx::PgPool;

use iqrah_backend_domain::{ArtifactRole, DatasetReleaseStatus};
use iqrah_backend_storage::{PgPackRepository, PgReleaseRepository};

async fn seed_published_pack(
    pack_repo: &PgPackRepository,
    package_id: &str,
    version: &str,
) -> Result<(), sqlx::Error> {
    let sha256 = format!("{package_id}{version}").repeat(4) + "hash";

    pack_repo
        .register_pack(package_id, "quran", "en", package_id, Some("test"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    pack_repo
        .add_version(
            package_id,
            version,
            &format!("{package_id}-{version}.pack"),
            1024,
            &sha256,
            None,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    pack_repo
        .publish_pack(package_id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_repository_full_publish_workflow(pool: PgPool) -> Result<(), sqlx::Error> {
    let pack_repo = PgPackRepository::new(pool.clone());
    let release_repo = PgReleaseRepository::new(pool);

    seed_published_pack(&pack_repo, "core-content-pack", "1.0.0").await?;
    seed_published_pack(&pack_repo, "knowledge-graph-pack", "2.1.0").await?;
    seed_published_pack(&pack_repo, "optional-audio-pack", "3.0.0").await?;

    let release = release_repo
        .create_draft_release("2026.02.20.1", Some("phase-1 release"), "admin@iqrah")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert_eq!(release.status, DatasetReleaseStatus::Draft);

    release_repo
        .attach_artifact(
            release.id,
            "core-content-pack",
            ArtifactRole::CoreContentDb,
            true,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    release_repo
        .attach_artifact(
            release.id,
            "knowledge-graph-pack",
            ArtifactRole::KnowledgeGraph,
            true,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    release_repo
        .attach_artifact(
            release.id,
            "optional-audio-pack",
            ArtifactRole::AudioCatalog,
            false,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let validation = release_repo
        .validate_release(release.id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(validation.valid);
    assert!(validation.failures.is_empty());

    let published = release_repo
        .publish_release(release.id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert_eq!(published.status, DatasetReleaseStatus::Published);
    assert!(published.published_at.is_some());

    let latest = release_repo
        .get_latest_release()
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .expect("latest release should exist");
    assert_eq!(latest.id, release.id);
    assert_eq!(latest.version, "2026.02.20.1");

    let manifest = release_repo
        .get_release_manifest(release.id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .expect("published manifest should exist");
    assert_eq!(manifest.release.id, release.id);
    assert_eq!(manifest.artifacts.len(), 3);
    assert!(manifest.artifacts.iter().any(|artifact| {
        artifact.package_id == "core-content-pack"
            && artifact.artifact_role == ArtifactRole::CoreContentDb
            && artifact.required
    }));

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_validation_reports_unpublished_and_missing_metadata(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let pack_repo = PgPackRepository::new(pool.clone());
    let release_repo = PgReleaseRepository::new(pool);

    pack_repo
        .register_pack(
            "unpublished-core",
            "quran",
            "en",
            "unpublished-core",
            Some("test"),
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    pack_repo
        .add_version(
            "unpublished-core",
            "0.1.0",
            "unpublished-core-0.1.0.pack",
            500,
            "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca",
            None,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    pack_repo
        .register_pack(
            "published-no-metadata",
            "quran",
            "en",
            "published-no-metadata",
            None,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    pack_repo
        .publish_pack("published-no-metadata")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let release = release_repo
        .create_draft_release("2026.02.20.2", None, "admin@iqrah")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    release_repo
        .attach_artifact(
            release.id,
            "unpublished-core",
            ArtifactRole::CoreContentDb,
            true,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    release_repo
        .attach_artifact(
            release.id,
            "published-no-metadata",
            ArtifactRole::KnowledgeGraph,
            true,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let report = release_repo
        .validate_release(release.id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(!report.valid);

    let codes = report
        .failures
        .iter()
        .map(|failure| failure.code.as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"package_not_published"));
    assert!(codes.contains(&"package_metadata_missing"));

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn publish_fails_for_invalid_release(pool: PgPool) -> Result<(), sqlx::Error> {
    let release_repo = PgReleaseRepository::new(pool);

    let release = release_repo
        .create_draft_release("2026.02.20.3", None, "admin@iqrah")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let err = release_repo
        .publish_release(release.id)
        .await
        .expect_err("publish should fail when release has no artifacts");

    let message = err.to_string();
    assert!(message.contains("release_validation_failed"));
    assert!(
        release_repo
            .get_release_manifest(release.id)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
            .is_none()
    );

    Ok(())
}
