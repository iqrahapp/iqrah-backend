#![cfg(feature = "postgres-tests")]

use sqlx::PgPool;

use iqrah_backend_storage::{PackRepository, PgPackRepository};

#[sqlx::test(migrations = "../../migrations")]
async fn list_active_pack_versions_filters_to_active_published(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool.clone());

    repo.register_pack("published-pack", "quran", "en", "Published Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version(
        "published-pack",
        "1.0.0",
        "published-v1.pack",
        100,
        "sha-old",
        None,
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("published-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version(
        "published-pack",
        "1.1.0",
        "published-v2.pack",
        120,
        "sha-new",
        None,
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    repo.register_pack("draft-pack", "quran", "en", "Draft Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version(
        "draft-pack",
        "0.1.0",
        "draft-v1.pack",
        50,
        "sha-draft",
        None,
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let packs = repo
        .list_active_pack_versions()
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert_eq!(packs.len(), 1);
    assert_eq!(packs[0].id, "published-pack");
    assert_eq!(packs[0].version, "1.1.0");

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_active_pack_versions_returns_empty_when_none(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    let packs = repo
        .list_active_pack_versions()
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert!(packs.is_empty());

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_active_pack_versions_returns_sha_and_version(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    repo.register_pack("tafsir-ar", "tafsir", "ar", "Tafsir", Some("desc"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version(
        "tafsir-ar",
        "2.3.4",
        "tafsir-ar-v234.pack",
        400,
        "sha256-value",
        None,
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("tafsir-ar")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let packs = repo
        .list_active_pack_versions()
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert_eq!(packs.len(), 1);
    assert_eq!(packs[0].sha256, "sha256-value");
    assert_eq!(packs[0].version, "2.3.4");

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_all_packs_returns_latest_version_for_draft_and_published(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    repo.register_pack("draft-pack", "quran", "en", "Draft Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("draft-pack", "0.1.0", "draft-v1.pack", 11, "sha-d1", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("draft-pack", "0.2.0", "draft-v2.pack", 22, "sha-d2", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    repo.register_pack("published-pack", "quran", "ar", "Published Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version(
        "published-pack",
        "1.0.0",
        "published-v1.pack",
        33,
        "sha-p1",
        None,
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("published-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let packs = repo
        .list_all_packs()
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert_eq!(packs.len(), 2);
    assert_eq!(packs[0].id, "draft-pack");
    assert_eq!(packs[0].version, "0.2.0");
    assert_eq!(packs[1].id, "published-pack");
    assert_eq!(packs[1].version, "1.0.0");

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_active_version_id_returns_current_version_id(pool: PgPool) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    repo.register_pack("cache-pack", "quran", "en", "Cache Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("cache-pack", "1.0.0", "cache-v1.pack", 10, "sha-1", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let first_id = repo
        .get_active_version_id("cache-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .expect("active version id");

    repo.add_version("cache-pack", "1.1.0", "cache-v2.pack", 11, "sha-2", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let second_id = repo
        .get_active_version_id("cache-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .expect("active version id");

    assert_ne!(first_id, second_id);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_available_all_versions_includes_historical_published_versions(
    pool: PgPool,
) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    repo.register_pack("hist-pack", "quran", "en", "History Pack", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("hist-pack", "1.0.0", "hist-v1.pack", 10, "sha-1", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("hist-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("hist-pack", "1.1.0", "hist-v2.pack", 11, "sha-2", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let versions = repo
        .list_available_all_versions(Some("quran"), Some("en"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, "1.1.0");
    assert_eq!(versions[1].version, "1.0.0");

    Ok(())
}
