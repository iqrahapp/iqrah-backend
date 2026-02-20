#![cfg(feature = "postgres-tests")]

use sqlx::PgPool;

use iqrah_backend_storage::{PgAuthRepository, PgPackRepository};

#[sqlx::test(migrations = "../../migrations")]
async fn pack_repository_register_publish_and_filter(pool: PgPool) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool.clone());

    repo.register_pack(
        "quran-ar",
        "quran",
        "ar",
        "Quran Arabic",
        Some("Arabic pack"),
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("quran-ar", "1.0.0", "quran-ar-v1.pack", 100, "sha-v1", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("quran-ar")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    repo.add_version(
        "quran-ar",
        "1.1.0",
        "quran-ar-v2.pack",
        120,
        "sha-v2",
        Some("1.2.0"),
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let list = repo
        .list_available(Some("quran"), Some("ar"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].version, "1.1.0");
    assert_eq!(list[0].sha256, "sha-v2");

    let pack = repo
        .get_pack("quran-ar")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .expect("pack should exist");
    assert_eq!(pack.file_path, "quran-ar-v2.pack");

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*)::BIGINT as \"count!\" FROM pack_versions WHERE package_id = $1 AND is_active = true",
        "quran-ar"
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(count, 1);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn user_repository_find_or_create_is_idempotent(pool: PgPool) -> Result<(), sqlx::Error> {
    let repo = PgAuthRepository::new(pool.clone());

    let first = repo
        .find_or_create("sub-123")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let second = repo
        .find_or_create("sub-123")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    assert_eq!(first.id, second.id);
    assert!(second.last_seen_at >= first.last_seen_at);

    let loaded = repo
        .get_by_id(first.id)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(loaded.is_some());

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn disable_pack_hides_pack_from_public_queries(pool: PgPool) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool.clone());

    repo.register_pack(
        "quran-en",
        "quran",
        "en",
        "Quran English",
        Some("English pack"),
    )
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.add_version("quran-en", "1.0.0", "quran-en-v1.pack", 100, "sha-v1", None)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    repo.publish_pack("quran-en")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let initially_available = repo
        .list_available(Some("quran"), Some("en"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert_eq!(initially_available.len(), 1);
    assert!(
        repo.get_pack("quran-en")
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
            .is_some()
    );

    let disabled = repo
        .disable_pack("quran-en")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(disabled);

    let after_disable = repo
        .list_available(Some("quran"), Some("en"))
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(after_disable.is_empty());
    assert!(
        repo.get_pack("quran-en")
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
            .is_none()
    );

    repo.publish_pack("quran-en")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(
        repo.get_pack("quran-en")
            .await
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
            .is_some()
    );

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn disable_pack_returns_false_for_unknown_pack(pool: PgPool) -> Result<(), sqlx::Error> {
    let repo = PgPackRepository::new(pool);

    let disabled = repo
        .disable_pack("missing-pack")
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    assert!(!disabled);

    Ok(())
}
