#[path = "support/sqlite.rs"]
mod test_support_sqlite;

use sqlx::Row;

use test_support_sqlite::{seed_common_fixtures, setup_test_db};

#[tokio::test]
async fn happy_path_crud_for_user_and_pack_version() -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_test_db().await?;
    seed_common_fixtures(&db.pool).await?;

    sqlx::query(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind("pack-1")
    .bind("1.0.0")
    .bind("pack-1-v1.bin")
    .bind(100_i64)
    .bind("sha-1")
    .bind(1_i64)
    .execute(&db.pool)
    .await?;

    let row = sqlx::query("SELECT version, size_bytes FROM pack_versions WHERE package_id = ?1")
        .bind("pack-1")
        .fetch_one(&db.pool)
        .await?;

    assert_eq!(row.try_get::<String, _>("version")?, "1.0.0");
    assert_eq!(row.try_get::<i64, _>("size_bytes")?, 100);

    sqlx::query(
        "UPDATE users SET last_seen_at = STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
    )
    .bind("user-1")
    .execute(&db.pool)
    .await?;

    let user_count = sqlx::query("SELECT COUNT(*) as c FROM users")
        .fetch_one(&db.pool)
        .await?
        .try_get::<i64, _>("c")?;
    assert_eq!(user_count, 1);

    Ok(())
}

#[tokio::test]
async fn constraints_enforce_unique_and_foreign_keys() -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_test_db().await?;
    seed_common_fixtures(&db.pool).await?;

    let duplicate = sqlx::query("INSERT INTO users (id, oauth_sub) VALUES (?1, ?2)")
        .bind("user-2")
        .bind("sub-user-1")
        .execute(&db.pool)
        .await;
    assert!(
        duplicate.is_err(),
        "unique constraint should reject duplicate oauth_sub"
    );

    let fk_violation = sqlx::query(
        "INSERT INTO pack_versions (package_id, version, file_path, size_bytes, sha256, is_active) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind("missing-pack")
    .bind("1.0.0")
    .bind("missing.bin")
    .bind(1_i64)
    .bind("sha")
    .bind(1_i64)
    .execute(&db.pool)
    .await;

    assert!(
        fk_violation.is_err(),
        "foreign key constraint must be enabled"
    );

    Ok(())
}

#[tokio::test]
async fn transaction_rollback_does_not_persist_rows() -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_test_db().await?;

    {
        let mut tx = db.pool.begin().await?;
        sqlx::query("INSERT INTO users (id, oauth_sub) VALUES (?1, ?2)")
            .bind("user-tx")
            .bind("sub-user-tx")
            .execute(&mut *tx)
            .await?;

        tx.rollback().await?;
    }

    let count = sqlx::query("SELECT COUNT(*) as c FROM users WHERE id = ?1")
        .bind("user-tx")
        .fetch_one(&db.pool)
        .await?
        .try_get::<i64, _>("c")?;

    assert_eq!(count, 0);

    Ok(())
}
