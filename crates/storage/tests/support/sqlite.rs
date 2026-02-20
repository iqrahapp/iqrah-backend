use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations_sqlite");
static COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct SqliteTestDb {
    pub pool: SqlitePool,
    pub db_path: PathBuf,
    keep_db: bool,
}

impl Drop for SqliteTestDb {
    fn drop(&mut self) {
        if self.keep_db {
            return;
        }

        let _ = std::fs::remove_file(&self.db_path);
    }
}

pub async fn setup_test_db() -> Result<SqliteTestDb, sqlx::Error> {
    let keep_db = std::env::var("TEST_KEEP_DB").ok().as_deref() == Some("1");
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let db_path = std::env::temp_dir().join(format!(
        "iqrah-storage-sqlite-test-{}-{}.db",
        std::process::id(),
        unique
    ));

    if db_path.exists() {
        let _ = std::fs::remove_file(&db_path);
    }

    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;

    migrate(&pool).await?;

    Ok(SqliteTestDb {
        pool,
        db_path,
        keep_db,
    })
}

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("sqlite migration failed: {e}")))
}

pub async fn seed_common_fixtures(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO users (id, oauth_sub, last_seen_at) VALUES (?1, ?2, STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))")
        .bind("user-1")
        .bind("sub-user-1")
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO packs (package_id, pack_type, language, name, description, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind("pack-1")
    .bind("quran")
    .bind("en")
    .bind("Pack One")
    .bind("fixture pack")
    .bind("published")
    .execute(pool)
    .await?;

    Ok(())
}
