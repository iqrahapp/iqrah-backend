//! File-system backed store for downloadable pack assets.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs::{self, File};

/// Trait boundary for pack asset I/O.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PackAssetStore: Send + Sync {
    /// Resolves the absolute storage path for a relative pack file.
    fn resolve_path(&self, relative_path: &str) -> PathBuf;

    /// Checks if a relative file exists.
    async fn exists(&self, relative_path: &str) -> std::io::Result<bool>;

    /// Opens a pack file for reading.
    async fn open_for_read(&self, relative_path: &str) -> std::io::Result<File>;

    /// Creates a pack file for writing.
    async fn create_for_write(&self, relative_path: &str) -> std::io::Result<File>;

    /// Creates parent directories for a relative file path.
    async fn ensure_parent_dirs(&self, relative_path: &str) -> std::io::Result<()>;
}

/// File-system implementation for [`PackAssetStore`].
#[derive(Debug, Clone)]
pub struct FsPackAssetStore {
    base_path: PathBuf,
}

impl FsPackAssetStore {
    /// Creates a store rooted at `base_path`.
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl PackAssetStore for FsPackAssetStore {
    fn resolve_path(&self, relative_path: &str) -> PathBuf {
        self.base_path.join(relative_path)
    }

    async fn exists(&self, relative_path: &str) -> std::io::Result<bool> {
        Ok(fs::metadata(self.resolve_path(relative_path)).await.is_ok())
    }

    async fn open_for_read(&self, relative_path: &str) -> std::io::Result<File> {
        File::open(self.resolve_path(relative_path)).await
    }

    async fn create_for_write(&self, relative_path: &str) -> std::io::Result<File> {
        File::create(self.resolve_path(relative_path)).await
    }

    async fn ensure_parent_dirs(&self, relative_path: &str) -> std::io::Result<()> {
        if let Some(parent) = self.resolve_path(relative_path).parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn fs_pack_asset_store_creates_dirs_writes_and_reads_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = FsPackAssetStore::new(temp.path());
        let relative = "packs/en/1.0.0/pack.bin";

        store
            .ensure_parent_dirs(relative)
            .await
            .expect("dirs should be created");
        let mut writer = store
            .create_for_write(relative)
            .await
            .expect("file should be created");
        writer
            .write_all(b"abc")
            .await
            .expect("write should succeed");
        writer.flush().await.expect("flush should succeed");

        assert!(store.exists(relative).await.expect("exists should succeed"));

        let mut reader = store
            .open_for_read(relative)
            .await
            .expect("file should open");
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
            .await
            .expect("read should succeed");
        assert_eq!(data, b"abc");
    }

    #[tokio::test]
    async fn fs_pack_asset_store_resolve_path_joins_base_and_relative() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = FsPackAssetStore::new(temp.path());

        let resolved = store.resolve_path("a/b/c.bin");
        assert!(resolved.ends_with("a/b/c.bin"));
    }
}
