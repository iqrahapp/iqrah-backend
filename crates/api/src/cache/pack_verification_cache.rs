use std::sync::Arc;

use dashmap::DashMap;

#[derive(Debug, Clone, Default)]
pub struct PackVerificationCache {
    entries: Arc<DashMap<i32, bool>>,
}

impl PackVerificationCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    pub fn is_verified(&self, version_id: i32) -> bool {
        self.entries.contains_key(&version_id)
    }

    pub fn mark_verified(&self, version_id: i32) {
        self.entries.insert(version_id, true);
    }

    pub fn invalidate(&self, version_id: i32) {
        self.entries.remove(&version_id);
    }

    pub fn clear(&self) {
        self.entries.clear();
    }
}
