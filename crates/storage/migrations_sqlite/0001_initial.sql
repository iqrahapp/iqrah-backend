PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    oauth_sub TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT
);

CREATE TABLE packs (
    package_id TEXT PRIMARY KEY,
    pack_type TEXT NOT NULL,
    language TEXT NOT NULL,
    name TEXT,
    description TEXT,
    status TEXT NOT NULL
);

CREATE TABLE pack_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL,
    version TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    min_app_version TEXT,
    published_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(package_id) REFERENCES packs(package_id) ON DELETE CASCADE,
    UNIQUE(package_id, version)
);
