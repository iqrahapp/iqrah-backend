-- Pack registry schema update

-- Rename/update packs table to match spec
ALTER TABLE packs ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE packs ADD COLUMN IF NOT EXISTS description TEXT;

-- Pack versions table for version management
CREATE TABLE IF NOT EXISTS pack_versions (
    id SERIAL PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES packs(package_id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    min_app_version TEXT,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(package_id, version)
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_pack_versions_package_id ON pack_versions(package_id);
CREATE INDEX IF NOT EXISTS idx_pack_versions_active ON pack_versions(is_active) WHERE is_active = true;
