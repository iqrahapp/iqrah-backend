-- Initial schema for Iqrah backend

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oauth_sub TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create index on oauth_sub for fast lookups
CREATE INDEX IF NOT EXISTS idx_users_oauth_sub ON users(oauth_sub);

-- Packs table
CREATE TABLE IF NOT EXISTS packs (
    package_id TEXT PRIMARY KEY,
    pack_type TEXT NOT NULL,
    version TEXT NOT NULL,
    language TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    file_path TEXT,
    sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create index on language and status for filtering
CREATE INDEX IF NOT EXISTS idx_packs_language ON packs(language);
CREATE INDEX IF NOT EXISTS idx_packs_status ON packs(status);
