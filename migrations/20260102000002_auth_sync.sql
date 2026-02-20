-- Auth and Sync schema (Phase 2)

-- Update users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

-- Devices table for multi-device sync
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

-- User settings (synced)
CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_device UUID REFERENCES devices(id),
    PRIMARY KEY (user_id, key)
);

-- Memory states (synced)
CREATE TABLE IF NOT EXISTS memory_states (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id BIGINT NOT NULL,
    energy REAL NOT NULL DEFAULT 0.0,
    fsrs_stability REAL,
    fsrs_difficulty REAL,
    last_reviewed_at TIMESTAMPTZ,
    next_review_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_device UUID REFERENCES devices(id),
    PRIMARY KEY (user_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_states_updated ON memory_states(user_id, updated_at);

-- Sessions (synced)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    goal_id TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    items_completed INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_device UUID REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(user_id, updated_at);

-- Session items (synced)
CREATE TABLE IF NOT EXISTS session_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    node_id BIGINT NOT NULL,
    exercise_type TEXT NOT NULL,
    grade INT,
    duration_ms INT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_device UUID REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_session_items_session ON session_items(session_id);
