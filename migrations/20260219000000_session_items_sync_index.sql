-- Add user_id to session_items for efficient direct sync queries (avoids JOIN through sessions)
-- and add indexes to support cursor-based pagination in sync pull.

ALTER TABLE session_items ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- Backfill user_id from the parent session
UPDATE session_items si
SET user_id = s.user_id
FROM sessions s
WHERE si.session_id = s.id
  AND si.user_id IS NULL;

-- Make user_id non-nullable now that it is populated
ALTER TABLE session_items ALTER COLUMN user_id SET NOT NULL;

-- Index for direct user-scoped sync queries (replaces JOIN with sessions)
CREATE INDEX IF NOT EXISTS idx_session_items_user_updated ON session_items(user_id, updated_at, id);

-- Index for cursor-based pagination (updated_at, id order)
CREATE INDEX IF NOT EXISTS idx_session_items_updated ON session_items(updated_at, id);
