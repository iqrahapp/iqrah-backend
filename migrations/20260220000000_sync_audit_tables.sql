-- Phase 3 incremental sync observability tables.

CREATE TABLE IF NOT EXISTS sync_events (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    source_device_id UUID REFERENCES devices(id),
    entity_updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sync_events_user_id_id
    ON sync_events(user_id, id);

CREATE INDEX IF NOT EXISTS idx_sync_events_user_entity
    ON sync_events(user_id, entity_type, entity_key, id);

CREATE TABLE IF NOT EXISTS conflict_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    incoming_metadata JSONB NOT NULL,
    winning_metadata JSONB NOT NULL,
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_conflict_logs_user_resolved
    ON conflict_logs(user_id, resolved_at DESC);
