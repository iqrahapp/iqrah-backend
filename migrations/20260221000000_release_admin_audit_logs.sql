-- Admin audit records for release lifecycle actions.

CREATE TABLE IF NOT EXISTS release_admin_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    release_id UUID NOT NULL REFERENCES dataset_releases(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('publish', 'deprecate')),
    actor TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_release_admin_audit_logs_release_created
    ON release_admin_audit_logs(release_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_release_admin_audit_logs_action_created
    ON release_admin_audit_logs(action, created_at DESC);
