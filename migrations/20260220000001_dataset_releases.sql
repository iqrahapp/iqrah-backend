-- Dataset release model for atomic artifact publishing.

CREATE TABLE IF NOT EXISTS dataset_releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'deprecated')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dataset_releases_status_published
    ON dataset_releases(status, published_at DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS dataset_release_artifacts (
    release_id UUID NOT NULL REFERENCES dataset_releases(id) ON DELETE CASCADE,
    package_id TEXT NOT NULL REFERENCES packs(package_id) ON DELETE RESTRICT,
    required BOOLEAN NOT NULL DEFAULT false,
    artifact_role TEXT NOT NULL CHECK (
        artifact_role IN (
            'core_content_db',
            'knowledge_graph',
            'morphology',
            'translation_catalog',
            'audio_catalog',
            'optional_pack'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, package_id)
);

CREATE INDEX IF NOT EXISTS idx_dataset_release_artifacts_release_role
    ON dataset_release_artifacts(release_id, artifact_role);
