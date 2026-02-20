-- Verify pack reads are version-backed, backfill legacy data, and deprecate legacy pack columns.

BEGIN;

-- 1) Runtime-read safety checks at the database boundary.
-- Ensure no database object still depends on legacy pack payload columns before deprecating them.
DO $$
DECLARE
    dependency_count integer;
BEGIN
    SELECT COUNT(*)
    INTO dependency_count
    FROM pg_depend d
    JOIN pg_attribute a
      ON a.attrelid = d.refobjid
     AND a.attnum = d.refobjsubid
    JOIN pg_class c
      ON c.oid = a.attrelid
    WHERE c.relname = 'packs'
      AND a.attname IN ('version', 'file_path', 'sha256')
      AND d.classid <> 'pg_class'::regclass;

    IF dependency_count > 0 THEN
        RAISE EXCEPTION 'Cannot deprecate packs.version/file_path/sha256: % dependent database object(s) still reference them', dependency_count;
    END IF;
END $$;

-- 2) Backfill pack_versions from legacy packs columns if any rows are still only present in packs.
INSERT INTO pack_versions (
    package_id,
    version,
    file_path,
    size_bytes,
    sha256,
    min_app_version,
    published_at,
    is_active
)
SELECT
    p.package_id,
    p.version,
    p.file_path,
    0 AS size_bytes,
    p.sha256,
    NULL AS min_app_version,
    p.created_at,
    true AS is_active
FROM packs p
WHERE p.version IS NOT NULL
  AND p.file_path IS NOT NULL
  AND p.sha256 IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM pack_versions pv
      WHERE pv.package_id = p.package_id
        AND pv.version = p.version
  );

-- Ensure each package has at most one active version (latest wins).
WITH ranked AS (
    SELECT
        id,
        package_id,
        ROW_NUMBER() OVER (
            PARTITION BY package_id
            ORDER BY is_active DESC, published_at DESC, id DESC
        ) AS rn
    FROM pack_versions
)
UPDATE pack_versions pv
SET is_active = (ranked.rn = 1)
FROM ranked
WHERE pv.id = ranked.id;

-- Require every published pack to have an active version row before deprecating legacy columns.
DO $$
DECLARE
    missing_count integer;
BEGIN
    SELECT COUNT(*)
    INTO missing_count
    FROM packs p
    WHERE p.status = 'published'
      AND NOT EXISTS (
          SELECT 1
          FROM pack_versions pv
          WHERE pv.package_id = p.package_id
            AND pv.is_active = true
      );

    IF missing_count > 0 THEN
        RAISE EXCEPTION 'Found % published pack(s) without an active pack_versions row', missing_count;
    END IF;
END $$;

-- 3) Safely deprecate legacy payload columns in packs by renaming them.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'version'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'legacy_version'
    ) THEN
        ALTER TABLE packs RENAME COLUMN version TO legacy_version;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'file_path'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'legacy_file_path'
    ) THEN
        ALTER TABLE packs RENAME COLUMN file_path TO legacy_file_path;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'sha256'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'packs'
          AND column_name = 'legacy_sha256'
    ) THEN
        ALTER TABLE packs RENAME COLUMN sha256 TO legacy_sha256;
    END IF;
END $$;

COMMENT ON COLUMN packs.legacy_version IS 'Deprecated: use pack_versions.version';
COMMENT ON COLUMN packs.legacy_file_path IS 'Deprecated: use pack_versions.file_path';
COMMENT ON COLUMN packs.legacy_sha256 IS 'Deprecated: use pack_versions.sha256';

COMMIT;
