# Phase 1: Packs + Manifest API

Document Version: 1.0
Date: 2024-12-28

## Purpose
Deliver a backend that lists and serves addon packs (translations, recitations) with versioning and integrity checks.

## Goals
- Pack registry in DB.
- API for listing available packs and downloading pack bytes.
- Pack format with manifest + zstd compression.
- Versioning and update checks.

## Acceptance Criteria
- `GET /v1/packs/available` returns list with download URLs.
- `GET /v1/packs/{id}/download` streams pack bytes and supports HTTP range.
- Pack metadata stored and versioned in Postgres.
- Client can validate sha256 and re-download on mismatch.

## Pack Format v1
- `pack.tar.zst` containing:
  - `manifest.json` (metadata)
  - `content.sqlite` (translation DB)
  - `checksums.sha256` (per file)
- Manifest fields:
  - `package_id`, `package_type`, `version`, `language_code`, `name`
  - `description`, `min_app_version`, `created_at`, `size_bytes`, `sha256`
  - `files[]` with `path`, `size`, `sha256`

## API Endpoints

### List available packs
```
GET /v1/packs/available?type=verse_translation&language=en
```
Response:
```
{
  "packs": [
    {
      "package_id": "en_sahih",
      "package_type": "verse_translation",
      "version": "1.0.3",
      "language_code": "en",
      "name": "Sahih International",
      "size_bytes": 8420012,
      "sha256": "...",
      "download_url": "https://api.iqrah/v1/packs/en_sahih/download"
    }
  ]
}
```

### Download pack
```
GET /v1/packs/{id}/download
Range: bytes=0-1048575
```
- Supports Range for resumable downloads.
- Content-Type: `application/octet-stream`.
- Served directly from local disk in v1; keep endpoint stable for future object storage.
- Auth can be optional in v1 (public packs), but the handler should accept auth for future gating.

### Pack manifest (optional)
```
GET /v1/packs/{id}/manifest
```
Returns `manifest.json` only.

## DB Schema
Tables:
- `packs`:
  - `package_id` (PK)
  - `package_type`
  - `language_code`
  - `status`
  - `name`
  - `description`
  - `created_at`
  - Legacy payload columns (`legacy_version`, `legacy_file_path`, `legacy_sha256`) are deprecated and retained only for migration safety.
- `pack_versions`:
  - `id` (PK)
  - `package_id` (FK)
  - `version`
  - `file_path`
  - `size_bytes`
  - `sha256`
  - `min_app_version`
  - `published_at`
  - `is_active`

`pack_versions` is the runtime source of truth for version/file metadata used by listing and download APIs. Published packs must have an active `pack_versions` row.

## Task Breakdown

### Task 1.1: Pack Registry Models
- Add SQLx models + repository methods.
- Queries for available packs filtered by type/language.

### Task 1.2: Pack Download Handler
- Stream file from disk.
- Support HTTP range.
- Return `Content-Range` and `Accept-Ranges` headers.
 - Use `PACK_STORAGE_PATH` to resolve file locations.

### Task 1.3: Ingest Tool (CLI)
- CLI to register a pack:
  - Validate manifest + checksum.
  - Insert into DB.
  - Store file under `PACK_STORAGE_PATH/{package_id}/{version}.tar.zst`.

### Task 1.4: Versioning and Updates
- Only latest `is_active` version returned by default.
- Endpoint supports `?include_all_versions=true` for debug.

## Testing Requirements
- Unit test: manifest parser + checksum validation.
- Integration test: pack listing and range download (partial content).

## Estimated Effort
- 5 to 7 days.
