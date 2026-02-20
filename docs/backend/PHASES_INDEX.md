# Iqrah Backend Phases Index

Document Version: 1.0
Date: 2024-12-28

## Purpose
Define a phased backend program to support addon distribution (translations, recitations), auth, offline-first sync, and future multiplayer features.

## Guiding Decisions (Confirmed)
- Stack: Rust (Axum), SQLx, Postgres.
- Hosting: single home server initially; Docker Compose; CI/CD with GitHub Actions.
- Auth MVP: Google OAuth only.
- Sync: offline-first, periodic (about every 1 minute), last-write-wins with server timestamps.
- Pack format: single compressed pack file using zstd; integrity via sha256 (signing optional later).
- API versioning: path-based `/v1`.

## Pack Format (v1)
- File: `pack.tar.zst` (or `.iqp` if you want a branded extension).
- Contents:
  - `manifest.json`
  - `content.sqlite`
  - `checksums.sha256`
- Manifest fields (minimum):
  - `package_id`, `package_type`, `version`, `language_code`, `name`, `description`
  - `min_app_version`, `created_at`, `size_bytes`, `sha256`
  - `files[]` with per-file hashes

## Phase Summary

### Phase 0: Foundation
Goal: Stand up the Rust service, DB schema, CI/CD, and basic health/metrics.
Output: Running server with `/v1/health`, DB migrations, Docker Compose.

### Phase 1: Packs + Manifest API
Goal: List, download, and version addon packs (translations, recitations).
Output: `/v1/packs/available`, `/v1/packs/{id}/download`, pack registry DB.

### Phase 2: Auth + Sync v1
Goal: Google OAuth, user identity, minimal sync for profile/settings/memory/session history.
Output: `/v1/auth/google`, `/v1/sync/push`, `/v1/sync/pull`.

### Phase 3: Incremental Sync + Resilience
Goal: Efficient delta sync, resumable downloads, and retries.
Output: cursor-based sync, range downloads, conflict audit logs.

### Phase 4: Admin Tooling
Goal: Pack upload/publish and user support tools.
Output: CLI or minimal admin UI, pack publishing workflow.

### Phase 5: Matchmaking Foundation
Goal: Queue-based session matching + low-latency recitation groups groundwork.
Output: matchmaking service contracts, WebSocket gateway skeleton.

## Deliverables
Each phase doc includes:
- Goals and acceptance criteria
- API endpoints and payload contracts
- DB tables and migration notes
- Infrastructure and testing requirements
- Estimated effort

## Open Questions (Deferred)
- Ed25519 signing for packs (planned for Phase 3+).
- Object storage (S3/R2) offload (planned after Phase 2).
- Real-time protocols for recitation groups (planned for Phase 5).
