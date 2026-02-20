# Phase 4: Admin Tooling

Document Version: 1.0
Date: 2024-12-28

## Purpose
Provide simple admin tooling for publishing packs and managing users without manual DB edits.

## Goals
- Pack upload and publish workflow.
- Admin authentication (simple allowlist).
- Basic admin endpoints or CLI.

## Acceptance Criteria
- Admin can upload a new pack version and publish it.
- Admin can enable/disable packs.
- Admin can query user sync status.

## Options
- CLI tool (recommended for speed).
- Minimal admin web UI (optional).

## API Endpoints (Admin)
```
POST /v1/admin/packs/upload
POST /v1/admin/packs/{id}/publish
POST /v1/admin/packs/{id}/disable
GET  /v1/admin/users/{id}/sync_status
```

## Task Breakdown

### Task 4.1: Admin Auth
- Allowlist of admin emails.
- Admin JWT claim `role=admin`.

### Task 4.2: Pack Upload CLI
- CLI reads pack file + manifest.
- Uploads to server or copies to pack storage.
- Registers pack in DB.

### Task 4.3: Admin Endpoints
- Publish/unpublish pack.
- Query installed counts and last download stats.

## Testing Requirements
- CLI smoke test (upload pack into local server).
- Admin endpoints require role.

## Estimated Effort
- 4 to 6 days.
