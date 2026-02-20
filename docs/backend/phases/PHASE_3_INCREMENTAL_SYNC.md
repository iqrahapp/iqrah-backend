# Phase 3: Incremental Sync + Resilience

Document Version: 1.0
Date: 2024-12-28

## Purpose
Make sync and pack downloads resilient, efficient, and safe for poor connections.

## Goals
- Cursor-based incremental sync.
- Conflict audit logging for debugging.
- Resumable pack downloads with checksums.
- Automatic pack update checks.

## Acceptance Criteria
- Client can sync by cursor instead of timestamp.
- Sync payload sizes remain small as data grows.
- Pack downloads resume via HTTP range without corruption.
- Pack update endpoint returns only outdated packs.

## API Additions

### Sync Cursor Pull
```
POST /v1/sync/pull
{ "device_id": "uuid", "cursor": "opaque" }
```
Response includes new cursor.

### Pack Updates
```
POST /v1/packs/updates
{ "installed": [ {"package_id": "en_sahih", "version": "1.0.0"} ] }
```
Response lists newer versions only.

## Data Model Updates
- `sync_events` (id, user_id, entity_type, entity_id, updated_at)
- `conflict_logs` (id, user_id, entity, local_value, remote_value, resolved_at)

## Task Breakdown

### Task 3.1: Cursor-Based Sync
- Generate a monotonically increasing cursor (e.g., ULID or DB sequence).
- Store per-entity `sync_events`.
- Pull changes by cursor > last_cursor.

### Task 3.2: Conflict Audit
- Store conflict resolution decisions for debugging.
- Provide admin-only endpoint to inspect conflicts.

### Task 3.3: Resumable Downloads
- Ensure `Content-Range` and `Accept-Ranges` headers.
- Add checksum verification endpoint:
  - `GET /v1/packs/{id}/checksum`.

### Task 3.4: Update Checks
- Implement `/v1/packs/updates`.
- Return latest version per package.

## Testing Requirements
- Cursor sync integration test across two devices.
- Resume download test (partial + final hash).

## Estimated Effort
- 5 to 7 days.
