# Phase 2: Auth + Sync v1

Document Version: 1.0
Date: 2024-12-28

## Purpose
Add Google OAuth login and minimal offline-first sync for user profile, settings, memory states, and session history.

## Goals
- Google OAuth login (ID token verification).
- Issue API JWT access token + refresh token (optional).
- Sync API with last-write-wins and server timestamps.

## Acceptance Criteria
- User can sign in with Google and receive an API token.
- Client can push local changes and pull remote changes.
- Sync works across devices (last-write-wins).
- Sync is fast enough to run every ~60 seconds.

## API Endpoints

### Auth
```
POST /v1/auth/google
{ "id_token": "..." }
```
Response:
```
{ "access_token": "...", "user_id": "...", "expires_in": 3600 }
```

### User
```
GET /v1/users/me
Authorization: Bearer <token>
```

### Sync Push
```
POST /v1/sync/push
Authorization: Bearer <token>
{
  "device_id": "uuid",
  "changes": {
    "settings": [...],
    "memory_states": [...],
    "sessions": [...],
    "session_items": [...]
  }
}
```
Response:
```
{ "applied": 4, "skipped": 0, "server_time": 1735344000000 }
```

### Sync Pull
```
POST /v1/sync/pull
Authorization: Bearer <token>
{
  "device_id": "uuid",
  "since": 1735340000000,
  "limit": 1000,
  "cursor": {
    "settings": { "updated_at": 1735340000000, "key": "theme" },
    "memory_states": { "updated_at": 1735340000000, "node_id": 42 },
    "sessions": { "updated_at": 1735340000000, "id": "uuid" },
    "session_items": { "updated_at": 1735340000000, "id": "uuid" }
  }
}
```
Response:
```
{
  "server_time": 1735344000000,
  "changes": { ... },
  "has_more": false,
  "next_cursor": {
    "settings": { "updated_at": 1735340000000, "key": "theme" },
    "memory_states": { "updated_at": 1735340000000, "node_id": 42 },
    "sessions": { "updated_at": 1735340000000, "id": "uuid" },
    "session_items": { "updated_at": 1735340000000, "id": "uuid" }
  }
}
```

## Conflict Resolution
- Last-write-wins by server-assigned `updated_at` only.
- The server ignores client logical timestamps for conflict resolution.
- Tie-break rule: updates are applied only when `existing.updated_at < incoming.updated_at`; equal timestamps keep the existing row.
- Server stores `updated_at` and `updated_by_device` for auditability.

## DB Schema (v1)
- `users` (id, oauth_sub, created_at, last_seen_at)
- `devices` (id, user_id, created_at, last_seen_at)
- `settings` (user_id, key, value, updated_at)
- `memory_states` (user_id, node_id, energy, fsrs_stability, fsrs_difficulty, updated_at)
- `sessions` (id, user_id, started_at, completed_at, updated_at)
- `session_items` (id, session_id, node_id, exercise_type, grade, duration_ms, updated_at)

Indexes:
- `memory_states(user_id, node_id)`
- `session_items(session_id)`

## Task Breakdown

### Task 2.1: Google OAuth Verification
- Verify ID token using Google public keys.
- Map `sub` to `users` table.

### Task 2.2: JWT Issuance
- Issue JWT with `user_id` and expiration.
- Add middleware to guard `/v1/*` endpoints.

### Task 2.3: Sync Push/Pull
- Implement LWW logic in repositories using server write time.
- Store `updated_at` server timestamp on every accepted write.
- Pull changes since `since` timestamp using per-entity cursors (`updated_at`, primary key).

### Task 2.4: Device Tracking
- Register device on first sync.
- Track `last_seen_at` for monitoring.

## Testing Requirements
- Auth tests: valid/invalid ID token.
- Sync tests: push then pull returns expected changes.
- LWW test: later server write wins across devices (arrival order under server timestamps).

## Local Testing (Docker)
Use the existing backend compose file for Postgres only:
```
docker compose -f backend/docker-compose.yml up -d postgres
DATABASE_URL=postgres://iqrah:iqrah@localhost:5432/iqrah cargo test -p iqrah-backend-storage -p iqrah-backend-api
```

## Estimated Effort
- 7 to 10 days.
