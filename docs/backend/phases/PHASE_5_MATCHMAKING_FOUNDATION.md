# Phase 5: Matchmaking Foundation

Document Version: 1.0
Date: 2024-12-28

## Purpose
Lay groundwork for queue-based matchmaking and low-latency recitation groups without committing to a final realtime protocol.

## Goals
- Matchmaking queue service.
- Lobby creation and membership tracking.
- WebSocket gateway skeleton for realtime events.

## Acceptance Criteria
- Client can join/leave matchmaking queue.
- Server can pair users into a lobby.
- WebSocket broadcasts lobby updates (join/leave/ready).

## Architecture Notes
- Queue-based matching (polling or WebSocket events).
- Realtime transport is deferred: WebSocket for control; audio will likely require WebRTC/UDP later.

## API Endpoints
```
POST /v1/matchmaking/join
POST /v1/matchmaking/leave
GET  /v1/matchmaking/status
```
WebSocket:
```
GET /v1/ws
```

## Data Model
- `matchmaking_queue` (user_id, mode, enqueued_at)
- `lobbies` (id, mode, created_at, status)
- `lobby_members` (lobby_id, user_id, joined_at, role)

## Task Breakdown

### Task 5.1: Queue + Lobby Service
- Enqueue/dequeue users.
- Simple matching rules (first-come).

### Task 5.2: WebSocket Gateway
- Authenticated WS connection.
- Emit lobby events (joined, ready, start).

### Task 5.3: Metrics
- Queue time histogram.
- Lobby creation counts.

## Testing Requirements
- Unit test: matchmaking pairing.
- Integration test: join queue -> lobby created.

## Estimated Effort
- 6 to 10 days.
