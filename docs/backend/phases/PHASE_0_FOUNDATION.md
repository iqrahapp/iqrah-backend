# Phase 0: Foundation

Document Version: 1.0
Date: 2024-12-28

## Purpose
Stand up the backend project with clean architecture, configuration, and deployment scaffolding so future phases can build quickly.

## Goals
- Create a dedicated backend project skeleton (Rust + Axum + SQLx + Postgres).
- Provide health endpoints and logging/metrics.
- Establish migrations and a minimal schema for users and packs.
- Enable local dev with Docker Compose and CI for checks.

## Acceptance Criteria
- `GET /v1/health` returns 200 with build info.
- `GET /v1/ready` checks DB connectivity.
- DB migrations apply cleanly on a fresh Postgres instance.
- Docker Compose brings up API + DB in one command.
- CI runs `cargo fmt`, `cargo clippy`, `cargo test`.

## Architecture Baseline
- Monorepo folder: `backend/` (new).
- Rust crates:
  - `backend/api` (Axum handlers, routing, auth middleware)
  - `backend/domain` (DTOs, core types)
  - `backend/storage` (SQLx, migrations, repositories)
  - `backend/config` (env parsing, secrets)
- Database: Postgres 15+.
- Logging: `tracing` + `tracing-subscriber`.
- Metrics: `axum-prometheus` or OpenTelemetry exporter.

## Task Breakdown

### Task 0.1: Create Project Skeleton
Files/dirs to create:
```
backend/
  Cargo.toml
  api/
  domain/
  storage/
  config/
  migrations/
```

### Task 0.2: Base Config + Secrets
- Environment variables:
  - `DATABASE_URL`
  - `JWT_SECRET`
  - `PACK_STORAGE_PATH`
  - `GOOGLE_CLIENT_ID`
  - `BIND_ADDRESS`
- Load via `dotenvy` + typed config struct.

### Task 0.3: Health + Ready Endpoints
- `GET /v1/health` -> build SHA, version, uptime.
- `GET /v1/ready` -> DB ping.

### Task 0.4: DB Schema v0
Tables:
- `users` (id, oauth_sub, created_at)
- `packs` (package_id, type, version, language, status, file_path, sha256)
- `pack_versions` (package_id, version, published_at, size_bytes, sha256)

### Task 0.5: Docker Compose
- `docker-compose.yml` with:
  - `postgres` container
  - `backend` container

### Task 0.6: CI
- GitHub Actions:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all -- -D warnings`
  - `cargo test`

## Testing Requirements
- Unit tests for config parsing.
- Smoke test for `/v1/health`.

## Estimated Effort
- 3 to 4 days.
