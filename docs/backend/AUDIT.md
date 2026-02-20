# Iqrah Backend — Codebase Audit

> Audited: 2026-02-19
> Auditor: Claude (senior Rust backend review)
> Scope: `backend/` workspace

---

## 1. Project Structure

**Workspace root**: `backend/Cargo.toml` — Cargo workspace, `resolver = "2"`, edition 2024.

**Crates** (`backend/crates/`):

| Crate | Package name | Role |
|---|---|---|
| `crates/api/` | `iqrah-backend-api` | HTTP layer — routes, handlers, middleware |
| `crates/domain/` | `iqrah-backend-domain` | Shared types, error types, request/response DTOs |
| `crates/storage/` | `iqrah-backend-storage` | Database repositories, migrations |
| `crates/config/` | `iqrah-backend-config` | Environment-variable configuration |

**Entry points**:
- Binary: `crates/api/src/main.rs` — bootstraps tracing, loads config, creates DB pool, runs migrations, wires `AppState`, calls `axum::serve`.
- Library surface: `crates/api/src/lib.rs` — exposes `build_router` and `AppState`; used by both `main.rs` and integration tests.

**Key directories**:
- `backend/migrations/` — 7 Postgres migration files (sqlx `migrate!` macro, path `../../migrations` relative to the storage crate).
- `backend/crates/storage/migrations_sqlite/` — 1 SQLite migration used only by integration tests.
- `backend/crates/storage/tests/` — SQLite-first integration tests, Postgres suite stubs.
- `backend/crates/api/tests/` — API-level integration tests.

---

## 2. Web Framework & Server

**Framework**: Axum 0.8 (with `macros` feature). `tokio` 1.45 full runtime.

**Route table** (defined in `crates/api/src/lib.rs`):

| Method | Path | Handler |
|---|---|---|
| GET | `/v1/health` | `health` (inline) |
| GET | `/v1/ready` | `ready` (inline) |
| POST | `/v1/auth/google` | `handlers::auth::google_auth` |
| GET | `/v1/users/me` | `handlers::auth::get_me` |
| GET | `/v1/packs/available` | `handlers::packs::list_packs` |
| GET | `/v1/packs/{id}/download` | `handlers::packs::download_pack` |
| GET | `/v1/packs/{id}/manifest` | `handlers::packs::get_manifest` |
| POST | `/v1/sync/push` | `handlers::sync::sync_push` |
| POST | `/v1/sync/pull` | `handlers::sync::sync_pull` |
| GET | `/v1/admin/sync/conflicts/{user_id}` | `handlers::sync::admin_recent_conflicts` |

**Middleware stack** (applied via `.layer()`, outermost first at call time):

| Middleware | Source | Config |
|---|---|---|
| `CorsLayer::permissive()` | `tower-http` | Allows all origins, all methods |
| `TraceLayer::new_for_http()` | `tower-http` | Request/response tracing |
| `SetRequestIdLayer` | `tower-http` | Injects `x-request-id` UUID header |
| `PropagateRequestIdLayer` | `tower-http` | Propagates request ID to responses |

**Auth** is handled via Axum extractors (`crates/api/src/middleware/auth.rs`):
- `AuthUser` — JWT Bearer verification using `jsonwebtoken`, injected as a handler param.
- `AdminApiKey` — Static `x-admin-key` header comparison, used only on the admin conflict endpoint.

**Not present**: no compression layer, no request body size limit, no rate-limit layer (despite `tower_governor` being in workspace deps — it is never used).

---

## 3. Data Layer

**Primary database**: PostgreSQL, accessed via `sqlx 0.8` with `PgPool` / `PgPoolOptions` (`crates/storage/src/lib.rs`). Pool max connections: 10, hardcoded.

**Test database**: SQLite, used exclusively in `crates/storage/tests/integration_sqlite_tests.rs` via a separate migration set in `migrations_sqlite/`. The production storage crate only compiles against Postgres types.

**No ORM** — all queries are raw SQL with `sqlx::query` / `sqlx::query_as`. Result rows are mapped via `#[derive(sqlx::FromRow)]` structs internal to each repository module.

**Repositories** (all hold a `PgPool` clone):

| Struct | File | Operations |
|---|---|---|
| `PackRepository` | `pack_repository.rs` | `list_available`, `get_pack`, `register_pack`, `add_version`, `publish_pack` |
| `UserRepository` | `user_repository.rs` | `find_or_create` (upsert), `get_by_id` |
| `SyncRepository` | `sync_repository.rs` | `touch_device`, `apply_changes` (LWW upserts in transaction), `get_changes_since` (cursor pagination), `list_recent_conflicts` |

**Migrations** — `sqlx::migrate!("../../migrations")` macro resolves to `backend/migrations/`:

| File | Purpose |
|---|---|
| `20260102000000_initial_schema.sql` | `users`, `packs` tables |
| `20260102000001_pack_versions.sql` | `pack_versions` table, `name`/`description` added to `packs` |
| `20260102000002_auth_sync.sql` | `devices`, `user_settings`, `memory_states`, `sessions`, `session_items` |
| `20260103000000_device_metadata.sql` | Adds `os`, `app_version`, `device_model` to `devices` |
| `20260219000000_session_items_sync_index.sql` | Adds `user_id` to `session_items`, backfill, indexes for cursor pagination |
| `20260219000001_deprecate_legacy_pack_columns.sql` | Backfills `pack_versions`, renames legacy `packs.version/file_path/sha256` to `legacy_*` |
| `20260220000000_sync_audit_tables.sql` | `sync_events`, `conflict_logs` tables |

---

## 4. Asset / File Handling

**Storage backend**: Local filesystem. Pack files live under `config.pack_storage_path` (env var `PACK_STORAGE_PATH`, defaults to `./packs`). The DB column `pack_versions.file_path` stores a relative path within that root.

**Serving** (`crates/api/src/handlers/packs.rs`):
- Opens files with `tokio::fs::File`.
- Streams via `tokio_util::io::ReaderStream` wrapped in `axum::body::Body::from_stream`.
- Full RFC 7233 HTTP Range request support (`bytes=start-end`, `bytes=start-`, `bytes=-suffix`). Returns 206 Partial Content or 416 Range Not Satisfiable correctly.
- Sets `Accept-Ranges: bytes` and `X-Pack-SHA256: <hash>` on every response.

**Versioning**: `pack_versions` table tracks per-pack versions with an `is_active` boolean. Only one version is active at a time; `add_version()` deactivates all prior rows before inserting the new one.

**Checksum**: SHA256 is stored in `pack_versions.sha256` and returned in the `X-Pack-SHA256` response header and in `PackDto.sha256`. The server does **not** compute or validate the checksum at request time — it is pre-registered when a pack is added via `add_version`.

**No hot-reload or file watching**: pack file paths are static configuration; no `notify`/`inotify`-based watcher exists.

**No cloud storage**: no S3, GCS, or CDN integration.

---

## 5. Serialization & API Contracts

**Serde**: `serde 1.0` with `derive` feature throughout. All request/response types use `#[derive(Serialize, Deserialize)]`.

**Response types** live in `crates/domain/`:
- `domain/src/auth.rs` — `GoogleAuthRequest`, `AuthResponse`, `UserProfile`, `Claims`
- `domain/src/sync.rs` — all sync push/pull request and response types, cursor types, change types
- `domain/src/lib.rs` — `User`, `Pack`, `PackType`, `PackStatus`, `HealthResponse`, `ReadyResponse`
- `domain/src/errors.rs` — `DomainError` (implements `IntoResponse` for Axum) and `ErrorResponse`

**DTO layer**: `PackDto` (`handlers/packs.rs`) is the only handler-local DTO — a thin projection from `PackInfo` adding a computed `download_url`.

**API versioning**: URL-prefix only (`/v1/`). No `Accept-Version` header, no version negotiation, no changelogs or deprecation notices.

**Validation**: `validator 0.18` with `#[derive(Validate)]` on sync request types. Called explicitly via `req.validate()` at the top of sync handlers.

**Error format**: All errors serialize as `{"error": "...", "details": [...]}` (details field present only for validation errors).

**Frontend sharing**: No shared schema — no OpenAPI spec, no Protobuf, no code generation. The domain crate is backend-only Rust.

---

## 6. Dependencies

**Workspace-level** (`backend/Cargo.toml`):

| Crate | Version | Notes |
|---|---|---|
| `tokio` | 1.45 | full features |
| `axum` | 0.8 | macros feature |
| `tower` | 0.5 | — |
| `tower-http` | 0.6 | cors, trace, request-id |
| `tower_governor` | 0.8 | **declared but never used** |
| `sqlx` | 0.8 | postgres + sqlite + uuid + chrono + migrate |
| `serde` | 1.0 | derive |
| `serde_json` | 1.0 | — |
| `dotenvy` | 0.15 | — |
| `tracing` | 0.1 | — |
| `tracing-subscriber` | 0.3 | env-filter + json |
| `uuid` | 1.17 | v4 + serde |
| `chrono` | 0.4 | serde |
| `anyhow` | 1.0 | — |
| `thiserror` | 2.0 | — |
| `validator` | 0.18 | derive |

**Per-crate extras**:

| Crate | Dependency | Version | Notes |
|---|---|---|---|
| api | `jsonwebtoken` | 9 | JWT encode/decode |
| api | `google-jwt-verify` | 0.3.0 | Google ID token verification; synchronous, run via `spawn_blocking` |
| api | `tokio-util` | 0.7 | `ReaderStream` for file streaming |
| api | `tempfile` | 3 | dev-dep for handler unit tests |

**Flags**:
- `tower_governor` is in `[workspace.dependencies]` but no crate's `Cargo.toml` lists it — dead weight.
- `domain` depends on `axum` and `sqlx` — cross-layer coupling (see Section 7).
- `google-jwt-verify 0.3.0` is an older, minimally-maintained crate.

---

## 7. Gaps & Observations

### Critical: Unresolved Merge Conflict

`crates/storage/src/sync_repository.rs` contains active Git conflict markers (`<<<<<<< HEAD`, `=======`, `>>>>>>> main`) inside `get_changes_since`. **The file will not compile in this state.**

The two branches differ on:
- **Pagination strategy**: per-entity independent cursors (HEAD) vs. cross-entity merge-sort with a global limit (main).
- **`client_updated_at` field**: present in all change types on main, absent on HEAD — reflecting an unresolved decision about whether LWW ordering uses client-supplied or server-assigned timestamps.

### Architectural: `domain` Crate Depends on `axum` and `sqlx`

`crates/domain/Cargo.toml` lists `axum` and `sqlx` as direct dependencies so that `DomainError` can implement `IntoResponse` and `From<sqlx::Error>`. This couples the domain layer to infrastructure details. A cleaner boundary would have the `api` crate perform error mapping, keeping `domain` as pure data types with no framework dependencies.

### Missing: Rate Limiting

`tower_governor 0.8` is declared in `[workspace.dependencies]` but never applied anywhere. There is no rate-limiting on any endpoint, including auth and sync push.

### Missing: Response Compression

No `tower_http::compression::CompressionLayer` is applied. Sync pull responses (potentially large JSON payloads) are served uncompressed.

### Missing: Global Asset Manifest Endpoint

There is a per-pack manifest (`GET /v1/packs/{id}/manifest`) but no aggregate catalog endpoint (e.g. `GET /v1/packs/manifest`) that returns all published packs with checksums and versions in a single call. Clients must enumerate via `GET /v1/packs/available` and then resolve manifests individually.

### Missing: Server-side Checksum Verification at Serve Time

SHA256 is pre-populated at pack registration. The server does not hash the file before streaming. A corrupted file on disk streams silently with the correct hash in the response header.

### Missing: Hot-reload / File Watching

Pack files are read from disk on every request with no in-memory cache and no `notify`-based watcher. Removing a file from disk while the DB still references it produces a 404 or mid-stream error.

### Missing: JWT Refresh

Tokens expire in 3600 seconds (hardcoded in `handlers/auth.rs`). There is no refresh token or sliding expiry mechanism. Clients re-authenticate via Google after every hour.

### Missing: Request Body Size Limit

Axum defaults to no body size limit. A large sync push payload is accepted without constraint. `axum::extract::DefaultBodyLimit` or `tower_http::limit::RequestBodyLimitLayer` would mitigate this.

### Minor: CORS Permissive Without Documentation

`CorsLayer::permissive()` allows all origins. Acceptable for a mobile API, but should be documented as an intentional decision (or scoped to known origins in production).

### Minor: Pool Size Hardcoded

`max_connections(10)` in `storage/src/lib.rs` is hardcoded. Should be driven by an env var (e.g. `DATABASE_POOL_SIZE`).

### Minor: CI Test Step Missing `RUSTFLAGS=-D warnings`

`.github/workflows/backend-ci.yml` runs clippy with `-D warnings` but the `cargo test --all` step does not set `RUSTFLAGS="-D warnings"`. A warning that only appears in test code (and escapes clippy) would not fail CI.
