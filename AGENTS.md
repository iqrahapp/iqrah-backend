# AGENTS.md

Canonical guidance for AI coding agents in `iqrah-backend`.

## Project
`iqrah-backend` is the standalone backend for Iqrah mobile: an Axum HTTP API with PostgreSQL persistence (`sqlx`), Tokio async runtime, Rust 2024 edition, typed domain models, and repository-based data access. The workspace is intentionally backend-only and does not depend on Flutter/mobile code or R&D folders.

## Architecture Map
- `crates/api/src/main.rs` - binary entrypoint, runtime bootstrapping, dependency wiring.
- `crates/api/src/lib.rs` - `AppState`, top-level router composition, health/ready endpoints.
- `crates/api/src/routes/` - feature routers (`auth`, `packs`, `sync`, `admin`).
- `crates/api/src/handlers/` - HTTP handlers; orchestrate domain/repository calls only.
- `crates/api/src/middleware/` - auth/admin request extractors and request guards.
- `crates/api/src/auth/jwt_verifier.rs` - Google ID token verification boundary + JWKS-backed implementation.
- `crates/api/src/assets/pack_asset_store.rs` - pack file I/O boundary + filesystem implementation.
- `crates/api/src/cache/` - in-process pack integrity cache.
- `crates/storage/src/lib.rs` - DB pool, migration runner, storage exports.
- `crates/storage/src/auth_repository.rs` - auth/user repository trait and PostgreSQL impl.
- `crates/storage/src/pack_repository.rs` - pack repository trait and PostgreSQL impl.
- `crates/storage/src/sync_repository.rs` - sync repository trait and PostgreSQL impl.
- `crates/storage/src/error.rs` - storage error contract (`thiserror`).
- `crates/domain/src/` - domain types, newtypes, error mapping, request/response DTOs.
- `crates/config/src/lib.rs` - env parsing and validation into strongly typed config.
- `migrations/` - canonical PostgreSQL schema history.
- `.sqlx/` - committed SQLx query metadata cache for offline compilation.

## Trait Boundary Registry
| Trait | File | Concrete Impl | Mock (tests) |
|---|---|---|---|
| `AuthRepository` | `crates/storage/src/auth_repository.rs` | `PgAuthRepository` | `MockAuthRepository` |
| `PackRepository` | `crates/storage/src/pack_repository.rs` | `PgPackRepository` | `MockPackRepository` |
| `SyncRepository` | `crates/storage/src/sync_repository.rs` | `PgSyncRepository` | `MockSyncRepository` |
| `JwtVerifier` | `crates/api/src/auth/jwt_verifier.rs` | `GoogleJwtVerifier` | `MockJwtVerifier` |
| `PackAssetStore` | `crates/api/src/assets/pack_asset_store.rs` | `FsPackAssetStore` | `MockPackAssetStore` |

## Actor Registry
No actors are currently implemented.

`kameo` is intentionally absent until a component meets both criteria:
1. Concurrent operations must be coordinated over shared mutable state (mailbox semantics needed).
2. The component has an explicit lifecycle requirement (`on_start`/`on_stop`, supervision, or restart policy).

If a component is stateless or only needs simple read-heavy caching, keep it as plain structs + typed APIs.

## Build & Run
Run from repo root:
- `just fmt-check`
- `just lint`
- `just build`
- `just test`
- `just run`
- `just ci`

Security/hygiene:
- `just audit`
- `just deny`

SQLx cache maintenance:
- `just sqlx-prepare`
- `just sqlx-check`

## Environment Variables
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `DATABASE_URL` | `String` | Yes | none | PostgreSQL connection URL, must start with `postgres://` or `postgresql://`. |
| `JWT_SECRET` | `SecretString` | Yes | none | JWT signing secret (never log this value). |
| `PACK_STORAGE_PATH` | `PathBuf` | No | `./packs` | Base directory for pack file storage. |
| `GOOGLE_CLIENT_ID` | `String` | No | empty | Expected Google OAuth client id for ID token audience checks. |
| `BIND_ADDRESS` | `SocketAddr` | No | `0.0.0.0:8080` | HTTP bind address; `port` is derived from this value. |
| `BASE_URL` | `String` | No | `http://localhost:8080` | External base URL used in generated download links. |
| `ADMIN_API_KEY` | `String` | No | empty | Shared key for admin endpoints; empty disables admin access. |

## SQLx Offline Mode
- After any migration or query change, run `cargo sqlx prepare --workspace` with a live `DATABASE_URL`, then commit the updated `.sqlx/` directory.
- `SQLX_OFFLINE=true` belongs only in CI env vars, never in `.env`.
- The `.sqlx/` folder must always be committed and must never be gitignored.
- CI freshness check must use a live DB: `cargo sqlx prepare --check --workspace -- --all-targets --all-features`.

## Testing Strategy
- Unit tests: use `mockall` mocks generated from trait boundaries (`MockXxx`).
- Storage integration tests: PostgreSQL + migrations (feature-gated via `postgres-tests`).
- HTTP integration tests: in-process Axum app, no external network calls.
- Business logic should be tested without live DB/network by injecting mocked trait objects.

## Testing Contract

### Golden Rule
**Every behaviour change MUST be accompanied by a test that would fail
without that change.** If you modify a function and no test fails when you
revert your change, your test is worthless. Write the test first or
immediately after, never skip it.

### Coverage Gates (enforced in CI)
- `crates/domain`: 95% line coverage minimum
- `crates/api`: 85% line coverage minimum
- `crates/storage`: excluded from coverage gate — integration tests only
- Run `just coverage-ci` before submitting any change

### Test File Conventions
- Unit tests live in `#[cfg(test)] mod tests {}` at the bottom of the file
  they test — NOT in a separate `tests/` file
- Integration tests (requiring live DB) live in `crates/storage/tests/`
  behind `#[cfg(feature = "postgres-tests")]`
- Never test storage logic with mocked DB — mock at the repository trait
  boundary, not inside the DB layer

### Mandatory Test Cases Per Handler
Every Axum handler must have unit tests covering:
1. Happy path → correct HTTP status + response shape
2. Auth failure → 401
3. Input validation failure → 400
4. Downstream (repo/service) error → 500

### Mandatory Test Cases Per Domain Type
Every newtype must have:
1. Valid construction
2. Serde round-trip
3. Rejection of invalid input (if validation exists)

### Mock Usage Rules
- All I/O traits are annotated with `#[cfg_attr(test, mockall::automock)]`
- Inject mocks via `Arc<dyn Trait + Send + Sync>` — never use concrete types
  in handler/service signatures
- MockXxx structs are available automatically — do not hand-write fakes
- Always assert `.times(n)` on expectations to catch unexpected extra calls

### What You Must NOT Do
- Do NOT add `#[allow(dead_code)]` to silence untested code — fix or delete it
- Do NOT write tests that only assert `result.is_ok()` without checking the value
- Do NOT mock the storage layer internals (sqlx, PgPool) — mock at the
  repository trait boundary only
- Do NOT skip tests to meet a deadline — coverage gate will block CI
- Do NOT commit with `SQLX_OFFLINE=false` or missing `.sqlx/` cache

### Running Tests Locally
```bash
just test                  # unit tests only, no DB needed
just test-integration      # requires: docker compose up -d postgres
just coverage              # HTML report, opens in browser
just coverage-ci           # same as CI gate, fails under 85%
```

## Error Handling Contract
- Library crates (`api`, `storage`, `domain`, `config`) use typed `thiserror` error enums.
- Binary crate (`crates/api/src/main.rs`) uses `anyhow` at the top-level boundary.
- Handlers return `DomainError` only.
- `unwrap()`/`expect()` are forbidden outside tests and startup initialization.

## Anti-Patterns (Forbidden)
1. Raw `sqlx::query()`/`query_as()` in production code (use SQLx typed macros).
2. `unwrap()`/`expect()` in async request/repository paths.
3. Business logic embedded directly in DB access layer SQL blocks.
4. Direct `std::env::var` reads outside `iqrah-backend-config`.
5. Adding `kameo` actors without satisfying the two actor criteria above.

## API Contract

### Source of Truth
The `openapi.json` file at repo root is **auto-generated** from utoipa
annotations on Axum handlers. It is the single source of truth for the
entire REST API surface.

**Never edit `openapi.json` manually.**

### After Any Handler Change
1. Add or update the `#[utoipa::path(...)]` annotation on the handler
2. Add `#[derive(utoipa::ToSchema)]` to any new request/response types
3. Register new paths and schemas in `crates/api/src/openapi.rs`
4. Run `just spec` and commit the updated `openapi.json`
5. CI `spec-check` job will fail if you forget step 4

### Breaking vs Non-Breaking Changes
- Adding a new optional field: non-breaking - safe to ship
- Removing a field: breaking - coordinate with iqrah-mobile team first
- Renaming a field: breaking - use `#[serde(rename = "...")]` to keep
  wire name stable while renaming the Rust field
- Changing a field type: breaking - version the endpoint instead

### Swagger UI (local dev only)
Run `just swagger` to open the interactive Swagger UI at
`http://localhost:8080/swagger-ui`. Never enable in production builds.

### Anti-Patterns
- Do NOT return ad-hoc `serde_json::json!({...})` error bodies -
  always use the typed `ApiError` struct
- Do NOT add a handler without a `#[utoipa::path]` annotation -
  undocumented endpoints don't exist as far as the mobile client is concerned
- Do NOT merge a PR that makes `just spec-check` fail
