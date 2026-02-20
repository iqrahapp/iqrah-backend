# iqrah-backend-storage

Storage layer for the Iqrah backend, providing repositories for users, packs, and sync operations.

## Testing Strategy

### Default: SQLite integration tests (fast, sandbox-safe)

Run:

```bash
cd backend
cargo test -p iqrah-backend-storage --test integration_sqlite_tests
```

These tests use `tests/integration_sqlite/test_support.rs`, which:
- creates a unique file-backed SQLite DB per test
- runs migrations automatically from `migrations_sqlite/` using `sqlx::migrate!`
- enables `PRAGMA foreign_keys=ON`
- sets WAL mode for local concurrency friendliness
- removes DB files after test completion

To keep DB files for debugging:

```bash
TEST_KEEP_DB=1 cargo test -p iqrah-backend-storage --test integration_sqlite_tests
```

### Existing Postgres tests

Postgres-specific tests are feature-gated and disabled by default.

```bash
RUN_PG_TESTS=1 DATABASE_URL=postgres://... cargo test -p iqrah-backend-storage --tests --features postgres-tests
```

## Future Postgres expansion (placeholder)

`tests/integration_postgres/` is reserved for future Postgres-specific integration tests.
The intended gate is `RUN_PG_TESTS=1` once those are added.
