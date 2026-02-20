# Backend Concurrency Rework

> Audited: 2026-02-19
> Scope: `backend/` workspace

## Executive Summary

The backend has **one shared mutable primitive** with the wrong ownership model:
`Arc<DashMap<i32, bool>>` in `AppState` — the pack integrity verification cache.

The problem is not the DashMap itself (shard-based RwLock is fine for a read-heavy cache). The problem is **naked ownership**: a raw concurrent primitive exposed directly in `AppState` and accessed from three different files with no typed API. This scatters all cache logic across the codebase with no single owner.

**Verdict:** Wrap `DashMap` in a `PackVerificationCache` struct with a typed, centralised API. No framework needed. The `kameo` actor pattern is reserved for state that needs cross-operation coordination — this cache does not.

---

## Design Decision: Wrapper Struct vs Actor

| Primitive | Location | Verdict |
|-----------|----------|---------|
| `Arc<DashMap<i32, bool>>` (`verified_packs`) | `lib.rs:39`, `packs.rs:180,209,211,239`, `main.rs:49` | **WRAP** in `PackVerificationCache` |
| `Arc<dyn IdTokenVerifier>` | `lib.rs:37`, `auth.rs:138` | OK — shared immutable trait object |
| `Arc<AppState>` | every handler via Axum `State` extractor | OK — Axum standard, read-only after init |
| `spawn_blocking` (Google JWT verify) | `auth.rs:140` | OK — correct use for sync crypto call |
| `PgPool` (Arc-backed internally) | all repository structs | OK — pool owns all connection concurrency |
| Postgres transactions | `sync_repository.rs` (`pool.begin()`) | OK — database handles isolation |
| `Mutex` / `RwLock` | **nowhere** | N/A |

---

## Issue: Naked `Arc<DashMap<i32, bool>>`

### What it does

`verified_packs` caches SHA256 integrity check results. On first download of a pack version, the server hashes the file on disk and compares it to the stored checksum. If it matches, `version_id → true` is stored. Subsequent downloads skip the hash.

### Why the current shape is wrong

The issue is not DashMap's performance — shard-based concurrent reads are fine for a cache that is mostly read. The issue is that a raw `Arc<DashMap>` has no owner and no typed API:

| Operation | Location |
|-----------|----------|
| Initialisation (`DashMap::new()`) | `main.rs:49` |
| Read (`contains_key`) | `packs.rs:211` |
| Write (`insert`) | `packs.rs:239` |
| Invalidate (`remove`) | `lib.rs:45` (`invalidate_pack_cache`) |
| Clear (`clear`) | `lib.rs:68` (`add_pack_version`) |

Any new cache behaviour (TTL eviction, metrics, size limits) requires touching multiple files. There is no single place to look to understand what the cache does or how it behaves.

### Why an actor is overkill here

An actor would serialise all reads through a single-threaded mailbox — worse throughput than DashMap's concurrent shard reads for a read-heavy workload. It would also add an async round-trip to every download request just to check a bool. The actor pattern is the right choice when state needs cross-operation coordination; this cache is append-only with occasional full clears.

---

## Fix: `PackVerificationCache` Wrapper Struct

A named struct with a typed API centralises all cache logic in one file with no new dependencies and no async overhead.

### New file: `backend/crates/api/src/cache/pack_verification.rs`

```rust
use std::sync::Arc;
use dashmap::DashMap;

/// Cache of SHA256-verified pack version IDs.
/// Avoids re-hashing files on every download request.
/// Thread-safe: DashMap allows concurrent reads.
#[derive(Clone)]
pub struct PackVerificationCache(Arc<DashMap<i32, bool>>);

impl PackVerificationCache {
    pub fn new() -> Self {
        Self(Arc::new(DashMap::new()))
    }

    /// Returns true if this version has already been verified.
    pub fn is_verified(&self, version_id: i32) -> bool {
        self.0.contains_key(&version_id)
    }

    /// Mark a version as verified after successful SHA256 check.
    pub fn mark_verified(&self, version_id: i32) {
        self.0.insert(version_id, true);
    }

    /// Remove a single version (called when a pack version is invalidated).
    pub fn invalidate(&self, version_id: i32) {
        self.0.remove(&version_id);
    }

    /// Clear all entries (called when a new pack version is registered).
    pub fn clear(&self) {
        self.0.clear();
    }
}
```

New module file: `backend/crates/api/src/cache/mod.rs`

```rust
pub mod pack_verification;
```

### Change: `backend/crates/api/src/lib.rs`

**Add module:**
```rust
pub mod cache;
```

**`AppState` field** — replace:

```rust
// Before
pub verified_packs: Arc<DashMap<i32, bool>>,

// After
pub pack_cache: PackVerificationCache,
```

**`invalidate_pack_cache`** — replace:

```rust
// Before
self.verified_packs.remove(&pack_version_id);

// After
self.pack_cache.invalidate(pack_version_id);
```

**`add_pack_version`** — replace:

```rust
// Before
self.verified_packs.clear();

// After
self.pack_cache.clear();
```

Remove `use dashmap::DashMap;` import.

### Change: `backend/crates/api/src/main.rs`

```rust
// Before
verified_packs: Arc::new(DashMap::new()),

// After
pack_cache: PackVerificationCache::new(),
```

Remove `use dashmap::DashMap;` import.

### Change: `backend/crates/api/src/handlers/packs.rs`

**`verify_pack_integrity` signature** — replace `&DashMap<i32, bool>` with `&PackVerificationCache`.

**Cache operations** — replace:

```rust
// Before
if verified_packs.contains_key(&version_id) {
    return Ok(());
}
// ...
verified_packs.insert(version_id, true);

// After
if pack_cache.is_verified(version_id) {
    return Ok(());
}
// ...
pack_cache.mark_verified(version_id);
```

Remove `use dashmap::DashMap;` import. Update call sites to pass `&state.pack_cache`.

---

## Actor Pattern: When It Actually Applies

Use `kameo` actors when shared mutable state needs **cross-operation coordination** — where you can't reason about correctness with a simple read/write API:

| Situation | Pattern |
|-----------|---------|
| Read-heavy cache, simple gets/sets | Wrapper struct (like `PackVerificationCache`) |
| State with complex transitions or invariants | `kameo` actor |
| Rate limiting (per-IP counters, sliding windows) | `kameo` actor |
| In-flight request deduplication | `kameo` actor |
| Anything needing serialised access for correctness | `kameo` actor |

The decision criterion: **can a simple typed API on a concurrent primitive express all invariants?** If yes, use a wrapper struct. If operations need to be atomic across multiple steps (check-then-act with side effects), use an actor.

---

## Future Actor Candidates

The following features are absent from the backend (documented in `docs/backend/AUDIT.md`). When built, they require actors — not wrapper structs.

| Feature | Why actor (not wrapper struct) |
|---------|-------------------------------|
| Rate limiting | Sliding window counters require atomic check-and-decrement across multiple requests |
| In-flight download deduplication | "Already computing SHA256 for this version" requires parking callers until work completes |
| JWT token cache with expiry | TTL eviction needs a background task coordinated with reads |
| Nonce/session invalidation | Requires tracking complex state transitions across requests |

---

## What Must Not Change

- Repositories remain stateless `PgPool` wrappers.
- `Arc<dyn IdTokenVerifier>` remains immutable shared dependency.
- `spawn_blocking` for Google JWT verification stays.
- Transaction logic in `SyncRepository` stays.

---

## Implementation Tasks

For the scheduling agent — execute in order, each is independently verifiable:

**Task 1 — Create `PackVerificationCache`**
- Create `backend/crates/api/src/cache/mod.rs`
- Create `backend/crates/api/src/cache/pack_verification.rs` with the spec above
- Add `pub mod cache;` to `backend/crates/api/src/lib.rs`
- Run `cargo build -p iqrah-backend-api` to confirm it compiles

**Task 2 — Update `AppState`**
- File: `backend/crates/api/src/lib.rs`
- Replace `verified_packs: Arc<DashMap<i32, bool>>` with `pack_cache: PackVerificationCache`
- Update `invalidate_pack_cache` and `add_pack_version` to use typed methods
- Remove `use dashmap::DashMap`

**Task 3 — Update `main.rs`**
- File: `backend/crates/api/src/main.rs`
- Replace `Arc::new(DashMap::new())` with `PackVerificationCache::new()`
- Remove `use dashmap::DashMap`

**Task 4 — Update `packs.rs`**
- File: `backend/crates/api/src/handlers/packs.rs`
- Change `verify_pack_integrity` parameter from `&DashMap<i32, bool>` to `&PackVerificationCache`
- Replace `contains_key` + `insert` with `is_verified` + `mark_verified`
- Remove `use dashmap::DashMap`
- Update call sites to pass `&state.pack_cache`

**Task 5 — Run full CI checks**

```bash
cd backend
cargo fmt --all -- --check
cargo clippy --all -- -D warnings
cargo test --all
```

All must pass before closing this rework.
