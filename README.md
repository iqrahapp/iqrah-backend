# iqrah-backend

Standalone Rust backend workspace for Iqrah mobile.

## Overview
This repository contains only backend concerns: HTTP API (`axum`), domain contracts, storage repositories (`sqlx` + PostgreSQL), and configuration/loading. Flutter/mobile, assets monorepo data, and R&D projects are intentionally decoupled.

## Workspace
- `crates/api` - HTTP server, middleware, handlers, route composition.
- `crates/domain` - domain DTOs, newtypes, domain error mapping.
- `crates/storage` - repository traits + PostgreSQL implementations.
- `crates/config` - environment loading/validation.
- `migrations/` - PostgreSQL schema migrations.
- `.sqlx/` - SQLx offline metadata cache (must be committed).
- `docs/backend/` - backend docs migrated from monorepo.

## Prerequisites
- Rust `1.93.1` (pinned in `rust-toolchain.toml`).
- PostgreSQL for runtime and SQLx cache refresh.

## Environment Variables
| Name | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | none | PostgreSQL URL (`postgres://...`). |
| `JWT_SECRET` | yes | none | JWT signing secret. |
| `PACK_STORAGE_PATH` | no | `./packs` | Pack file storage root. |
| `GOOGLE_CLIENT_ID` | no | empty | Google OAuth audience id. |
| `BIND_ADDRESS` | no | `0.0.0.0:8080` | HTTP bind address. |
| `BASE_URL` | no | `http://localhost:8080` | Public API base URL. |
| `ADMIN_API_KEY` | no | empty | Enables admin endpoints when set. |

## Common Commands
- `just fmt-check`
- `just lint`
- `just build`
- `just test`
- `just run`
- `just ci`

## SQLx Offline Cache
1. Set a live `DATABASE_URL`.
2. Run `cargo sqlx prepare --workspace`.
3. Commit `.sqlx/` updates.

Important:
- Do not set `SQLX_OFFLINE=true` in `.env`.
- `SQLX_OFFLINE=true` belongs only in CI env vars.
- `.sqlx/` must always be committed (never gitignored).
