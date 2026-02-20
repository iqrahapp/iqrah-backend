# Backend Architecture

## Layers
- `api` - HTTP transport, auth extraction, response mapping.
- `domain` - shared data contracts and newtypes.
- `storage` - repository boundaries and PostgreSQL implementations.
- `config` - environment parsing and runtime configuration.

## Request Flow
1. Axum route dispatches to a feature handler.
2. Handler validates input and delegates to trait-backed dependencies from `AppState`.
3. Repository implementations perform SQLx operations.
4. Handler maps outputs/errors into `DomainError` and JSON responses.

## External Boundaries
- DB: `AuthRepository`, `PackRepository`, `SyncRepository`.
- Google JWT: `JwtVerifier`.
- Filesystem: `PackAssetStore`.

## Concurrency
- Tokio is the only async runtime.
- Shared mutable cache state is encapsulated in dedicated structs (`PackVerificationCache`).
- Actor model is intentionally not used until lifecycle/coordinated-mutation requirements appear.
