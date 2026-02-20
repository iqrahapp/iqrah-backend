set shell := ["bash", "-cu"]

default:
    @just --list

build:
    cargo build --workspace --locked

# Run all unit tests (no DB required)
test:
    cargo nextest run --workspace

# Run integration tests (requires live DB)
test-integration:
    cargo nextest run --workspace --features postgres-tests

# Coverage report (HTML)
coverage:
    cargo llvm-cov --workspace \
      --ignore-filename-regex "(migrations|tests|main\\.rs|crates/storage/src)" \
      --html --open

# Coverage in CI (fail under threshold)
coverage-ci:
    cargo llvm-cov --workspace \
      --ignore-filename-regex "(migrations|tests|main\\.rs|crates/storage/src)" \
      --fail-under-lines 85

# Mutation testing (run occasionally, not in main CI)
mutants:
    cargo mutants --workspace

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

sqlx-prepare:
    cargo sqlx prepare --workspace -- --all-targets --all-features

sqlx-check:
    cargo sqlx prepare --check --workspace -- --all-targets --all-features

audit:
    cargo audit

deny:
    cargo deny check

ci:
    just fmt-check
    just lint
    just build
    just test

run:
    cargo run -p iqrah-backend-api --bin iqrah-server

# Generate OpenAPI spec - always commit the result
spec:
    cargo run -p iqrah-backend-api --bin generate_spec > openapi.json
    @echo "openapi.json updated - commit this file"

# Used by CI to ensure spec is never stale
spec-check:
    cargo run -p iqrah-backend-api --bin generate_spec > /tmp/openapi_fresh.json
    diff openapi.json /tmp/openapi_fresh.json || \
      (echo "ERROR: openapi.json is stale - run 'just spec' and commit" && exit 1)

# Open Swagger UI locally (dev only)
swagger:
    cargo run -p iqrah-backend-api --bin iqrah-server --features swagger-ui
