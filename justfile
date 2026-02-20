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
