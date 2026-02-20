set shell := ["bash", "-cu"]

default:
    @just --list

build:
    cargo build --workspace --locked

test:
    cargo test --workspace --locked

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
