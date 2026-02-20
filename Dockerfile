# Build stage
FROM rust:1.83 AS builder

WORKDIR /app

# Copy workspace manifests
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/
COPY migrations/ migrations/

# Build release binary
RUN cargo build --release --bin iqrah-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/iqrah-server /app/iqrah-server
COPY --from=builder /app/migrations /app/migrations

EXPOSE 8080

CMD ["/app/iqrah-server"]
