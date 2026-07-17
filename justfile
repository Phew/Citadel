# Citadel developer commands. Requires: cargo, docker, just.

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set dotenv-load := true

default:
    @just --list

# Install pinned Rust toolchain components (from rust-toolchain.toml).
setup:
    rustup show
    rustup component add rustfmt clippy

# Format all workspace crates.
fmt:
    cargo fmt --all

# Check formatting without writing.
fmt-check:
    cargo fmt --all -- --check

# Clippy with warnings denied (CI parity).
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Run all unit/integration tests that do not need docker.
test:
    cargo test --workspace

# Full local gate: fmt + clippy + test.
check: fmt-check clippy test

# Build all workspace members (release).
build:
    cargo build --workspace --release

# Bring up postgres, minio, and all service stubs.
up:
    docker compose -f deploy/docker-compose.yml up -d --build

# Tear down the stack (keeps volumes).
down:
    docker compose -f deploy/docker-compose.yml down

# Tear down and remove volumes.
down-v:
    docker compose -f deploy/docker-compose.yml down -v

# Tail compose logs.
logs:
    docker compose -f deploy/docker-compose.yml logs -f

# One-command dev stack: build images, start, wait for health.
dev: up wait-healthy
    @echo "Citadel stack is up. Auth :8081 Delivery :8082 Directory :8083 Blobstore :8084"

# Poll service health endpoints until ready (or timeout).
wait-healthy:
    cargo run -p test-harness --bin wait-healthy -- --timeout-secs 120

# Status of compose services.
ps:
    docker compose -f deploy/docker-compose.yml ps
