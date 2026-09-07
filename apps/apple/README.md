# Citadel for macOS

A SwiftUI host over the Rust core (`crates/citadel-ffi` → `crates/citadel-app`
→ `crates/citadel-core`). The app renders; every trust decision — key
transparency verification of peers, wire-version checks, MLS — happens in
Rust. Keys never leave the machine: the identity and device signing seeds
and the database encryption key live in the macOS Keychain, the MLS state in
a SQLCipher database under the profile directory.

## Run it (dev stack)

```sh
# 1. The stack: postgres + minio in compose, the four services natively.
docker compose -f deploy/docker-compose.yml up -d postgres minio
export DATABASE_URL=postgres://citadel:citadel@127.0.0.1:5432/citadel
export CITADEL_KT_LOG_SEED=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=   # dev seed, public
cargo run -p citadel-migrations --bin citadel-migrate
PORT=8081 cargo run -p auth-service &  PORT=8082 cargo run -p delivery-service &
PORT=8083 cargo run -p directory-service &  PORT=8084 cargo run -p blobstore-service &

# 2. The core, then the app.
cargo build -p citadel-ffi
cd apps/apple && swift run CitadelApp
```

Two instances on one Mac (to talk to yourself):

```sh
CITADEL_PROFILE=/tmp/citadel-a CITADEL_KEYCHAIN_SERVICE=Citadel-dev-a swift run CitadelApp &
CITADEL_PROFILE=/tmp/citadel-b CITADEL_KEYCHAIN_SERVICE=Citadel-dev-b swift run CitadelApp &
```

Register a handle in each, then **New DM** with the other's handle. The
peer is resolved through `GET /v1/kt/leaf` and its identity key verified
against the key-transparency log before the DM is created.

`CITADEL_AUTH_URL` / `CITADEL_DELIVERY_URL` override the service bases. The
dev build derives the log anchor from the public dev seed; a shipped build
embeds the real anchor via `Client.open(…, ktAnchorHex:)`.

## Regenerate the binding

After changing `crates/citadel-ffi`:

```sh
apps/apple/scripts/generate-bindings.sh
```

## Layout

- `Sources/CitadelFFI` — the UniFFI-generated C header and modulemap.
- `Sources/Citadel` — the generated Swift binding; links `libcitadel_ffi.a`
  from `../../target/<profile>` (`CITADEL_RUST_TARGET_DIR`, `CITADEL_RUST_PROFILE`).
- `Sources/CitadelApp` — the SwiftUI app: `AppModel` (all core calls off the
  main thread, events back on it), `RootView`.

Not yet: an Xcode project and signed bundle, iOS target, XCTest coverage of
`AppModel`. The terminal client (`cargo run -p citadel-cli`) exercises the
same core calls and is the quickest way to drive a second peer.
