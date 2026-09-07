# 016: SPIKE — does `citadel-core` compile for `wasm32-unknown-unknown`?

**Date:** 2026-09-06. **Lane:** core. **Status:** RESOLVED — yes, with three
target-scoped feature enables and no source change. Feeds ADR-0008 (client
architecture) and ADR-0009 (web client trust tier and storage).

## Question

The web client (PLAN §3, pending ADR-0008) needs the client core in the
browser. Nothing in the repo had ever targeted wasm. Does `citadel-core` on
`main` (`bc67710`, in-memory OpenMLS provider, no store) compile for
`wasm32-unknown-unknown` under the pinned toolchain (1.95.0), and what does it
take?

## Method

A scratch clone of `main`, `rustup target add wasm32-unknown-unknown` on the
pinned toolchain, and `cargo check -p citadel-core --target wasm32-unknown-unknown`
iterated until green. Each failure and its fix is listed so the next reader
does not re-derive them.

| Pass | Result | Cause | Fix |
|---|---|---|---|
| 1 | fail | `getrandom 0.2.17`: "wasm*-unknown-unknown targets are not supported by default, enable the `js` feature" | `getrandom = { version = "0.2", features = ["js"] }` for the wasm32 target |
| 2 | fail | `openmls 0.8.1` `compile_error!`: "JavaScript APIs must be available (secure randomness and the current time)… set the `js` feature on OpenMLS"; plus `fluvio_wasm_timer` unresolved in `key_packages/lifetime.rs` | `openmls = { version = "=0.8.1", features = ["js"] }` for the wasm32 target (the feature pulls `fluvio-wasm-timer` and `getrandom/js` itself) |
| 3 | fail | my own mistake: `package = "openmls"` under a second name is "depends on crate `openmls` multiple times with different names" | use the canonical dependency name in the target table; Cargo unifies features across `[dependencies]` and `[target.*.dependencies]` |
| 4 | **pass** | — | — |

The passing target table, verbatim:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
openmls = { version = "=0.8.1", features = ["js"] }
getrandom = { version = "0.2", features = ["js"] }
uuid = { version = "1", features = ["js"] }
```

Also verified on pass 4: `--features testing` compiles for wasm32 (the harness
path), and the native `cargo check -p citadel-core` is unaffected by the
presence of the wasm target table.

## Findings that matter for the ADRs

1. **Upstream supports it.** OpenMLS ships a `js` feature specifically for
   `wasm32-unknown-unknown`; this is not an unsupported target being coerced.
   Its `compile_error!` names the two things a browser must supply:
   randomness and the clock. Both come from the JavaScript host.
2. **Entropy is one chain.** On wasm32 only `getrandom 0.2` reaches
   `citadel-core`, via `openmls_rust_crypto → hpke-rs-rust-crypto → p256/k256 →
   … → rand_core 0.6`. `getrandom 0.3`/`0.4`, present elsewhere in the
   workspace lock, are not in the client core's wasm graph, so no
   `--cfg getrandom_backend` flag is needed. INV-9 in the browser therefore
   means `crypto.getRandomValues` through `getrandom/js`; ADR-0009 should say
   so explicitly.
3. **The store does not come along.** This spike is against `main`, whose
   provider is in-memory. PR #69's store (`rusqlite` with vendored SQLCipher,
   `keyring`, `libc`) does not target wasm32, which is why ADR-0008 makes the
   `store` feature optional and non-default on wasm and why ADR-0009 defines
   web storage tiers instead of porting SQLCipher.
4. **`std::time` did not bite** at `cargo check` on `main`; OpenMLS's own
   lifetime checks route through `fluvio-wasm-timer` under `js`. Any
   `SystemTime::now()` the app core adds later must go behind the
   `Spawner`/clock abstraction ADR-0008 specifies, because on wasm32 a bare
   `SystemTime::now()` panics at runtime rather than failing to compile.

## What this does not prove

`cargo check` proves the graph resolves and type-checks. It does not run a
single MLS operation in a browser. The first evidence test in
`crates/citadel-web` (`web_core_compiles_for_wasm32`, a CI `wasm` job) turns
this into a standing check; the first `wasm-bindgen-test` run in headless
Chromium is what proves execution.

## Commands

```sh
rustup target add wasm32-unknown-unknown            # on the pinned 1.95.0 toolchain
cargo check -p citadel-core --target wasm32-unknown-unknown
cargo check -p citadel-core --features testing --target wasm32-unknown-unknown
```
