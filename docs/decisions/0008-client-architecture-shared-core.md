# ADR-0008: Client architecture — one Rust core under native UIs and a web client

- **Status:** PROPOSED
- **Date:** 2026-09-06
- **Deciders:** charge (required for ACCEPTED); author: core
- **Invariants touched:** INV-1 (the plaintext boundary moves from "the Tauri process" to "the Rust core plus the host UI process"), INV-2 (signing seeds and the database encryption key cross a host callback on mobile), INV-4 (the production KT verifier moves into the core), INV-5 (wire-version refusal moves into the core), INV-9 (browser entropy is `crypto.getRandomValues` through `getrandom/js`), INV-10 (no new primitives; wasm uses the same OpenMLS/RustCrypto chain)
- **Related:** plans/PLAN.md §1 non-goals (mobile), §3, §4 (Tauri is a fixed stack pin; this ADR is the substitution §4 requires), §5, §12 (mobile via UniFFI); ADR-0007 (the store this core carries) and its Amendment 3 (proposed below); ADR-0009 (web trust tier and storage); docs/issues/016 (wasm32 spike); PR #69

## Context

PLAN §4 pins the client as "Tauri 2 + React" over `citadel-core` and lists
mobile as "the same crate later reused via UniFFI." On 2026-09-06 charge
decided the shipped clients are **truly native**: SwiftUI on macOS and iOS,
Jetpack Compose on Android, WinUI on Windows, plus a **browser client** as a
lower-trust tier. That replaces a fixed §4 technology, which §4 says happens
only by ADR. This is that ADR.

What exists: `citadel-core` owns MLS (OpenMLS 0.8.1, one pinned ciphersuite),
credential verification, padding, and — on PR #69 — the SQLCipher-backed local
store with an OS credential-store contract (`store::credentials::CredentialStore`,
a trait object already injected at `LocalStore::open`). What does not exist:
any transport implementation (`transport::DeliveryTransport` has no
implementor in the crate), any production `IdentityVerifier` (the real one is
`crates/test-harness/src/dm.rs`), any session state machine, any FFI, any wasm
build, and any client that links the core at all (`apps/desktop` is a mock).

Constraints: the ten invariants; ADR-0007's store boundary (§6) and its
desktop-only credential backends (§2, `compile_error!` elsewhere); the
`testing` feature must never enter a shipped binary (docs/issues/015 N4);
docs/issues/016's finding that the core compiles for wasm32 with three
target-scoped feature enables and that the store does not.

## Decision

**One Rust core, four native hosts, one browser host.** Concretely:

1. **`citadel-core` stays the plaintext boundary** (INV-1) and gains a feature
   layout so the same crate serves every target:
   - `store` — the ADR-0007 SQLCipher store and `openmls_sqlite_storage`.
     Default on every non-wasm target. Not buildable for wasm32.
   - `native-credentials` — the Windows, macOS, and Linux adapters. Implied by
     `store` on those targets. Other targets get **no** `NativeCredentialStore`
     and no compile error: the host provides one (ADR-0007 Amendment 3).
   - `host-paths` — `ProfilePaths::host_root(PathBuf)` for hosts whose
     application-data directory is not derivable from the environment
     (iOS, Android). Not a `testing` sub-feature.
   - `web-storage` — the ADR-0009 browser storage tiers. wasm32 only.
   - `testing` — unchanged; release graphs are checked to exclude it.
   - the wasm32 target table from docs/issues/016 (`openmls/js`,
     `getrandom/js`, `uuid/js`).
   Two gaps the core closes at the same time because every host would
   otherwise re-implement them: `Envelope::version_supported()` is checked on
   every received envelope (INV-5) and every MLS wire message is
   length-bounded (`citadel_proto::envelope::MAX_WIRE_BYTES` per
   `EnvelopeKind`) before `tls_deserialize_exact_bytes`.

2. **`crates/citadel-app` is the app core: pure Rust, no FFI, no runtime
   dependency.** It owns what a client *does* with the core: the session state
   machine (`NoProfile → Registered → Enrolled → Online`), F1 registration and
   enrollment (seeds through `CredentialStore`, self-inclusion verification per
   `docs/protocol/auth.md`, KeyPackage publication), F2 create/join, F4
   send/receive, the **outbox loop** (drain `pending_transmissions()`, submit
   under the stored idempotency key, acknowledge only on terminal acceptance;
   self-updates confirm on acceptance, abort on terminal rejection, hold on
   indeterminate), the **inbox loop** (gateway frames and `fetch(after=)` both
   feed `receive`, dedup is the store's), and the **production KT verifier**
   moved out of the harness (head → consistency against the persisted
   checkpoint → inclusion, attesting nothing without a verified proof). It
   talks to servers only through two traits it defines, `AuthTransport` and
   the existing `DeliveryTransport` (extended with a gateway stream), and
   schedules only through a `Spawner`/`Sleep`/`Clock` abstraction, so the same
   loops run on tokio and on `wasm-bindgen-futures`. Its storage seam is an
   `MlsStateStore` trait: the subset of `LocalStore` the app uses. Native
   hosts get `LocalStore`; web gets ADR-0009's tiers.

3. **`crates/citadel-ffi` is the UniFFI surface for native hosts.** Proc-macro
   UniFFI (no UDL), `crate-type = ["cdylib", "staticlib"]`, a tokio runtime
   inside the library, async methods exported with
   `uniffi::export(async_runtime = "tokio")`. Hosts implement three callback
   interfaces: `HostCredentialStore` (read/write/delete of the three 32-byte
   `SecretItem`s plus `backend_name`, mirroring `CredentialStore` exactly),
   `AppEventListener` (messages, epoch changes, KT alerts, connection state,
   errors), and `HostPaths`. Desktop hosts may pass the Rust
   `NativeCredentialStore` instead of implementing the callback. Bindings:
   Swift and Kotlin from `uniffi-bindgen`; C# from `uniffi-bindgen-cs`. The
   `uniffi` version is pinned at the time spike S3 (a hello-world binding for
   all three languages) passes, and `uniffi-bindgen-cs` is pinned to the
   release that matches it; 0.32 is current at the time of writing.

4. **`crates/citadel-web` is the wasm-bindgen surface for the browser.** Not
   UniFFI. Same `citadel-app`; transports over `fetch` and `WebSocket`
   (`gloo-net` or `web-sys`); spawner over `wasm-bindgen-futures`; storage and
   trust tier per ADR-0009.

5. **Hosts.** One SwiftUI multiplatform target for macOS 14+ and iOS 17+
   (`apps/apple`, xcframework from the staticlib); Jetpack Compose
   (`apps/android`, `cargo-ndk` → `jniLibs`); WinUI 3 with C# (`apps/windows`);
   Vite + React (`apps/web`, reusing the honesty-typed components of the
   current shell). `apps/desktop` (Tauri) is **retired** once `apps/web`
   renders against the real core: a fourth desktop shell over the same core is
   maintenance without a user, and a webview shell would blur the "native"
   claim. Its mock remains valuable only as the type-level "no `encrypted`
   variant unless the real core says so" pattern, which `apps/web` keeps.

6. **The host is inside the trust boundary, and the ADR says so.** Plaintext
   message content crosses the FFI to be rendered; the database encryption key
   and both signing seeds cross the credential-store callback on mobile. A
   host UI is therefore part of the client TCB exactly as the Tauri process
   was. Nothing in this design lets a host see MLS group secrets, private HPKE
   keys, or the OpenMLS state: those never leave `citadel-core`. Hosts never
   parse MLS bytes, never see a KeyPackage, and never make a trust decision:
   the KT alert a host renders is the core's verdict, not the host's.

7. **Web is a different tier**, stated in ADR-0009 and rendered permanently in
   the web UI. Web devices are ordinary MLS leaves and ordinary KT-attested
   devices; the tier difference is about who delivers the code and where keys
   rest, not about the protocol.

## Alternatives considered

1. **Tauri 2 everywhere (desktop + mobile), web via the same React UI over
   wasm.** Fastest to four platforms with one UI. Rejected by charge on
   2026-09-06: the shipped apps are to be native, not webviews. Kept as the
   fallback for Windows only if `uniffi-bindgen-cs` proves unmaintained at
   spike S3.
2. **Native UIs each with their own MLS stack** (e.g. a Swift MLS library on
   Apple). Rejected: four cryptographic implementations to audit, four codec
   corpora, four KT verifiers; INV-10 becomes four times harder to hold.
3. **Flutter or React Native over the Rust core.** Rejected: neither is native
   in the sense charge chose, and each adds a second FFI layer (Dart/JS ↔
   platform ↔ Rust) between the UI and the core.
4. **Loops in each host instead of in Rust.** Rejected: the outbox and inbox
   loops encode ADR-0007 §5's atomic units and the ledger's acknowledge /
   confirm / abort discipline. Five re-implementations would drift, and the
   one that drifted would be the one that double-applied a self-update.
5. **UniFFI for the browser too.** Not possible: UniFFI targets native ABIs;
   the browser needs wasm-bindgen. Two thin surfaces over one `citadel-app`
   is the smallest honest answer.

## Consequences

- Positive: one MLS implementation, one store, one KT verifier, one outbox
  discipline across five hosts; the M2 "LocalStore-backed drivable client"
  nobody owned (docs/status/core.md) becomes `citadel-app`, which the harness
  drives for the FS and PCS evidence too.
- Negative: five UI codebases to keep in step (mitigated: they are thin, and
  every trust decision is in Rust); two binding surfaces; Windows depends on a
  third-party binding generator; the credential-store callback widens the
  code that handles 32-byte secrets to Swift and Kotlin.
- Follow-ups:
  - **ADR-0007 Amendment 3** (proposed with this ADR, ruled on with it):
    §2's "on an unsupported target the crate does not compile" becomes "on a
    target with no native adapter the host must provide a `CredentialStore`;
    the store still never generates a replacement key and still fails closed
    on every error class." iOS uses the Keychain with
    `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no iCloud sync); Android
    uses a Keystore-resident AES key wrapping the 32-byte secret. Whether
    `keyring`'s iOS module could serve instead of the Swift host store is a
    spike, not a claim.
  - **Spike S2**: SQLCipher (`rusqlite` with vendored OpenSSL) for
    `aarch64-apple-ios` and `aarch64-linux-android`. Expected to pass
    (`openssl-src` ships both configurations), which keeps `cipher_provider =
    "openssl"` pinned; the iOS fallback (CommonCrypto) changes that pin and
    needs its own amendment.
  - **Spike S3**: pin `uniffi` and `uniffi-bindgen-cs` by generating and
    compiling a hello-world binding for Swift, Kotlin, and C#.
  - `GET /v1/kt/leaf?account=` on auth-service: the production verifier needs
    leaf coordinates for a peer it did not register itself (the harness only
    ever verified peers it created). Server-supplied hint; the client verifies
    inclusion (INV-4). PLAN §8 gains the endpoint.
  - `PendingTransmission::disposition` in `store/actor.rs` plus schema V2, so
    the outbox can distinguish acknowledge-on-accept from confirm-self-update.
  - docs/issues/012 DEFECT 2 (orphaned KeyPackages) is reached by every
    client; resolve before M3 (published flag + reaper as a §5 atomic unit).

## Evidence

- `citadel-core`: `receive_rejects_oversized_wire_message`,
  `join_rejects_oversized_welcome`,
  `receive_rejects_commit_adding_unattested_member`, and a CI
  `cargo check -p citadel-core --no-default-features` step.
- `citadel-app` (fake transports): `app_registers_verifies_own_kt_inclusion_and_enrolls`,
  `app_outbox_submits_stored_pending_bytes_under_stored_keys_and_acknowledges_only_on_acceptance`,
  `app_self_update_confirms_after_acceptance_aborts_after_rejection_and_holds_on_indeterminate`,
  `app_inbox_dedups_overlapping_ws_and_sync_delivery`,
  `app_rejects_unsupported_wire_version`,
  `app_never_publishes_key_packages_without_a_verified_self_inclusion`,
  `kt_verifier_attests_nothing_without_a_verified_inclusion_proof`,
  `kt_verifier_rejects_a_larger_head_without_consistency_proof`,
  `kt_verifier_rejects_head_under_wrong_anchor`; harness
  `adversarial_as_serves_forked_tree_head_rejected`.
- `citadel-ffi`: `ffi_host_credential_store_roundtrips_through_callback`;
  `ci/check_release_features.sh` proving `testing` and the credential double
  are absent from the `citadel-ffi` release graph; a CI job generating the
  Swift, Kotlin, and C# bindings.
- `citadel-web`: a CI `wasm` job (`cargo check -p citadel-web --target
  wasm32-unknown-unknown`), then the ADR-0009 tests.
- Harness: `f2_three_client_dm_creation_durable` through `citadel-app` over
  `LocalStore`, which is the client the M2 FS and PCS evidence then uses.
