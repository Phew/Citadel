# merkle-go — independent RFC 6962 oracle for kt-log

A small, standalone Go implementation of the RFC 6962 §2.1 Merkle algorithms
(Merkle Tree Hash, audit `PATH`, consistency `SUBPROOF`), used **only at test
time** to cross-check `crates/kt-log`'s Rust implementation.

## Why it exists

`PLAN.md` §13 requires capability claims to carry "an independent oracle where
one exists (e.g. the Go oracle pattern for Merkle structures)." kt-log's
`tree.rs` and this oracle are two independent implementations of the same RFC,
in different languages, written from the spec rather than from each other. When
kt-log reproduces this oracle's roots and proofs byte-for-byte, that agreement
is evidence both match RFC 6962 — not evidence they share a bug.

Approved in `docs/issues/001-import-verified-components.md` (Option A): a
test-time cross-check only. It ships in no product artifact, imports nothing
from any predecessor project, and links no Citadel code (no facade, no proto).

## What it produces

`go run .` writes the fixture corpus to stdout as deterministic JSON:

```
cd crates/test-harness/oracles/merkle-go
go run . > ../../../kt-log/tests/fixtures/merkle_rfc6962.json
```

The output is byte-stable (same corpora in → identical bytes out), so a
regenerate-and-diff CI step can detect drift between the oracle and the
committed fixtures. That CI wiring is owned by K3 (issue 001); the committed
fixtures and the consuming test (`crates/kt-log/tests/go_oracle_fixtures.rs`)
are owned by Opus.

The fixture contains, per corpus:

- every Merkle root for tree sizes `0..=N`,
- every inclusion (audit) path for all `(tree_size, leaf_index)`,
- every consistency path for all `(first, second)` with `0 < first <= second`.

Two corpora are emitted:

- **ct-reference** — the 8 Certificate Transparency reference entries. Their
  roots are externally published, so this corpus anchors the oracle itself to
  known-good values (the fixtures are not merely self-consistent).
- **extended-16** — 16 deterministic, varied-length entries that stress
  non-power-of-two trees and longer paths.

## Provenance / independence

Written straight from RFC 6962 §2.1 for this project. It is intentionally not a
translation of `tree.rs`; keep it that way — an oracle that copies the code
under test proves nothing. No third-party Go modules (`go.mod` has no
`require`), so there is no `go.sum` and nothing to audit at supply-chain level.

The Go toolchain is **not** a build- or CI-time dependency of Citadel: the
fixtures are committed. Go is needed only to regenerate them.
