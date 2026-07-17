# Issue 001: Proposal — import previously verified components (Go Merkle oracle first)

- **Raised by:** Opus, 2026-07-17
- **Decision needed from:** charge
- **Related:** ADR-0001, plans/PLAN.md §13 (independent-oracle evidence rule)

## Summary

Citadel is clean-slate and nothing from any predecessor is authoritative.
That said, PLAN.md §13 explicitly names "the Go oracle pattern for Merkle
structures" as the evidence bar, and a predecessor project produced
candidate components that — **if and only if charge judges them verified** —
could be imported rather than rebuilt:

1. **Go Merkle oracle** — an independent Go implementation of the RFC 6962
   algorithms used to cross-check a Rust Merkle core, plus its fixture
   format.
2. **Verification facade** — a small verify/sha256/random crate analogous to
   what is now `citadel-service-crypto`.
3. **Proto contracts** — wire/signing-contract definitions analogous to
   `citadel-proto`.

## Current state (no import assumed)

M1 work proceeded clean-slate. `kt-log`, `citadel-service-crypto`, and the
`citadel-proto` M1 contracts are freshly written on `opus/m1-proto`, with the
Certificate Transparency reference roots pinned as an interim independent
oracle for the Merkle core.

## What I actually recommend importing

Only item 1, the **Go oracle**, and only as a *test-time* cross-check:

- It is exactly the §13 evidence pattern: same RFC, different language,
  different author-model, different failure modes.
- It never ships; it runs in CI to compare roots/proofs against `kt-log`
  over generated fixtures. Low blast radius even if imported imperfectly.
- Items 2 and 3 are already re-implemented here and reviewed under this
  project's rules; importing predecessor versions now would *replace
  reviewed code with unreviewed code* — I recommend against, beyond mining
  their test vectors (worth doing: append any predecessor fixtures to our
  test corpus).

## Options for charge

- **A (recommended):** approve importing the Go oracle into
  `test-harness/oracles/merkle-go/` (or similar), CI-wired by K3, with
  fixture generation owned by Opus. Mine predecessor test vectors for
  kt-log's corpus. Do not import items 2–3.
- **B:** no import; Opus writes a fresh Go oracle in a later M1 PR (adds a
  few hours, keeps everything clean-slate).
- **C:** import items 2–3 as well after diff review against the new crates
  (not recommended; churn without security gain).

## Blocked work

None — M1 continues either way. This only affects the strength/cost of the
kt-log evidence package before M1 sign-off.
