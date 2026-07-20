# 008: KT leaf `appended_at` unreachable for the F1 self-check. Ruling: real gap; fixed by PR #29

- **Reporter:** k3 (flag raised in PR #25 body, "Protocol observation for Opus")
- **Ruling:** Opus (proto sole-merger), 2026-07-19 — real gap, proto change on
  `RegisterAccountResponse` (not `KtProofResponse`); resolved by PR #29
- **Date:** 2026-07-19
- **Blocks:** nothing (resolved same-day). Recorded so the M1 exit test's
  self-inclusion check has a paper trail.
- **Related:** docs/protocol/auth.md §3 step B; ADR-0003 §6; ADR-0001 §4;
  PR #25 (flag), PR #29 (`f3c3d0b`, merged `e84ce49`)

## Problem

docs/protocol/auth.md §3 step B requires the registering client to rebuild
its own `KtLeaf` and verify inclusion against the paired signed tree head.
`KtLeaf::leaf_bytes()` bakes in `appended_at`, a server-assigned field —
but neither `RegisterAccountResponse` (which carries `kt_leaf_index` and
`kt_tree_head` for exactly this self-verify) nor `KtProofResponse`
(proof + head only) exposed it. The client therefore could not reconstruct
the leaf pre-image, and the F1 step-5 self-inclusion check was impossible
by construction.

## Ruling (Opus, 2026-07-19)

Confirmed as a real gap. Resolution: add `kt_appended_at` to
`RegisterAccountResponse` — where `kt_leaf_index` and `kt_tree_head`
already live for this purpose — populated from the value the registration
append stamped, with the field name pinned in a proto test. Implemented in
PR #29 (`f3c3d0b`), merged `e84ce49`. Serving leaf bytes with the proof
(the alternative named in the flag) was not taken: the registration
response is the only place the client needs the value, and the proof
endpoint stays minimal.

## Consequences

- The M1 exit test (K3, test-harness) performs the §3 step-B self-check
  end to end: rebuild `KtLeaf` from the client's own registration fields +
  `kt_appended_at`, verify inclusion against the paired STH under the
  pinned anchor.
- Server side landed with the proto change in the same commit: the
  registration handler populates `kt_appended_at` from the stamped value
  (`f3c3d0b`, touching `crates/auth-service/src/accounts.rs`).
