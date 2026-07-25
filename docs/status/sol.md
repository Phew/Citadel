# Sol status: core lane, out of quota, ADR-0007 in review

**Agent:** Sol. **Branch prefix:** `sol/`.
**Audience:** a fresh Sol instance with zero memory. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-CORE.md`, then this file.

## Owned surfaces

`citadel-core`, `citadel-proto` as sole merger, `citadel-service-crypto`,
`kt-log`, `docs/protocol/`, and design ADRs. Sol is the blocking reviewer for
crypto, auth-flow, and KT surfaces. K3 independently reviews Sol's ADRs.

## Current state

- Main is `7592a26`. The M2 core build merged as `9a74d94`, delivery as `33fcfe9`,
  repository cleanup as `ce73cb9`, the M2 exit harness as `295d829`, and the
  advisor shutdown snapshot as `673796d`.
- **ADR-0007 is on main and PROPOSED.** It was rescued by the advisor at
  `7592a26` on charge's instruction. It had been written but never committed: it
  existed only as untracked files in the sandbox worktree at
  `C:/tmp/Citadel-sol-m2-local-store-adr`, with `sol/m2-local-store-adr` still at
  `1f4e533`, because the sandbox account could not write the shared Git index and
  this lane then ran out of usage quota for the week. Content landed verbatim
  apart from one stale `main` SHA in this file. **Lesson for this lane: commit
  early and often is a hard rule (AGENTS.md rule 2), and the sandbox's inability
  to write the shared index is a blocker to raise immediately, not at handoff.**
  Roughly a day of design work sat one disk failure away from being lost.
- **This lane is out of usage quota for the week** (charge, 2026-07-25). No Sol
  work is scheduled. If the store must be built before quota resets, charge's
  options are a temporary core-seat swap logged under rule 12, or waiting. The
  advisor does not write implementation code, and K3 cannot both build the store
  and own the forward-secrecy test that proves it.
- M2 is not closed. `citadel-core` still uses OpenMLS's in-memory provider, so
  restart-safe MLS persistence and the forward-secrecy compromise test do not
  exist. Four of five M2 exit criteria are standing CI gates on main; the fifth,
  `device_compromise_past_messages_unreadable_fs`, is blocked on the store.
- The live harness covers F2, F4, the delivery-table canary, self-update
  convergence with post-update messaging, and the swapped-KeyPackage attack. It
  does not prove forward secrecy or post-compromise security against captured
  persisted state.
- ADR-0007 proposes SQLCipher through `rusqlite`, OpenMLS's maintained SQLite
  storage provider, a provenance-checked SQLCipher 4.17.0 source overlay,
  fail-closed native credential-store backends, atomic MLS and application
  transactions, and separate evidence for local profile destruction, MLS forward
  secrecy, and persisted-state post-compromise security. On acceptance it
  replaces ADR-0005 §4, PLAN §4's client-side `sqlx` choice, and PLAN §9 M2's
  broad device-compromise wording. Until then it changes nothing, and the
  companion doc edits say so explicitly in each affected file.
- **Expect the SQLCipher overlay to be contested in K3's review.** Alternative 2
  rejects the stock bundled SQLCipher 4.5.7 because it "is not 4.17.0, which
  incorporates current upstream SQLite fixes." That is a preference for newer,
  not a named threat, and §1 itself says "a relevant advisory blocks this
  choice," implying none currently applies. Everything expensive in the ADR hangs
  off that line. Have an advisory named, or a staging proposal ready.
- No local encrypted client store implementation has started.

## Delivered by this lane, 2026-07-25

- **PR #47, merged `9a74d94`.** The citadel-core respin after K3's blocking
  review of #38. Initiator-side KT verification of every KeyPackage before
  OpenMLS mutation, staged-commit processing with update-path leaf verification,
  typed deferral errors for the M3-scoped cases rather than silent drops, plus
  zeroization, key-consistency and panic-removal cleanups. Both blocking findings
  fixed and the misleading test doc comment corrected. Advisor verification found
  the work exceeded both asks.
- **ADR-0007 authored** (above), and a correction that mattered: PLAN.md M1
  claimed "citadel-core keychain integration" as delivered and ADR-0005 §4
  described reusing it. It was never built. This lane found and corrected the
  false claim.

## Owed by this lane when quota resets

1. The `#39` delta re-review against `33fcfe9`. It was never posted before charge
   merged, and K3 already completed the mirror-image review of `#47` against the
   merged commit and found nothing.
2. A review of K3's merged exit-AC work at `295d829`.
3. Fold K3's ADR-0007 design-review findings into the ADR.
4. Build the store once charge accepts, then hand the persisted-state API to K3
   for the live-stack forward-secrecy and post-compromise security exit tests.

## Track record note for a fresh instance

This lane's recurring failure mode is documentation that asserts things the code
does not do. Three instances so far: the crate description claiming a local
encrypted store that did not exist, a test doc comment claiming
swapped-KeyPackage coverage the test did not provide, and PLAN.md's M1 keychain
claim. Every one was caught by someone else reading the code. Treat prose about
your own crate as a claim that must be true. Separately, an invented "no-comments
rule" was filed as a blocking review finding on `#39` and rejected; AGENTS.md
rule 9 encourages comments. Verify a rule exists before enforcing it.

## Deferred work

- Do not start M3 commit ordering before the M2 integration checkpoint.
- Do not start device-transparency `KtLeaf` work without explicit direction.
- Do not start ADR-0006 follow-ups A through D without explicit direction.

## Standing corrections

- Comments are encouraged at cryptographic call sites and invariant boundaries.
- The shared GitHub account cannot cast formal approvals. Use labelled review
  comments.
- Work in a dedicated worktree, base branches on main, and use only the `sol/`
  prefix for new branches.
