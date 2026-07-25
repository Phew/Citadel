# Sol status: M2 local encrypted client store design gate

**Agent:** Sol. **Branch prefix:** `sol/`.
**Audience:** a fresh Sol instance with zero memory. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-CORE.md`, then this file.

## Owned surfaces

`citadel-core`, `citadel-proto` as sole merger, `citadel-service-crypto`,
`kt-log`, `docs/protocol/`, and design ADRs. Sol is the blocking reviewer for
crypto, auth-flow, and KT surfaces. K3 independently reviews Sol's ADRs.

## Current state

- Main was `295d829` when this was written; it is `673796d` after the advisor shutdown snapshot. The M2 core build merged as `9a74d94`, delivery merged as
  `33fcfe9`, repository cleanup merged as `ce73cb9`, and the M2 exit harness
  merged as `295d829`.
- Both M2 build PRs are on main. Their requested independent delta re-reviews
  did not happen before merge.
- M2 is not closed. `citadel-core` still uses OpenMLS's in-memory provider, so
  restart-safe MLS persistence and the forward-secrecy compromise test do not
  exist.
- The live harness now covers F2, F4, the delivery-table canary, self-update
  convergence with post-update messaging, and the swapped-KeyPackage attack.
  It does not prove forward secrecy or post-compromise security against
  captured persisted state.
- Branch `sol/m2-local-store-adr` contains proposed ADR-0007. On charge's
  acceptance it replaces ADR-0005 §4, PLAN §4's client-side `sqlx` choice, and
  PLAN §9 M2's broad device-compromise wording with explicit persisted-state
  evidence boundaries.
- ADR-0007 proposes SQLCipher through `rusqlite`, OpenMLS's maintained SQLite
  storage provider, a provenance-checked SQLCipher 4.17.0 source overlay,
  fail-closed native credential-store backends, atomic MLS and application
  transactions, and separate evidence for local profile destruction, MLS
  forward secrecy, and persisted-state post-compromise security.
- No local encrypted client store implementation has started. K3 design review
  and charge acceptance are required first.

## Next actions

1. Put ADR-0007 through K3's independent design review.
2. Fold any real design findings into the proposed ADR.
3. Wait for charge to commit ACCEPTED status.
4. Build the local encrypted client store and its named evidence tests.
5. Hand the persisted-state API to K3 for the M2 live-stack forward-secrecy
   and post-compromise security exit tests.

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
