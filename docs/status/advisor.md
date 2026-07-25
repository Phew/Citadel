# Advisor status — shutdown 2026-07-25 (M2: one component left)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is the
immediate resume queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.
Verify every agent report against the repo/CI logs before endorsing — this milestone every
cross-review surfaced something green CI missed.

## FIRST ACTION next session

**Check whether Sol committed and pushed ADR-0007.** At shutdown it was NOT committed: the
~48KB document existed only as an untracked file in Sol's worktree at
`C:/tmp/Citadel-sol-m2-local-store-adr`, with branch `sol/m2-local-store-adr` still sitting at
`1f4e533` and nothing staged. Sol's sandbox account was blocked from writing the shared Git
index and asked charge to approve staging, committing, and rebasing; charge approved and the
relay went out, but the result was never confirmed in the repo. This is the single fragile
thing in the project right now and it is a straight rule-2 violation ("no work exists only in a
working tree between sessions"). If it is gone, it is a day of Sol's work, and the design
reasoning was good enough to be worth reconstructing rather than redoing from scratch.

If it landed: K3 design-reviews ADR-0007, pressing on Alternative 2 (below), then charge makes
the two decisions in items 1 and 2 of the queue. If it did not land: get Sol to recommit before
anything else.

## Resume queue, in order

M2's build PRs and the exit-AC harness are merged and green on main. Four of M2's five exit
criteria are now standing CI gates. One component and one test remain.

1. **ADR-0007 (local encrypted client store): K3 design-reviews, then charge accepts.** Sol
   authored it 2026-07-24, PROPOSED, ~48KB. The security reasoning is strong and its evidence
   design is deliberately harder than what was asked for: the forward-secrecy test hands the
   attacker the database, every SQLite sidecar file, AND the correct database encryption key,
   then demands the exact `SecretTreeError::TooDistantInThePast` chain, explicitly refusing
   parser errors, application-level epoch comparison, or replay rejection as evidence. It pins
   `max_past_epochs` to zero rather than inheriting the OpenMLS default and fails closed on
   drift. The PCS evidence uses a test-only secret extractor plus two independent third-party
   MLS oracles, states that an epoch-number mismatch alone is insufficient, and blocks M2 close
   rather than substituting a self-referential test. Version pins were advisor-spot-checked
   against primary sources and are real, not fabricated.

   **The contested part, and where K3's review should press: Alternative 2.** The ADR rejects
   the stock bundled SQLCipher 4.5.7 because it "is not 4.17.0, which incorporates current
   upstream SQLite fixes." That is a preference for newer, not a threat statement. No advisory
   is named, and §1 itself says "a relevant advisory blocks this choice," implying none
   currently applies. Everything expensive in the ADR hangs off that single line: a
   repository-local patch of `libsqlite3-sys`, vendored OpenSSL with pinned Configure
   transcripts, pinned NASM, three-OS byte-comparison of regenerated amalgamations, a CycloneDX
   SBOM, and OSV scanning. That is plausibly more work than the rest of M2 combined, and
   maintaining a local patch of a C crypto library's build glue is a standing burden. Either an
   advisory is named, or the work stages: ship the store on the stock bundle for M2 and track
   the reproducibility program as its own ADR. Both are defensible; "newer is better" is not,
   at this price.

2. **charge: an explicit acceptance-criterion decision, separate from accepting the ADR.**
   ADR-0007 replaces PLAN §9 M2's "past messages unreadable" with a narrower persisted-state
   boundary: current MLS secret state cannot decrypt old-epoch ciphertext, but deliberately
   retained decrypted history stays readable to anyone holding the database encryption key.
   Advisor position: the narrowing is CORRECT. MLS forward secrecy is a property of key
   material, not of a local plaintext archive, and Signal behaves the same way; making retained
   history unreadable is a retention feature, which the ADR defers to a separate design. But
   AGENTS.md reserves acceptance-criterion changes to charge specifically, so this must be a
   conscious decision rather than something inherited by accepting an ADR. Do not let it ride
   along silently.

3. **Sol: build the store**, once ADR-0007 is accepted.
4. **K3: `device_compromise_past_messages_unreadable_fs`**, the fifth and last exit criterion,
   once the store lands. K3 deliberately did not write it against in-memory state, and was right
   not to: its note in `crates/test-harness/tests/m2_dm.rs` records that an in-memory FS test
   "would pass while proving nothing."
5. **Integration checkpoint**, then charge declares M2. All lanes pass the multi-client harness
   together before anyone starts M3.
6. ADR-0006 follow-ups A-D remain binding, tracked, not started (A role isolation + bootstrap,
   B startup min-version, C risk-classification enforcement, D remaining probes).

Outstanding from Sol, both small: the #39 delta re-review against `33fcfe9` (never posted before
charge merged it), and a review of K3's merged exit-AC work at `295d829`. K3 already ran the
equivalent review on Sol's #47 against the merged commit and found nothing.

Deliberately NOT started: Grok's real-core desktop wiring. It is genuinely unblocked now that
citadel-core is on main, and it is M3 scope, so the integration checkpoint holds it. Being
unblocked is not the same as being in scope.

## Lane assignment rationale (2026-07-25)

Assignments were checked against current published model strengths rather than left on
ownership alone; both landed where ownership already put them, which is a result, not a
formality. K3 leads SWE Marathon (42.0, ahead of Sol 39.0, Opus 4.8 40.0, Fable 5 35.0), the
benchmark measuring sustained multi-step reasoning over extended codebases, and its documented
profile is iterating against logs, tests, and runtime feedback. That is the exit AC exactly, and
at $3/$15 per M tokens with cache discounts it is also the cheapest lane for the most
context-heavy work left. Sol leads the coding-agent indexes and writes tighter code, which suits
a focused component behind a real security boundary.

Two operational constraints that follow from the models, not from preference:

- **K3 is documented as over-proactive when boundaries are ambiguous** (Moonshot recommends
  explicit behavioral limits). This is why `PLAN-KIMI-K3.md` makes K3 restate six Scope
  Discipline Rules verbatim. Every K3 tasking must name its boundary explicitly or K3 drifts
  into adjacent fixes.
- **Sol advertises ~1M context but is capped near 272K in the Codex CLI harness.** Now that
  citadel-core is substantial, keep its handoffs lean rather than loading whole crates.

No roster swap was made. Fable 5 has the strongest published scorecard and PLAN-CORE.md
authorizes paying premium for this seat, but the Sol/Fable margins sit inside harness noise, a
mid-milestone swap costs a full context reload, and Sol is on its best work here. The decisive
argument: nothing this project has lost time to was a capability gap. Every real defect this
milestone was caught by cross-review and verification discipline, which is a process property.
A better model would not have caught the one-sided INV-4 check; K3 reading the code did.

## State

- main `ce73cb9`. M1 closed and declared. M2 NOT closed. ADRs 0001-0006 all ACCEPTED
  (0006 + Amendment 1 = `search_path = public, pg_temp`).
- Zero open PRs. Remote is `main` only. Merged 2026-07-25: **#47** `9a74d94` (citadel-core:
  initiator KT checks + staged-commit processing), **#39** `33fcfe9` (delivery-service message
  path + WS gateway + ADR-0006 migration CORE), **#46** `ce73cb9` (repo cleanup), **#48**
  `1f4e533` (M2 final lap), **#49** `295d829` (M2 exit-AC harness).
- M2 exit criteria: F2 three-client DM, F4 roundtrip, delivery-table no-plaintext scan, PCS
  recovery, and the adversarial swapped-KeyPackage test are all GREEN and, verified in the main
  run log rather than the badge, actually execute on every push to main. The adversarial test
  drives a live HTTP proxy that rewrites the KeyPackage fetch, asserts the swap byte-for-byte on
  the real fetch path, checks the live KT log, and includes a control proving the honest package
  is accepted. The canary scan now injects real DM plaintext through the live F2+F4 path, so
  INV-1 is checked against the thing it is actually about. Only the forward-secrecy test remains.
- Both merge runs fully green on main, all seven jobs, log-verified rather than badge-read. The
  canary scan on `33fcfe9` reported `control_db_found: true` / `control_log_found: true`, so
  "clean" means the scanner proved it can find planted canaries first.
- **Process debt from this session, stated plainly:** #47 and #39 were merged on charge's
  instruction WITHOUT the delta re-reviews the advisor had recommended. The advisor verified
  both fixes line by line against source, but the advisor also wrote the review directives, so
  the independent second look did not happen. Recommended remedy, still open: have Sol and K3
  run their delta reviews against the merged commits, with anything found becoming a follow-up
  PR. Also not independently reproduced: K3's claim that each new migration test was
  mutation-checked to fail against the pre-fix code.
- Roster: Sol (GPT-5.6 Sol) core lane, K3 (Kimi K3) services/CI/harness, Grok (Grok 4.5) desktop,
  parked. The M3 churn rig moved Grok to K3 on 2026-07-25 (see AGENTS.md sequencing).
- Advisor self-corrections on record: (a) "#38 only blocked by deny.toml" was wrong, CI runs
  cargo-audit too; (b) my `search_path` ordering `public, pg_catalog, pg_temp` was weaker than
  Sol's accepted `public, pg_temp`; (c) I called the RUSTSEC-2023-0071 precedent a confabulation
  when it existed in `.cargo/audit.toml` all along.
- charge open calls, still open: **LICENSE file** (public repo, all-rights-reserved by default),
  gh-token tightening, Citadel trademark check.
- Sol's worktrees are owned by a separate Windows account (`CodexSandboxOffline`, the Codex
  sandbox user), so the advisor cannot inspect or clean them. Three finished ones remain on
  disk; only charge or Sol can remove them.

## Shutdown snapshot 2026-07-25

- **main `3d9d232`. Zero open PRs. Remote is `main` and nothing else.** Last full CI run on main
  (`295d829`, run 30141369632) green across all seven jobs, log-verified. The two advisor commits
  after it are docs-only and skip CI by design.
- **M1 closed and declared. M2 NOT closed.** Four of five exit criteria are standing CI gates.
  The fifth, `device_compromise_past_messages_unreadable_fs`, is blocked on the store, which is
  blocked on ADR-0007, which at shutdown was uncommitted (see FIRST ACTION).
- **Nothing is in flight.** No agent had work in review at shutdown. The only unlanded work is
  Sol's uncommitted ADR-0007.
- **Two decisions are open and both are charge's**, recorded in queue items 1 and 2: whether
  ADR-0007's SQLCipher overlay is justified without a named advisory, and the explicit
  acceptance-criterion change that AGENTS.md reserves to charge. Neither has been decided. Do not
  let the second ride along inside an ADR acceptance.
- **charge open calls, still open and carried across three sessions now:** LICENSE file (public
  repo, all-rights-reserved by default), gh-token tightening, Citadel trademark check.
- **Local machine housekeeping** (advisor cannot do these): the compose stack may still be up
  (`docker compose -f deploy/docker-compose.yml down -v`, and note `-v` drops volumes). Sol has
  five worktrees on disk, four of them finished work
  (`citadel-sol-adr0006-search-path`, `citadel-sol-audit-parity`, `citadel-sol-pr38`,
  `citadel-sol-pr39-review` detached, plus `C:/tmp/Citadel-sol-m2-core-respin`). They are owned
  by the `CodexSandboxOffline` Windows account, so only charge or Sol can remove them. The live
  one to keep until ADR-0007 lands is `C:/tmp/Citadel-sol-m2-local-store-adr`.
- **Process note for whoever resumes:** this session merged two code PRs without their delta
  re-reviews, on charge's instruction. K3 later ran its review against the merged commit and
  found nothing; Sol's equivalent review of `33fcfe9` is still outstanding, along with a review
  of `295d829`. The pairing discipline is what has caught every real defect this milestone, so
  it is worth closing that loop rather than letting it lapse into precedent.

## Suppression config (both needed — cargo-audit AND cargo-deny run)

`deny.toml`: 8 ignores (#41). `.cargo/audit.toml`: 6 fatal ignores + pre-existing
RUSTSEC-2023-0071 (#42). All in the OpenMLS/hpke-rs libcrux chain, off the runtime crypto
path; revisit on an hpke-rs optional-dep fix.

## Repo cleanup 2026-07-24 (branch hygiene)

Remote branch count went 32 → 3 (`main`, plus the two live PR heads). Nothing unique was lost;
every deleted branch was either merged into main or superseded. SHAs recorded here so any
deletion is one `git push origin <sha>:refs/heads/<name>` away from reversal.

**Merged into main, deleted (23):**

```
d57bc00 advisor/day4-close                  56bed13 advisor/day4-sync
f6fd0db advisor/m1-acceptances              aa50bd3 advisor/readme-m1
1abe898 advisor/status-desktop-note         ec223e1 grok/desktop-ci
0f99258 k3/m1-adr0002-review                9899c3c k3/m1-auth-challenge-token
8168cba k3/m1-auth-params-adr               621a2ae k3/m1-canary-scan
476291a k3/m1-ci-hardening                  b8bfae1 k3/m1-harness-coverage
a626fa2 k3/m1-harness-framework             de40d71 k3/m1-issue-008-appended-at
5cafdf9 k3/m1-keypackage-pool               d3d8d03 k3/m1-kt-adr-review
703f70d k3/m1-kt-persistence                92902a8 k3/m1-registration-pool-endpoints
03cf96d opus/m1-adr0004-enrollment          21ed625 opus/m1-go-oracle-fixtures
b1467fb opus/m1-proto-key-id                f3c3d0b opus/m1-register-appended-at
d34a8da sol/migration-architecture
```

**Not merged but superseded, deleted (5), with the reason each was safe:**

```
d15921d advisor/setup       stale 2026-07-17 wind-down; main's advisor.md and
                            ADVISOR-CONTEXT.md are a week newer. charge's own open call.
f9f58a6 k3/spike-deny-bans  its only file, ci/check_crypto_confinement.py, is already on main.
5d857da grok/status         2026-07-17 M0 handoff; main's docs/status/grok.md is 2026-07-20.
2b94f98 k3/status           2026-07-19 day-4 handoff; PR #39 carries a 2026-07-24 k3.md.
43b1f48 opus/status         2026-07-19 day-4 handoff that never merged, leaving main's
                            opus.md stranded at day 2. The SHA above is the salvage
                            point if anything from that handoff is ever wanted back.
```

**Structural defect this exposed, now fixed:** per-agent status files were being written on
side branches that were never merged, so `main` carried a day-2 Opus status for a week while
the real handoff sat unmerged. Status files are cold-start context; if they are not on `main`
they do not exist. Rule going forward: **a status file lands on `main` in the same PR as the
work it describes, or in a docs-only PR of its own.** Never on a branch that stays open.

Also cleaned locally on charge's machine: stale git worktrees (the finished
`citadel-sol-adr0006-search-path`, `citadel-sol-audit-parity`, `citadel-sol-pr39-review`
detached checkout, and `Citadel-opus` for the retired agent) and the matching local branches.
Live worktrees kept: `Citadel` (charge's primary), `citadel-advisor`, `citadel-k3`,
`citadel-grok`, `citadel-sol-pr38`.
