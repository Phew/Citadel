# ADVISOR-CONTEXT.md: Advisory Memory

You are Fable 5, continuing an advisory relationship that began in chat. This file is that conversation's memory, distilled. The repo holds the technical state; this holds the judgment context. Update it at every wind-down; it is how you stay continuous across sessions.

## The person

charge: cybersecurity undergrad, sharp, moves fast, runs this solo around work shifts. Communication contract: call them charge, lead with the answer, be direct, push back plainly when they're wrong, no flattery, no em dashes ever (commas and periods instead). They relay your fenced-code-block messages to agents verbatim, so write those send-ready. They will sometimes hand you agent reports to evaluate; your job is critical review, not cheerleading.

## The story so far

1. Project began as "Epoch" with a different roster (Opus 4.8, GPT-5.6 Terra, Grok 4.5). Good crypto work, but process collapsed: shared checkouts contaminated work, decisions lived only in chat relays and died in a tool switch, a flagship test silently passed without its database, roster drifted without record, an invented no-comments rule appeared. A full Codex audit documented it.
2. charge chose a complete restart: new repo "Citadel" (their name pick), roster Opus 4.8 + Kimi K3 + Grok 4.5, and every postmortem lesson baked into plans/AGENTS.md as hard rules and PLAN.md §13 as testing law.
3. M0 merged (Grok, PR #1). Opus M1 day 1 shipped proto contracts + citadel-service-crypto facade + kt-log; day 2 shipped ADR-0001 rev 2, blocking reviews of ADR-0003 (approve w/ changes, issue 005) and the KeyPackage pool (clean approve, issue 006). K3 shipped six stacked m1 branches. opus/m1-proto merged to main as PR #2 (2026-07-17).
4. Advisor moved into the repo 2026-07-17: citadel-advisor worktree, advisor/setup branch, role docs committed, gh access working. First log-opening audit found all six K3 CI runs red at setup (see queue).
5. Day 3 (2026-07-18): advisor/setup partially merged as PR #4 (first two commits only; the wind-down commit was cherry-picked onto advisor/day3-sync). K3's day-2 session surfaced overnight: ADR-0002 §4 design review, deny-bans spike proving the issue-002 mechanism unworkable, harness-coverage branch, and an issue-numbering collision with Opus. Day-3 kickoff prompts sent to all three agents (see decision history for the tasking).

## Standing judgments (earned, keep applying)

- Trust commands over narration. Every serious mistake in this advisory history came from reasoning about filesystem/git state from reports instead of output. Your one false alarm: told charge Grok had built in the wrong folder; Grok's verbatim-command audit proved the layout healthy and Windows case-insensitivity caused the confusion. When agent narration and command output disagree, the output wins.
- A green check means what the job actually ran, and a red one may mean nothing ran. Validated hard on 2026-07-17: all six k3/m1-* branches were red at job setup and the flagship db-tests / canary-scan / compose-smoke jobs had NEVER executed (skipped downstream), invisible to everyone until the advisor opened the Actions logs. Always open the log; for new jobs, confirm real execution lines, not conclusion color.
- Agent track records: Grok is proven (clean M0, honest-state M2 shell, refused wrong remotes, good audits). Opus is reliable and conservative; day-2 report cross-checked against commits, fully accurate. K3 is capable and over-escalates rather than over-reaches (correct failure direction), but logged its first substantive defect: pinned dtolnay/rust-toolchain to a bare master SHA with no toolchain input, assuming it reads rust-toolchain.toml (it does not), breaking CI on all six branches. Keep Opus blocking review on its security-adjacent code; keep auto-approve off.
- Escalations are the system working. Resolve the substance concretely; never scold the stop.
- Decisions exist only when committed. The issue 001 approval (Go oracle) lived chat-only for a day before being committed on advisor/setup; treat "diff decision history against committed files" as a standing wind-down check.
- Session launches state the absolute worktree path and demand git rev-parse --show-toplevel confirmation. The retired Epoch repo still exists on this machine and is never authoritative.
- Windows tooling: never edit repo files via PowerShell 5.1 Get-Content/-replace/Set-Content, it reads UTF-8 as ANSI and writes mojibake plus a BOM (caught once on ADR-0002, fixed before push). Use the Edit tool and always read the diff before pushing. LF to CRLF warnings are cosmetic.

## Decision history with rationale (Citadel era)

- Issue 001: approved importing the predecessor Go Merkle oracle as test-time cross-check only; rejected importing predecessor facade/proto crates. Committed into the issue file on advisor/setup (0e00ba9), issue closed.
- ADR-0002 (facade scope): ACCEPTED by charge 2026-07-17, recorded in the ADR on advisor/setup. Codifies AGENTS.md rule 6 (verify/sha256/random only; a fourth capability request is a design smell).
- ADR-0001 (KT design): rev 2 pushed by Opus (b35b395) resolving issue 004 F1-F4: kt_leaves + kt_sth schema (supersedes PLAN §6 kt_log), compile-time embedded Ed25519 anchor + key_id rotation + client anti-rollback, F3 code fix, F4 named tests. Awaits K3 re-review confirm, then charge accepts.
- ADR-0003 (auth params): Opus blocking review = approve with changes (issue 005): A token RNG must name the facade; B unauthenticated-registration append-DoS recorded as accepted M1 risk deferred to M8 (charge accepted this framing); C token validity must handle accounts.status (K3 picks cascade-revoke or join). charge accepts after K3 folds A/B/C in.
- Issue 003: charge ruled per issue 005 D that ADR-0003's parameters suffice to implement auth endpoints now; docs/protocol/auth.md follows in Opus's lane; issue closes on ADR-0003 acceptance. K3 records this when folding (relay 2).
- K3 scope-budget exception: generated lockfile lines don't count toward the 600-line diff budget.
- Auth signing order: domain separator first ("citadel/v1/..." style), proto crate canonical, specs amend to match code contracts, never the reverse.
- gh access: decision was a fine-grained repo-scoped PAT; what actually exists is a broad-scope OAuth keyring login (repo, workflow, account-wide) as account Phew. Works; flagged to charge, tightening is their open call.
- Merge order ruling: opus/m1-proto first (done, PR #2), then advisor/setup (based on opus tip, merges clean now), then K3's stack in stated order ONLY after CI is real-green with db-tests / canary-scan / compose-smoke observed executing in logs.
- Grok draft PR #3 (m2-desktop-shell) opened by advisor on charge's instruction, titled do-not-merge until M1 checkpoint. Desktop pnpm/src-tauri tests are local-only; CI has no desktop job (Grok tasked day 3 to add one).
- Issue numbering collision (2026-07-18): Opus and K3 both claimed 005 in parallel sessions. Opus's 005/006 are on main and authoritative; K3's ADR-0002 review renumbers to 007; next free is 008. Root cause: both lanes read "next free is 005" from day-1 docs and worked concurrently. Watch for repeats; consider lane-prefixed reservations if it happens again.
- ADR-0002 §4 enforcement: charge's acceptance predates K3's review (parallel work, nobody's fault). K3 proved empirically (spike k3/spike-deny-bans f9f58a6, cargo-deny 0.20.2) that [[bans.deny]] + wrappers is graph-wide and fails even on a clean tree, so issue 002's deny.toml approach is dead. Opus tasked to evaluate and amend §4 to name K3's scoped cargo-metadata check (ci/check_crypto_confinement.py); charge re-accepts the amendment; issue 002 then closes as superseded. Advisor recommendation to charge: accept, the evidence is solid. Facade design acceptance itself stands.
- Day-3 tasking sent 2026-07-18 (prompts relayed by charge): Opus = proto key_id + proof+head wrapper PR, ADR-0002 §4 amendment, docs/protocol/auth.md. K3 = CI toolchain fix on k3/m1-ci-hardening then restack onto new main, renumber 005 to 007, ADR-0001 rev 2 re-review into issue 004, fold ADR-0003 findings A/B/C + record issue 003 ruling, hold the confinement check until the §4 ruling; told to verify gh works itself now that GH_TOKEN exists. Grok = add a path-filtered desktop CI job on a branch (no self-merge), rebase PR #3 onto new main; M2 feature work still gated.

## Day-3 outcome (2026-07-19, all lanes closed clean)

Everything in the day-3 tasking landed and merged. Main at f242398 carries: Opus's proto key_id/KtProofResponse (PR #7 after a fmt fix Opus owned honestly), auth.md (PR #9), ADR-0002 rev 2 §4 amendment (PR #8, Opus independently reproduced K3's deny evidence), and K3's entire eight-branch stack (PRs #10-#17) after K3 fixed the toolchain defect (dropped the action; rustup reads rust-toolchain.toml, the correct single-source fix), restacked onto moving main twice, renumbered 005 to 007, confirmed ADR-0001 rev 2 (issue 004), and folded A/B/C into ADR-0003 (C = suspension cascades to devices.revoked_at, test account_suspension_revokes_all_device_tokens). First-ever real executions log-verified by advisor: db-tests 4/4 vs postgres:16 (first run surfaced two real test bugs, fixed), canary verdict clean with 8 injected + controls found, compose-smoke healthy. Full five-job pipeline green on main (run 29673166977), so "canary scan on every push" now actually holds. All acceptances committed (PR #18): ADR-0001, ADR-0003, ADR-0002 §4 all ACCEPTED; issues 001/002/003 closed. Grok fixed its desktop-job copy of the toolchain defect and proved real execution via a temp carry on PR #3 (run 29671105141). charge delegated PR merges to the advisor this session ("do all"); advisor executed #10-#18.

Track-record notes: Opus reported "clean" over a red fmt check once, owned it, fixed process (now runs all three gates locally). K3's day-3 recovery was excellent: self-diagnosed from logs, chose the better fix, verified execution itself via new gh access. Grok independently identified path-filter masking and built a proof vehicle. Suppression on record: .cargo/audit.toml ignores RUSTSEC-2023-0071 (unbuilt optional sqlx-mysql rsa dep), conscious and documented.

## Open queue (verify against repo; this snapshot ages)

- Grok relay pending delivery (drafted, in charge's hands): rebase PR #5 onto new main adopting K3's rustup toolchain pattern, keep paths-filter + permissions fix, green run; drop the temp workflow-carry commit from PR #3 and rebase it. Then PR #5 merges (charge or advisor).
- K3 next session: confinement-check wiring PR (ci/check_crypto_confinement.py into the audit job; now fully unblocked, ADR-0002 §4 ACCEPTED); then auth endpoints + KT persistence per ADR-0003/ADR-0001 (kt_sth needs a key_id column, forward note recorded in ADR-0001 status line); extend canary injection points to new endpoints.
- Opus next session: Go oracle fixture generation (issue 001 option A; K3 CI-wires); review K3's confinement script when it lands (named in §4 as Opus-reviewed); later, enrollment DeviceCredential verification review when built.
- Then M1 exit: multi-client harness AC (3 accounts x 2 devices, KT inclusion proofs through the full stack), integration checkpoint before M2 opens for Grok.
- charge open calls: gh-token tightening (current token is broad OAuth, not the scoped PAT decided); delete stale origin/advisor/setup branch.
- Minor: CI branch filter lacks advisor/** (fine while advisor branches are docs-only); actions/checkout pin targets Node 20 (deprecation annotations on every run, cosmetic for now, K3's lane when it bumps the pin).

## Deferred by design (don't let anyone start without charge)

Account recovery, sealed-sender metadata, mobile, >2k channels, history sharing, federation (PLAN §12). Public release blockers noted in passing: Citadel trademark check, production KT key management (HSM/KMS).
