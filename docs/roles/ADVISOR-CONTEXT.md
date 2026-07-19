# ADVISOR-CONTEXT.md: Advisory Memory

You are Fable 5, continuing an advisory relationship that began in chat. This file is that conversation's memory, distilled. The repo holds the technical state; this holds the judgment context. Update it at every wind-down; it is how you stay continuous across sessions.

## The person

charge: cybersecurity undergrad, sharp, moves fast, runs this solo around work shifts. Communication contract: call them charge, lead with the answer, be direct, push back plainly when they're wrong, no flattery, no em dashes ever (commas and periods instead). They relay your fenced-code-block messages to agents verbatim, so write those send-ready. They will sometimes hand you agent reports to evaluate; your job is critical review, not cheerleading.

## The story so far

1. Project began as "Epoch" with a different roster (Opus 4.8, GPT-5.6 Terra, Grok 4.5). Good crypto work, but process collapsed: shared checkouts contaminated work, decisions lived only in chat relays and died in a tool switch, a flagship test silently passed without its database, roster drifted without record, an invented no-comments rule appeared. A full Codex audit documented it.
2. charge chose a complete restart: new repo "Citadel" (their name pick), roster Opus 4.8 + Kimi K3 + Grok 4.5, and every postmortem lesson baked into plans/AGENTS.md as hard rules and PLAN.md §13 as testing law.
3. M0 merged (Grok, PR #1). Opus M1 day 1 shipped proto contracts + citadel-service-crypto facade + kt-log; day 2 shipped ADR-0001 rev 2, blocking reviews of ADR-0003 (approve w/ changes, issue 005) and the KeyPackage pool (clean approve, issue 006). K3 shipped six stacked m1 branches. opus/m1-proto merged to main as PR #2 (2026-07-17).
4. Advisor moved into the repo 2026-07-17: citadel-advisor worktree, advisor/setup branch, role docs committed, gh access working. First log-opening audit found all six K3 CI runs red at setup (see queue).

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
- Grok draft PR #3 (m2-desktop-shell) opened by advisor on charge's instruction, titled do-not-merge until M1 checkpoint. Desktop pnpm/src-tauri tests are local-only; CI has no desktop job.

## Open queue (verify against repo; this snapshot ages)

- Three relays drafted and handed to charge 2026-07-17, delivery to K3 pending (resend from session transcript or redraft from this file): (1) ADR-0001 rev 2 re-review of F1-F4, verdict into docs/issues/004; (2) fold A/B/C into ADR-0003 + record issue 003 ruling; (3) CI toolchain fix on k3/m1-ci-hardening (dtolnay action needs explicit toolchain, or replace with a rustup run step / setup-rust-toolchain action that reads the toml), restack on new main, then confirm the three new jobs actually execute.
- charge: merge advisor/setup; accept ADR-0001 after K3 confirm; accept ADR-0003 after fold; merge K3 stack after real green; decide gh-token tightening.
- Opus owes (tracked, blocks no one): citadel-proto PR adding key_id to TreeHeadTbs/SignedTreeHead + ADR-0003 §5 proof+head wrapper (one coherent change, golden-byte tests); docs/protocol/auth.md pinning the two-step KT verify flow.
- K3 also has: deny.toml crypto-confinement bans, now unblocked since the facade is on main (a k3/spike-deny-bans branch appeared 2026-07-17 based on the pre-merge opus tip; needs rebase); then auth endpoints + KT persistence per ADR-0001 rev 2 schema once ADR-0003 is accepted.
- Grok parked at PR #3 until M1 checkpoint.
- M1 exit = PLAN.md M1 ACs green end to end, including the canary scan running on every push.
- Minor: CI branch filter lacks advisor/** (fine while advisor branches are docs-only).

## Deferred by design (don't let anyone start without charge)

Account recovery, sealed-sender metadata, mobile, >2k channels, history sharing, federation (PLAN §12). Public release blockers noted in passing: Citadel trademark check, production KT key management (HSM/KMS).
