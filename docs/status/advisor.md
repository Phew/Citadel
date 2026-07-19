# Advisor status — end of day 3 merge wave (2026-07-19)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is only the immediate queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`, branch `advisor/day4-sync`.

## Immediate queue, in order

1. DONE 2026-07-19: Grok rebased PR #5 (rustup pattern) and cleaned PR #3 (zero .github delta, verified by diff); advisor verified and merged PR #5. OPEN VERIFICATION ITEM: the desktop job's final rustup form has never executed (skipped on workflow-only diffs; a PR #3 close/reopen did not retrigger CI). It proves itself automatically on the next push touching apps/desktop/**, which must happen before any M2 merge. Check the log for real pnpm/cargo execution then, do not accept a skip as proof.
2. K3's next session: confinement-check wiring PR, then auth endpoints + KT persistence (ADR-0003 ACCEPTED, fully unblocked). Verify endpoint tests ship in the same PRs and canary injection points extend to new endpoints.
3. Opus's next session: Go oracle fixtures (issue 001 option A), review of K3's confinement script.
4. M1 exit watch: multi-client harness AC is the last M1 gate; integration checkpoint before M2 opens for Grok.

## State at this sync

- main f242398: all ADRs ACCEPTED (0001, 0002 incl. §4 rev 2, 0003); issues 001/002/003 closed; K3 stack merged (PRs #10-#17); acceptances PR #18; full five-job pipeline green on main (run 29673166977), canary scan now runs on every push.
- Open PRs: #3 (M2 draft, gated), #5 (desktop CI, awaiting rebase).
- Stale: origin/advisor/setup (delete after confirming nothing unique remains).
