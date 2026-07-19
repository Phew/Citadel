# Advisor status — end of 2026-07-17 session

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is only the immediate queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`, branch `advisor/setup`.

## Immediate queue, in order

1. Confirm charge sent the three K3 relays (ADR-0001 rev 2 re-review; ADR-0003 A/B/C fold + issue 003 ruling; CI toolchain fix + restack). Contents summarized in ADVISOR-CONTEXT.md open queue.
2. When K3 pushes: verify the CI fix by opening Actions logs and confirming db-tests, canary-scan, and compose-smoke each show real execution lines. Only then is the K3 merge wave unblocked (charge merges, stated stack order).
3. Verify K3's issue 004 re-review confirm, then remind charge to accept ADR-0001; verify A/B/C landed in ADR-0003 text, then remind charge to accept it (issue 003 closes on that acceptance).
4. Track Opus's owed follow-ups: proto key_id + proof+head wrapper PR; docs/protocol/auth.md.
5. advisor/setup merge to main is pending with charge (merges clean, opus/m1-proto already landed as PR #2).

## State at wind-down

- main: 14bafbe + PR #2 (opus/m1-proto) merged.
- advisor/setup: role docs committed, issue 001 decision recorded (RESOLVED, option A), ADR-0002 marked ACCEPTED, this status doc + refreshed ADVISOR-CONTEXT.
- PR #3: grok/m2-desktop-shell draft, do not merge until M1 checkpoint.
- All six k3/m1-* branches: CI red at toolchain setup; new jobs never executed. Blocking their merge wave.
