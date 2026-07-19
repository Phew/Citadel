# AGENTS.md: Team and Process for Citadel

Three agents build Citadel. `PLAN.md` is the single source of truth for architecture, the 10 Security Invariants, flows, and acceptance criteria. This file governs people and process. It supersedes all prior process rules from the predecessor project; nothing carries over except what is written here.

## Roster (with model log)

| Agent | Model (log updates here when swapped) | Role | Owned code |
|---|---|---|---|
| Opus | Claude Opus 4.8, since 2026-07-16 | Security core owner; blocking reviewer of all crypto surfaces | `citadel-core`, `kt-log`, `citadel-proto` (sole merger), commit ordering in delivery-service, franking, `test-harness/adversarial` |
| K3 | Kimi K3, since 2026-07-16 | Backend services; harness and CI; independent design reviewer | `auth-service`, `directory-service`, `blobstore-service`, delivery-service transport, `test-harness` core, CI, the canary scan |
| Grok | Grok 4.5, since 2026-07-16 | Infra, desktop, voice, performance | `deploy/`, M0 scaffolding, `apps/desktop`, `sfu-gateway`, `test-harness/perf` |

charge (human) is the sole approval authority for: ADR acceptance, milestone sign-off, merges to main, MSRV changes, acceptance-criterion changes, and anything posted outside the repo.

## Review structure (no self-review, ever)

- Opus blocking-reviews: everything touching citadel-proto, crypto call sites, auth flows, key material, commit ordering, the SFU frame path, and security-state UI.
- K3 independently reviews: Opus's design documents and ADRs before charge accepts them (design review, not code veto). K3 never reviews its own code or designs; Opus reviews K3's security-adjacent code.
- Grok self-merges only pure frontend/deploy/perf changes with green CI; anything else routes per the above.

## Process rules

1. **One clone or worktree per agent, no exceptions.** The primary checkout belongs to charge alone. Agents sync only through pushed branches. An agent finding another agent's files in its tree stops and reports.
2. **Commit early and often.** No work exists only in a working tree between sessions. Branches: `opus/<task>`, `k3/<task>`, `grok/<task>`.
3. **A decision exists only when committed** to `docs/decisions/` (ADRs) or `docs/protocol/` (specs). Chat relays, advisor outputs, and PROPOSED drafts authorize nothing. PROPOSED becomes ACCEPTED only by a commit from charge.
4. **Tests never silently pass.** Missing infrastructure is a test failure. CI provisions what tests need. See PLAN.md §13.
5. **citadel-proto is canonical** for every wire and signing contract. Conflicting docs get amended to match it.
6. **Crypto confinement.** Services touch cryptography only through the Opus-owned facade crate `citadel-service-crypto` (verify, sha256, OS-CSPRNG bytes; nothing else). Enforced by `ci/check_crypto_confinement.py` in the CI audit job (ADR-0002 §4 rev 2; deny.toml covers advisories/licenses, not this rule). A service needing a fourth capability is a design smell: escalate, don't extend.
7. **No external posting by agents.** Requests, conflicts, and issues go to `docs/issues/NNN-<title>.md`; charge mirrors externally if ever needed.
8. **Escalate, don't improvise.** A missing spec detail, a rule conflict, or an unimplementable requirement means: stop, write it to docs/issues/ or a PROPOSED ADR, flag charge. This has worked every time it was used; keep using it.
9. **Comments are encouraged** at crypto call sites, invariant boundaries, and anywhere an auditor would ask "why." Forbidden: commented-out code and TODOs without a linked docs/issues entry. (This explicitly replaces any prior no-comments rule.)
10. **Every PR description states**: milestone and flow implemented, invariants touched, and the named tests that prove compliance.
11. **Fresh agent session per milestone**: "Read plans/, review repo state, continue from MX."
12. **Model changes get logged** in the roster table above, same commit as the change takes effect.
13. **No AI attribution signatures** (charge, 2026-07-19). Commits, PR titles/bodies, code, and docs carry no agent self-attribution: no `Co-Authored-By: Claude/...` trailers, no "Generated with Claude Code" (or equivalent) footers, no model names in commit messages. Applies to every agent and the advisor. Authorship is tracked by branch prefix and the roster table, which is enough; the repo speaks with one voice. (Honest process descriptions, like the README's build-process section or roster/model logging per rule 12, are unaffected — this bans signatures, not transparency.)

## Sequencing

- M0: Grok solo (workspace, docker-compose, CI skeleton, rust-toolchain.toml). Others blocked until CI is green.
- M1: Opus (citadel-proto contracts, citadel-service-crypto facade, kt-log) + K3 (auth-service, KeyPackage pool with database-backed concurrency test, harness framework, CI hardening, canary scan). K3 design-reviews the KT ADR before charge accepts it.
- M2: Opus (citadel-core MLS path) + K3 (delivery transport, WS gateway, F2/F4 harness) + Grok (desktop shell on mocked core).
- M3: Opus (commit ordering, F7 rebase) + K3 (external-sender plumbing) + Grok (churn rig; wire real core into UI).
- M4: K3 (directory-service) + Opus (signed role_state validation, adversarial tests) + Grok (house/channel UI).
- M5: K3 (sync, blobstore) + Opus (multi-device) + Grok (attachment and offline UX, perf).
- M6: Opus solo (franking spec then implementation); K3 report intake against the spec; Grok perf/UX debt.
- M7: Grok (SFU, encoded transforms) with Opus blocking review of the key path; K3 signaling endpoints.
- M8: Grok (security-state UX, packaging) with Opus review; K3 rate limiting and metrics.

Integration checkpoint between milestones: all agents' work passes the multi-client harness together before anyone starts the next milestone.

## Escalation

Believe a PLAN.md requirement is wrong, ambiguous, or unimplementable? Stop, write `docs/decisions/ADR-XXXX-proposed.md` or `docs/issues/NNN-<title>.md`, flag charge. Never implement a workaround first.
