# Advisor status — M2 opened (2026-07-21, ADR-0005 accepted, delivery + core building)

Read docs/roles/ADVISOR.md, then docs/roles/ADVISOR-CONTEXT.md (full memory; this file is only the immediate queue). Worktree: `C:\Users\charge\Documents\GitHub\Citadel\citadel-advisor`.

## Immediate queue, in order

1. Verify the two M2 build PRs as they land — do NOT endorse on agent narration:
   - Opus, citadel-core: F2/F4 OpenMLS path, padding framing module, encrypted SQLite store. Watch for real credential-against-KT verification on join (INV-4), pad-then-encrypt order, SQLCipher-style at-rest (not hand-rolled, INV-10), key in OS keychain (INV-2).
   - K3, delivery-service: POST/GET/WS per ADR-0005, lazy groups-row upsert, transactional next_seq, idempotency, participant-in-G on both submit and subscribe (Amendment 1), ciphertext-only storage, canary extended to group_messages.payload_bytes + welcome_deliveries. delivery-service must NOT depend on citadel-core/OpenMLS decrypt (crypto-confinement).
   - For each: open the actual CI log, confirm the named ADR-0005 evidence tests ran on real Postgres (#[ignore]+DATABASE_URL), never trust a green check alone.
2. M2 exit AC (the milestone gate): harness runs F2 + F4 end-to-end between 3 clients; no-plaintext scan finds zero hits in delivery tables; device_compromise_past_messages_unreadable_fs (forward secrecy) and pcs_recover_after_update (PCS) pass; adversarial_ds_swapped_keypackage_rejected (minimum) passes. This is what closes M2, same shape as M1's exit run.
3. Standing agent rules to enforce in relays: base every PR on main (never stacked branches, auto-close trap); open draft PRs early for CI, THEN mark "ready" when mergeable (a draft cannot be merged — cost us a retry on #36); the frozen citadel-proto::delivery wire is Opus's proto surface, coordinate contract edits; rule 13 = no AI attribution signatures.
4. charge open calls to surface when relevant: LICENSE file (public repo, currently all rights reserved), stale origin/advisor/setup deletion, gh-token tightening, trademark check.

## State at this sync

- main d2d9863: M1 complete and declared; M2 open. ADR-0001/0002/0003/0004/0005 all ACCEPTED. ADR-0005 (M2 DM delivery wire model) accepted with Amendment 1 (groups-row lifecycle + submit authorization = participant-in-G) folded; citadel-proto::delivery contracts are frozen on main.
- M2 build in progress: Opus on citadel-core (F2/F4 MLS, padding, encrypted store), K3 on delivery-service (message path + WS gateway + ciphertext storage), in parallel against the pinned contracts. Grok's desktop shell (PR #3) landed mock-backed on main (d380568); real-core wiring is a post-core follow-up.
- Repo is PUBLIC; CI minutes unlimited; trigger discipline per PR #26 (docs/plans/**.md skip CI).
- Open PRs: none at this sync (the two M2 build PRs will open next).

## Day-4/5 merge record (for context)

- Day 4: #21-#33 merged; M1 exit AC (3x2, KT proofs) green on main @ d2768c8; README made public; rule 13 added; repo made public after an Actions billing cutoff.
- Day 5: #35 (README M1-complete), #3 (desktop shell, mock-backed, d380568), #36 (ADR-0005 + delivery proto, d2d9863). M1 declared; M2 opened.
