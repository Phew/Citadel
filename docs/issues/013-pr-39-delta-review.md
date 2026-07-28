# 013: PR #39 post-merge delta review

- **Reporter:** core lane
- **Date:** 2026-07-27
- **Blocks:** honest closeout of the M2 delivery surface; PR #39 is already merged
- **Related:** commit `33fcfe9`, ADR-0005, ADR-0006

## Verdict

**CHANGES.** The transport behavior and its real-PostgreSQL evidence are
substantial and mostly sound, but the merged surface contains one unaccepted
contract change and two fail-closed/accuracy defects. This is a post-merge
review, so the verdict records follow-up work rather than pretending the merge
can be recalled.

## Findings

### 1. ADR-0005 still specifies the lossy Welcome acknowledgment that the code replaced

**Severity: high.**

ADR-0005 §1 says the gateway pushes an undelivered Welcome and then sets
`delivered_at` (`docs/decisions/0005-m2-dm-delivery-wire-model.md:117`). The
merged implementation intentionally does not mark at push time. It waits for
an accepted post-verification Subscribe
(`crates/delivery-service/src/gateway.rs:157`,
`crates/delivery-service/src/store.rs:447`). That behavior is stronger because
a socket flush does not prove the joiner consumed the Welcome, but it is still
a change to an accepted wire/lifecycle decision. The status file records the
fix; the controlling ADR does not.

**One-line fix:** propose an ADR-0005 amendment that makes accepted Subscribe
the delivery acknowledgment, then have charge accept or reject it.

### 2. Stored delivery rows are decoded with a production panic and unchecked signed conversions

**Severity: medium.**

`kind_from_text` panics on an unexpected database value
(`crates/delivery-service/src/store.rs:83-90`) because the migration has a
`CHECK` constraint. The same read path casts signed database `seq` and `epoch`
values to `u64` without validation (`:347-368`), while submit casts a client
`u64` epoch to `i64` (`:245`). A schema constraint is useful evidence, but it
does not make corruption, operator writes, or a future migration
infallible. The current behavior can panic a request task or turn malformed
negative state into a large wire value instead of failing closed.

**One-line fix:** make row decoding fallible, use checked conversions in both
directions, and reject out-of-range epochs before the insert.

### 3. The claimed migration-wide Tokio backstop wraps only `run_direct`

**Severity: medium.**

The migration module repeatedly calls its Tokio timeout a backstop over the
"whole run" (`crates/citadel-migrations/src/lib.rs:24,74,88`), but the timeout
begins only at `MIGRATOR.run_direct` (`:226`). Pool acquisition (`:136`),
session setup, advisory-lock acquisition, and exact-prefix preflight occur
outside it. PostgreSQL's lock and statement timeouts still bound individual
server statements and satisfy ADR-0006's accepted 60-second/300-second
requirements, but they do not make the additional whole-run claim true.

**One-line fix:** either wrap the complete acquired-connection workflow in the
Tokio deadline with a cancellation-safe exit path, or narrow every whole-run
claim to the migrator apply phase.

### 4. Immutable migration 0004 carries two stale comments

**Severity: low, documentation only.**

Migration 0004 says both service migrators use `ignore_missing`
(`crates/citadel-migrations/migrations/0004_delivery_groups_messages.sql:6`)
and that a Welcome is marked delivered immediately after push (`:55`). The
canonical runner now forbids `ignore_missing`, and delivery is acknowledged by
Subscribe. The SQL bytes are immutable after application, so editing this file
would be the wrong repair.

**One-line fix:** record both lines as historical comments superseded by
ADR-0006 and the proposed ADR-0005 lifecycle amendment; do not rewrite applied
migration bytes.

## What held under review

- Submit sequencing and idempotent-race rollback use one real PostgreSQL
  serialization point and preserve gap-free sequence assignment.
- Founder and participant checks are transactionally ordered with first-group
  creation.
- REST is the only write path; fanout occurs only after commit.
- Gateway lag is recoverable through the authoritative sequence cursor.
- Bearer validation matches ADR-0003's stored token semantics.
- The canonical migration corpus, prefix check, lock cleanup, and
  real-PostgreSQL evidence are non-vacuous.
- The delivery canary and compose harness exercise real rows and real service
  paths.

## What I need from charge

Rule on the ADR-0005 Welcome-acknowledgment amendment after K3 reviews it. The
code-hardening findings can land as ordinary fixes under the accepted
fail-closed posture; they do not require a new design decision.

## Non-goals / what I will not improvise

This review does not rewrite immutable migration 0004, revert the safer
Subscribe acknowledgment, or claim that an already merged commit was approved
after the fact.
