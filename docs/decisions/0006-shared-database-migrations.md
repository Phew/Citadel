# ADR-0006: Canonical migrations for the shared database

- **Status:** PROPOSED
- **Date:** 2026-07-21
- **Deciders:** charge (required for ACCEPTED)
- **Invariants touched:** INV-1, INV-4, INV-6, INV-7
- **Related:** plans/PLAN.md §§2, 3, 6, 9, 13; plans/AGENTS.md rules 3, 4, 8; docs/decisions/0001 §4, 0005 §2 and Amendment 1; PR #39

## Context

Citadel's backend services share one PostgreSQL 16 database and therefore one
SQLx `_sqlx_migrations` table. Auth-service currently embeds migrations
0001-0003. PR #39 adds delivery-service migration 0004 through a second,
partial migrator. Once delivery's row exists, auth-service's partial migrator
sees an applied version absent from its local corpus and fails with SQLx's
`VersionMissing` error.

PR #39 works around that failure by setting `ignore_missing = true` in both
migrators. In the locked SQLx 0.8.6 implementation, that flag skips the entire
validation that every applied version is present in the resolved corpus.
Checksum validation still protects migration files that remain present, but an
applied auth migration can be deleted from a later auth binary without failing
startup. The same hole allows an older service artifact to start without
detecting migration history that its partial corpus cannot classify as foreign
or deleted. A code comment cannot distinguish those cases.

This becomes more dangerous as directory-service adds shared relational state
in M4 and blobstore-service adds attachment metadata in M5. Per-service partial
histories would require every new service to know global numbering, foreign-row
handling, deletion detection, collision handling, and cross-service rollback
ordering before it can add one table. The database is already a shared
deployment boundary, so hiding parts of its history from each migrator creates
failure modes without creating service independence.

Migration integrity supports security properties implemented by schema:
ciphertext-only columns and table coverage protect INV-1; clients must not gain
trust from inconsistent server state under INV-4; unique sequence and commit
constraints protect INV-6; later signed role-state storage supports INV-7.
PLAN.md §13 therefore applies: migration claims need named, real-PostgreSQL
evidence and must fail loudly when the database is unavailable or divergent.

## Decision

### 1. One canonical corpus and one production migrator

Citadel will have one append-only, globally ordered migration corpus for the
shared PostgreSQL database. The implementation will place that corpus under a
dedicated workspace package, `crates/citadel-migrations`, and expose one binary,
`citadel-migrate`. Auth, delivery, directory, and blobstore may contribute
migration files through their normal reviewed changes, but they do not own
separate migration directories or migration ledgers.

`citadel-migrate` is the only production component that may apply schema
changes or mutate `_sqlx_migrations`. Normal service startup never runs a
partial migrator. Database-backed tests initialize their database through the
same canonical library entry point used by the binary, so production and test
schema construction cannot drift.

The canonical SQLx `Migrator` keeps its default database locking and
`ignore_missing = false`. Enabling `ignore_missing` anywhere in production code
is forbidden. The migration runner performs an exact-prefix preflight under the
migration lock before applying anything: successful rows in
`_sqlx_migrations`, ordered by version, must exactly match a prefix of the
embedded canonical ledger by version and SQLx SHA-384 checksum. Unknown rows,
missing rows, holes, checksum drift, or a failed migration stop the run before
new SQL executes. This exact-prefix check is additional to SQLx's own
`VersionMissing`, `VersionMismatch`, dirty-state, and locking behavior.

### 2. Canonical numbering and immutable history

Migration versions are globally unique across every service. Existing versions
0001-0003 retain their numbers and delivery's pending schema is version 0004.
Later migrations use the next integer greater than the highest version on
main. A branch collision is resolved by rebasing on main and renumbering only
the migration that has never reached main. Once a migration reaches main, its
version, filename, transaction mode, and bytes never change and it is never
deleted or renumbered. Corrections are new forward migrations.

The corpus includes an append-only machine-readable ledger containing, for
each migration, its version, filename, SQLx SHA-384 checksum, owning service or
`shared`, transaction mode, and recovery classification. The ledger records
review responsibility; it does not split execution history. CI compares the
pull request against the protected base ledger, so changing a ledger entry and
its SQL file together cannot disguise a rewrite.

Migrations are transactional and forward-only by default. A non-transactional
or destructive migration requires a separately accepted ADR defining failure
recovery and rollout evidence before its SQL can merge. Automated per-service
down migrations are forbidden because a service-local rollback can invalidate
later migrations owned by another service.

### 3. Deployment and rollback behavior

Every deployment runs the canonical migration artifact before starting any
service version that requires its schema. Failure prevents that rollout. Local
Compose uses a one-shot migration service and gates database-backed services on
its successful completion. Production uses the same release artifact as an
explicit migration job. Only that job needs schema-owner privileges; runtime
services do not need permission to create, alter, or drop schema objects.

Schema changes follow expand, migrate, contract:

1. Add a backward-compatible schema expansion.
2. Run the canonical migrator and verify schema invariants.
3. Deploy readers and writers that tolerate both the old and expanded shape.
4. Retire all consumers of the old shape.
5. Apply a contract migration in a later release only after its separate ADR
   and consumer-retirement evidence are accepted.

Services declare the minimum canonical schema version they require. They do not
require an exact head, because an older binary must tolerate additive newer
schema during a rolling deployment. Application rollback does not run down
migrations. It is allowed only while the target binary remains compatible with
the current expanded schema. If a contract migration has retired that binary's
schema, rollback fails closed and requires a forward repair or a separately
tested database restore procedure. Running an older migration artifact against
a database with newer applied versions also fails its exact-prefix preflight;
it can never silently reinterpret or remove the newer history.

### 4. Machine enforcement

Implementation adds the stdlib-only `ci/check_migrations.py`, following the
fail-loudly and injected-control pattern of
`ci/check_crypto_confinement.py`. The check is required in CI and proves:

- exactly one production migration corpus and one allowed `migrate!` call
  exist;
- no service-local migration directory or partial production migrator exists;
- no production path sets `ignore_missing` or disables migration locking;
- versions are positive, globally unique, and strictly append after the base
  ledger's maximum;
- every base-ledger entry remains byte-identical at the same filename and its
  recorded SHA-384 checksum matches the SQL file;
- every new ledger entry has a recognized owner, transaction mode, and recovery
  classification;
- down migrations, non-transactional migrations, and destructive
  classifications carry the accepted ADR required by this decision;
- injected duplicate-version, deleted-file, edited-file, service-local-file,
  ledger-rewrite, and `ignore_missing` probes all make the checker fail; and
- all four expected service crates and the canonical migration package are
  present, so a stale workspace view cannot pass vacuously.

The CI database job uses real PostgreSQL 16 and the canonical runner. It applies
the corpus to an empty database, reapplies it as a no-op, upgrades a committed
previous-schema fixture, and tests two concurrent runners. It also exercises
the divergence failures named under Evidence. This complements the static
checker: Git history proves append-only source discipline, while PostgreSQL
proves the runtime behavior.

### 5. Immediate disposition of PR #39

The `auth-service` change that sets `ignore_missing = true` is removed. The
equivalent delivery setting is not retained. Auth migrations 0001-0003 and
delivery migration 0004 move unchanged into the canonical corpus. Auth and
delivery production startup stop applying service-local migrations; their
database tests call the canonical migration library. PR #39 may implement
these changes only after this ADR is ACCEPTED.

Directory-service in M4 and blobstore-service in M5 follow the same path from
their first database table: add the next canonical migration, ledger entry,
named PostgreSQL evidence, and no service-local migrator. No new architecture
choice or `ignore_missing` exception is available to those services.

## Alternatives considered

1. **Per-service partial migrators with `ignore_missing = true`.** Rejected.
   SQLx cannot distinguish a legitimate foreign applied version from a deleted
   owned migration, so deletion and old-artifact detection disappear.
2. **Partial migrators with owned version ranges and a second global
   validator.** Rejected. Safe operation would require a global allocator,
   immutable ownership ledger, checksum registry, prefix validator, migration
   lock, deployment coordinator, and cross-service rollback policy. That
   recreates the canonical migrator while retaining more ways for a service to
   bypass it. Fixed ranges also become a permanent allocation footgun as
   services and shared migrations evolve.
3. **Embed the full canonical corpus in every service and migrate on every
   startup.** Rejected. It preserves history validation but gives every runtime
   service DDL authority, couples availability to migration races, and lets an
   old replica interfere with a rolling deployment. A dedicated job provides
   one auditable schema-change boundary.
4. **Keep service-local ledgers in separate PostgreSQL schemas or databases.**
   Rejected for v1. PLAN.md fixes one shared data model, and delivery already
   validates auth tokens against auth-owned tables. Splitting databases would
   change service boundaries and transaction assumptions beyond this defect.

## Consequences

- **Positive:** SQLx missing-version and checksum checks regain their intended
  meaning; schema history is globally visible, append-only, and fail-closed.
  Directory and blobstore add schema through the same proven path instead of
  inventing another numbering and `ignore_missing` convention.
- **Positive:** only one artifact holds DDL authority, tests and production use
  the same migration entry point, and rollout ordering is explicit.
- **Negative:** a schema change is a shared release event even when one service
  owns the table. That coupling already exists in the shared database and is
  made visible rather than hidden.
- **Negative:** destructive changes take at least two releases and a separate
  ADR. This is deliberate friction for preserving rollback safety and security
  constraints.
- **Follow-up:** after acceptance, the backend/CI owner implements the canonical
  package, migration job, Compose gate, source move, checker, and tests before
  any further service migration lands.

## Evidence

Implementation evidence, all against real PostgreSQL 16 where a database is
required:

- `canonical_migrations_apply_from_empty_postgres`
- `canonical_migrations_reapply_is_noop`
- `canonical_migrations_upgrade_previous_schema_fixture`
- `canonical_migrations_reject_unknown_applied_version`
- `canonical_migrations_reject_missing_applied_version`
- `canonical_migrations_reject_checksum_drift`
- `canonical_migrations_reject_non_prefix_history`
- `canonical_migrations_concurrent_runners_serialize`
- `migration_checker_rejects_history_rewrite_and_partial_migrator`
- Compose smoke evidence that services do not start when the one-shot migration
  job fails and do start after it succeeds.

## Ruling requested

Accept the canonical corpus and dedicated `citadel-migrate` job described
above. Reject per-service partial migrators and remove both `ignore_missing`
settings from PR #39.
