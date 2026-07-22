# ADR-0006: Canonical migrations for the shared database

- **Status:** ACCEPTED
- **Date:** 2026-07-21
- **Accepted:** charge, 2026-07-21
- **Implementation scope:** phased
- **Invariants touched:** INV-1, INV-4, INV-6, INV-7
- **Related:** plans/PLAN.md §§2, 3, 6, 9, 13; plans/AGENTS.md rules 3, 4, 8;
  docs/decisions/0001 §4, 0005 §2 and Amendment 1; PR #39

## Acceptance note

The decision is accepted in full with phased implementation per the design
review recorded on PR #40. CORE is the merge gate for the PR #39 rework.
Follow-ups A-D remain binding and land as tracked, independent PRs without
blocking PR #39.

CORE delivers:

- `crates/citadel-migrations` with migrations 0001-0004 moved byte-identically,
  the exact-prefix preflight, canonical library, `citadel-migrate` binary, and
  migration manifest;
- PR #39 reworked to remove both `ignore_missing` overrides, service-local
  migration directories, and service-startup migrators;
- the Compose migration-job gate and a `just migrate` recipe for development
  outside Compose;
- `ci/check_migrations.py` with the canonical-corpus, runner, locking,
  append-only, base-manifest, checksum, explicit-base-SHA, LF, and Git-blob-byte
  rules plus their injected controls; and
- the core PostgreSQL 16 evidence for clean apply, no-op reapply, upgrade,
  divergence rejection, concurrent serialization, lock timeout, Compose
  gating, and checker behavior.

The follow-ups are:

- **A:** role isolation, idempotent role bootstrap, runtime credentials, and
  PostgreSQL permission evidence;
- **B:** service minimum-schema declarations, read-only startup checks, and
  service-discovery enforcement;
- **C:** fail-closed migration risk-classification enforcement and its
  PostgreSQL compatibility evidence; and
- **D:** rollback check-only evidence, failed-migration Compose gating, and the
  remaining injected probes.

Review flag 2 is confirmed safe: an in-progress canonical history remains an
exact prefix before concurrent runners serialize. Review flag 3 remains in
CORE because LF checkout and Git-blob-byte hashing protect embedded SQLx
checksums. Review flag 5 is folded into the CORE development flow through
`just migrate`. Review flag 1 is addressed by follow-up A.

## Context

Citadel's backend services share one PostgreSQL 16 database. Their current
connections use the same default schema, so their SQLx migrators contend for
`public._sqlx_migrations`. PostgreSQL can hold same-named tables in different
schemas, so database sharing alone does not guarantee one history. This ADR
pins the schema and search path rather than relying on that default.

Auth-service currently embeds migrations 0001-0003. PR #39 adds
delivery-service migration 0004 through a second, partial migrator. Once the
delivery-service row exists, auth-service's partial migrator sees an applied
version absent from its local corpus and fails with SQLx's `VersionMissing`
error.

PR #39 works around that failure by setting `ignore_missing = true` in both
migrators. In the locked SQLx 0.8.6 implementation, that flag skips the entire
validation that every applied version is present in the resolved corpus.
Checksum validation still protects migration files that remain present, but an
applied auth-service migration can be deleted from a later auth-service binary
without failing startup. The same hole allows an older service artifact to
start without detecting migration history that its partial corpus cannot
classify as foreign or deleted. A code comment cannot distinguish those cases.

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
`citadel-migrate`. Auth-service, delivery-service, directory-service, and
blobstore-service may contribute migration files through their normal reviewed
changes, but they do not own separate migration directories or
`_sqlx_migrations` histories.

Terms are fixed throughout this decision:

- **migration runner:** the `citadel-migrate` binary;
- **migration artifact:** the immutable release artifact containing that
  binary, canonical SQL corpus, and migration manifest; and
- **migration job:** one deployment invocation of the migration artifact.

The migration runner is the only production component that may apply schema
changes or mutate `_sqlx_migrations`. Normal service startup never runs a
partial migrator. Database-backed tests initialize their database through the
same canonical library entry point used by the binary, so production and test
schema construction cannot drift.

The canonical history is `public._sqlx_migrations`. The migration connection
sets `search_path` to `pg_catalog, public, pg_temp`, placing PostgreSQL's
otherwise first-searched temporary schema last, and custom preflight queries
fully qualify the table. `CREATE` on schema `public` is revoked from `PUBLIC`;
only the migration role can create schema objects there. A second migration
history in another schema is a fatal configuration error, not an independent
service history.

The canonical SQLx `Migrator` keeps its default database locking and
`ignore_missing = false`. Enabling `ignore_missing` anywhere in production code
is forbidden. The migration runner performs an exact-prefix preflight under the
migration lock before applying anything: successful rows in
`public._sqlx_migrations`, ordered by version, must exactly match a prefix of
the embedded migration manifest by version and SQLx SHA-384 checksum. Unknown
rows, missing rows, holes, checksum drift, or a failed migration stop the run
before new SQL executes. This exact-prefix check is additional to SQLx's own
`VersionMissing`, `VersionMismatch`, dirty-state, and locking behavior.

Migration lock acquisition is bounded to 60 seconds and each migration
execution to 300 seconds. Timeout is a fatal, non-zero migration-job result;
services remain stopped. A migration that cannot fit those bounds requires an
accepted ADR for its online execution and recovery plan rather than a quiet
timeout increase.

### 2. Canonical numbering and immutable history

Migration versions are globally unique across every service. Existing versions
0001-0003 retain their numbers and delivery-service's pending schema is version
0004.
Later migrations use the next integer greater than the highest version on
main. A branch collision is resolved by rebasing on main and renumbering only
the migration that has never reached main. Once a migration reaches main, its
version, filename, transaction mode, and bytes never change and it is never
deleted or renumbered. Corrections are new forward migrations.

The corpus includes the append-only machine-readable migration manifest
`crates/citadel-migrations/manifest.json`. Each entry contains its version,
filename, SQLx SHA-384 checksum, responsible service or `shared`, transaction
mode, migration risk classification, recovery method, and accepted ADR. The
manifest records review responsibility; it does not split execution history.
CI compares the pull request against the protected base manifest, so changing
a manifest entry and its SQL file together cannot disguise a rewrite.

Risk classifications are `expand`, `contract`, and `data`. Every migration
traces through its manifest entry to an ACCEPTED ADR that governs its schema
decision; it does not require a fresh ADR for each migration file. For example,
migration 0004 traces to ADR-0005. The manifest records the classification and
recovery method in CORE, while follow-up C adds the fail-closed classification
enforcement described below.
`expand` is intentionally narrow: it may add a table, index, or nullable column
without a default, and may not execute DML or alter, rename, remove, constrain,
or change privileges on an existing object. `contract` covers every removal,
narrowing, rename, new constraint, privilege change, or other mutation of an
existing schema contract. `data` changes existing rows. Anything outside the
machine-recognized `expand` subset fails closed as `contract` or `data`; a
manifest label and finite fixtures are never proof of semantic compatibility.

Migrations are transactional and forward-only by default. A non-transactional,
`contract`, or `data` migration requires its ADR to define failure recovery and
rollout evidence before its SQL can merge. Automated per-service down
migrations are forbidden because a service-local rollback can invalidate later
migrations contributed by another service.

### 3. Deployment and rollback behavior

Every forward deployment runs the incoming migration artifact before starting
any service version that requires its schema. Failure prevents that rollout.
Local Compose uses a one-shot migration job and gates database-backed services
on its successful completion. Production invokes the same release artifact as
an explicit migration job.

The migration role owns `public._sqlx_migrations` and the application schema.
Runtime service roles are `NOINHERIT`, are not members of the migration role or
any role that owns application objects, and cannot create, alter, or drop
schema objects. They have only `SELECT` on `public._sqlx_migrations`;
`INSERT`, `UPDATE`, `DELETE`, and `TRUNCATE` are revoked. Default privileges
must preserve these rules for later
tables. Permission tests run each service under its runtime role and prove raw
DDL and migration-history writes fail.

Schema changes follow expand, migrate, contract:

1. Add a backward-compatible schema expansion.
2. Run the canonical migrator and verify schema invariants.
3. Deploy readers and writers that tolerate both the old and expanded shape.
4. Retire all consumers of the old shape.
5. Apply a contract migration in a later release only after its separate ADR
   and consumer-retirement evidence are accepted.

Each service declares its minimum canonical schema version in machine-readable
package metadata. Before serving, it runs a read-only startup check that the
qualified migration history exactly matches the manifest through that minimum.
Missing history, checksum drift, or a schema below the compiled minimum is a
fatal startup error. Services do not require an exact head, because an older
binary must tolerate additive newer schema during a rolling deployment.

Application rollback never invokes the target release's older migration
artifact and never runs down migrations. Deployment retains the current
schema-head migration artifact, runs its check-only preflight, and starts the
target binary only if its declared minimum is satisfied and no accepted
`contract` ADR has retired that binary's schema. If a contract migration has
retired it, rollback fails closed and requires a forward repair or a separately
tested database restore. An older migration artifact invoked by mistake also
fails against newer applied versions; it can never reinterpret or remove them.

### 4. Machine enforcement

Implementation adds the stdlib-only `ci/check_migrations.py`, following the
fail-loudly and injected-control pattern of
`ci/check_crypto_confinement.py`. The check is required in CI and enforces:

- exactly one production migration corpus, runner, and allowed `migrate!` call
  exist;
- no service-local migration directory or partial production migrator exists;
- no production path enables `ignore_missing` or disables SQLx migration
  locking;
- only the canonical package declares SQLx's `migrate` feature or depends on
  the runner feature; source checks reject known direct migration APIs,
  service-local SQL, and direct `_sqlx_migrations` writes as defense in depth;
- runtime database permissions remain the capability boundary for dynamically
  assembled DDL or indirect history writes, and the PostgreSQL permission tests
  prove those operations fail from every service role;
- versions are positive, globally unique, and strictly append after the base
  manifest's maximum;
- every base-manifest entry remains byte-identical at the same filename and its
  recorded SHA-384 checksum matches the SQL file;
- `.gitattributes` pins the canonical SQL and manifest to LF, and the checker
  hashes Git blob bytes rather than platform-normalized working-tree bytes;
- every new manifest entry has a recognized responsible service, transaction
  mode, migration risk classification, recovery method, and ACCEPTED ADR;
- down migrations, non-transactional migrations, and `contract` or `data`
  risk classifications carry the accepted ADR required by this decision;
- injected duplicate-version, deleted-file, edited-file, service-local-file,
  manifest-rewrite, wrong-schema, wrong-search-path, raw-DDL, and
  `ignore_missing` probes all make the checker fail; and
- database-consuming services are discovered from canonical workspace package
  metadata, every discovered service declares a valid minimum schema version,
  and the canonical migration package is present, so a stale or newly added
  service cannot pass vacuously.

The CI database job uses real PostgreSQL 16 and the canonical runner. It applies
the corpus to an empty database, reapplies it as a no-op, upgrades a committed
previous-schema fixture, tests two concurrent runners, and exercises the pinned
timeouts. A real-PostgreSQL catalog-and-data comparison supplies regression
evidence for each migration but does not claim to prove semantic compatibility.
This complements the static checker: protected Git history proves append-only
source discipline, while PostgreSQL proves runtime behavior and permissions.
CI receives the pull request's exact base SHA explicitly; absence of that
immutable comparison base is a failure.

### 5. Immediate disposition of PR #39

The `auth-service` change that sets `ignore_missing = true` is removed. The
equivalent delivery-service setting is not retained. Auth-service migrations
0001-0003 and delivery-service migration 0004 move unchanged into the canonical
corpus. Auth-service and delivery-service production startup stop applying
service-local migrations; their database tests call the canonical migration
library. This accepted ADR authorizes those changes in the CORE phase.

Directory-service in M4 and blobstore-service in M5 follow the same specified
path from their first database table: add the next canonical migration,
manifest entry, named PostgreSQL evidence, and no service-local migrator. No
new architecture choice or `ignore_missing` exception is available to those
services.

## Alternatives considered

1. **Per-service partial migrators with `ignore_missing = true`.** Rejected.
   SQLx cannot distinguish a legitimate foreign applied version from a deleted
   owned migration, so deletion and old-artifact detection disappear.
2. **Partial migrators with owned version ranges and a second global
   validator.** Rejected. Safe operation would require a global allocator,
   immutable ownership manifest, checksum registry, prefix validator, migration
   lock, deployment coordinator, and cross-service rollback policy. That
   recreates the canonical migrator while retaining more ways for a service to
   bypass it. Fixed ranges also become a permanent allocation footgun as
   services and shared migrations evolve.
3. **Embed the full canonical corpus in every service and migrate on every
   startup.** Rejected. It preserves history validation but gives every runtime
   service DDL authority, couples availability to migration races, and lets an
   old replica interfere with a rolling deployment. A dedicated job provides
   one auditable schema-change boundary.
4. **Keep service-local histories in separate PostgreSQL schemas or
   databases.**
   Rejected for v1. PLAN.md fixes one shared data model, and delivery-service
   already validates auth-service tokens against auth-service-owned tables.
   Splitting databases would change service boundaries and transaction
   assumptions beyond this defect.

## Consequences

- **Positive:** SQLx missing-version and checksum checks regain their intended
  meaning; schema history is globally visible, append-only, and fail-closed.
  Directory-service and blobstore-service add schema through the same specified
  path instead of inventing another numbering and `ignore_missing` convention.
- **Positive:** only the migration artifact holds DDL authority, tests and
  production use the same migration entry point, and rollout ordering is
  explicit.
- **Negative:** a schema change is a shared release event even when one service
  owns the table. That coupling already exists in the shared database and is
  made visible rather than hidden.
- **Negative:** destructive changes take at least two releases and a separate
  ADR. This is deliberate friction for preserving rollback safety and security
  constraints.
- **Follow-up:** after acceptance, the backend/CI maintainer implements the
  canonical package, migration job, Compose gate, source move, checker, and
  tests before any further service migration lands.

## Required acceptance evidence

Required implementation evidence, all against real PostgreSQL 16 where a
database is required:

- `canonical_migrations_apply_from_empty_postgres`
- `canonical_migrations_reapply_is_noop`
- `canonical_migrations_upgrade_previous_schema_fixture`
- `canonical_migrations_reject_unknown_applied_version`
- `canonical_migrations_reject_missing_applied_version`
- `canonical_migrations_reject_checksum_drift`
- `canonical_migrations_reject_non_prefix_history`
- `canonical_migrations_reject_wrong_schema_history`
- `canonical_migrations_concurrent_runners_serialize`
- `canonical_migration_lock_timeout_fails_closed`
- `runtime_roles_cannot_mutate_schema_or_migration_history`
- `services_reject_schema_below_compiled_minimum`
- `application_rollback_uses_schema_head_check_only`
- `expand_classification_preserves_existing_schema_and_rows`
- `migration_checker_rejects_history_rewrite_and_partial_migrator`
- `compose_services_wait_for_successful_migration_job`
- `compose_services_stay_stopped_after_migration_failure`

## Ruling

charge accepted the canonical corpus and dedicated `citadel-migrate` job on
2026-07-21 with the phased scope recorded above. Per-service partial migrators
remain rejected, and both `ignore_missing` settings are removed from PR #39.
