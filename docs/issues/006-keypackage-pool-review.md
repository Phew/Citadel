# 006: Blocking review — KeyPackage one-time pool (M1.3 race-safety). Verdict: approve

- **Reviewer:** Opus (M1 task 3: review K3's KeyPackage consumption path for race-safety; AGENTS.md review matrix)
- **Date:** 2026-07-17
- **Blocks:** nothing — clean approve. Non-blocking notes are for the future HTTP endpoint, not this branch.
- **Related:** `origin/k3/m1-keypackage-pool` @ 7d3ce27 (also in `k3/m1-kt-adr-review`):
  migrations/0001_accounts_devices_key_packages.sql, auth-service/src/store.rs,
  auth-service/tests/key_package_pool.rs, .github/workflows/ci.yml (db-tests job);
  plans/PLAN.md §6, §9 M1 AC, §10, §13; AGENTS.md rule 4, rule 6

## Scope

Reviewed the one-time KeyPackage pool for the three properties this milestone
turns on: (1) a package is consumed at most once under arbitrary concurrent
load (PLAN §9 M1 AC), (2) the concurrency property test actually runs against
real PostgreSQL in CI and fails loudly without it (PLAN §13, rule 4), and
(3) no cryptography escapes the Opus-owned facade (rule 6). Read the migration,
`store.rs` in full, all four tests in `key_package_pool.rs`, and the `db-tests`
CI job.

## 1. Transactional single-consumption — CORRECT

- `consume_one_in` is the shared core: `SELECT id, package_bytes … WHERE
  device_id = $1 AND consumed_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP
  LOCKED`, then `UPDATE … SET consumed_at = now() WHERE id = $1`, both inside
  one transaction that the caller commits. This is the correct PostgreSQL
  queue pattern:
  - `FOR UPDATE` takes a row lock held until the transaction commits; a
    concurrent consumer's `SKIP LOCKED` skips that row rather than blocking or
    reading it, so **no row is ever handed to two committed transactions**.
  - `consumed_at` is set in the *same* transaction that returns the bytes and
    is only visible after commit; on rollback the row reverts to
    `consumed_at IS NULL` and correctly re-enters the pool. There is no window
    where a package is both returned to a caller and still available.
  - The post-select `UPDATE … WHERE id = $1` needs no `consumed_at IS NULL`
    re-guard because the row lock makes concurrent mutation impossible; the
    `SELECT`'s own `consumed_at IS NULL` filter already excludes
    already-committed consumptions.
- `consume_for_account` (F2's "one package per active device, all-or-nothing")
  iterates devices in deterministic `ORDER BY id` and rolls the whole
  transaction back on the first empty device, so a fetch the caller cannot
  complete burns nothing. Because it uses `SKIP LOCKED` (never waits), there is
  no lock-ordering deadlock across racing account fetches.
- Migration backs this correctly: `key_packages.id BIGINT GENERATED ALWAYS AS
  IDENTITY` gives FIFO order, and the partial index
  `key_packages_available (device_id, id) WHERE consumed_at IS NULL` matches the
  hot consuming query exactly.

## 2. The property test genuinely runs against real PostgreSQL in CI — CONFIRMED

- `key_package_pool.rs` tests are `#[ignore]` so bare `cargo test` stays
  infra-free, and `db_url()` uses `std::env::var("DATABASE_URL").expect(…)` —
  **a missing DB is a hard failure, never a skip** (PLAN §13, rule 4). The
  expect message says exactly that.
- CI `db-tests` job provisions `postgres:16-alpine` as a service with a
  healthcheck, sets `DATABASE_URL`, and runs
  `cargo test --locked -p auth-service -- --include-ignored` — so the ignored
  pool tests are the ones actually exercised there. A green check therefore
  means the property was tested against a real database, which is the whole
  point of §13.
- Coverage is real, not a token test: `exactly_once_deterministic_hammer`
  (16 racers drain 64 packages; asserts unique == published == drained and the
  pool ends dry), `account_fetch_is_all_or_nothing` (failed fetch rolls back,
  burns nothing), `account_fetch_races_never_double_consume` (8 racers,
  30 packages consumed exactly once across account-level races), and a
  proptest over randomized `(packages, consumers)`. The double-consumption
  assertion is explicit (`unique.len() != all.len()` → `DOUBLE CONSUMPTION`).

## 3. No crypto outside the facade — HOLDS (trivially)

`auth-service/Cargo.toml` pulls in no crypto crate — no ed25519/sha2/ring/rand/
getrandom, and not even `citadel-service-crypto`. The pool store is pure
sqlx/serde/thiserror and performs no cryptographic operation, so rule 6 is not
even reachable on this path. (The migration comment correctly defers
`DeviceCredential` verification to enrollment, which is a separate, later
surface — I'll review that when it lands, since it *will* touch the facade.)

## Non-blocking notes (for the future HTTP endpoint, not defects in this branch)

- **False-exhaustion under contention.** Because `consume_for_account` uses
  `SKIP LOCKED`, a concurrent account fetch can see a device's only package as
  momentarily *locked* and return `PoolExhausted` even though stock exists.
  This is safe (it never double-consumes — the racing test relies on exactly
  this to terminate) but it is a liveness quirk: the F2 HTTP layer should treat
  `KeyPackageUnavailable` as *possibly transient under load* and let the client
  retry, not surface it as a definitive "device has no packages."
- **Consumption is at-most-once w.r.t. delivery.** Once the endpoint exists, a
  transaction that commits but whose HTTP response is lost will have burned a
  package the client never received. For one-time KeyPackages this is the right
  trade (a wasted package, not a reused one); worth a one-line comment at the
  endpoint so it is a conscious choice rather than a surprise.

## Verdict

**Approve.** The exactly-once-under-concurrency property is implemented
correctly and is genuinely exercised against real PostgreSQL in CI (not
skipped), and no cryptography leaves the facade on this path. Nothing blocks;
the two notes above are guidance for when the consuming HTTP endpoint is built.
This satisfies my PLAN-OPUS-4.8 M1 task 3.
