# Opus status — end of 2026-07-17

For a fresh Opus instance with zero memory of today. Read `plans/PLAN.md`,
`plans/AGENTS.md`, `plans/PLAN-OPUS-4.8.md` first, then this. You are the
security core owner and blocking reviewer of all crypto surfaces.

## Where the work lives

- Worktree: `C:\Users\charge\Documents\GitHub\Citadel\Citadel-opus`
  (git worktree of the primary checkout; primary belongs to charge).
- Branch: **`opus/m1-proto`** — all M1 work below is here, pushed to
  `origin/opus/m1-proto`. Head commit at session end: **`d700149`** (plus
  this status doc committed on top). Worktree was clean before this doc.
- This branch is based on **`origin/grok/m0-scaffolding`**, NOT on `main` —
  M0 was not merged to main when I started. If M0 lands on main differently,
  rebase `opus/m1-proto` onto it before it merges.

## M1 task state (my lane: PLAN-OPUS-4.8 M1)

### DONE and pushed (opus/m1-proto)

1. **citadel-proto M1 contracts** — commit `d11dfcb`. `credential.rs`
   (DeviceCredential binding device→identity key, DeviceEndorsement),
   `kt.rs` (KtLeaf/SignedTreeHead/InclusionProof/ConsistencyProof, RFC 6962
   shapes), `auth.rs` (register/enroll/keypackage/challenge-verify bodies,
   challenge binds device_id), `envelope.rs::CommitConflict` (INV-6/F7 409
   body), `bytes.rs` (strict-length base64 serde). All signing inputs are
   deterministic, domain-separated (`citadel/v1/...`), golden-byte pinned.
   Tests green, clippy -D warnings clean.

2. **citadel-service-crypto facade** — commit `25a79c4`. Exactly three
   capabilities (verify_strict / sha256 / getrandom). AGENTS.md rule 6.
   ADR-0002 documents it.

3. **kt-log** — commit `e8e29d1`. RFC 6962 §2.1 generation + RFC 9162
   verification (`tree.rs`), append-only `KtLog`, encapsulated
   `TreeHeadSigner` (signs only TreeHeadTbs; no signing leaks to
   auth-service), pure client verifiers. Evidence: CT reference roots pinned
   as independent oracle; exhaustive ≤8 tests; proptests for append-only
   invariant (`tests/append_only.rs`). K3 design-reviewed it — see below.

4. **ADRs + issues** — commit `d700149`. ADR-0001 (KT design, PROPOSED),
   ADR-0002 (facade, PROPOSED), issue 001 (import Go oracle — decision for
   charge), issue 002 (request K3 wire deny bans for facade).

### PENDING — exact next actions

**A. ADR-0001 rev 2 — address issue 004 (F2 is priority).**
K3 approved ADR-0001 *with changes* in
`docs/issues/004-adr-0001-kt-design-review.md` (on branch
`origin/k3/m1-kt-adr-review`, commit `290f570`). Do NOT mark ADR-0001
ACCEPTED — only charge does that (rule 3), and only after these land. Amend
ADR-0001 (or write a short superseding note) on `opus/m1-proto`:
  - **F2 (PRIORITY) — log public-key distribution.** ADR says "clients pin
    the log public key" but never says how it reaches the client; F1 step 5
    self-inclusion verification is circular without it. Add one precise
    paragraph: v1 = log pubkey pinned in the client build / distributed with
    the client artifact via the release channel; document TOFU as an
    explicit threat-model gap otherwise. This is the honesty-critical one.
  - **F1 — persistence schema.** ADR §4 ("persist leaf bytes, rebuild")
    contradicts PLAN.md §6's `kt_log(seq, leaf_hash, tree_head, signature,
    timestamp)`, and *both* shapes are needed (leaf bytes for proofs +
    startup root check; STH history for serving consistency proofs across
    restarts without re-signing). Define the physical schema in the ADR:
    K3's suggestion `kt_leaves(seq BIGSERIAL PK, leaf_bytes BYTEA)` +
    `kt_sth(tree_size BIGINT PK, root_hash BYTEA, signed_at TIMESTAMPTZ,
    signature BYTEA)`, and note it supersedes PLAN §6's `kt_log` row
    (rule 5 doc amendment). K3's KT persistence PR is blocked on this.
  - **F3 — handle u16 length-prefix truncation** (`proto kt.rs
    KtLeaf::leaf_bytes`). Fix in code, not just ADR: add a hard/debug assert
    `handle.len() <= u16::MAX`, and require auth-service to cap handle length
    at registration (suggest ≤64 bytes). Latent footgun once any later leaf
    field becomes variable-width.
  - **F4 — startup root-mismatch test name.** Add to ADR-0001 Evidence:
    `auth-service tests/kt_persistence.rs::startup_fails_on_tampered_leaf_bytes`
    (K3 delivers the test; you just name the property so charge can hold the
    lane to it).
  - Non-blocking note worth folding in: pin the F1 step-5 flow (proof must
    be fetched at the STH's *exact* tree_size via `GET /v1/kt/proof`, not
    verified against a fresh head) in the future `docs/protocol/auth.md`.

**B. ADR-0003 blocking review — auth-flow operational parameters.**
K3 pushed `docs/decisions/0003-auth-flow-parameters.md` (PROPOSED) on
`origin/k3/m1-auth-params-adr`, commit `dd21881`. This is auth-flow / key
material → your blocking-review surface (AGENTS.md review matrix). It exists
because issue 003 flagged that auth-service must not improvise operational
params (token TTL, challenge size/expiry, KeyPackage pool sizing, handle
rules) that no spec pins. Review it: confirm challenge ≥32 bytes from OS
CSPRNG (INV-9), single-use + expiry; token TTL sane; no key material in
tokens (INV-2); handle cap consistent with F3 above. Note: `docs/protocol/
auth.md` (F1 flow spec, PLAN §7) still does not exist — `docs/protocol/` is
your lane; decide whether ADR-0003 + a short auth.md together pin F1, and
coordinate with K3 so auth-service isn't blocked. Record the review verdict
in a new `docs/issues/NNN` (next free number is 005).

**C. KeyPackage pool review (M1 task 3) — race-safety.**
K3 pushed the one-time KeyPackage pool on `origin/k3/m1-keypackage-pool`
(also in `k3/m1-kt-adr-review`, commit `7d3ce27`): migration
`0001_accounts_devices_key_packages.sql`, `auth-service/src/store.rs`
(SKIP LOCKED consuming fetch), `tests/key_package_pool.rs` (concurrency
property test). Your M1.3 is to review token issuance + KeyPackage
consumption for the "consumed at most once under concurrent load" property
(PLAN §9 M1 AC, §10 property-test rule). Verify: `FOR UPDATE SKIP LOCKED`
(or equivalent) actually prevents double-consumption; `consumed_at` is set
transactionally in the same statement/tx that returns the package; the
concurrency test asserts a hard failure (rule: tests never silently pass —
if it can't reach the DB it must FAIL, not skip). Record verdict in
`docs/issues/005+`.

## Blocked on / by whom

- Nothing blocks *my* writing (A can proceed now; B and C are reviews I can
  do against K3's pushed branches immediately).
- **charge** blocks: acceptance of ADR-0001 (after A), ADR-0002, ADR-0003
  (after B), and issue 001 decision (import Go oracle y/n). Merges to main.
- **K3** blocks on *me*: ADR-0001 rev 2 F1 schema (their KT persistence PR
  is stuck until the schema is pinned).
- Integration checkpoint (AGENTS.md): all agents' M1 work must pass the
  multi-client harness together before M2. K3's harness framework + canary
  scan are on `k3/m1-*` branches; not yet run against merged main.

## Context a fresh instance won't find in plans/ or docs/

- K3's branches are all `origin/k3/m1-*` and NOT merged to main yet;
  `k3/m1-kt-adr-review` is the superset (contains CI hardening, harness,
  canary scan, KeyPackage pool, and the issue-004 review). `main` is still
  just the plan docs + M0 nothing-merged.
- Issue numbering: Opus owns 001/002; K3 renumbered its auth-spec issue to
  003; K3's KT review is 004. Next free issue number is **005**.
- ADR numbering: 0001 (Opus, KT), 0002 (Opus, facade), 0003 (K3, auth
  params). Next free ADR is **0004**.
- git line-ending warnings (LF→CRLF) on every commit are cosmetic (Windows
  worktree); ignore them.
- Remote is `github.com/Phew/Citadel`.
