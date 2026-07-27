# 011: ADR-0007 non-blocking notes, to land with the store build

**Status:** **CLOSED** — both notes landed with the store build, in the same PR.
**Raised by:** K3, in the Amendment 1 re-review
(`docs/issues/009` rev 2, merged `289c570`, verdict APPROVE).
**Owner:** the core lane. **Blocks:** nothing.

## How each was closed

- **N1** — the mechanism is named and implemented as a **behavioral probe**:
  `citadel_core::store::open::probe_extension_loading_is_refused` runs
  `SELECT load_extension(<a name that does not exist>)` at the end of every open
  sequence and requires the exact `not authorized` refusal, aborting the open otherwise.
  It is wired into `store_release_uses_only_pinned_sqlcipher`, which additionally asserts
  `ENABLE_LOAD_EXTENSION` **is** compiled in — so the test would notice if the probe ever
  started passing for the wrong reason. Requiring that exact string is what separates a
  refusal from "reached the loader and could not find the file", which is what a set flag
  would produce. Folded into ADR-0007 Amendment 1 §A.5 and named in §A.7. The rusqlite
  feature-gating argument is recorded there as *supporting*, explicitly not as a
  replacement for the probe.
- **N2** — FTS3 now has its own row in the §A.5 flag table, alongside FTS5, with the same
  accepted reasoning and the same `build.rs` line citations.

## One finding from the build that neither note anticipated

Implementing §6's fail-closed past-epoch check turned up an API gap worth recording:
**openmls 0.8.1 exposes `max_past_epochs()` on `MlsGroupCreateConfig` but not on
`MlsGroupJoinConfig`**, whose field is `pub(crate)` with no accessor
(`openmls-0.8.1/src/group/mls_group/config.rs:44-81`; the getter at `:191` belongs to the
create config). `MlsGroup::configuration()` returns the *join* config, so the obvious
implementation of "loading a group whose persisted configuration retains past epochs fails
closed" does not compile.

`crate::crypto::retained_past_epochs` resolves it by reading the field out of the config's
serde representation — which is the same representation the storage provider persists as
the `join_group_config` row, so the check reads what is actually on disk rather than an
in-memory constant. `store_codec_v1_roundtrips_golden_corpus_and_migrates` asserts that
persisted row really carries `max_past_epochs: 0`, and
`a_group_whose_persisted_configuration_retains_past_epochs_fails_closed` rewrites the row
to a widened config and proves the load refuses. An unreadable field is its own error
(`GroupError::PastEpochRetentionUnreadable`) and is never treated as zero.

---

## The original notes, retained for the record

ADR-0007 and Amendment 1 were ACCEPTED (charge, 2026-07-26) with these two notes
deliberately **not** folded first. They are recorded here rather than left in a review
comment so they cannot evaporate, which is the whole point of rule 3.

## N1 — "the open sequence asserts the flag is off" needs a named mechanism

Amendment 1 §A.5 states that the open sequence asserts extension loading is off. It does
not say **how**, and an unnamed assertion is not evidence.

This is the note the advisor would have folded before acceptance. It is the exact defect
shape this crate has produced three times: prose asserting a property the code does not
demonstrably have (the crate description claiming a local encrypted store, a test comment
claiming swapped-KeyPackage coverage, PLAN's M1 keychain-integration claim). Do not let
it be a fourth.

**Required:** pin a *behavioral* probe, not an inspection. Attempt `load_extension()` on
the open connection and require the call to fail with "not authorized". Name it in the
evidence list and wire it into `store_release_uses_only_pinned_sqlcipher`, which already
reads the A.5 flag table back from the built artifact.

Supporting fact found during the re-review and worth keeping: rusqlite 0.32.1's
`load_extension_enable` is `#[cfg(feature = "load_extension")]`-gated, and rusqlite
0.32.1 declares **no default features at all**, so the safe enabling API is not compiled
on the staged graph. The residual is deliberate `unsafe` FFI only, which is outside the
threat the original compile-time pin addressed. That strengthens the position but does
not replace the probe: the point of the probe is that it keeps holding if a future
dependency change quietly enables the feature.

## N2 — FTS3 is also compiled in; A.5's table should say so

`libsqlite3-sys` 0.30.1 compiles `-DSQLITE_ENABLE_FTS3` (`build.rs:127`) and
`-DSQLITE_ENABLE_FTS3_PARENTHESIS` (`:128`) alongside FTS5 (`:129`). A.5's flag table
lists FTS5 but not FTS3.

**Required:** one row in the A.5 table. The applicability reasoning is unchanged, since
FTS3 falls in the same compiled-but-unreachable class as FTS5 (the schema creates no
FTS table of any kind and the app issues no attacker-influenced SQL). The reason to
record it is that A.5 is the standing reference for what the staged bundle actually
compiles, and a reader checking a future FTS3 advisory against an incomplete table would
get the wrong answer.

## Verification status

Both notes were advisor-verified against the pinned crate source rather than taken on
report: FTS3 at `build.rs:127`, `load_extension_enable` gated at `rusqlite/src/lib.rs:853`
as `pub unsafe fn`, and rusqlite 0.32.1's `[features]` block containing no `default` key.
