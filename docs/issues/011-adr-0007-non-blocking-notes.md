# 011: ADR-0007 non-blocking notes, to land with the store build

**Status:** OPEN. **Raised by:** K3, in the Amendment 1 re-review
(`docs/issues/009` rev 2, merged `289c570`, verdict APPROVE).
**Owner:** the core lane. **Blocks:** nothing. **Must land with:** the store build.

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
