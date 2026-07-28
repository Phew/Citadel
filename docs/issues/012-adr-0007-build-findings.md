# 012: ADR-0007 build findings

**Status:** OPEN — recorded for the next occupant of the core lane. Nothing here blocks a
merge; one item (DEFECT 2) is a design question that wants a decision before M3.
**Raised by:** the core lane, while building the store (PR #69), against an ADR that had
already passed K3's independent design review and been ACCEPTED (charge, 2026-07-26,
`d302e76`).
**Verdicts by:** charge, 2026-07-27, verified against source.
**Owner:** the core lane. **Blocks:** nothing.

Four defects were raised. **Three hold, one is withdrawn.** The withdrawn one is kept here with
its reasoning rather than deleted, because a finding that turned out to be wrong is evidence
about the review process and deleting it would leave the next reader wondering whether the
question was ever asked.

Two smaller findings from the same build are carried at the bottom.

---

## Read this first: `libsqlite3-sys` 0.30.1 ships **two** files called `sqlite3.c`

Every `sqlite3.c:NNNNN` citation in this repository is ambiguous unless you know which one it
means, and the two files are far enough apart that a line number valid in one lands in
unrelated code in the other.

```
libsqlite3-sys-0.30.1/
  sqlcipher/sqlite3.c   <- SQLCipher 4.5.7 amalgamation. THIS is what Citadel compiles.
  sqlite3/sqlite3.c     <- plain SQLite amalgamation. Not compiled by this project.
```

`build.rs:143` (`if cfg!(feature = "bundled-sqlcipher")`) is what selects the SQLCipher tree,
and Citadel enables `bundled-sqlcipher-vendored-openssl`.

**The convention in this repository is the `sqlcipher/` amalgamation**, and every existing
citation already follows it. Spot-check, in `sqlcipher/sqlite3.c`:

| Line | What is there | In `sqlite3/sqlite3.c` the same line is |
|---|---|---|
| 106612 | `#define CIPHER_VERSION_NUMBER 4.5.7` | `return rc;` |
| 109000 | `int sqlcipher_get_mem_security() {` | an expression-resolver call |
| 135068 | the `load_extension()` disallow comment | a trigger-counting comment |
| 142378 | `db->flags \|= SQLITE_LoadExtension\|SQLITE_LoadExtFunc;` | a table-lock free |

Three of those four are SQLCipher-only symbols, so they cannot resolve in the plain tree at
all. This trap is what DEFECT 1's citation review ran into; see below.

---

## DEFECT 4 — §6's fail-closed past-epoch check cannot be written against a public API. **CONFIRMED.**

ADR-0007 §6 requires a check that a group whose persisted configuration retains past epochs
fails closed. The obvious implementation — ask the loaded group for its `max_past_epochs` —
does not compile, because openmls 0.8.1 exposes no such accessor on the config that
`MlsGroup::configuration()` actually returns.

Verified in `openmls-0.8.1/src/group/mls_group/config.rs`:

- `MlsGroupJoinConfig` is declared at `:44`, and its `max_past_epochs` field is `pub(crate)`
  at `:52`.
- Its inherent `impl` block runs `:61-81` and contains exactly four items — `builder`,
  `wire_format_policy`, `padding_size`, `sender_ratchet_configuration`. **There is no
  `max_past_epochs` accessor in it.**
- The public `max_past_epochs()` getter at `:191` is inside `impl MlsGroupCreateConfig`, which
  opens at `:174`. It belongs to the *create* config.
- `MlsGroup::configuration()` returns `&MlsGroupJoinConfig`.

So the getter exists, but not on the type you can reach from a loaded group.

**This overturns K3's §D.2 verification.** §D.2 of ADR-0007 Amendment 1 lists "the
`max_past_epochs = 0` pin with fail-closed behavior on OpenMLS default drift" among the items
K3 verified and that were not to be reopened. K3's conclusion — that the pin is right and that
drift must fail closed — stands. What does not stand is the implicit premise that the check
could be written against the public API. It could not. That premise was inherited into an
ACCEPTED ADR and is corrected here.

**The implementation reads the value out of the config's serde representation instead**
(`crate::crypto::retained_past_epochs`), and **that is arguably the stronger check, not a
workaround.** The serde representation is the same representation the storage provider
persists as the `join_group_config` row, so the check reads what is actually on disk rather
than an in-memory constant that a load path could have defaulted. An accessor would have told
you what the running process believes; the serde read tells you what the file says. An
unreadable field is its own error (`GroupError::PastEpochRetentionUnreadable`) and is never
treated as zero.

Evidence: `store_codec_v1_roundtrips_golden_corpus_and_migrates` asserts the persisted row
carries `max_past_epochs: 0`; `a_group_whose_persisted_configuration_retains_past_epochs_fails_closed`
rewrites the row to `max_past_epochs = 3` and proves the load refuses.

---

## DEFECT 2 — §5's universal quantifier conflicts with single-use KeyPackages. **CONFIRMED.**

§5 opens with a universal claim: "Every state-changing public core operation requires an
opaque 16-byte `OperationId`," and closes the loop with "Retrying a retained operation ID with
the same fingerprint returns the stored outcome." §5 then enumerates seven atomic units.
**KeyPackage generation is not one of them**, but it is a state-changing public core operation
(`LocalStore::new_key_package`), so the quantifier covers it and the enumeration does not.

That gap is not bookkeeping. RFC 9420 treats a KeyPackage as **single-use**: its private init
key is consumed when someone joins with it and must not be reused. An idempotent-retry
contract and a single-use object pull in opposite directions, and §5 never says which wins.

**The orphaned-private-key case, put on the record explicitly**, because it is the one the
current design leaves unresolved:

A caller submits `new_key_package`. The transaction commits — the private init, encryption and
signature key material is now persisted in the provider — and then the caller never sees the
response (process killed, IPC dropped, UI closed). Two things follow:

1. **The public KeyPackage was never published.** Nobody can ever consume it, so nothing will
   ever trigger its deletion. OpenMLS deletes a KeyPackage's private keys when the KeyPackage
   is *used*; an unused one is deleted by nothing. The key material sits in the encrypted
   store indefinitely.
2. **Whether it is recoverable depends entirely on caller discipline.** A caller that retained
   its `OperationId` and retries gets the stored outcome back — the same KeyPackage bytes —
   and can publish them. That is the correct path and it works. A caller that generates a
   fresh `OperationId` instead gets a *second* KeyPackage, and the first is orphaned for good.

So the failure mode is unbounded accumulation of unpublished private key material, at a rate
set by how often callers crash between commit and response. It is not a confidentiality break
— the material is inside SQLCipher and each key is still single-use — but it is key material
at rest that no protocol event will ever remove, in the one component whose job is to bound
exactly that.

**Not fixed in this PR.** The decision it needs is whose responsibility reaping is, and that
interacts with the KeyPackage pool design in M1 and the M5 multi-device work. Options worth
weighing, none chosen here: give KeyPackage generation its own atomic unit in §5 with an
explicit "published" flag and a reaper for unpublished entries older than some bound; or make
`OperationId` retention mandatory rather than advisory for this one operation and say so in
§5; or move generation behind the pool so the pool owns the lifecycle.

---

## DEFECT 1 — `SQLITE_OPEN_NOFOLLOW` is inert on Windows. **CONFIRMED IN SUBSTANCE. Citation stands as originally written — see the disagreement note.**

ADR-0007 §2 (`:268-272`) states that the database, staging path, sidecar files and lock "must
not traverse symbolic links or Windows reparse points," and the store passes
`SQLITE_OPEN_NOFOLLOW` when opening the database (`store/open.rs:96-102`). On Windows that
flag does nothing.

The mechanism, verified in `sqlcipher/sqlite3.c`:

- `SQLITE_OK_SYMLINK` has exactly **one** producer in the whole amalgamation:
  `unixFullPathname`, declared at `:44874`, returning it at `:44897`
  (`if( path.nSymlink ) return SQLITE_OK_SYMLINK;`).
- `SQLITE_OPEN_NOFOLLOW` is honored in exactly **one** place, and only on receiving that
  return: `:61795-61797`, where `rc==SQLITE_OK_SYMLINK` plus the flag becomes
  `SQLITE_CANTOPEN_SYMLINK`, and without the flag is flattened back to `SQLITE_OK`.
- The only other `rc==SQLITE_OK_SYMLINK` site, `:73094`, does not consult the flag at all — it
  just normalizes the code to `SQLITE_OK`.
- `winFullPathname` (`:52228`, via `winFullPathnameNoMutex` at `:52049`) never returns
  `SQLITE_OK_SYMLINK`.

So on the Windows VFS the honoring branch is unreachable and the flag is inert. **The
containment guarantee on Windows comes entirely from `ProfilePaths::validate`**, which does a
`symlink_metadata` check by path (`store/paths.rs:11-19`), plus the lock's
`FILE_FLAG_OPEN_REPARSE_POINT` open and re-validation from the open handle
(`store/lock.rs:74-81`). The lock check is link-race-free because it validates the handle; the
database check is by path and therefore is not. That asymmetry is real and is the part a future
reader should care about — it is documented in `paths.rs` and is not changed by this PR.

### Disagreement note, recorded rather than silently resolved

The verdict on this finding instructed a citation fix: that `61796` was wrong because it "lands
in a pager comment block about temporary files," and that the honoring site is `61874-61875`
with `unixFullPathname` at `:45073` returning at `:45096`.

**Those three line numbers are all correct — in `sqlite3/sqlite3.c`, the plain SQLite
amalgamation this project does not compile.** In the `sqlcipher/sqlite3.c` amalgamation that
Citadel actually builds, the same constructs sit at `:44874`, `:44897` and `:61795-61796`, and
`:61874-61875` is a `ROUND8(pVfs->szOsFile)` size computation in `sqlite3PagerOpen` — which is
exactly the "pager block about temporary files" the verdict describes, one file over.

The original citation `sqlite3.c:61796` in `store/open.rs:98` is therefore **correct under this
repository's existing convention**, and has been left as written. Changing it to `61874-61875`
would have made it the only citation in the repo pointing at an amalgamation the build never
compiles, and would have broken it against the four SQLCipher-only citations listed at the top
of this file.

What the review did surface is a real hazard: two files, one name, one package, no disambiguation
in any citation. That is now fixed at the source — `store/open.rs:97-102` names the amalgamation
explicitly, and the table at the top of this file gives the next reader a way to tell in one
lookup which tree a citation belongs to.

The substance of the finding is unaffected either way. `SQLITE_OPEN_NOFOLLOW` is inert on
Windows in both amalgamations, for the same reason.

---

## DEFECT 3 — "receive application vs receive commit must be one operation kind." **WITHDRAWN. The premise was false.**

The finding claimed that a caller cannot distinguish an application message from a commit
without decrypting it, and therefore could not choose the right operation kind before opening
the transaction — which would have made §5's split of "receive application message" and
"receive commit" into two atomic units unimplementable at the API boundary.

**That is wrong.** `content_type` is a **cleartext** field of `PrivateMessage` under RFC 9420
§6.3.2 — it sits outside the encrypted payload precisely so a recipient can dispatch on it —
and openmls 0.8.1 carries it that way and exposes it publicly:

- `PrivateMessage.content_type` is a plain struct field at
  `openmls-0.8.1/src/framing/private_message.rs:35`, alongside `group_id` and `epoch` and
  *before* `ciphertext`.
- `MlsMessageIn::try_into_protocol_message()` at `framing/message_in.rs:115` yields a
  `ProtocolMessage` with no key material and no decryption.
- `ProtocolMessage::content_type()` at `framing/message_in.rs:212` is `pub` and dispatches to
  the private and public message variants.

So a caller can distinguish the two kinds from the wire bytes alone, before any transaction and
before any decryption. The finding is withdrawn.

### The one-kind decision it argued for may still be correct — kept, with the real justification

The implementation uses a **single** `receive` operation kind rather than splitting it, and the
next occupant should decide whether to keep that. The withdrawn premise is not why it is
defensible. This is:

1. **The idempotency fingerprint is computed over the raw wire bytes.** An identical retry
   therefore matches its ledger row regardless of content type, so splitting the kind buys
   nothing for the property the ledger exists to provide. Two kinds would only matter if the
   same bytes could legitimately be submitted as either kind, which they cannot.
2. **Splitting forces a parse before the transaction opens.** The caller would have to run
   `try_into_protocol_message()` to pick a kind, which moves attacker-controlled bytes through
   a parse *outside* the transaction and outside the actor, and creates a new failure mode —
   caller picks a kind, actor parses again and disagrees — that the single kind does not have.
   The actor parsing once, inside the transaction, on its own thread, is the narrower surface.

Neither of those is affected by DEFECT 3 being wrong. If the next occupant does split the kind,
§5's atomic-unit list is already written for two, so the ADR does not need amending — only the
actor and the fingerprint domain separator do.

---

## Two smaller findings from the same build

### `PRAGMA cipher_memory_security` must be set *before* `PRAGMA key`, and it returns TEXT

`sqlcipher_get_mem_security` (`sqlcipher/sqlite3.c:109000-109004`) reports enabled only when
the pragma is on **and** SQLCipher's allocator has already run — and the codec allocation
during keying is what runs it. So the intuitive order (key the database, then harden it, then
read back) reads back `0` and aborts a store that is in fact correctly configured. The pragma
has to be set before `PRAGMA key` and verified after.

It also returns **TEXT**, not INTEGER, so a readback that binds it as an integer fails on a
correctly configured connection. Both halves are load-bearing in `store/open.rs`; changing
either the order or the column type breaks a store that is working.

### §2's "lock content is empty" holds only for a lock file this code created

ADR-0007 §2 (`:265`) states "Lock content is empty" as a flat property. It is not one. §2 also
specifies — correctly, and the code does this — that the lock is opened "read-write **without
truncation**." So if the lock file already exists with content in it, the open sequence
preserves that content; nothing empties it.

This is **not** exploitable as written, and no code change is made: Citadel never reads, writes
or parses lock content, and the lock's security value is entirely in `File::try_lock` plus the
handle-based regular-file re-validation. The reason to record it is that "lock content is empty"
reads like an invariant a future reader could rely on — for instance by deciding it is safe to
put a PID or a profile fingerprint in there and trust what comes back. It is an observation
about files this code creates, not a property the open sequence enforces. Anyone who wants it
to be an invariant has to add the enforcement first.
