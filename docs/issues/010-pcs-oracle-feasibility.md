# 010: SPIKE — ADR-0007 §6 PCS oracle feasibility

- **Reporter:** grok (infra / independent probe; no crate ownership of the store)
- **Date:** 2026-07-26
- **Kind:** SPIKE (evidence only — no implementation, no workspace deps, no PR against crates)
- **Blocks nothing by itself.** Informs charge's decision on the PCS evidence
  rung for ADR-0007 / M2 close. ADR-0007 remains PROPOSED until charge accepts.
- **Related:** docs/decisions/0007-local-encrypted-client-store.md §6 (PCS
  paragraphs); plans/PLAN.md §9 M2; evidence test
  `post_restart_update_proves_post_compromise_security`

## Contract under test (ADR-0007 §6, paraphrased)

Post-compromise security evidence requires:

1. A **test-only extractor** that recovers the prior init secret and every
   retained HPKE private key from a captured `openmls_sqlite_storage` snapshot.
2. An **independent differential driver** that parses the public self-update
   commit with `mls-spec` 2.0.1 and attempts every UpdatePath ciphertext with
   every captured key using `mls-rs-crypto-awslc` 0.25.0 — must recover no path
   secret / commit secret / post-update exporter.
3. A **second mirror** with `mls-rs` 0.55.2 as updater: clone pre-update group
   state, produce a detached self-update, **withhold** `CommitSecrets` from the
   captured clone, give them only to the honest control.

If the extractor or either pinned oracle cannot implement this contract for
the selected ciphersuite, **PCS evidence and M2 close are BLOCKED** rather than
replaced with a self-referential test.

Citadel ciphersuite (PLAN §4):
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (IANA id 1).

## Method

Throwaway crate **outside the repo** at `C:\tmp\citadel-pcs-oracle-probe`
(same pattern as K3's ADR-0007 provider probe). Exact pins:

| Crate | Version |
|---|---|
| `mls-rs` | 0.55.2 |
| `mls-rs-crypto-awslc` | 0.25.0 |
| `mls-spec` | 2.0.1 |
| `openmls` | 0.8.1 |
| `openmls_traits` | 0.5.0 |
| `openmls_rust_crypto` | 0.5.1 |
| `openmls_basic_credential` | 0.5.0 |
| `openmls_sqlite_storage` | 0.2.0 |
| `rusqlite` | 0.32.1 (`bundled`) |

Four binaries: `q1_awslc`, `q2_mls_rs`, `q3_mls_spec`, `q4_extractor`.
Compiled and executed on this machine (Windows). Probe deleted after this
write-up; it is not in the Citadel workspace.

---

## Q1 — Does `mls-rs-crypto-awslc` 0.25.0 support the Citadel ciphersuite?

### Answer

**YES.**

### Evidence

- **API / docs:** `mls-rs-core` 0.27.0 defines
  `CipherSuite::CURVE25519_AES128` as
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` with `raw_value() == 1`.
- **Source (0.25.0 `lib.rs`):**
  `AwsLcCryptoProvider::supported_classical_cipher_suites()` returns
  `CURVE25519_AES128`, `CURVE25519_CHACHA`, `P256_AES128`, `P384_AES256`,
  `P521_AES256` (IANA ids 1, 3, 2, 7, 5).
- **Actually ran:** `cargo run --bin q1_awslc`

```
supported_classical: raw_value=1,3,2,7,5
CURVE25519_AES128 raw_value=1
listed_in_supported=true cipher_suite_provider_is_some=true
hpke_seal/open round-trip on CURVE25519_AES128: OK
Q1_RESULT: YES
```

The HPKE seal/open round-trip is the primitive the PCS driver needs when
attempting each UpdatePath ciphertext against captured keys.

### Confidence

**High.** Runtime listing + provider construction + HPKE round-trip on the
exact suite id.

---

## Q2 — Detached self-update and withholding `CommitSecrets` from a clone?

### Answer

**YES.**

### Evidence

- **API signature (docs.rs `mls-rs` 0.55.2 `Group`):**
  ```text
  pub fn commit_detached(&mut self, authenticated_data: Vec<u8>)
      -> Result<(CommitOutput, CommitSecrets), MlsError>
  ```
  Docs: *"the secrets generated for the commit are outputted instead of being
  cached internally."* Companion:
  `apply_detached_commit(&mut self, commit_secrets: CommitSecrets)`.
  `Group<C>: Clone` when config/storage/crypto are `Clone`.
- **Actually ran:** `cargo run --bin q2_mls_rs` (2-member group, empty-commit
  path update as self-update)

```
cloned pre-update Group epoch=1 (Group: Clone confirmed)
commit_detached OK -> (CommitOutput, CommitSecrets)
honest epoch=2 exporter=d718e8ba… (32 bytes)
captured process_incoming_message: Err(message from self can't be processed)
captured epoch=1 exporter=e19b955f… matches_honest=false
Q2_RESULT: YES — secrets withheld; exporters differ
```

The captured clone did **not** receive `CommitSecrets`. The honest control
did, via `apply_detached_commit`, and advanced to epoch 2. Captured stayed at
epoch 1 with a different exporter.

**Note (not a blocker):** `process_incoming_message` rejects the committer's
own public commit (`message from self can't be processed`). ADR-0007 §6
already scopes the mirror as *"consumes the same public commit as far as the
independent API permits"* — that is this case. The load-bearing property is
withholding `CommitSecrets`; without them the clone cannot match the control
exporter or post-update ciphertext. That property holds.

### Confidence

**High** for the API surface and withhold semantics. **Medium-high** that a
full end-to-end PCS corpus driver needs only this surface (no private mls-rs
hooks) — the probe exercised the exact clone / detach / withhold / export
sequence the ADR describes.

---

## Q3 — Does `mls-spec` 2.0.1 expose UpdatePath ciphertexts per-node?

### Answer

**YES.**

### Evidence

- **Source (`mls-spec` 2.0.1 `src/tree.rs`):**
  ```rust
  pub struct UpdatePathNode {
      pub encryption_key: HpkePublicKey,
      pub encrypted_path_secret: Vec<HpkeCiphertext>,
  }
  pub struct UpdatePath {
      pub leaf_node: LeafNode,
      pub nodes: Vec<UpdatePathNode>,
  }
  ```
  `HpkeCiphertext` exposes `kem_output` and `ciphertext` as public fields.
  All three types implement `tls_codec::{TlsSerialize, TlsDeserialize}`.
- **Actually ran:** `cargo run --bin q3_mls_spec`

```
node[0] encryption_key_len=32 n_ciphertexts=2
  ct[0] kem_len=32 ct_len=16
  ct[1] kem_len=32 ct_len=16
UpdatePath/UpdatePathNode/HpkeCiphertext: TlsSerialize+TlsDeserialize
Q3_RESULT: YES — per-node Vec<HpkeCiphertext> exposed
```

A driver can iterate `path.nodes[i].encrypted_path_secret[j]` and feed each
ciphertext to AWS-LC `hpke_open` against every captured private key.

### Confidence

**High.** Types, public fields, and codec bounds verified by compile + run.

---

## Q4 — Extractor from `openmls_sqlite_storage` without forking OpenMLS?

### Answer

**YES — via SQL query + JSON codec decode. Not surgery on private Rust structs.**

### Evidence

Staging to `openmls_sqlite_storage` 0.2.0 was decisive: secrets land in named
SQLite tables as codec blobs (probe used a JSON codec matching ADR-0007's
`citadel-openmls-json-v1` shape).

**Schema (post-migration):**

| Table | Role |
|---|---|
| `openmls_encryption_keys` | `(public_key PK, key_pair BLOB)` — HPKE key pairs |
| `openmls_epoch_keys_pairs` | `(group_id, epoch_id, leaf_index) → key_pairs BLOB` |
| `openmls_group_data` | keyed by `data_type`, including `group_epoch_secrets` |
| others | tree, proposals, signature keys, … |

**Actually ran:** `cargo run --bin q4_extractor` — created a real OpenMLS
0.8.1 group on the sqlite provider, self-updated, merged, then selected every
row.

Recovered without any OpenMLS private module:

1. **HPKE private key** from `openmls_epoch_keys_pairs.key_pairs`:
   ```json
   [{"private_key":{"key":{"vec":[/* 32 bytes */]}},
     "public_key":{"key":{"vec":[/* 32 bytes */]}}}]
   ```
2. **Init secret** from `openmls_group_data` where
   `data_type = 'group_epoch_secrets'`:
   ```json
   {"init_secret":{"secret":{"value":{"vec":[/* 32 bytes */]}}},
    "exporter_secret":…, "epoch_authenticator":…, …}
   ```
3. `MlsGroup::load` from the same snapshot returned the group at epoch 1
   (public reload path; not required for the extractor but confirms the
   boundary).

For the PCS capture story: the attacker snapshot is taken **before** the
honest self-update. That DB copy retains the **prior** epoch's
`group_epoch_secrets.init_secret` and retained HPKE keys. The probe showed
those fields are plain queryable blobs under the codec; no OpenMLS fork is
required to read them in a `#[cfg(test)]` extractor.

**Caveat recorded honestly:** on a 1-member post-self-update DB,
`openmls_encryption_keys` was empty and path material lived in
`openmls_epoch_keys_pairs`. Multi-member groups will also populate
`openmls_encryption_keys` for path recipients; the table exists and the
codec shape is the same. The extractor should scan **both** tables. That is
implementation detail for the build, not a feasibility block.

### Confidence

**High** that prior init secret + retained HPKE private keys are recoverable
from a persisted snapshot by SQL + decode without forking OpenMLS.
**Medium-high** on multi-member path-key enumeration until the store build
writes a multi-member corpus (schema supports it; probe used 1 member).

---

## Ladder recommendation

Charge pre-committed to mechanical selection from:

| Rung | Description |
|---|---|
| 1 | Full differential PCS as specified (both oracles work) |
| 2 | Single oracle: drop the mls-rs mirror, keep mls-spec + extractor |
| 3 | Extractor-only, no third-party oracle (self-referential) |
| 4 | Defer PCS evidence to M3 |

### Selected rung: **1 — Full differential PCS as specified**

Every component the ADR pins is achievable for the Citadel ciphersuite on
the pinned versions:

| Component | Feasible? |
|---|---|
| `mls-rs-crypto-awslc` 0.25.0 on suite id 1 | YES (Q1) |
| `mls-rs` 0.55.2 detached self-update + withhold secrets | YES (Q2) |
| `mls-spec` 2.0.1 per-node UpdatePath ciphertexts | YES (Q3) |
| Extractor from `openmls_sqlite_storage` without OpenMLS fork | YES (Q4) |

This is **not** a stretch to reach rung 1. All four probes compiled and ran
green. A negative result would have selected a lower rung; that did not
happen.

### What this spike does **not** do

- Does not implement the extractor, the driver, or the store.
- Does not accept ADR-0007 (charge only).
- Does not claim the full CI corpus / byte-compare job is written — only that
  the pinned oracles **can** implement the contract.
- Does not re-litigate Amendment 1 or deny.toml.

### Residual risks (implementation, not feasibility)

1. mls-rs rejects processing one's own commit; the mirror must use
   `apply_detached_commit` for the honest path and treat captured
   self-process failure as "API permits no further" per the ADR wording.
2. Extractor must cover both `openmls_epoch_keys_pairs` and
   `openmls_encryption_keys`, and must run against a **pre-update** file
   snapshot (not post-merge live state).
3. HPKE info / context labels for UpdatePath open must match RFC 9420 /
   OpenMLS exactly when the driver is built — Q1 only proved the suite can
   seal/open; label binding is build work.

---

## Process note

This spike followed AGENTS.md rule 8 (escalate / report, don't improvise a
weaker test) and the charge ladder (mechanical rung selection). The probe
crate lived only under `C:\tmp\` and is deleted after this document lands.
No Citadel `Cargo.toml` / `crates/` was modified.
