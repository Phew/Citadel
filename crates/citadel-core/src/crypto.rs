//! OpenMLS providers and the single v1 ciphersuite (PLAN §4).
//!
//! v1 pins exactly one ciphersuite; version negotiation that would ever deliver
//! plaintext is forbidden (INV-5). All randomness comes from a provider's RNG
//! (INV-9); citadel-core never calls `rand::thread_rng` for key material.
//!
//! There are two providers, and the difference between them matters:
//!
//! - [`EphemeralProvider`] keeps MLS state **in memory only**. It is used for
//!   work that has no store yet — generating a KeyPackage for the one-time pool
//!   before enrollment — and for tests that deliberately model a peer with no
//!   persistence. A process restart loses everything it holds.
//! - [`crate::store::StoreProvider`] persists into the local encrypted client
//!   store (ADR-0007 §1) and is the provider every operation inside the store
//!   actor uses.
//!
//! Naming them apart is deliberate. This crate previously exported a single
//! `Provider` alias for the in-memory provider while its own description
//! claimed a local encrypted store that did not exist; a name that does not say
//! which one you are holding is how that happens.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The single ciphersuite for v1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// How many past epochs a Citadel group may retain: none.
///
/// ADR-0007 §6 pins this explicitly rather than relying on the OpenMLS default,
/// which is already 0 in openmls 0.8.1. The pin's value is entirely fail-closed
/// protection: an upgrade that widened the default would otherwise silently
/// extend the window in which old-epoch ciphertext stays decryptable, and the
/// forward-secrecy evidence would keep passing while meaning less.
pub const MAX_PAST_EPOCHS: usize = 0;

/// The in-memory OpenMLS provider (RustCrypto primitives + memory storage).
///
/// **Nothing it stores survives the process.** For persisted MLS state use the
/// store actor, which supplies [`crate::store::StoreProvider`] over the
/// encrypted SQLite connection inside a transaction.
pub type EphemeralProvider = OpenMlsRustCrypto;

/// Group-creation config pinned to [`CIPHERSUITE`]. `use_ratchet_tree_extension`
/// ships the ratchet tree inside Welcomes so a joiner needs no side channel to
/// reconstruct the tree.
pub fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

/// Join config used when processing a Welcome or ongoing traffic.
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

/// How many past epochs a join config retains.
///
/// openmls 0.8.1 exposes `max_past_epochs()` on `MlsGroupCreateConfig` but
/// **not** on `MlsGroupJoinConfig`, whose field is `pub(crate)` with no
/// accessor (`openmls-0.8.1/src/group/mls_group/config.rs:44-81`). Since
/// `MlsGroupJoinConfig` derives `Serialize`, and that same serde representation
/// is what the storage provider persists as the `join_group_config` row, reading
/// the value out of it is not a workaround around a missing getter — it is a
/// check against the exact bytes that end up on disk.
///
/// Returns `None` only if a future openmls renames or removes the field, which
/// callers must treat as fail-closed rather than as "zero".
pub fn retained_past_epochs(config: &MlsGroupJoinConfig) -> Option<usize> {
    serde_json::to_value(config)
        .ok()?
        .get("max_past_epochs")?
        .as_u64()
        .map(|value| value as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_configs_retain_no_past_epochs() {
        assert_eq!(create_config().max_past_epochs(), MAX_PAST_EPOCHS);
        assert_eq!(
            retained_past_epochs(create_config().join_config()),
            Some(MAX_PAST_EPOCHS)
        );
        assert_eq!(retained_past_epochs(&join_config()), Some(MAX_PAST_EPOCHS));
    }

    #[test]
    fn retained_past_epochs_reads_the_field_the_provider_persists() {
        // A non-zero config must be visible through the same path, or the
        // fail-closed check in `DmGroup::load` would be reading a constant.
        let widened = MlsGroupJoinConfig::builder().max_past_epochs(3).build();
        assert_eq!(retained_past_epochs(&widened), Some(3));
    }
}
