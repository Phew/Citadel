//! OpenMLS provider and the single v1 ciphersuite (PLAN §4).
//!
//! v1 pins exactly one ciphersuite; version negotiation that would ever deliver
//! plaintext is forbidden (INV-5). All randomness comes from the provider's RNG
//! (INV-9); citadel-core never calls `rand::thread_rng` for key material.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The single ciphersuite for v1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// The concrete OpenMLS provider (RustCrypto primitives + in-memory storage).
/// The encrypted-at-rest store (INV-2) wraps this provider's storage in a later
/// phase; the crypto and RNG paths are unchanged by that.
pub type Provider = OpenMlsRustCrypto;

/// Group-creation config pinned to [`CIPHERSUITE`]. `use_ratchet_tree_extension`
/// ships the ratchet tree inside Welcomes so a joiner needs no side channel to
/// reconstruct the tree.
pub fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Join config used when processing a Welcome or ongoing traffic.
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}
