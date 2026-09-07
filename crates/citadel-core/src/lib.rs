//! Client core for Citadel.
//!
//! **This is the only place plaintext message content may exist (INV-1, INV-2).**
//! citadel-core owns the OpenMLS group state machine (create/join/send/receive),
//! member-credential verification against the KT log (INV-4), length-hiding
//! padding, the local encrypted client store (ADR-0007), and delivery envelope
//! construction. It speaks the frozen `citadel-proto` wire contracts (ADR-0005)
//! and exposes the [`transport::DeliveryTransport`] integration seam.
//!
//! MLS state is durable: [`store::LocalStore`] persists it into a SQLCipher
//! database whose 32-byte key lives in the OS credential store. The in-memory
//! [`crypto::EphemeralProvider`] remains for work that has no store yet, and is
//! named so it cannot be mistaken for the persisted one.

pub mod credential;
pub mod crypto;
pub mod group;
pub mod identity;
pub mod padding;
pub mod store;
pub mod transport;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests_e2e;

// Client core always speaks the shared wire contract.
pub use citadel_proto::WIRE_VERSION;

/// Crate version string for diagnostics and desktop about screens.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }
}
