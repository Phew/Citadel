//! Client core for Citadel.
//!
//! **This is the only place plaintext message content may exist (INV-1, INV-2).**
//! citadel-core owns the OpenMLS group state machine (create/join/send/receive),
//! member-credential verification against the KT log (INV-4), length-hiding
//! padding, and the local encrypted store. It speaks the frozen
//! `citadel-proto` wire contracts (ADR-0005) and reaches the delivery service
//! only through the injected [`transport::DeliveryTransport`] trait, so the core
//! is testable without a live server.

pub mod credential;
pub mod crypto;
pub mod group;
pub mod identity;
pub mod padding;
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
