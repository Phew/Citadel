//! Client core for Citadel.
//!
//! **This is the only place plaintext message content may exist (INV-1, INV-2).**
//! M0 ships a compile-ready stub. OpenMLS integration begins in M2 (Opus).

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
