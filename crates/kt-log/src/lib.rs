//! Append-only key transparency log (Merkle) library.
//!
//! Stub in M0. Full design is Opus-owned in M1; K3 design-reviews the KT ADR.

/// Placeholder so dependents can link against `kt-log` before M1 lands.
pub fn stub_ready() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_ready() {
        assert!(stub_ready());
    }
}
