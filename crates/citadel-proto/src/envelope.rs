//! JSON-framed wire envelope for REST bodies and WebSocket fanout.
//!
//! MLS payloads travel as base64 (v1). Binary framing may replace this later;
//! until then every service and client must use these types (PLAN.md §4).

use crate::ids::{DeviceId, GroupId};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Current wire format version. Bump only with an ADR and coordinated clients.
pub const WIRE_VERSION: u16 = 1;

/// Alias for documentation at call sites.
pub type WireVersion = u16;

/// Kind of MLS (or control) payload carried by an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// Encrypted application message (ciphertext only; INV-1).
    Application,
    /// MLS proposal (add/remove/update).
    Proposal,
    /// MLS commit. Subject to one-commit-per-epoch (INV-6).
    Commit,
    /// MLS welcome for new members.
    Welcome,
    /// Non-MLS control / service event (e.g. health fanout stubs in M0).
    Control,
}

/// JSON envelope wrapping a base64-encoded MLS (or control) payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Wire format version. Receivers must reject unsupported versions (INV-5: no silent downgrade).
    pub version: WireVersion,
    pub kind: EnvelopeKind,
    /// Target MLS group, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<GroupId>,
    /// Epoch at send time for commit/app messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// Per-group sequence assigned by the delivery service (None on client submit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Sending device, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<DeviceId>,
    /// Base64-encoded opaque payload. Never plaintext content (INV-1).
    pub payload_b64: String,
}

impl Envelope {
    /// Build an envelope from raw payload bytes (encoded as standard base64).
    pub fn new(kind: EnvelopeKind, group_id: Option<GroupId>, payload: &[u8]) -> Self {
        Self {
            version: WIRE_VERSION,
            kind,
            group_id,
            epoch: None,
            seq: None,
            sender_device_id: None,
            payload_b64: B64.encode(payload),
        }
    }

    /// Decode the base64 payload. Does not interpret MLS structure.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        B64.decode(&self.payload_b64)
    }

    /// True when the envelope version is the one this build understands.
    pub fn version_supported(&self) -> bool {
        self.version == WIRE_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip_json_and_payload() {
        let gid = GroupId::new();
        let env = Envelope::new(
            EnvelopeKind::Application,
            Some(gid),
            b"ciphertext-not-plaintext",
        );
        assert!(env.version_supported());
        assert_eq!(env.payload_bytes().unwrap(), b"ciphertext-not-plaintext");

        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
        // Ensure we never accidentally embed a "plaintext" field name on the wire shape.
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn rejects_concept_of_silent_downgrade_via_version_check() {
        let mut env = Envelope::new(EnvelopeKind::Control, None, b"{}");
        env.version = WIRE_VERSION + 1;
        assert!(!env.version_supported());
    }
}
