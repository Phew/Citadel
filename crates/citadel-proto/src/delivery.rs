//! Delivery-service wire contracts for M2 encrypted DMs (F2 Welcome, F4 send/receive).
//!
//! Every payload here is opaque MLS bytes or addressing metadata. The delivery
//! service never receives, stores, or logs plaintext content or group secrets
//! (INV-1) and links no decryption path.
//!
//! `seq` is the server's authoritative, gap-free, monotonic per-group ordering.
//! `epoch` is a CLIENT-DECLARED hint the server echoes but never derives from
//! ciphertext (it cannot parse MLS) and never trusts as a security fact (INV-4).
//! One-commit-per-epoch enforcement over the `commit` kind is M3, not here.
//!
//! See docs/decisions/0005-m2-dm-delivery-wire-model.md.

use crate::envelope::{Envelope, EnvelopeKind};
use crate::error::ErrorCode;
use crate::ids::{DeviceId, GroupId, MessageId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Max messages returned by one `GET /v1/groups/{gid}/messages` page (bounds
/// response size; clients page with `?after=`).
pub const MESSAGES_PAGE_LIMIT: usize = 500;

// ---------- POST /v1/groups/{gid}/messages ----------

/// Submit one MLS message (application/proposal/commit/welcome) to a group.
///
/// `envelope.payload_b64` is a serialized OpenMLS `MlsMessageOut`; the server
/// does not parse it. `envelope.seq` MUST be `None` on submit (the server
/// assigns it). `envelope.epoch` is the client's current epoch, stored and
/// echoed as an ordering hint only. `envelope.sender_device_id` is ignored on
/// submit: the server derives the sender from the authenticated bearer token
/// (ADR-0003 §3), it never trusts a client-claimed sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageRequest {
    pub envelope: Envelope,
    /// Client-generated dedup key. Two submits with the same
    /// `(group_id, idempotency_key)` are the same message: the server inserts
    /// once and returns the original assignment (see [`SubmitMessageResponse`]).
    pub idempotency_key: Uuid,
    /// Target devices for a Welcome (`envelope.kind == Welcome`). Required
    /// non-empty for Welcome, MUST be empty otherwise. The server addresses the
    /// Welcome to exactly these devices; each receives it on its next gateway
    /// connect and joins after verifying every member credential against the KT
    /// log (INV-4). These are device UUIDs (addressing metadata), never content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_device_ids: Vec<DeviceId>,
}

impl SubmitMessageRequest {
    /// Structural preconditions the delivery service checks before assigning a
    /// seq. Returns a stable reason string on violation (maps to
    /// `ErrorCode::InvalidRequest`). This is not a security check — MLS validity
    /// is the client's job (INV-4) — only wire-shape hygiene.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.envelope.seq.is_some() {
            return Err("seq must be unset on submit; the server assigns it");
        }
        match self.envelope.kind {
            EnvelopeKind::Welcome if self.recipient_device_ids.is_empty() => {
                Err("welcome requires at least one recipient device")
            }
            EnvelopeKind::Welcome => Ok(()),
            _ if !self.recipient_device_ids.is_empty() => {
                Err("recipient_device_ids is only valid for welcome messages")
            }
            _ => Ok(()),
        }
    }
}

/// Server assignment returned by a successful submit. On idempotent replay the
/// server returns the original values (same `seq`, `message_id`) rather than
/// inserting a second row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageResponse {
    pub message_id: MessageId,
    pub group_id: GroupId,
    /// Client-declared epoch, echoed. Ordering hint only, not trusted (INV-4).
    pub epoch: u64,
    /// Server-assigned: authoritative, gap-free, monotonic per group.
    pub seq: u64,
    /// Server receive time, Unix milliseconds. Informational; server time is
    /// not a trusted value (INV-4).
    pub server_ts: i64,
}

// ---------- GET /v1/groups/{gid}/messages?after=<seq> ----------

/// One page of ciphertext sync. `after` is the last `seq` the client holds
/// (`0` or omitted for a fresh sync); the server returns rows with `seq > after`
/// in ascending `seq`, at most [`MESSAGES_PAGE_LIMIT`]. Each returned
/// [`Envelope`] has `seq`, `epoch`, and `sender_device_id` populated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagesPage {
    pub group_id: GroupId,
    pub messages: Vec<Envelope>,
    /// Pass as the next `?after=`. Equals the largest `seq` in `messages`, or
    /// the request's `after` when `messages` is empty.
    pub next_after: u64,
    pub has_more: bool,
}

// ---------- WS /v1/gateway ----------

/// Frames the client sends over the gateway after an authenticated upgrade.
///
/// The upgrade request carries `Authorization: Bearer <token>`, validated
/// exactly per ADR-0003 §3 (unexpired, not revoked, device live); failure is a
/// `401` on the upgrade and no socket is opened. Messages are NOT sent over the
/// gateway: sends go over the REST submit path so seq assignment and dedup have
/// one home. The gateway is receive/fanout plus subscription control only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayClientFrame {
    /// Subscribe to live fanout for these groups. Subscription is spam-hygiene
    /// authorization only, never a confidentiality boundary: fanned-out
    /// ciphertext is useless to a non-member (INV-1), and MLS membership is the
    /// client-verified authority (INV-4).
    Subscribe { group_ids: Vec<GroupId> },
    /// Stop receiving fanout for these groups.
    Unsubscribe { group_ids: Vec<GroupId> },
}

/// Frames the server pushes over the gateway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayServerFrame {
    /// Acknowledges a [`GatewayClientFrame::Subscribe`].
    Subscribed { group_ids: Vec<GroupId> },
    /// A fanned-out message. Any kind, including a Welcome addressed to this
    /// device on connect. `seq`/`epoch`/`sender_device_id` are populated.
    Message { envelope: Envelope },
    /// A non-fatal error bound to a group or the connection.
    Error {
        code: ErrorCode,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        group_id: Option<GroupId>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_envelope(gid: GroupId) -> Envelope {
        Envelope::new(
            EnvelopeKind::Application,
            Some(gid),
            b"opaque-mls-ciphertext",
        )
    }

    #[test]
    fn submit_request_roundtrip_and_no_plaintext_field() {
        let gid = GroupId::new();
        let req = SubmitMessageRequest {
            envelope: app_envelope(gid),
            idempotency_key: Uuid::from_bytes([0x11; 16]),
            recipient_device_ids: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("plaintext"));
        // recipient_device_ids is empty -> omitted from the wire.
        assert!(!json.contains("recipient_device_ids"));
        let back: SubmitMessageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn validate_accepts_plain_application_submit() {
        let req = SubmitMessageRequest {
            envelope: app_envelope(GroupId::new()),
            idempotency_key: Uuid::from_bytes([1; 16]),
            recipient_device_ids: vec![],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rejects_preassigned_seq() {
        let mut env = app_envelope(GroupId::new());
        env.seq = Some(7);
        let req = SubmitMessageRequest {
            envelope: env,
            idempotency_key: Uuid::from_bytes([2; 16]),
            recipient_device_ids: vec![],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_requires_recipients_for_welcome() {
        let mut env = app_envelope(GroupId::new());
        env.kind = EnvelopeKind::Welcome;
        let req = SubmitMessageRequest {
            envelope: env.clone(),
            idempotency_key: Uuid::from_bytes([3; 16]),
            recipient_device_ids: vec![],
        };
        assert!(req.validate().is_err());

        let ok = SubmitMessageRequest {
            envelope: env,
            idempotency_key: Uuid::from_bytes([3; 16]),
            recipient_device_ids: vec![DeviceId::new()],
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn validate_forbids_recipients_on_non_welcome() {
        let req = SubmitMessageRequest {
            envelope: app_envelope(GroupId::new()),
            idempotency_key: Uuid::from_bytes([4; 16]),
            recipient_device_ids: vec![DeviceId::new()],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn gateway_frames_are_type_tagged() {
        let sub = GatewayClientFrame::Subscribe {
            group_ids: vec![GroupId::new()],
        };
        let json = serde_json::to_string(&sub).unwrap();
        assert!(json.contains("\"type\":\"subscribe\""));
        let back: GatewayClientFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(sub, back);

        let msg = GatewayServerFrame::Message {
            envelope: app_envelope(GroupId::new()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"message\""));
        assert!(!json.contains("plaintext"));
        let back: GatewayServerFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn messages_page_roundtrip() {
        let gid = GroupId::new();
        let mut env = app_envelope(gid);
        env.seq = Some(42);
        env.epoch = Some(3);
        let page = MessagesPage {
            group_id: gid,
            messages: vec![env],
            next_after: 42,
            has_more: false,
        };
        let json = serde_json::to_string(&page).unwrap();
        let back: MessagesPage = serde_json::from_str(&json).unwrap();
        assert_eq!(page, back);
    }
}
