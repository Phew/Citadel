//! The boundary between citadel-core and the delivery service (K3).
//!
//! citadel-core produces and consumes `citadel-proto` wire types (ADR-0005,
//! frozen) and never talks to a live server directly: a host wires a concrete
//! [`DeliveryTransport`] (HTTP submit/sync + WS gateway) behind this trait, so
//! the core is unit-testable with an in-memory fake and K3's delivery-service
//! is swapped in for integration and adversarial tests.

use citadel_proto::delivery::{MessagesPage, SubmitMessageRequest, SubmitMessageResponse};
use citadel_proto::ids::{DeviceId, GroupId};
use citadel_proto::{Envelope, EnvelopeKind};

/// Build an `Application` envelope carrying an encrypted, padded message
/// (F4 send). `epoch` is the client's current epoch, an ordering hint the server
/// echoes but never trusts (ADR-0005 §1).
pub fn application_envelope(group_id: GroupId, epoch: u64, message_bytes: &[u8]) -> Envelope {
    let mut e = Envelope::new(EnvelopeKind::Application, Some(group_id), message_bytes);
    e.epoch = Some(epoch);
    e
}

/// Build a `Commit` envelope (membership change; sequenced by the DS, INV-6
/// enforcement is M3).
pub fn commit_envelope(group_id: GroupId, epoch: u64, commit_bytes: &[u8]) -> Envelope {
    let mut e = Envelope::new(EnvelopeKind::Commit, Some(group_id), commit_bytes);
    e.epoch = Some(epoch);
    e
}

/// Build a `Welcome` envelope addressed to the joiners' devices (F2 step 2/3).
/// Pair the returned envelope with `recipient_device_ids` in a
/// [`SubmitMessageRequest`]; the DS requires that non-empty for Welcome
/// (ADR-0005 §1, `SubmitMessageRequest::validate`).
pub fn welcome_envelope(group_id: GroupId, epoch: u64, welcome_bytes: &[u8]) -> Envelope {
    let mut e = Envelope::new(EnvelopeKind::Welcome, Some(group_id), welcome_bytes);
    e.epoch = Some(epoch);
    e
}

/// The delivery-service client seam. Implemented by the host (HTTP/WS) for
/// integration; faked in-memory for core unit tests. Kept minimal: sends go over
/// submit (REST), sync pulls a page, and the gateway push is a stream the host
/// owns (not modeled here in M2).
#[allow(async_fn_in_trait)]
pub trait DeliveryTransport {
    type Error;

    /// `POST /v1/groups/{gid}/messages` — submit one MLS message, get its
    /// server-assigned `(seq, epoch echoed)` back.
    async fn submit(&self, req: SubmitMessageRequest)
        -> Result<SubmitMessageResponse, Self::Error>;

    /// `GET /v1/groups/{gid}/messages?after=` — one ciphertext page.
    async fn fetch(&self, group_id: GroupId, after: u64) -> Result<MessagesPage, Self::Error>;

    /// Pending Welcomes addressed to this device, delivered on gateway connect
    /// (ADR-0005 §1 F2). The host drains these before subscribing to groups.
    async fn pending_welcomes(&self, device_id: DeviceId) -> Result<Vec<Envelope>, Self::Error>;
}
