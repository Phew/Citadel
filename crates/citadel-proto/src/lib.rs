//! Shared protocol types for Citadel.
//!
//! This crate is canonical for every wire and signing contract (AGENTS.md rule 5).
//! Service and client crates must not redefine envelopes or error codes.

pub mod envelope;
pub mod error;
pub mod ids;

pub use envelope::{Envelope, EnvelopeKind, WireVersion, WIRE_VERSION};
pub use error::{ErrorCode, ErrorResponse};
pub use ids::{AccountId, ChannelId, DeviceId, GroupId, HouseId, MessageId};
