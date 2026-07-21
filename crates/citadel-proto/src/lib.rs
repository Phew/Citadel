//! Shared protocol types for Citadel.
//!
//! This crate is canonical for every wire and signing contract (AGENTS.md rule 5).
//! Service and client crates must not redefine envelopes or error codes.

pub mod auth;
pub mod bytes;
pub mod credential;
pub mod delivery;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod kt;

pub use credential::{DeviceCredential, DeviceEndorsement, IdentityPublicKey, Signature};
pub use delivery::{
    GatewayClientFrame, GatewayServerFrame, MessagesPage, SubmitMessageRequest,
    SubmitMessageResponse, MESSAGES_PAGE_LIMIT,
};
pub use envelope::{CommitConflict, Envelope, EnvelopeKind, WireVersion, WIRE_VERSION};
pub use error::{ErrorCode, ErrorResponse};
pub use ids::{AccountId, ChannelId, DeviceId, GroupId, HouseId, MessageId};
pub use kt::{ConsistencyProof, InclusionProof, KeyId, KtLeaf, KtProofResponse, SignedTreeHead};
