use citadel_core::identity::IdentityError;
use citadel_core::store::{CredentialStoreError, StoreError};
use citadel_proto::error::ErrorCode;
use citadel_proto::ids::AccountId;

/// Everything the app core can fail with. Transport failures are retryable;
/// rejections carry the service's error code; KT failures are never retried
/// silently.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("credential store: {0}")]
    Credentials(#[from] CredentialStoreError),
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("service rejected with HTTP {status} ({code:?}): {message}")]
    Rejected {
        status: u16,
        code: ErrorCode,
        message: String,
    },
    #[error("key transparency verification failed: {0}")]
    KtVerification(String),
    #[error("no profile is registered on this device")]
    NoProfile,
    #[error("this device already has a registered profile")]
    AlreadyRegistered,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("unsupported wire version {0}; this build speaks {supported}", supported = citadel_proto::WIRE_VERSION)]
    UnsupportedWireVersion(u16),
    #[error("malformed envelope from the delivery service: {0}")]
    MalformedEnvelope(String),
    #[error("mls: {0}")]
    Mls(String),
    #[error("no KeyPackage is available for account {0}")]
    NoKeyPackage(AccountId),
    #[error("gateway closed")]
    GatewayClosed,
}

impl AppError {
    pub fn transport(error: impl std::fmt::Display) -> Self {
        Self::Transport(error.to_string())
    }
}
