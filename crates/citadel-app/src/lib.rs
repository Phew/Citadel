//! The Citadel app core.
//!
//! Everything a client *does* that is not MLS itself: registration and login
//! (F1), KT verification of peers (INV-4), DM creation and joining (F2),
//! sending and receiving (F4), the outbox that retries stored wire bytes under
//! their stored idempotency keys, and the inbox that feeds gateway frames and
//! sync pages into the store in sequence order. Hosts — native UIs through
//! `citadel-ffi`, the browser through `citadel-web` — render what this crate
//! reports and never make a trust decision themselves.
//!
//! Plaintext exists here only as message content returned to the host to
//! render (INV-1). Signing seeds and the database encryption key live in the
//! OS credential store and are read only to sign (INV-2). Every peer identity
//! is verified against the KT log before it can be added to a group, and
//! every received envelope's wire version is checked before its bytes reach
//! OpenMLS (INV-4, INV-5).

pub mod app;
pub mod error;
pub mod kt;
pub mod transport;

pub use app::{AppEvent, CitadelApp, Config, Conversation, Message, Profile};
pub use error::AppError;
pub use kt::KtVerifier;
