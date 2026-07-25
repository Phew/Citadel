//! delivery-service: ciphertext store + live fanout for M2 encrypted DMs
//! (F2 Welcome, F4 send/receive; ADR-0005).
//!
//! The service is an untrusted router and ciphertext store: it sequences and
//! fans out opaque MLS bytes and may never read, derive, or persist content
//! or group secrets (INV-1). [`store`] owns the submit transaction (per-group
//! serialization point, idempotent retry, Amendment 1 participant
//! authorization) and the sync/welcome queries; [`auth`] replicates ADR-0003
//! §3 bearer-token validation against the shared auth schema; [`server`] is
//! the HTTP edge; [`gateway`] is the WebSocket receive/fanout path (sends go
//! over REST only — one write path, ADR-0005 decision #4).

pub mod auth;
pub mod gateway;
pub mod server;
pub mod store;
