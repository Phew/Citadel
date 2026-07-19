//! auth-service: accounts, devices, KeyPackage pool, KT log API.
//!
//! M1 so far: the database store layer (schema 0001) with the transactional
//! one-time KeyPackage pool. HTTP endpoints land with the F1 auth flow once
//! docs/protocol/auth.md is published (docs/issues/003).

pub mod store;
