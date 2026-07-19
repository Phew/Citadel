//! auth-service: accounts, devices, KeyPackage pool, KT log API.
//!
//! M1 so far: the database store layer (schema 0001) with the transactional
//! one-time KeyPackage pool, and the F1 challenge-response / bearer-token
//! flow (ADR-0003): [`auth`] (store semantics) + [`server`] (HTTP edge).
//! Registration and the KT endpoints land with the KT persistence PR
//! (ADR-0001 §4).

pub mod auth;
pub mod server;
pub mod store;
