//! auth-service: accounts, devices, KeyPackage pool, KT log API.
//!
//! M1 so far: the database store layer (schema 0001) with the transactional
//! one-time KeyPackage pool; the F1 challenge-response / bearer-token flow
//! (ADR-0003, [`auth`]); KT persistence with the fatal startup root check
//! (ADR-0001 §4, [`kt_store`]); and the HTTP edge over both ([`server`]).
//! Registration and the KeyPackage pool endpoints land next.

pub mod auth;
pub mod kt_store;
pub mod server;
pub mod store;
