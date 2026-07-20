//! auth-service: accounts, devices, KeyPackage pool, KT log API.
//!
//! M1: the database store layer (schema 0001) with the transactional
//! one-time KeyPackage pool ([`store`]); the F1 challenge-response /
//! bearer-token flow (ADR-0003, [`auth`]); unauthenticated registration
//! with the atomic KT leaf append (ADR-0003 §6, ADR-0001 §4(b),
//! [`accounts`]); authenticated device enrollment (ADR-0004, [`enroll`]);
//! KT persistence with the fatal startup root check (ADR-0001 §4,
//! [`kt_store`]); and the HTTP edge over all of it ([`server`]).

pub mod accounts;
pub mod auth;
pub mod enroll;
pub mod kt_store;
pub mod server;
pub mod store;
