// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Deterministic fault-injection simulator for the ownership protocol.

pub mod browser;
pub mod engine;
pub mod fault;
pub mod invariants;
pub mod scenarios;
pub mod world;
