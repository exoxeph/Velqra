// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Velqra core: durable ownership state machine for browser-to-app hand-off.

pub mod bounded;
pub mod core;
pub mod store;
pub mod vault;

pub use crate::core::{
    Core, DispatchEvent, Engine, EngineError, EngineRequest, EngineStatus, Poll,
};
pub mod destination;
pub mod file_vault;
pub mod path_policy;
pub mod settings;
pub mod write_probe;
