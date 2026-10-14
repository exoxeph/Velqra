// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Velqra core: durable ownership state machine for browser-to-app hand-off.

pub mod core;
pub mod store;
pub mod vault;

pub use crate::core::{Core, DispatchEvent, Engine, EngineError, EngineRequest};
