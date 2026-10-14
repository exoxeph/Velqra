// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Velqra runtime: the core process and the native-messaging host.
#[cfg(windows)]
pub mod host_main;
pub mod paths;
pub mod runtime;
