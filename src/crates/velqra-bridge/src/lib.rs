// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Velqra bridge: framing, authenticated handshake and session handling between the browser
//! extension and the ownership core. Pure logic: no I/O lives here.

pub mod backend;
pub mod frame;
pub mod handshake;
pub mod host;
pub mod secret;
pub mod server;
pub mod sim;
pub mod testkit;
