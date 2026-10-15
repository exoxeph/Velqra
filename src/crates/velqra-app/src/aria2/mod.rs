// SPDX-License-Identifier: GPL-3.0-only
//! The aria2 transfer engine: a pinned aria2 process driven over a loopback JSON-RPC connection.

pub mod adapter;
pub mod process;
pub mod rpc;
pub mod supervisor;
