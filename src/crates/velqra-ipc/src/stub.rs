// SPDX-License-Identifier: GPL-3.0-only
//! Non-Windows builds compile, but there is no transport: every call reports `Unsupported`.

use std::io;
use std::time::Duration;

fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "named pipes are only implemented on Windows",
    ))
}

pub struct Connection;
pub struct PipeServer;

impl PipeServer {
    pub fn create_first(_name: &str) -> io::Result<PipeServer> {
        unsupported()
    }
    pub fn accept(&mut self) -> io::Result<Connection> {
        unsupported()
    }
}

impl Connection {
    pub fn read_timeout(&mut self, _buf: &mut [u8], _timeout: Duration) -> io::Result<usize> {
        unsupported()
    }
    pub fn write_all(&mut self, _data: &[u8]) -> io::Result<()> {
        unsupported()
    }
}

pub fn connect(_name: &str, _timeout: Duration) -> io::Result<Connection> {
    unsupported()
}

pub fn current_user_sid() -> io::Result<String> {
    unsupported()
}

pub fn spawn_detached(_exe: &std::path::Path) -> io::Result<()> {
    unsupported()
}
