// SPDX-License-Identifier: GPL-3.0-only
//! Same-user IPC for Velqra. The only crate in the workspace allowed to contain `unsafe`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;

mod protect;
pub use protect::DpapiProtector;
mod containment;
pub use containment::DirectoryLease;

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::{
    connect, current_user_sid, make_private_dir, spawn_detached, Connection, PipeServer,
};

#[cfg(not(windows))]
mod stub;
#[cfg(not(windows))]
pub use stub::{
    connect, current_user_sid, make_private_dir, spawn_detached, Connection, PipeServer,
};

/// `\.\pipe\velqra-core-v1-<suffix>`. The suffix is the per-user part and must be a plain token:
/// anything else could point the client at a different pipe.
pub fn pipe_name(suffix: &str) -> io::Result<String> {
    let ok = !suffix.is_empty()
        && suffix.len() <= 64
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if !ok || suffix.starts_with('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid pipe name suffix",
        ));
    }
    Ok(format!(
        "{bs}{bs}.{bs}pipe{bs}velqra-core-v1-{suffix}",
        bs = char::from(92u8)
    ))
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn pipe_names_are_a_fixed_prefix_plus_a_plain_token() {
        let bs = char::from(92u8);
        assert_eq!(
            pipe_name("alice").unwrap(),
            format!("{bs}{bs}.{bs}pipe{bs}velqra-core-v1-alice")
        );
        for bad in [
            "",
            "..",
            ".hidden",
            "a/b",
            r"a\b",
            "a b",
            "a:b",
            "x\0y",
            &"a".repeat(65),
            "caf\u{e9}",
        ] {
            assert!(pipe_name(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
