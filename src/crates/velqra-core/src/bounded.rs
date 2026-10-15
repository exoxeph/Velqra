// SPDX-License-Identifier: GPL-3.0-only
//! Reads that cannot be talked into allocating more than their cap. A size check made after the
//! whole file was read is no check, so every read of a file whose size we do not control goes
//! through here: at most `max + 1` bytes are ever requested.

use std::io::{self, Read};
use std::path::Path;

/// Reads at most `max` bytes; a source with more is `FileTooLarge` (and the extra byte proves it).
pub fn read_capped<R: Read>(reader: R, max: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge));
    }
    Ok(out)
}

pub fn read_file_capped(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    read_capped(std::fs::File::open(path)?, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves endless bytes and counts how many were asked for.
    struct Endless(std::cell::Cell<u64>);
    impl Read for &Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.set(self.0.get() + buf.len() as u64);
            buf.fill(b'x');
            Ok(buf.len())
        }
    }

    #[test]
    fn an_endless_source_is_stopped_at_the_cap() {
        let src = Endless(std::cell::Cell::new(0));
        let err = read_capped(&src, 1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        assert!(
            src.0.get() <= 1001 + 8192,
            "asked for {} bytes",
            src.0.get()
        );
    }

    #[test]
    fn the_cap_is_inclusive() {
        assert_eq!(read_capped(&[1u8; 10][..], 10).unwrap().len(), 10);
        assert!(read_capped(&[1u8; 11][..], 10).is_err());
        assert!(read_capped(&[][..], 0).unwrap().is_empty());
        assert!(read_capped(&[1u8][..], 0).is_err());
    }
}
