// SPDX-License-Identifier: GPL-3.0-only
//! Can we create a file in this folder? Asked at Prepare, before the browser download is cancelled,
//! so an unwritable destination keeps the download in the browser instead of failing it afterwards.
//! The probe creates one uniquely named empty file that disappears when it is closed; it never
//! opens, replaces or deletes anything that was already there.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn dir_is_writable(dir: &Path) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    probe_with(dir, &mut || {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // the counter makes two probes in one process differ even when the clock does not
        format!(
            ".velqra-probe-{}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    })
}

/// A name that already exists is somebody else's file: skip it (never open or delete it) and try the next name.
fn probe_with(dir: &Path, next_name: &mut dyn FnMut() -> String) -> io::Result<()> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..8 {
        let path = dir.join(next_name());
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
            options.custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
        }
        match options.open(&path) {
            Ok(file) => {
                drop(file);
                #[cfg(not(windows))]
                std::fs::remove_file(&path)?;
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn a_writable_directory_passes_and_nothing_is_left_behind() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("keep.txt"), b"mine").unwrap();
        for _ in 0..20 {
            dir_is_writable(d.path()).unwrap();
        }
        assert_eq!(leftovers(d.path()), 1);
        assert_eq!(std::fs::read(d.path().join("keep.txt")).unwrap(), b"mine");
    }

    #[test]
    fn many_threads_probing_at_once_never_collide_on_the_probe_name() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().to_path_buf();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || (0..300).all(|_| dir_is_writable(&p).is_ok()))
            })
            .collect();
        for h in handles {
            assert!(
                h.join().unwrap(),
                "a probe failed because another one had its name"
            );
        }
        assert_eq!(leftovers(d.path()), 0);
    }

    #[test]
    fn a_name_that_already_exists_is_skipped_and_the_existing_file_is_left_alone() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("taken"), b"not ours").unwrap();
        let mut names = ["taken", "taken", "free"].into_iter();
        let ok = probe_with(d.path(), &mut || names.next().unwrap().to_string());
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(std::fs::read(d.path().join("taken")).unwrap(), b"not ours");
        assert_eq!(
            leftovers(d.path()),
            1,
            "the probe file is gone, ours is not touched"
        );
        // names that keep colliding give up instead of looping or touching anything
        let stuck = probe_with(d.path(), &mut || "taken".to_string());
        assert_eq!(stuck.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(d.path().join("taken")).unwrap(), b"not ours");
    }

    #[test]
    fn a_missing_directory_fails() {
        let d = tempfile::tempdir().unwrap();
        assert!(dir_is_writable(&d.path().join("absent")).is_err());
    }

    /// Restores the folder's permissions even if the test panics.
    #[cfg(windows)]
    struct DenyGuard(std::path::PathBuf);
    #[cfg(windows)]
    impl Drop for DenyGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("icacls")
                .arg(&self.0)
                .args(["/remove:d", "*S-1-1-0"])
                .output();
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_directory_that_denies_file_creation_fails() {
        let d = tempfile::tempdir().unwrap();
        let guard = DenyGuard(d.path().to_path_buf());
        let out = std::process::Command::new("icacls")
            .arg(d.path())
            .args(["/deny", "*S-1-1-0:(WD,AD)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "icacls could not set the deny entry");
        assert!(dir_is_writable(d.path()).is_err());
        drop(guard);
        assert!(
            dir_is_writable(d.path()).is_ok(),
            "permissions were restored"
        );
    }
}
