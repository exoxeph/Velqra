// SPDX-License-Identifier: GPL-3.0-only
//! A vault that keeps every secret in its own file, protected by a `Protector` (DPAPI in the
//! product). The core stores only the opaque reference; the file name is derived from it and the
//! reference is also the protector's context, so a blob copied under another name cannot be opened.

use crate::bounded::read_file_capped;
use crate::vault::SecretVault;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use velqra_protocol::Secret;

/// The largest secret the vault stores; the file read back is capped a little above it.
pub const MAX_SECRET_BYTES: usize = 512 * 1024;
const MAX_ENTRY_BYTES: usize = 1024 * 1024;

pub trait Protector {
    fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct FileVault<P: Protector> {
    dir: PathBuf,
    protector: P,
    counter: AtomicU64,
}

/// References are plain tokens: they become file names, so nothing else may get through.
fn valid_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 128
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl<P: Protector> FileVault<P> {
    pub fn open(dir: &Path, protector: P) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            protector,
            counter: AtomicU64::new(0),
        })
    }

    fn path_of(&self, reference: &str) -> PathBuf {
        self.dir.join(format!("{reference}.vlt"))
    }

    /// `Ok(None)` means there is no such entry; `Err` means there is one and it cannot be read.
    pub fn try_get(&self, reference: &str) -> Result<Option<Secret>, String> {
        if !valid_reference(reference) {
            return Err("invalid vault reference".into());
        }
        let blob = match read_file_capped(&self.path_of(reference), MAX_ENTRY_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("vault read failed: {}", e.kind())),
        };
        let plain = self.protector.unprotect(&blob, reference.as_bytes())?;
        String::from_utf8(plain)
            .map(|s| Some(Secret(s)))
            .map_err(|_| "vault entry is not text".to_string())
    }
}

impl<P: Protector> SecretVault for FileVault<P> {
    fn put(&self, task_id: u64, secret: &Secret) -> Result<String, String> {
        if secret.0.len() > MAX_SECRET_BYTES {
            return Err("secret too large for the vault".into());
        }
        for _ in 0..64 {
            // Uniqueness is decided by the file system, not by the counter: a new instance (after a
            // restart) or another thread can pick the same number, and the loser simply retries.
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let reference = format!("ctx-{task_id}-{nanos:x}-{n}");
            let blob = self
                .protector
                .protect(secret.0.as_bytes(), reference.as_bytes())?;
            let tmp = self.dir.join(format!("{reference}.tmp"));
            let written = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .and_then(|mut f| f.write_all(&blob).and_then(|_| f.sync_all()));
            match written {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(format!("vault write failed: {}", e.kind()));
                }
            }
            // a hard link fails if the name exists, so an entry is never replaced, and it appears whole
            let linked = std::fs::hard_link(&tmp, self.path_of(&reference));
            let _ = std::fs::remove_file(&tmp);
            match linked {
                Ok(()) => return Ok(reference),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("vault write failed: {}", e.kind())),
            }
        }
        Err("vault could not allocate a reference".into())
    }

    fn get(&self, reference: &str) -> Option<Secret> {
        self.try_get(reference).ok().flatten()
    }

    fn remove(&self, reference: &str) {
        if !valid_reference(reference) {
            return;
        }
        let path = self.path_of(reference);
        // overwrite first so the bytes do not linger in a file that is merely unlinked; the zeros
        // go out in small pieces, so a huge file never costs a huge buffer
        if let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                let zeros = [0u8; 4096];
                let mut left = len;
                while left > 0 {
                    let n = left.min(zeros.len() as u64) as usize;
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    left -= n as u64;
                }
                let _ = f.sync_all();
            }
        }
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::sync::Arc;

    /// Reversible stand-in for DPAPI: scrambles the bytes and binds a tag to the context.
    struct TestProtector;
    fn tag(context: &[u8]) -> u8 {
        context
            .iter()
            .fold(0x5au8, |a, b| a.wrapping_mul(31).wrapping_add(*b))
    }
    impl Protector for TestProtector {
        fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = vec![tag(context)];
            out.extend(plain.iter().map(|b| b ^ 0xa7));
            Ok(out)
        }
        fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            match blob.split_first() {
                Some((t, rest)) if *t == tag(context) => {
                    Ok(rest.iter().map(|b| b ^ 0xa7).collect())
                }
                _ => Err("bad blob".into()),
            }
        }
    }
    /// Control: stores the plain bytes, so the sentinel scan must find them.
    struct Identity;
    impl Protector for Identity {
        fn protect(&self, plain: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
            Ok(plain.to_vec())
        }
        fn unprotect(&self, blob: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
            Ok(blob.to_vec())
        }
    }
    struct Failing;
    impl Protector for Failing {
        fn protect(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
            Err("no key".into())
        }
        fn unprotect(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
            Err("no key".into())
        }
    }

    const SENTINEL: &str = "CTX-SENTINEL-https://secret.example/token=abc123";

    fn secret(s: &str) -> Secret {
        Secret(s.to_string())
    }
    fn files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }

    #[test]
    fn a_secret_round_trips_and_removal_makes_it_disappear() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        let r = v.put(7, &secret(SENTINEL)).unwrap();
        assert_eq!(v.get(&r), Some(secret(SENTINEL)));
        v.remove(&r);
        assert_eq!(v.get(&r), None);
        assert!(files(d.path()).is_empty(), "no file is left behind");
        v.remove(&r); // removing twice is harmless
    }

    #[test]
    fn a_new_vault_over_the_same_directory_still_reads() {
        let d = tempfile::tempdir().unwrap();
        let r = FileVault::open(d.path(), TestProtector)
            .unwrap()
            .put(1, &secret("a"))
            .unwrap();
        let again = FileVault::open(d.path(), TestProtector).unwrap();
        assert_eq!(again.get(&r), Some(secret("a")));
    }

    #[test]
    fn references_are_unique_across_concurrent_puts_and_across_vault_instances() {
        let d = tempfile::tempdir().unwrap();
        let path = Arc::new(d.path().to_path_buf());
        let mut handles = Vec::new();
        for t in 0..8 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                // a fresh instance per thread: counters restart, so uniqueness must not rely on them
                let v = FileVault::open(&path, TestProtector).unwrap();
                (0..40)
                    .map(|i| {
                        let text = format!("{t}-{i}");
                        (v.put(5, &secret(&text)).unwrap(), text)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let all: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        let refs: HashSet<_> = all.iter().map(|(r, _)| r.clone()).collect();
        assert_eq!(refs.len(), 320, "every put got its own reference");
        let v = FileVault::open(&path, TestProtector).unwrap();
        for (r, want) in &all {
            assert_eq!(v.get(r), Some(secret(want)), "no put overwrote another");
        }
        assert_eq!(files(&path).len(), 320);
    }

    #[test]
    fn a_damaged_file_is_an_error_never_a_panic_or_a_wrong_secret() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        let r = v.put(1, &secret("x")).unwrap();
        let f = files(d.path()).pop().unwrap();
        fs::write(&f, b"").unwrap();
        assert!(v.try_get(&r).is_err());
        assert_eq!(v.get(&r), None);
        fs::write(&f, [0xffu8; 40]).unwrap();
        assert!(v.try_get(&r).is_err());
    }

    #[test]
    fn a_missing_reference_is_none_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        assert_eq!(v.try_get("ctx-1-gone"), Ok(None));
    }

    #[test]
    fn a_blob_copied_under_another_reference_does_not_open() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        let a = v.put(1, &secret("for-a")).unwrap();
        let b = v.put(2, &secret("for-b")).unwrap();
        let find = |r: &str| {
            files(d.path())
                .into_iter()
                .find(|p| p.to_string_lossy().contains(r))
                .unwrap()
        };
        fs::copy(find(&a), find(&b)).unwrap();
        assert!(
            v.try_get(&b).is_err(),
            "the reference is part of the protection"
        );
        assert_eq!(v.get(&a), Some(secret("for-a")));
    }

    #[test]
    fn references_that_are_not_plain_tokens_never_touch_the_filesystem() {
        let d = tempfile::tempdir().unwrap();
        let outside = d.path().join("outside.vlt");
        fs::write(&outside, b"keep me").unwrap();
        let inner = d.path().join("vault");
        let v = FileVault::open(&inner, TestProtector).unwrap();
        let bs = char::from(92u8);
        for bad in [
            "",
            "..",
            "../outside",
            &format!("..{bs}outside"),
            "a/b",
            "C:x",
            "x\0y",
            "outside.vlt/..",
        ] {
            assert_eq!(v.get(bad), None, "{bad:?}");
            assert!(v.try_get(bad).is_err(), "{bad:?}");
            v.remove(bad);
        }
        assert_eq!(fs::read(&outside).unwrap(), b"keep me");
    }

    #[test]
    fn the_sentinel_is_in_no_file_and_the_scan_can_see_it_when_it_is_there() {
        let contains = |dir: &Path| {
            files(dir).iter().any(|f| {
                let bytes = fs::read(f).unwrap();
                bytes
                    .windows(SENTINEL.len())
                    .any(|w| w == SENTINEL.as_bytes())
                    || f.to_string_lossy().contains("secret.example")
            })
        };
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        for i in 0..5 {
            v.put(i, &secret(SENTINEL)).unwrap();
        }
        assert!(!contains(d.path()));
        let control = tempfile::tempdir().unwrap();
        FileVault::open(control.path(), Identity)
            .unwrap()
            .put(1, &secret(SENTINEL))
            .unwrap();
        assert!(
            contains(control.path()),
            "the control proves the scan works"
        );
    }

    #[test]
    fn a_failed_protect_leaves_nothing_and_reports_the_failure() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), Failing).unwrap();
        assert!(v.put(1, &secret("x")).is_err());
        assert!(files(d.path()).is_empty());
    }

    #[test]
    fn removal_overwrites_the_bytes_before_deleting() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), Identity).unwrap();
        let r = v.put(1, &secret(SENTINEL)).unwrap();
        let file = files(d.path()).pop().unwrap();
        let keep = d.path().join("keep-link");
        fs::hard_link(&file, &keep).unwrap(); // a second name for the same bytes survives the delete
        v.remove(&r);
        let left = fs::read(&keep).unwrap();
        assert!(!left.is_empty());
        assert!(left.iter().all(|b| *b == 0), "plaintext was wiped");
    }

    #[test]
    fn no_temporary_files_remain_after_puts() {
        let d = tempfile::tempdir().unwrap();
        let v = FileVault::open(d.path(), TestProtector).unwrap();
        for i in 0..10 {
            v.put(i, &secret("x")).unwrap();
        }
        assert!(files(d.path())
            .iter()
            .all(|f| f.extension().is_some_and(|e| e == "vlt")));
    }
}
