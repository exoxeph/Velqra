// SPDX-License-Identifier: GPL-3.0-only
//! Review 26b I2: a size limit that is checked after the whole file was read is no limit. Every
//! disk read of an untrusted-size file must stop at its cap. A counting allocator watches the
//! largest single allocation, so the test fails on memory use, not just on the final error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use velqra_core::file_vault::{FileVault, Protector};
use velqra_core::settings::Settings;
use velqra_core::vault::SecretVault;

struct Counting;
static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call unchanged to the system allocator; only records the size.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LARGEST.fetch_max(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LARGEST.fetch_max(n, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

struct Refuse;
impl Protector for Refuse {
    fn protect(&self, p: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.to_vec())
    }
    fn unprotect(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Err("refused".into())
    }
}

static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const BIG: usize = 32 * 1024 * 1024;
const BUDGET: usize = 4 * 1024 * 1024; // proportional to the cap, far below the file size

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.store(0, Ordering::Relaxed);
    let out = f();
    (out, LARGEST.load(Ordering::Relaxed))
}

#[test]
fn oversized_files_are_refused_without_allocating_their_size() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();

    // settings.json
    let path = d.path().join("settings.json");
    std::fs::write(&path, vec![b' '; BIG]).unwrap();
    let (loaded, peak) = measure(|| Settings::load_file(&path));
    assert_eq!(loaded.problem, Some("the settings file is too large"));
    assert!(peak < BUDGET, "settings load allocated {peak} bytes");

    // vault entry: read, then removal
    let vault_dir = d.path().join("vault");
    let v = FileVault::open(&vault_dir, Refuse).unwrap();
    let r = v.put(1, &velqra_protocol::Secret("x".into())).unwrap();
    let entry = vault_dir.join(format!("{r}.vlt"));
    std::fs::write(&entry, vec![7u8; BIG]).unwrap();
    let (got, peak) = measure(|| v.try_get(&r));
    assert!(got.is_err(), "an oversized entry is an error");
    assert!(peak < BUDGET, "vault read allocated {peak} bytes");
    let (_, peak) = measure(|| v.remove(&r));
    assert!(peak < BUDGET, "vault removal allocated {peak} bytes");
    assert!(!entry.exists(), "the oversized entry is still removed");
}

#[test]
fn a_secret_too_large_to_read_back_is_refused_at_put() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let v = FileVault::open(&d.path().join("v"), Refuse).unwrap();
    let huge = velqra_protocol::Secret("a".repeat(2 * 1024 * 1024));
    assert!(v.put(1, &huge).is_err());
    assert_eq!(std::fs::read_dir(d.path().join("v")).unwrap().count(), 0);
}
