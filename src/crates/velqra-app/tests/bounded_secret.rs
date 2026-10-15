// SPDX-License-Identifier: GPL-3.0-only
//! Review 26b I2: the install-secret file is read with a cap, so a huge file cannot cost its size in memory.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use velqra_app::paths::{load_secret, secret_path};

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

#[test]
fn a_huge_install_secret_file_is_refused_without_allocating_its_size() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(secret_path(d.path()), vec![b'A'; 32 * 1024 * 1024]).unwrap();
    LARGEST.store(0, Ordering::Relaxed);
    let result = load_secret(d.path());
    let peak = LARGEST.load(Ordering::Relaxed);
    assert!(result.is_err(), "an oversized secret file is damaged");
    assert!(peak < 1024 * 1024, "load allocated {peak} bytes");
}
