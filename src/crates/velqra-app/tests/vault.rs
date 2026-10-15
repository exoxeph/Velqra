// SPDX-License-Identifier: GPL-3.0-only
//! The real FileVault with the real DPAPI protector.
#![cfg(windows)]

use velqra_app::protector::UserProtector;
use velqra_core::file_vault::FileVault;
use velqra_core::vault::SecretVault;
use velqra_protocol::Secret;

const SENTINEL: &str = "DPAPI-VAULT-SENTINEL-https://secret.example/t=1";

fn handle_count() -> u32 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut n = 0u32;
    // SAFETY: GetCurrentProcess returns a pseudo handle that is always valid; `n` is a valid out pointer.
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) };
    n
}

#[test]
fn dpapi_vault_round_trips_and_keeps_the_sentinel_off_disk() {
    let d = tempfile::tempdir().unwrap();
    let v = FileVault::open(d.path(), UserProtector::default()).unwrap();
    let r = v.put(1, &Secret(SENTINEL.into())).unwrap();
    for f in std::fs::read_dir(d.path()).unwrap() {
        let bytes = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!bytes.windows(12).any(|w| w == &SENTINEL.as_bytes()[..12]));
    }
    let again = FileVault::open(d.path(), UserProtector::default()).unwrap();
    assert_eq!(again.get(&r), Some(Secret(SENTINEL.into())));
    again.remove(&r);
    assert_eq!(v.get(&r), None);
}

#[test]
fn five_hundred_put_get_remove_cycles_do_not_leak_handles() {
    let d = tempfile::tempdir().unwrap();
    let v = FileVault::open(d.path(), UserProtector::default()).unwrap();
    // warm up so one-time handles (crypto providers, thread pools) are not counted
    for i in 0..5 {
        let r = v.put(i, &Secret("warm".into())).unwrap();
        v.remove(&r);
    }
    let before = handle_count();
    for i in 0..500 {
        let r = v.put(i, &Secret(SENTINEL.into())).unwrap();
        assert!(v.get(&r).is_some());
        v.remove(&r);
    }
    let after = handle_count();
    assert!(
        after <= before + 10,
        "handle count grew from {before} to {after}"
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}
