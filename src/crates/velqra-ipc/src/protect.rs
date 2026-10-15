// SPDX-License-Identifier: GPL-3.0-only
//! Current-user data protection (DPAPI). The blob can be opened only by the same Windows user on
//! the same machine; the caller-supplied `context` is mixed into the entropy so a blob cannot be
//! moved to a different purpose or file name. No UI is ever shown.

use std::io;

/// Domain separation for every Velqra blob.
const ENTROPY_PREFIX: &[u8] = b"velqra-dpapi-v1\0";

#[derive(Clone, Default)]
pub struct DpapiProtector;

fn entropy_for(context: &[u8]) -> Vec<u8> {
    let mut e = ENTROPY_PREFIX.to_vec();
    e.extend_from_slice(context);
    e
}

impl DpapiProtector {
    pub fn protect(&self, plain: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
        dpapi::protect(plain, &entropy_for(context))
    }

    pub fn unprotect(&self, blob: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
        dpapi::unprotect(blob, &entropy_for(context))
    }
}

#[cfg(windows)]
mod dpapi {
    use std::io;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob_of(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
        let cb = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "input too large"))?;
        Ok(CRYPT_INTEGER_BLOB {
            cbData: cb,
            pbData: data.as_ptr().cast_mut(),
        })
    }

    /// Copies the OS-allocated output into a Vec, wipes it, and frees it exactly once.
    fn take_output(out: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
        // SAFETY: on success the OS filled `out` with a LocalAlloc'd buffer of `cbData` bytes.
        let copy = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        if wipe {
            // SAFETY: the same buffer, still allocated and exclusively ours until freed below.
            unsafe { std::ptr::write_bytes(out.pbData, 0, out.cbData as usize) };
        }
        // SAFETY: `pbData` was allocated by the OS with LocalAlloc and is freed once.
        unsafe { LocalFree(out.pbData.cast()) };
        copy
    }

    pub fn protect(plain: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
        let input = blob_of(plain)?;
        let ent = blob_of(entropy)?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: `input` and `ent` point at live slices for the call; the description and
        // reserved/prompt pointers are null; `out` is a valid out parameter.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(take_output(out, false))
    }

    pub fn unprotect(blob: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
        if blob.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty blob"));
        }
        let input = blob_of(blob)?;
        let ent = blob_of(entropy)?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`; the description out pointer is null (not requested).
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(take_output(out, true))
    }

    #[cfg(test)]
    pub fn protect_raw(plain: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
        protect(plain, entropy)
    }
}

#[cfg(not(windows))]
mod dpapi {
    use std::io;
    pub fn protect(_: &[u8], _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    pub fn unprotect(_: &[u8], _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    #[cfg(test)]
    pub fn protect_raw(_: &[u8], _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &[u8] = b"S3CR3T-DPAPI-SENTINEL-0123456789";

    #[test]
    fn round_trip_returns_the_original_bytes() {
        let p = DpapiProtector;
        let blob = p.protect(SENTINEL, b"ctx-1").unwrap();
        assert_eq!(p.unprotect(&blob, b"ctx-1").unwrap(), SENTINEL);
    }

    #[test]
    fn the_blob_never_contains_the_plaintext() {
        let blob = DpapiProtector.protect(SENTINEL, b"ctx-1").unwrap();
        assert!(!blob.windows(SENTINEL.len()).any(|w| w == SENTINEL));
        assert_ne!(blob, SENTINEL);
    }

    #[test]
    fn a_tampered_blob_is_refused() {
        let p = DpapiProtector;
        let blob = p.protect(SENTINEL, b"ctx-1").unwrap();
        for at in [0, blob.len() / 2, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[at] ^= 1;
            assert!(p.unprotect(&bad, b"ctx-1").is_err(), "flip at {at}");
        }
        assert!(p.unprotect(&blob[..blob.len() - 1], b"ctx-1").is_err());
        assert!(p.unprotect(&[], b"ctx-1").is_err());
        assert!(
            p.unprotect(SENTINEL, b"ctx-1").is_err(),
            "plain bytes are not a blob"
        );
    }

    #[test]
    fn a_blob_opens_only_with_the_context_it_was_made_for() {
        let p = DpapiProtector;
        let blob = p.protect(SENTINEL, b"ctx-1").unwrap();
        assert!(p.unprotect(&blob, b"ctx-2").is_err());
        assert!(p.unprotect(&blob, b"").is_err());
    }

    #[test]
    fn empty_and_large_inputs_round_trip() {
        let p = DpapiProtector;
        let blob = p.protect(&[], b"e").unwrap();
        assert_eq!(p.unprotect(&blob, b"e").unwrap(), Vec::<u8>::new());
        let big: Vec<u8> = (0..1024 * 1024).map(|i| (i * 31 % 251) as u8).collect();
        let blob = p.protect(&big, b"big").unwrap();
        assert_eq!(p.unprotect(&blob, b"big").unwrap(), big);
    }

    #[test]
    fn the_entropy_prefix_is_part_of_the_protection() {
        // a blob made with the raw context alone (no Velqra prefix) must not open
        let raw = raw_protect(SENTINEL, b"ctx-1");
        assert!(DpapiProtector.unprotect(&raw, b"ctx-1").is_err());
    }

    fn raw_protect(plain: &[u8], entropy: &[u8]) -> Vec<u8> {
        dpapi::protect_raw(plain, entropy).unwrap()
    }
}
