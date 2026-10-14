// SPDX-License-Identifier: GPL-3.0-only
//! The per-install secret. It never prints, and it is only ever read through `expose`.

use rand::RngCore;

pub struct InstallSecret([u8; 32]);

impl InstallSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate(rng: &mut impl RngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    /// The raw key bytes. The name is deliberate: every call site is a place a secret is handled.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for InstallSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstallSecret(<redacted>)")
    }
}

impl Drop for InstallSecret {
    fn drop(&mut self) {
        // best effort without unsafe: the optimiser may elide it, so this is not a security boundary
        self.0 = [0; 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_key_bytes() {
        let s = InstallSecret::from_bytes([0xAB; 32]);
        let d = format!("{s:?}");
        assert!(
            !d.to_lowercase().contains("ab") && !d.contains("171"),
            "{d}"
        );
        assert!(d.contains("redacted"));
    }

    #[test]
    fn generated_secrets_differ_and_are_not_zero() {
        let mut rng = rand::rngs::OsRng;
        let a = InstallSecret::generate(&mut rng);
        let b = InstallSecret::generate(&mut rng);
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0u8; 32]);
    }
}
