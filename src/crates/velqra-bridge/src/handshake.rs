// SPDX-License-Identifier: GPL-3.0-only
//! Handshake cryptography: strict base64, HMAC-SHA256 transcripts for mutual authentication.

use crate::secret::InstallSecret;

pub const LABEL_SERVER: &[u8] = b"velqra/v1/server";
pub const LABEL_CLIENT: &[u8] = b"velqra/v1/client";
pub const MAC_LEN: usize = 32;

/// The values both sides bind into every MAC.
pub struct Fields<'a> {
    pub cn: &'a [u8],
    pub sn: &'a [u8],
    pub origin: &'a [u8],
    pub core: &'a [u8],
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|a| *a == c).map(|p| p as u32)
}

/// Strict RFC 4648 standard alphabet with padding: no whitespace, no URL-safe characters, and the
/// unused trailing bits must be zero, so every value has exactly one spelling.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 || bytes[..bytes.len() - pad].contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quanta = bytes.len() / 4;
    for (i, q) in bytes.chunks(4).enumerate() {
        let last = i + 1 == quanta;
        let keep = if last { 4 - pad } else { 4 };
        let mut n = 0u32;
        for (j, c) in q.iter().enumerate() {
            let v = if j < keep { sextet(*c)? } else { 0 };
            n = (n << 6) | v;
        }
        let triple = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let produced = keep - 1 + usize::from(keep == 4);
        // bits below the last data bit must be zero, otherwise a value has several spellings
        if last && pad > 0 && triple[produced..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&triple[..produced.min(3)]);
    }
    Some(out)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    use hmac::{Hmac, Mac};
    let mut m =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_be_bytes());
    out.extend_from_slice(x);
}

/// label and every field are length-prefixed, so no byte can migrate between fields unnoticed.
pub fn transcript(label: &[u8], f: &Fields) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, label);
    lp(&mut out, f.cn);
    lp(&mut out, f.sn);
    lp(&mut out, f.origin);
    lp(&mut out, f.core);
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

pub fn mac(secret: &InstallSecret, label: &[u8], f: &Fields) -> [u8; MAC_LEN] {
    hmac_sha256(secret.expose(), &transcript(label, f))
}

/// Constant-time check of a received MAC.
pub fn verify(secret: &InstallSecret, label: &[u8], f: &Fields, tag: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.expose())
        .expect("hmac accepts any key length");
    m.update(&transcript(label, f));
    m.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> InstallSecret {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        InstallSecret::from_bytes(b)
    }

    fn fields() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            vec![1; 16],
            vec![2; 16],
            b"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".to_vec(),
            vec![3; 16],
        )
    }

    #[test]
    fn base64_rfc4648_vectors_both_ways() {
        let v = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in v {
            assert_eq!(b64_encode(plain.as_bytes()), enc);
            assert_eq!(b64_decode(enc).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn base64_decoding_is_strict() {
        for bad in [
            "Zg=", "Zg", "Zg==\n", " Zg==", "Zh==", "Zm9=", "Z===", "Zm9v!", "Zm-v", "Zm_v",
            "Zg==Zg==",
        ] {
            assert_eq!(b64_decode(bad), None, "{bad:?} was accepted");
        }
    }

    #[test]
    fn base64_round_trips_every_length_and_byte_pattern() {
        for len in 0..70usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)), Some(data));
        }
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let out = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn server_and_client_macs_differ_for_the_same_fields() {
        let (cn, sn, o, c) = fields();
        let f = Fields {
            cn: &cn,
            sn: &sn,
            origin: &o,
            core: &c,
        };
        assert_ne!(
            mac(&secret(), LABEL_SERVER, &f),
            mac(&secret(), LABEL_CLIENT, &f)
        );
    }

    #[test]
    fn flipping_any_bit_of_any_field_changes_the_mac() {
        let (cn, sn, o, c) = fields();
        let base = mac(
            &secret(),
            LABEL_CLIENT,
            &Fields {
                cn: &cn,
                sn: &sn,
                origin: &o,
                core: &c,
            },
        );
        for which in 0..4 {
            let len = [cn.len(), sn.len(), o.len(), c.len()][which];
            for bit in 0..len * 8 {
                let (mut a, mut b, mut d, mut e) = (cn.clone(), sn.clone(), o.clone(), c.clone());
                let target = match which {
                    0 => &mut a,
                    1 => &mut b,
                    2 => &mut d,
                    _ => &mut e,
                };
                target[bit / 8] ^= 1 << (bit % 8);
                let m = mac(
                    &secret(),
                    LABEL_CLIENT,
                    &Fields {
                        cn: &a,
                        sn: &b,
                        origin: &d,
                        core: &e,
                    },
                );
                assert_ne!(m, base, "field {which} bit {bit} did not affect the MAC");
            }
        }
    }

    #[test]
    fn moving_a_byte_between_fields_changes_the_mac() {
        let s = secret();
        let a = mac(
            &s,
            LABEL_CLIENT,
            &Fields {
                cn: b"ab",
                sn: b"c",
                origin: b"o",
                core: b"k",
            },
        );
        let b = mac(
            &s,
            LABEL_CLIENT,
            &Fields {
                cn: b"a",
                sn: b"bc",
                origin: b"o",
                core: b"k",
            },
        );
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_secret_gives_a_different_mac() {
        let (cn, sn, o, c) = fields();
        let f = Fields {
            cn: &cn,
            sn: &sn,
            origin: &o,
            core: &c,
        };
        let mut other = [0u8; 32];
        other[0] = 9;
        assert_ne!(
            mac(&secret(), LABEL_SERVER, &f),
            mac(&InstallSecret::from_bytes(other), LABEL_SERVER, &f)
        );
    }

    #[test]
    fn verify_accepts_only_the_exact_mac() {
        let (cn, sn, o, c) = fields();
        let f = Fields {
            cn: &cn,
            sn: &sn,
            origin: &o,
            core: &c,
        };
        let good = mac(&secret(), LABEL_SERVER, &f);
        assert!(verify(&secret(), LABEL_SERVER, &f, &good));
        assert!(
            !verify(&secret(), LABEL_CLIENT, &f, &good),
            "wrong label accepted"
        );
        assert!(!verify(&secret(), LABEL_SERVER, &f, &good[..31]));
        assert!(!verify(
            &secret(),
            LABEL_SERVER,
            &f,
            &[good.to_vec(), vec![0]].concat()
        ));
        assert!(!verify(&secret(), LABEL_SERVER, &f, &[]));
        for bit in 0..256 {
            let mut t = good;
            t[bit / 8] ^= 1 << (bit % 8);
            assert!(!verify(&secret(), LABEL_SERVER, &f, &t), "tag bit {bit}");
        }
    }
}
