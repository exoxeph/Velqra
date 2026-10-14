// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// Handshake primitives. Everything here mirrors crates/velqra-bridge/src/handshake.rs, and the golden
// vectors in test/vectors.json keep the two in step.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const encoder = new TextEncoder();

export const LABEL_SERVER = encoder.encode('velqra/v1/server');
export const LABEL_CLIENT = encoder.encode('velqra/v1/client');

/** @param {Uint8Array} data */
export function b64Encode(data) {
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const n = (data[i] << 16) | ((data[i + 1] ?? 0) << 8) | (data[i + 2] ?? 0);
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63];
    out += i + 1 < data.length ? ALPHABET[(n >> 6) & 63] : '=';
    out += i + 2 < data.length ? ALPHABET[n & 63] : '=';
  }
  return out;
}

/**
 * Strict RFC 4648 standard alphabet with padding. No whitespace, no URL-safe characters, and the unused
 * trailing bits must be zero, so every value has exactly one spelling.
 * @param {string} s
 * @returns {Uint8Array | null}
 */
export function b64Decode(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0) return null;
  let pad = 0;
  while (pad < s.length && s[s.length - 1 - pad] === '=') pad++;
  if (pad > 2 || s.slice(0, s.length - pad).includes('=')) return null;
  /** @type {number[]} */
  const out = [];
  const quanta = s.length / 4;
  for (let q = 0; q < quanta; q++) {
    const last = q === quanta - 1;
    const keep = last ? 4 - pad : 4;
    let n = 0;
    for (let j = 0; j < 4; j++) {
      let v = 0;
      if (j < keep) {
        v = ALPHABET.indexOf(s[q * 4 + j]);
        if (v < 0) return null;
      }
      n = (n << 6) | v;
    }
    const triple = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    const produced = keep === 4 ? 3 : keep - 1;
    if (last && pad > 0 && triple.slice(produced).some((b) => b !== 0)) return null;
    out.push(...triple.slice(0, produced));
  }
  return Uint8Array.from(out);
}

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function hmacSha256(key, data) {
  const k = await globalThis.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, data));
}

/** @param {number[]} out @param {Uint8Array} x */
function lp(out, x) {
  out.push((x.length >>> 24) & 255, (x.length >>> 16) & 255, (x.length >>> 8) & 255, x.length & 255, ...x);
}

/**
 * Label and every field are length-prefixed, so no byte can migrate between fields unnoticed.
 * @param {Uint8Array} label
 * @param {{cn: Uint8Array, sn: Uint8Array, origin: string, core: Uint8Array}} f
 */
export function transcript(label, f) {
  /** @type {number[]} */
  const out = [];
  lp(out, label);
  lp(out, f.cn);
  lp(out, f.sn);
  lp(out, encoder.encode(f.origin));
  lp(out, f.core);
  out.push(0, 1); // protocol version 1, big endian
  return Uint8Array.from(out);
}

/**
 * @param {Uint8Array} secret
 * @param {Uint8Array} label
 * @param {{cn: Uint8Array, sn: Uint8Array, origin: string, core: Uint8Array}} f
 */
export function mac(secret, label, f) {
  return hmacSha256(secret, transcript(label, f));
}

/**
 * Constant-time check (WebCrypto verify); a tag of the wrong length simply fails.
 * @param {Uint8Array} secret
 * @param {Uint8Array} label
 * @param {{cn: Uint8Array, sn: Uint8Array, origin: string, core: Uint8Array}} f
 * @param {Uint8Array} tag
 */
export async function verifyMac(secret, label, f, tag) {
  const k = await globalThis.crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return globalThis.crypto.subtle.verify('HMAC', k, tag, transcript(label, f));
}
