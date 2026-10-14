// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// The JavaScript handshake must agree with the Rust one byte for byte. The vectors file is written
// by `cargo test -p velqra-bridge --test vectors` and checked there for staleness.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  b64Encode,
  b64Decode,
  hmacSha256,
  transcript,
  mac,
  verifyMac,
  LABEL_SERVER,
  LABEL_CLIENT,
} from '../src/handshake.js';

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
const bytes = (/** @type {string} */ b64) => /** @type {Uint8Array} */ (b64Decode(b64));
const fields = () => ({
  cn: bytes(vectors.cn_b64),
  sn: bytes(vectors.sn_b64),
  origin: vectors.origin,
  core: bytes(vectors.core_b64),
});
const hex = (/** @type {Uint8Array} */ u) => [...u].map((b) => b.toString(16).padStart(2, '0')).join('');

test('base64 matches the RFC 4648 vectors in both directions', () => {
  for (const { plain, encoded } of vectors.base64) {
    const data = new TextEncoder().encode(plain);
    assert.equal(b64Encode(data), encoded);
    assert.deepEqual(b64Decode(encoded), data);
  }
});

test('base64 decoding is as strict as the Rust decoder', () => {
  for (const bad of ['Zg=', 'Zg', 'Zg==\n', ' Zg==', 'Zh==', 'Zm9=', 'Z===', 'Zm9v!', 'Zm-v', 'Zm_v', 'Zg==Zg==']) {
    assert.equal(b64Decode(bad), null, JSON.stringify(bad));
  }
});

test('base64 round trips every length', () => {
  for (let len = 0; len < 70; len++) {
    const data = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len) & 255);
    assert.deepEqual(b64Decode(b64Encode(data)), data);
  }
});

test('HMAC-SHA256 matches RFC 4231 test case 2', async () => {
  const out = await hmacSha256(new TextEncoder().encode('Jefe'), new TextEncoder().encode('what do ya want for nothing?'));
  assert.equal(hex(out), vectors.hmac_rfc4231_case2_hex);
});

test('the transcript and both MACs equal what Rust computed', async () => {
  const secret = bytes(vectors.secret_b64);
  assert.equal(b64Encode(transcript(LABEL_SERVER, fields())), vectors.server_transcript_b64);
  assert.equal(b64Encode(await mac(secret, LABEL_SERVER, fields())), vectors.server_mac_b64);
  assert.equal(b64Encode(await mac(secret, LABEL_CLIENT, fields())), vectors.client_mac_b64);
});

test('a MAC verifies only with the right secret, label and fields', async () => {
  const secret = bytes(vectors.secret_b64);
  const good = bytes(vectors.server_mac_b64);
  assert.equal(await verifyMac(secret, LABEL_SERVER, fields(), good), true);
  assert.equal(await verifyMac(secret, LABEL_CLIENT, fields(), good), false, 'wrong label');
  const other = secret.slice();
  other[0] ^= 1;
  assert.equal(await verifyMac(other, LABEL_SERVER, fields(), good), false, 'wrong secret');
  const moved = fields();
  moved.origin = moved.origin.replace('a', 'b');
  assert.equal(await verifyMac(secret, LABEL_SERVER, moved, good), false, 'wrong origin');
  assert.equal(await verifyMac(secret, LABEL_SERVER, fields(), good.slice(0, 31)), false, 'short tag');
  assert.equal(await verifyMac(secret, LABEL_SERVER, fields(), new Uint8Array(0)), false, 'empty tag');
});

test('flipping any single bit of the tag is rejected', async () => {
  const secret = bytes(vectors.secret_b64);
  const good = bytes(vectors.server_mac_b64);
  for (let bit = 0; bit < 256; bit++) {
    const t = good.slice();
    t[bit >> 3] ^= 1 << (bit & 7);
    assert.equal(await verifyMac(secret, LABEL_SERVER, fields(), t), false, `bit ${bit}`);
  }
});
