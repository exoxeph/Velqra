// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { watchPort } from '../src/port_lifecycle.js';
const event = () => { let fn; return { addListener(f) { assert.equal(fn, undefined); fn = f; }, fire(m) { fn(m); } }; };
const tick = () => new Promise(r => setImmediate(r));
test('one readiness hint per port waits for authenticated connect, not the inbound ready claim', async () => {
  const p = { onMessage: event(), onDisconnect: event() }; let calls = 0, ready = 0, release;
  watchPort(p, { isCurrent: () => true, connect: () => { calls++; return new Promise(r => { release = r; }); }, onReady: () => ready++, onDrop: () => {} });
  p.onMessage.fire({ t: 'challenge' }); assert.equal(calls, 0);
  for (let n = 0; n < 400; n++) p.onMessage.fire({ t: 'ready' });
  assert.equal(calls, 1); assert.equal(ready, 0); release(); await tick(); assert.equal(ready, 1);
});
test('old port hints, disconnects, successful and rejected continuations cannot act on its replacement', async () => {
  for (const reject of [false, true]) {
    const p = { onMessage: event(), onDisconnect: event() }; let current = true, ready = 0, drops = 0, release, refuse, calls = 0;
    watchPort(p, { isCurrent: () => current, connect: () => { calls++; return new Promise((r, j) => { release = r; refuse = j; }); }, onReady: () => ready++, onDrop: () => drops++ });
    p.onMessage.fire({ t: 'ready' }); current = false; p.onDisconnect.fire();
    if (reject) refuse(Error('old')); else release(); await tick(); assert.equal(ready, 0); assert.equal(drops, 0);
    p.onMessage.fire({ t: 'ready' }); assert.equal(calls, 1);
  }
  const p = { onMessage: event(), onDisconnect: event() }; let calls = 0;
  watchPort(p, { isCurrent: () => false, connect: () => calls++, onReady() {}, onDrop() {} });
  p.onMessage.fire({ t: 'ready' }); assert.equal(calls, 0);
});
test('current port rejection or disconnect reports unavailability; synchronous connect failure is contained', async () => {
  for (const sync of [false, true]) {
    const p = { onMessage: event(), onDisconnect: event() }; let drops = 0;
    watchPort(p, { isCurrent: () => true, connect: () => { if (sync) throw Error('fail'); return Promise.reject(Error('fail')); }, onReady() { assert.fail('not authenticated'); }, onDrop: () => drops++ });
    p.onMessage.fire({ t: 'ready' }); await tick(); assert.equal(drops, 1); p.onDisconnect.fire(); assert.equal(drops, 2);
  }
});

test('a stuck authenticated-connect wait does not retain an unrelated inbound payload after GC', async () => {
  assert.equal(typeof globalThis.gc, 'function');
  const p = { onMessage: event(), onDisconnect: event() }; let release;
  watchPort(p, { isCurrent: () => true, connect: () => new Promise(r => { release = r; }), onReady() {}, onDrop() {} });
  let m = { t: 'ready', unrelated: new Uint8Array(1024 * 1024) }; const weak = new WeakRef(m.unrelated);
  p.onMessage.fire(m); m = null;
  for (let n = 0; n < 8; n++) { await tick(); globalThis.gc(); }
  assert.equal(weak.deref(), undefined); release(); await tick();
});
