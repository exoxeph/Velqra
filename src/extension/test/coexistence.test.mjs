// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Coexistence } from '../src/coexistence.js';

test('optional management is requested only on a direct gesture; denied permission never enumerates', async () => {
  const log = [];
  const c = new Coexistence({ permissions: { request: async o => { log.push(['request', o]); return false; } }, management: { getAll: async () => { log.push('enumerate'); } } });
  await c.check(); await c.check(false); assert.deepEqual(log, []);
  assert.match(await c.check(true), /declined/); assert.deepEqual(log, [['request', { permissions: ['management'] }]]);
});
test('coexistence explains known active managers, ignores disabled ones, never changes any extension', async () => {
  const c = new Coexistence({ permissions: { request: async () => true }, management: { getAll: async () => [{ name: 'IDM Integration Module', enabled: true }, { name: 'Free Download Manager', enabled: false }, { name: 'random', enabled: true }] } });
  const text = await c.check(true); assert.match(text, /Internet Download Manager/); assert.doesNotMatch(text, /Free Download Manager/); assert.match(text, /changes nothing/);
});
test('stuck optional checks retain a single operation under repeated requests', async () => {
  let requests = 0;
  const c = new Coexistence({ timeoutMs: 2, permissions: { request: () => { requests++; return new Promise(() => {}); } }, management: {} });
  for (let i = 0; i < 100; i++) await c.check(true);
  assert.equal(requests, 1); assert.equal(c.steps.live, 1);
});

test('malformed and oversized management lists produce a fixed notice', async () => {
  for (const value of [null, Array(257).fill({ name: 'IDM Integration Module', enabled: true })]) {
    const c = new Coexistence({ permissions: { request: async () => true }, management: { getAll: async () => value } });
    assert.equal(await c.check(true), 'Extension list unavailable.');
  }
});

test('local options page does not ask permission until the button click and uses textContent', async () => {
  let requests = 0, click;
  const button = { disabled: false, addEventListener(name, fn) { assert.equal(name, 'click'); click = fn; } };
  const result = { textContent: '' };
  globalThis.document = { getElementById: id => id === 'check' ? button : result };
  globalThis.chrome = { permissions: { request: async () => { requests++; return false; } }, management: { getAll: async () => { throw Error('must not enumerate'); } } };
  await import('../src/options.js'); assert.equal(requests, 0);
  const pending = click(); assert.equal(requests, 1); assert.equal(button.disabled, true); await pending;
  assert.equal(button.disabled, false); assert.match(result.textContent, /declined/);
});
