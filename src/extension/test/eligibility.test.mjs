// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../src/eligibility.js';

const item = { id: 1, url: 'https://files.test/a.zip', filename: 'a.zip', state: 'in_progress', danger: 'safe' };
const settings = { mode: 'on', extensions: ['zip', 'gz'], allowed_sites: [], excluded_sites: [] };
const context = { method: 'GET', correlated: true, appReady: true, credentialsSeen: false };
const d = (i = {}, s = {}, c = {}) => decide({ ...item, ...i }, { ...settings, ...s }, { ...context, ...c });

test('eligible observed unauthenticated GET', () => assert.deepEqual(d(), { action: 'capture', reason: 'eligible' }));
for (const [name, i, s, c, reason] of [
  ['complete', { state: 'complete' }, {}, {}, 'complete'],
  ['cancelled is reconciliation, never replay', { state: 'interrupted' }, {}, {}, 'interrupted'],
  ['other extension', { byExtensionId: 'other' }, {}, {}, 'extension'],
  ['dangerous', { danger: 'dangerous' }, {}, {}, 'blocked'],
  ['policy', { error: 'FILE_BLOCKED' }, {}, {}, 'blocked'],
  ['off', {}, { mode: 'off' }, {}, 'disabled'],
  ['bypass', {}, {}, { bypass: true }, 'bypass'],
  ['type', { filename: 'archive.zip.txt' }, {}, {}, 'type'],
  ['minimum', { totalBytes: 10 }, { min_bytes: 11 }, {}, 'minimum'],
  ['unknown size with minimum', {}, { min_bytes: 11 }, {}, 'minimum'],
  ['unready', {}, {}, { appReady: false }, 'unavailable'],
  ['POST', {}, {}, { method: 'POST' }, 'method'],
  ['unseen', {}, {}, { correlated: false }, 'correlation'],
  ['ambiguous', {}, {}, { ambiguous: true }, 'correlation'],
  ['credentials', {}, {}, { credentialsSeen: true }, 'credentials'],
  ['unknown credentials', {}, {}, { credentialsSeen: undefined }, 'credentials'],
  ['cookie', {}, {}, { cookieSeen: true }, 'credentials'],
  ['authorization', {}, {}, { authorizationSeen: true }, 'credentials'],
  ['login redirect', {}, {}, { loginRedirect: true }, 'credentials'],
  ['one use', {}, {}, { suspectedOneUse: true }, 'replay_risk'],
  ['userinfo', { url: 'https://u:p@files.test/a.zip' }, {}, {}, 'credentials'],
]) test(name, () => assert.deepEqual(d(i, s, c), { action: 'keep', reason }));

for (const scheme of ['blob:', 'data:', 'filesystem:', 'chrome:', 'file:', 'javascript:']) {
  test(`scheme ${scheme}`, () => assert.equal(d({ url: `${scheme}//files.test/a.zip` }).reason, 'scheme'));
}
test('final suffix only, case insensitive and Windows paths', () => {
  assert.equal(d({ filename: 'C:\\Downloads\\archive.tar.GZ' }).action, 'capture');
  assert.equal(d({ filename: 'archive.zip.txt' }, { extensions: ['txt'] }).action, 'capture');
  assert.equal(d({ filename: 'archive.zip.' }).reason, 'type');
});
test('site patterns use host boundary; wildcard excludes bare host', () => {
  assert.equal(d({}, { mode: 'per_site', allowed_sites: ['files.test'] }).action, 'capture');
  assert.equal(d({}, { mode: 'per_site', allowed_sites: ['*.files.test'] }).reason, 'site');
  assert.equal(d({ url: 'https://sub.files.test/a' }, { mode: 'per_site', allowed_sites: ['*.files.test'] }).action, 'capture');
  assert.equal(d({ url: 'https://evilfiles.test/a' }, { mode: 'per_site', allowed_sites: ['*.files.test'] }).reason, 'site');
  assert.equal(d({}, { excluded_sites: ['files.test'], allowed_sites: ['files.test'] }).reason, 'site');
  assert.equal(d({ url: 'https://files.test./a.zip' }, { excluded_sites: ['files.test'] }).reason, 'site');
});
test('fail closed on missing settings or unknown mode', () => {
  assert.equal(decide(item, null, context).action, 'keep');
  assert.equal(d({}, { mode: 'wat' }).reason, 'disabled');
});
test('invalid shapes and browser identities have fixed invalid reason', () => {
  for (const x of [null, 1, true, 'x', []]) assert.equal(decide(x, settings, context).reason, 'invalid');
  for (const patch of [{ id: -1 }, { id: 0.5 }, { state: 'unknown' }]) assert.equal(d(patch).reason, 'invalid');
  assert.equal(d({ filename: 'a'.repeat(256) + '.zip' }).reason, 'invalid');
  assert.equal(d({ filename: 'x/'.repeat(17000) + 'a.zip' }).reason, 'invalid');
});
test('precedence pins security and browser-state checks before user policy', () => {
  assert.equal(d({ state: 'complete', byExtensionId: 'x' }, { mode: 'off' }).reason, 'complete');
  assert.equal(d({ byExtensionId: 'x', danger: 'dangerous' }).reason, 'extension');
  assert.equal(d({ danger: 'dangerous' }, { mode: 'off' }).reason, 'blocked');
  assert.equal(d({}, { mode: 'off' }, { bypass: true }).reason, 'disabled');
  assert.equal(d({}, {}, { bypass: true, appReady: false }).reason, 'bypass');
  assert.equal(d({}, {}, { appReady: false, method: 'POST' }).reason, 'unavailable');
  assert.equal(d({}, {}, { method: 'POST', correlated: false }).reason, 'method');
  assert.equal(d({}, {}, { correlated: false, credentialsSeen: true }).reason, 'correlation');
});
test('seeded arbitrary JSON inputs never throw or return a free-text reason', () => {
  let seed = 27;
  const rand = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  const values = [null, undefined, true, false, 1, -1, '', 'x', [], {}, { url: 7 }, { filename: {} }];
  for (let n = 0; n < 10000; n++) {
    const r = decide(values[rand() % values.length], values[rand() % values.length], values[rand() % values.length]);
    assert.match(r.reason, /^[a-z_]+$/);
    assert.ok(['keep', 'capture'].includes(r.action));
    const fields = ['url', 'filename', 'id', 'state', 'danger', 'byExtensionId'];
    const damaged = { ...item, [fields[rand() % fields.length]]: values[rand() % values.length] };
    assert.doesNotThrow(() => decide(damaged, settings, context));
  }
  assert.equal(decide(new Proxy({}, { get() { throw Error('PRIVATE'); } }), settings, context).action, 'keep');
});
