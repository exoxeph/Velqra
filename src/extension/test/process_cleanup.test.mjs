// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanupOwned } from './process_cleanup.mjs';
test('cleanup stops children first and retries EPERM with bounded backoff', async () => {
  const log = []; let tries = 0;
  const result = await cleanupOwned({ stop: async () => log.push('stop'), remove: async () => { log.push('remove'); if (++tries < 3) throw Object.assign(Error('busy'), { code: 'EPERM' }); }, delay: async ms => log.push(ms) });
  assert.deepEqual(result, []); assert.equal(log[0], 'stop'); assert.equal(tries, 3);
});
test('cleanup reports exhausted removal separately without replacing a case assertion', async () => {
  const assertion = Error('original case assertion'); let observed;
  try { throw assertion; } catch (e) { observed = e; }
  const result = await cleanupOwned({ stop: async () => {}, remove: async () => { throw Error('busy'); }, delay: async () => {} });
  assert.equal(result.length, 1); assert.equal(observed, assertion);
});
