// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Journal } from '../src/journal.js';

function storage() {
  let value;
  return { get: async () => structuredClone(value), set: async (_, v) => { value = structuredClone(v); } };
}
const record = (id, state = 'Seen') => ({ id, requestId: `d-${id}`, state, receipt: null, session: null, generation: 1, createdAt: 1, updatedAt: 1 });
test('writes are durable before exposed, survive a new instance, carry no URL', async () => {
  const s = storage(); const j = new Journal({ storage: s });
  await j.write(record(1));
  const k = new Journal({ storage: s }); await k.load();
  assert.equal(k.get(1).state, 'Seen');
  const copy = k.get(1); copy.state = 'HandedOff';
  assert.equal(k.get(1).state, 'Seen');
  await assert.rejects(j.write({ ...record(2), url: 'SECRET' }), /record/);
});
test('bounded records evict only resolved records; reconciliation is never terminal', async () => {
  const j = new Journal({ storage: storage(), maxRecords: 2 });
  await j.write(record(1, 'Returned')); await j.write(record(2, 'ReconcileRequired'));
  await j.write(record(3));
  assert.equal(j.get(1), undefined); assert.equal(j.list().length, 2);
  await assert.rejects(j.write(record(4)), /full/);
  assert.equal(j.get(2).state, 'ReconcileRequired');
});
test('failed writes never advance cached state; repeated failure is visible hold', async () => {
  const s = storage(); const j = new Journal({ storage: s }); await j.write(record(1));
  s.set = async () => { throw Error('SECRET'); };
  for (let n = 0; n < 5; n++) await assert.rejects(j.write(record(1, 'Paused')), /^Error: storage$/);
  assert.equal(j.get(1).state, 'Seen'); assert.equal(j.held, true);
});
test('a hung write poisons the journal; late completion cannot overlap a newer write', async () => {
  let release; const s = storage(); const j = new Journal({ storage: s, timeoutMs: 10 });
  s.set = () => new Promise(r => { release = r; });
  await assert.rejects(j.write(record(1)), /storage_timeout/);
  assert.equal(j.held, true);
  await assert.rejects(j.write(record(2)), /hold/);
  release();
});
test('corrupt and oversized snapshots fail closed, never reset unresolved history', async () => {
  for (const value of [{ version: 2, records: [] }, { version: 1, records: [record(1, 'garbage')] }, 'x'.repeat(300000)]) {
    const j = new Journal({ storage: { get: async () => value, set: async () => {} } });
    await assert.rejects(j.load()); assert.equal(j.held, true);
  }
});
test('terminal tombstones younger than thirty days cannot be evicted', async () => {
  const j = new Journal({ storage: storage(), maxRecords: 1, now: () => 100 });
  await j.write(record(1, 'Returned'));
  await assert.rejects(j.write(record(2)), /full/);
});
test('record validation rejects wrong identities and secret-bearing extra fields', async () => {
  const j = new Journal({ storage: storage() });
  for (const patch of [{ id: -1 }, { id: 1.5 }, { requestId: '' }, { requestId: 'bad?' }, { generation: 2 },
    { createdAt: NaN }, { updatedAt: Infinity }, { session: 'x' }, { receipt: {} }, { held: 1 }, { reason: 'PRIVATE text' },
    { state: 'CancelConfirmed' }, { state: 'HandedOff' }, { context: 'PRIVATE' },
    { receipt: { task_id: 0, fingerprint: 'a'.repeat(64) } }, { receipt: { task_id: 1, fingerprint: 'z'.repeat(64) } },
    { receipt: { task_id: 1, fingerprint: 'a'.repeat(64), context: 'PRIVATE' } }]) {
    await assert.rejects(j.write({ ...record(1), ...patch }), /record/);
  }
});
test('duplicate identities, terminal resurrection and oversized writes fail closed', async () => {
  const j = new Journal({ storage: storage() });
  await j.write(record(1, 'Returned'));
  await assert.rejects(j.write(record(1, 'Seen')), /record/);
  await assert.rejects(j.write({ ...record(1), requestId: 'different' }), /record/);
  await assert.rejects(j.write({ ...record(2), requestId: 'd-1' }), /record/);
  const small = new Journal({ storage: storage(), maxBytes: 10 });
  await assert.rejects(small.write(record(1)), /full/);
});
test('simultaneous writers are serialised: every write lands and none is lost', async () => {
  const s = storage(); const slow = s.set;
  s.set = async (k, v) => { await new Promise(r => setTimeout(r, 5)); return slow(k, v); };
  const j = new Journal({ storage: s });
  const results = await Promise.allSettled([1, 2, 3, 4, 5].map(id => j.write(record(id))));
  assert.deepEqual(results.map(r => r.status), Array(5).fill('fulfilled'));
  assert.deepEqual(j.list().map(r => r.id).sort(), [1, 2, 3, 4, 5]);
  const k = new Journal({ storage: s }); await k.load();
  assert.equal(k.list().length, 5, 'what is in storage matches what the journal says');
  // updates to one record from different callers apply in arrival order
  await Promise.all([j.write(record(1, 'Paused')), j.write(record(1, 'PrepareSent'))]);
  assert.equal(j.get(1).state, 'PrepareSent');
});
test('a queued writer sees the result of the one before it, not a stale snapshot', async () => {
  const s = storage(); const j = new Journal({ storage: s, maxRecords: 2 });
  await Promise.all([j.write(record(1)), j.write(record(2))]);
  await assert.rejects(j.write(record(3)), /full/);
  assert.equal(j.list().length, 2);
});
test('the queue is bounded: beyond sixteen waiting writes the rest are refused as busy', async () => {
  const s = storage(); const j = new Journal({ storage: s }); await j.load();
  let release; const gate = new Promise(r => { release = r; });
  s.set = async (k, v) => { await gate; };
  const writers = Array.from({ length: 20 }, (_, i) => j.write(record(i + 1)).then(() => 'ok', e => e.message));
  await new Promise(r => setImmediate(r));
  release();
  const out = await Promise.all(writers);
  assert.equal(out.filter(x => x === 'ok').length, 16);
  assert.equal(out.filter(x => x === 'busy').length, 4);
});
test('a failed write does not stop the writers queued behind it', async () => {
  const s = storage(); const real = s.set; let n = 0;
  s.set = async (k, v) => { if (++n === 1) throw Error('boom'); return real(k, v); };
  const j = new Journal({ storage: s });
  const out = await Promise.allSettled([j.write(record(1)), j.write(record(2))]);
  assert.deepEqual(out.map(r => r.status), ['rejected', 'fulfilled']);
  assert.equal(j.get(1), undefined, 'a failed write is not exposed');
  assert.equal(j.get(2).state, 'Seen');
});
test('a storage timeout poisons the journal and the writers queued behind it are refused', async () => {
  const s = storage(); s.set = () => new Promise(() => {});
  const j = new Journal({ storage: s, timeoutMs: 5 });
  const out = await Promise.allSettled([j.write(record(1)), j.write(record(2)), j.write(record(3))]);
  assert.match(String(out[0].reason), /storage_timeout/);
  assert.match(String(out[1].reason), /hold/);
  assert.match(String(out[2].reason), /hold/);
  assert.equal(j.held, true);
});
test('load enforces snapshot count and bytes even when every record is valid', async () => {
  for (const config of [{ maxRecords: 1 }, { maxBytes: 10 }]) {
    const j = new Journal({ storage: { get: async () => ({ version: 1, records: [record(1), record(2)] }), set: async () => {} }, ...config });
    await assert.rejects(j.load(), /corrupt/); assert.equal(j.held, true);
  }
});
test('a timed-out load cannot pile up more stuck reads', async () => {
  let reads = 0;
  const j = new Journal({ storage: { get: () => { reads++; return new Promise(() => {}); }, set: async () => {} }, timeoutMs: 5 });
  await assert.rejects(j.load(), /storage_timeout/);
  await assert.rejects(j.load(), /hold/); assert.equal(reads, 1);
});
