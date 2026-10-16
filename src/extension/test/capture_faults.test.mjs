// SPDX-License-Identifier: GPL-3.0-only
// Usage: node --expose-gc --test test/capture_faults.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World, checkTrace } from './capture_harness.mjs';

import { matrices } from './capture_matrix.mjs';
import { CaptureAgent } from '../src/capture_agent.js';
import { Journal } from '../src/journal.js';
import { ITEM, SETTINGS, CONTEXT } from './capture_harness.mjs';

test('C5 checker RED: rejects unsafe independent traces', async () => {
  const r = await new World().run();
  const cancel = r.log.findIndex(e => e.kind === 'call' && e.type === 'cancel');
  for (const state of ['ReceiptStored', 'CancelIntentStored', 'CancelRequested']) {
    assert.throws(() => checkTrace(r.log.filter(e => !(e.kind === 'durable' && e.value.records[0].state === state))), /cancel before/);
  }
  assert.throws(() => checkTrace(r.log.filter(e => !(e.kind === 'reply' && e.type === 'begin_handoff'))), /Armed/);
  for (const field of ['session_id', 'request_id', 'generation']) {
    const wrong = structuredClone(r.log), e = wrong.find(e => e.kind === 'reply' && e.type === 'begin_handoff').envelope;
    e[field] = field === 'generation' ? 2 : 'wrong';
    assert.throws(() => checkTrace(wrong), /Armed/);
  }
  const afterAbort = structuredClone(r.log); afterAbort.splice(cancel, 0, { kind: 'send', type: 'abort' });
  assert.throws(() => checkTrace(afterAbort), /after abort/);
  assert.throws(() => checkTrace([...r.log, { kind: 'submit' }]), /double submit/);
  assert.throws(() => checkTrace([], { browser: { state: 'interrupted' }, core: 'aborted', notices: [], result: {} }), /lost download/);
  assert.throws(() => checkTrace([{ kind: 'submit' }]), /engine before commit/);
  const dangerous = structuredClone(r.log); dangerous.splice(cancel, 0, { kind: 'injected', fault: 'danger' });
  assert.throws(() => checkTrace(dangerous), /danger change/);
  const offline = structuredClone(r.log); offline.splice(cancel, 0, { kind: 'ready', value: false });
  assert.throws(() => checkTrace(offline), /not ready/);
});

test('C5 happy path is actually handed off once', async () => {
  const r = await new World().run();
  assert.equal(r.final.result.state, 'HandedOff'); assert.equal(r.submits, 1);
});

test('C5 exhaustive single faults, reachable kind pairs and seeded prefixes', async t => {
  const s = await matrices(); const errors = {};
  for (const f of s.failures) errors[f.error] = (errors[f.error] ?? 0) + 1;
  const { runs, ...brief } = s;
  t.diagnostic(JSON.stringify({ ...brief, failures: s.failures.length, errors }));
  assert.equal(s.failures.length, 0, JSON.stringify(s.failures.slice(0, 3)));
});

test('C5 missing planned injections fail loudly', async () => {
  await assert.rejects(new World([{ name: 'does.not.exist', occurrence: 1, kind: 'lost' }]).run(), /never fired/);
});

test('C5 regression: erased history after pause cannot silently become Returned', async () => {
  const r = await new World([{ name: 'browser.pause.after', occurrence: 1, kind: 'erase' }]).run();
  assert.equal(r.final.result.state, 'Returned');
  assert.equal(r.final.result.reason, 'browser_item_gone');
  assert.equal(r.final.result.held, false);
  // The exception requires an actual erase fault AND the explicit disposition.
  assert.throws(() => checkTrace(r.log.filter(e => e.fault !== 'erase'), r.final), /erase evidence/);
  const unpaused = structuredClone(r.final); unpaused.browser.paused = false;
  assert.throws(() => checkTrace(r.log.filter(e => e.fault !== 'erase'), unpaused), /erase evidence/);
  const silent = structuredClone(r.final); silent.result.reason = 'returned';
  assert.throws(() => checkTrace(r.log, silent), /lost download/);
});

test('C5 regression: a failed fallback resume must remain visibly held', async () => {
  const r = await new World([
    { name: 'write.ReceiptStored.before', occurrence: 1, kind: 'fail' },
    { name: 'browser.resume.before', occurrence: 1, kind: 'fail' },
  ]).run();
  assert.equal(r.final.result.held, true);
  assert.equal(r.final.result.reason, 'browser_unknown');
  assert.equal(r.final.notices.at(-1).reason, 'browser_unknown');
});

for (const state of ['Returning', 'Returned']) {
  for (const outcome of ['resumed', 'failed', 'gone', 'still_paused']) test(`C5 recovery ${state} browser_unknown: ${outcome}`, async () => {
    const w = new World(); w.newAgent();
    await w.agent.d.journal.write({ id: 7, requestId: 'matrix_7', state, receipt: null, session: null, generation: 1, createdAt: 10, updatedAt: 10, held: true, reason: 'browser_unknown' });
    w.browserItem.paused = true;
    if (outcome === 'gone') w.browserItem.erased = true;
    if (outcome === 'failed') w.agent.d.browser.resume = async () => { throw Error('resume'); };
    if (outcome === 'still_paused') w.agent.d.browser.resume = async () => {};
    const r = await w.drive(w.agent.recover()), record = r.records[0];
    const held = ['failed', 'still_paused'].includes(outcome);
    assert.equal(record.held, held);
    assert.equal(record.reason, held ? 'browser_unknown' : outcome === 'gone' ? 'browser_item_gone' : 'returned');
    assert.equal(w.notices.at(-1).held, held);
    assert.equal(w.notices.at(-1).reason, record.reason);
    if (!held) assert.equal(record.state, 'Returned');
    assert.equal(w.log.some(e => e.kind === 'call' && e.type === 'cancel'), false);
    assert.equal(w.submits, 0);
  });
}

for (const [name, result] of [['two items', [{ id: 7 }, { id: 7 }]], ['wrong id', [{ id: 8 }]], ['non-array', {}]]) {
  test(`C5 ambiguous fallback search: ${name} retains browser_unknown`, async () => {
    const w = new World(); w.newAgent();
    w.agent.d.browser.search = async () => structuredClone(result);
    const r = await w.drive(w.agent.capture(ITEM, SETTINGS, CONTEXT, { requestId: 'matrix_7' }));
    assert.equal(r.held, true); assert.equal(r.reason, 'browser_unknown');
    assert.equal(w.agent.d.journal.get(7).held, true);
    assert.equal(w.notices.at(-1).reason, 'browser_unknown');
    assert.equal(w.browserItem.paused, false); // fresh admission search refused before pause
    assert.equal(w.submits, 0);
  });
  test(`C5 ambiguous resume confirmation: ${name} retains browser_unknown`, async () => {
    const w = new World(); w.newAgent();
    w.browserItem.paused = true;
    await w.agent.d.journal.write({ id: 7, requestId: 'matrix_7', state: 'Returning', receipt: null, session: null, generation: 1, createdAt: 10, updatedAt: 10, held: true, reason: 'browser_unknown' });
    let searches = 0;
    w.agent.d.browser.search = async () => ++searches < 3 ? [{ ...w.browserItem }] : structuredClone(result);
    const r = await w.drive(w.agent.recover());
    assert.equal(w.browserItem.paused, false);
    assert.equal(r.records[0].held, true);
    assert.equal(r.records[0].reason, 'browser_unknown');
  });
}

test('C5 replay is deterministic and an applied-but-lost cancel remains ambiguous', async () => {
  const plan = [{ name: 'browser.cancel.after', occurrence: 1, kind: 'lost' }];
  const a = await new World(plan).run(), b = await new World(plan).run();
  assert.deepEqual(a, b); assert.equal(a.final.result.state, 'ReconcileRequired'); assert.equal(a.submits, 0);
});

test('C5 admission is bounded even before a storage read settles', async () => {
  let release;
  const barrier = new Promise(r => { release = r; });
  const journal = new Journal({ storage: { get: () => barrier, set: async () => {} } });
  const agent = new CaptureAgent({ journal, bridge: { state: 'ready', request: async () => { throw Error('offline'); } },
    browser: { search: async () => [], resume: async () => {}, pause: async () => {} } });
  const running = [];
  try {
    for (let id = 0; id < 40; id++) running.push(agent.capture({ ...ITEM, id }, SETTINGS, CONTEXT, { requestId: `capacity_${id}` }));
    assert.equal(agent.status().active, 16);
  } finally { release(undefined); await Promise.all(running); }
});

test('C5 journal cannot clear a five-write failure hold by trying another write', async () => {
  let fail = true, writes = 0;
  const journal = new Journal({ storage: { get: async () => undefined, set: async () => { writes++; if (fail) throw Error('disk'); } } });
  const record = { id: 7, requestId: 'held', state: 'Seen', receipt: null, session: null, generation: 1, createdAt: 10, updatedAt: 10 };
  for (let i = 0; i < 5; i++) await assert.rejects(journal.write(record));
  assert.ok(journal.held); fail = false;
  await assert.rejects(journal.write(record), /hold/); assert.equal(writes, 5);
});
