// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CaptureAgent } from '../src/capture_agent.js';
import { Journal, STATES } from '../src/journal.js';

const SID = '1'.repeat(32), FP = 'a'.repeat(64);
const receipt = { task_id: 1, fingerprint: FP };
const item = { id: 7, url: 'https://files.test/a.zip?secret=URL_SENTINEL', filename: 'a.zip', state: 'in_progress', danger: 'safe' };
const settings = { mode: 'on', extensions: ['zip'], allowed_sites: [], excluded_sites: [] };
const context = { method: 'GET', correlated: true, credentialsSeen: false, appReady: true };
const post = ['CancelRequested', 'CancelConfirmed', 'CommitSent', 'ReconcileRequired'];

// Prefix checker is outside the agent, runs AFTER its promise settles (so its
// assertions cannot be swallowed by the agent's error handling).
function checkPrefixes(log) {
  const seen = new Set();
  for (const event of log) {
    if (event === 'cancel') {
      for (const required of ['write:ReceiptStored', 'reply:armed:armed', 'write:CancelIntentStored', 'write:CancelRequested']) assert.ok(seen.has(required), `cancel before ${required}`);
      assert.ok(!seen.has('send:abort'), 'cancel after abort');
    }
    if (event === 'send:commit') {
      assert.ok(seen.has('cancel'), 'commit before cancel');
      assert.ok(seen.has('write:CancelConfirmed'), 'commit before durable cancel evidence');
      assert.ok(!seen.has('send:abort'), 'commit after abort');
    }
    seen.add(event);
  }
}
test('independent checker rejects broken prefixes, even when a later event would hide them', () => {
  assert.throws(() => checkPrefixes(['cancel', 'write:ReceiptStored']));
  assert.throws(() => checkPrefixes(['send:commit', 'cancel', 'write:CancelConfirmed']));
  assert.throws(() => checkPrefixes(['write:ReceiptStored', 'reply:armed:armed', 'write:CancelIntentStored', 'write:CancelRequested', 'send:abort', 'cancel']));
});

// All boundary evidence is kept OUTSIDE the implementation under test.
function fixture(options = {}) {
  const log = []; let value; let core = 'none'; let now = 10;
  const browserItem = { ...item, paused: false };
  const storage = {
    async get() { return structuredClone(value); },
    async set(_, v) {
      const state = v.records.find(r => r.id === 7)?.state;
      await options.beforeWrite?.(state, f);
      if (options.failWrite === state || options.failAll) { log.push(`fail:${state}`); throw Error('PRIVATE_STORAGE_TEXT'); }
      value = structuredClone(v); log.push(`write:${state}`);
      await options.afterWrite?.(state, f);
    },
  };
  const browser = {
    async pause() { log.push('pause'); await options.beforePause?.(f); browserItem.paused = true; await options.afterPause?.(f); },
    async resume() { log.push('resume'); browserItem.paused = false; },
    async cancel() {
      log.push('cancel');
      assert.equal(core, 'armed', 'external checker: cancel requires durable ARMED');
      const r = value.records.find(r => r.id === 7);
      assert.equal(r.state, 'CancelRequested', 'external checker: cancel-requested must be durable');
      assert.ok(log.indexOf('write:ReceiptStored') < log.indexOf('write:CancelIntentStored'));
      assert.ok(log.indexOf('write:CancelIntentStored') < log.indexOf('write:CancelRequested'));
      assert.equal(bridge.state, 'ready');
      await options.onCancel?.(f);
      if (options.cancelUnknown) throw Error('PRIVATE_BROWSER_TEXT');
      if (browserItem.state !== 'complete') { browserItem.state = 'interrupted'; browserItem.error = 'USER_CANCELED'; }
    },
    async search() { log.push('search'); await options.onSearch?.(f); return browserItem.erased ? [] : [{ ...browserItem }]; },
  };
  const bridge = {
    state: 'ready',
    async request(body, opts) {
      log.push(`send:${body.type}`);
      await options.beforeReply?.(body.type, f, body);
      let type; let payload;
      switch (body.type) {
        case 'health': type = 'health_reply'; payload = { transfer_capable: true }; break;
        case 'prepare': core = 'prepared'; type = 'prepared'; payload = { ...receipt, state: core }; break;
        case 'begin_handoff': core = 'armed'; type = 'armed'; payload = { ...receipt, state: core }; break;
        case 'status': type = 'status_reply'; payload = { ...receipt, state: core }; break;
        case 'commit':
          assert.ok(['armed', 'committed'].includes(core));
          assert.equal(body.payload.cancel, 'confirmed');
          assert.ok(['CancelConfirmed', 'CommitSent'].some(s => log.includes(`write:${s}`)) || options.recovery);
          core = 'committed'; type = 'committed'; payload = { ...receipt, state: core }; break;
        case 'abort': core = 'aborted'; type = 'aborted'; payload = { ...(body.payload.receipt ?? { task_id: 1, fingerprint: '' }), state: core }; break;
        case 'reconcile':
          assert.equal(body.payload.owner, 'unknown');
          if (core !== 'committed') core = 'ownership_unknown';
          type = 'reconciled'; payload = { ...receipt, state: core }; break;
        default: throw Error('unexpected');
      }
      let e = { version: 1, generation: 1, message_id: 'reply', request_id: opts.requestId, session_id: SID, body: { type, payload } };
      e = options.reply?.(body.type, e, f) ?? e;
      log.push(`reply:${e.body.type}:${e.body.payload.state ?? ''}`);
      return e;
    },
  };
  const journal = new Journal({ storage, timeoutMs: 20 });
  const f = { log, storage, browser, bridge, journal, browserItem, get value() { return value; }, set value(v) { value = v; }, set core(v) { core = v; }, get core() { return core; }, advance(ms) { now += ms; } };
  f.agent = new CaptureAgent({ browser, bridge, journal, now: () => now, stepTimeoutMs: 30, preCancelMs: 5000 });
  f.run = async () => { const r = await f.agent.capture(item, settings, context, { requestId: 'capture-7' }); checkPrefixes(log); return r; };
  return f;
}

test('happy path; independent prefix ledger and no URL/context in journal', async () => {
  const f = fixture(); const r = await f.run();
  assert.equal(r.state, 'HandedOff'); assert.equal(f.core, 'committed');
  assert.equal(f.log.filter(x => x === 'cancel').length, 1);
  assert.ok(f.log.indexOf('write:CancelConfirmed') < f.log.indexOf('send:commit'));
  assert.ok(!JSON.stringify(f.value).includes('URL_SENTINEL'));
});

for (const state of ['Seen', 'Paused', 'PrepareSent', 'ReceiptStored', 'CancelIntentStored', 'CancelRequested', 'CancelConfirmed', 'CommitSent', 'HandedOff']) {
  test(`storage failure at ${state}`, async () => {
    const f = fixture({ failWrite: state }); const r = await f.run();
    assert.ok(f.log.includes(`fail:${state}`));
    if (['CancelConfirmed', 'CommitSent', 'HandedOff'].includes(state)) {
      assert.equal(r.state, 'ReconcileRequired'); assert.ok(!f.log.includes('resume'));
    } else {
      assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false);
      if (state !== 'Seen') assert.ok(f.log.includes('resume'));
    }
  });
}
for (const type of ['prepared', 'armed', 'committed']) {
  for (const field of ['receipt', 'session', 'request', 'generation', 'version', 'kind', 'state']) {
    test(`wrong ${field} on ${type} cannot advance ownership`, async () => {
      const f = fixture({ reply(_, e) {
        if (e.body.type !== type) return e;
        if (field === 'receipt') e.body.payload.fingerprint = 'b'.repeat(64);
        if (field === 'session') e.session_id = '2'.repeat(32);
        if (field === 'request') e.request_id = 'other';
        if (field === 'generation') e.generation = 2;
        if (field === 'version') e.version = 2;
        if (field === 'kind') e.body.type = 'aborted';
        if (field === 'state') e.body.payload.state = 'aborted';
        return e;
      } });
      // First prepared fingerprint has no independent expected hash: the core computes it.
      if (type === 'prepared' && field === 'receipt') {
        // Its later Armed receipt disagrees, so cancellation still must not occur.
        await f.run(); assert.ok(!f.log.includes('cancel')); return;
      }
      const r = await f.run();
      if (type === 'committed') {
        // A separate correctly identified reconciliation can prove the already committed task.
        assert.equal(r.state, 'HandedOff'); assert.ok(f.log.includes('send:reconcile')); assert.ok(!f.log.includes('resume'));
      }
      else assert.ok(!f.log.includes('cancel'));
    });
  }
}

for (const state of STATES) test(`recovery from ${state}`, async () => {
  const f = fixture({ recovery: true });
  const hasReceipt = !['Seen', 'Paused', 'PrepareSent'].includes(state);
  const r = { id: 7, requestId: 'capture-7', generation: 1, state, receipt: hasReceipt ? receipt : null, session: hasReceipt ? SID : null, createdAt: 1, updatedAt: 1 };
  f.value = { version: 1, records: [r] };
  f.core = ['CommitSent', 'HandedOff'].includes(state) ? 'committed' : hasReceipt ? 'armed' : 'none';
  if (post.includes(state)) f.browserItem.state = 'interrupted';
  await f.agent.recover();
  const result = f.journal.get(7);
  const expected = ['CancelConfirmed', 'CommitSent', 'HandedOff'].includes(state) ? 'HandedOff' : ['CancelRequested', 'ReconcileRequired'].includes(state) ? 'ReconcileRequired' : 'Returned';
  assert.equal(result.state, expected); assert.ok(!f.log.includes('cancel'));
});
test('a crash after the durable cancel marker but before any cancel call: the download is returned, never cancelled', async () => {
  const f = fixture({ recovery: true });
  f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state: 'CancelRequested', receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.core = 'armed'; // the browser item is still in progress and paused: nothing was cancelled
  f.browserItem.paused = true;
  await f.agent.recover();
  assert.equal(f.journal.get(7).state, 'Returned');
  assert.ok(!f.log.includes('cancel'), 'recovery must never issue a browser cancel');
  assert.ok(f.log.includes('resume'), 'the browser download must be resumed');
  assert.ok(f.log.includes('send:abort') && !f.log.includes('send:commit'));
});
test('erased history after cancel requested reconciles; generic USER_CANCELED is not proof', async () => {
  const f = fixture({ recovery: true });
  f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state: 'CancelRequested', receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.core = 'armed'; f.browserItem.erased = true;
  await f.agent.recover();
  assert.equal(f.journal.get(7).state, 'ReconcileRequired'); assert.equal(f.core, 'ownership_unknown');
  assert.ok(!f.log.includes('send:commit'));
});
test('unknown cancel outcome reconciles and never resumes', async () => {
  const f = fixture({ cancelUnknown: true }); const r = await f.run();
  assert.equal(r.state, 'ReconcileRequired'); assert.ok(!f.log.includes('resume'));
});
test('user cancel before cancel gate aborts without replay', async () => {
  const f = fixture({ beforeReply(type, f) { if (type === 'begin_handoff') f.agent.userCancel(7); } });
  const r = await f.run(); assert.equal(r.state, 'Returned');
  assert.ok(!f.log.includes('cancel')); assert.ok(!f.log.includes('resume')); assert.equal(f.core, 'aborted');
});
test('user cancel while our cancellation is in flight is ambiguity, never commit', async () => {
  const f = fixture({ onCancel(f) { f.agent.userCancel(7); } });
  const r = await f.run(); assert.equal(r.state, 'ReconcileRequired'); assert.ok(!f.log.includes('send:commit'));
});
test('browser completion racing cancellation stays with browser and aborts intent', async () => {
  const f = fixture({ onCancel(f) { f.browserItem.state = 'complete'; } });
  const r = await f.run(); assert.equal(r.state, 'Returned'); assert.equal(f.core, 'aborted');
});
test('pre-cancel deadline fails back, including time spent journaling', async () => {
  const f = fixture({ afterWrite(state, f) { if (state === 'CancelRequested') f.advance(5001); } });
  const r = await f.run(); assert.ok(!f.log.includes('cancel')); assert.equal(r.state, 'Returned');
});
for (const state of ['Seen', 'Paused', 'PrepareSent', 'ReceiptStored', 'CancelIntentStored', 'CancelRequested', 'CancelConfirmed', 'CommitSent', 'HandedOff']) {
  test(`bridge leaves ready after write ${state}`, async () => {
    const f = fixture({ afterWrite(s, f) { if (s === state) f.bridge.state = 'closed'; } });
    const r = await f.run();
    if (['CancelConfirmed', 'CommitSent', 'HandedOff'].includes(state)) assert.ok(['ReconcileRequired', 'HandedOff'].includes(r.state));
    else {
      assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false);
      if (state !== 'Seen') assert.ok(f.log.includes('resume'));
    }
  });
}
test('duplicate capture is fenced by persisted record; never cancel twice', async () => {
  const f = fixture(); const first = await f.run(); const length = f.log.length; const second = await f.run();
  assert.deepEqual(second, first, 'duplicate capture returns its existing disposition');
  assert.equal(f.log.length, length, 'completed identity has no further side effects');
  assert.equal(f.log.filter(x => x === 'cancel').length, 1);
});
test('all storage failures surface hold without browser cancellation', async () => {
  const f = fixture({ failAll: true }); const r = await f.run();
  assert.equal(r.held, true); assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false);
});
test('hung journal before cancel returns browser and leaves a visible hold', async () => {
  const f = fixture({ beforeWrite(state) { if (state === 'CancelRequested') return new Promise(() => {}); } });
  const r = await f.run(); assert.equal(r.held, true); assert.ok(!f.log.includes('cancel')); assert.ok(f.log.includes('resume'));
});

for (const type of ['health', 'prepare', 'begin_handoff', 'status', 'commit']) test(`disconnect during ${type} reply`, async () => {
  const f = fixture({ reply(t, e, f) { if (t === type) f.bridge.state = 'closed'; return e; } });
  const r = await f.run();
  if (type !== 'commit') { assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false); if (type !== 'health') assert.ok(f.log.includes('resume')); }
  else assert.equal(r.state, 'ReconcileRequired');
});
for (const when of ['pause', 'search', 'cancel']) test(`disconnect after browser ${when}`, async () => {
  let searches = 0;
  const f = fixture({
    afterPause(f) { if (when === 'pause') f.bridge.state = 'closed'; },
    onSearch(f) { if (when === 'search' && ++searches === 2) f.bridge.state = 'closed'; },
    onCancel(f) { if (when === 'cancel') f.bridge.state = 'closed'; },
  });
  const r = await f.run();
  if (when === 'cancel') assert.equal(r.state, 'ReconcileRequired');
  else assert.ok(!f.log.includes('cancel'));
});
test('same-ready reconnect during a journal await is caught by final session proof', async () => {
  const f = fixture({ reply(t, e) { if (t === 'status') e.session_id = '3'.repeat(32); return e; } });
  await f.run(); assert.ok(!f.log.includes('cancel'));
});
test('a delayed stale Armed reply cannot beat an abort fence', async () => {
  let release;
  const f = fixture({ beforeReply(t) { if (t === 'begin_handoff') return new Promise(r => { release = r; }); } });
  const r = await f.run();
  assert.equal(r.state, 'Returned'); assert.equal(f.core, 'aborted');
  release(); await new Promise(r => setImmediate(r));
  assert.ok(!f.log.includes('cancel')); assert.equal(f.journal.get(7).state, 'Returned');
});
for (const bad of ['kind', 'receipt', 'session', 'state']) test(`invalid abort acknowledgement ${bad} retains unresolved journal`, async () => {
  const f = fixture({ failWrite: 'ReceiptStored', reply(t, e) {
    if (t === 'abort') {
      if (bad === 'kind') e.body.type = 'committed';
      if (bad === 'receipt') e.body.payload.fingerprint = 'b'.repeat(64);
      if (bad === 'session') e.session_id = '2'.repeat(32);
      if (bad === 'state') e.body.payload.state = 'committed';
    }
    return e;
  } });
  const r = await f.run(); assert.equal(r.state, 'Returning'); assert.equal(r.held, true); assert.ok(!f.log.includes('cancel'));
});
for (const bad of ['kind', 'receipt', 'session', 'state']) test(`invalid reconciliation ${bad} remains held`, async () => {
  const f = fixture({ cancelUnknown: true, reply(t, e) {
    if (t === 'reconcile') {
      if (bad === 'kind') e.body.type = 'committed';
      if (bad === 'receipt') e.body.payload.fingerprint = 'b'.repeat(64);
      if (bad === 'session') e.session_id = '2'.repeat(32);
      if (bad === 'state') e.body.payload.state = 'prepared';
    }
    return e;
  } });
  const r = await f.run(); assert.equal(r.state, 'ReconcileRequired'); assert.equal(r.held, true);
});
test('Returning and Returned writes can fail without reopening cancellation', async () => {
  for (const failWrite of ['Returning', 'Returned']) {
    const f = fixture({ failWrite, beforeReply(t, f) { if (t === 'begin_handoff') f.agent.userCancel(7); } });
    const r = await f.run(); assert.ok(f.log.includes(`fail:${failWrite}`)); assert.ok(!f.log.includes('cancel'));
    if (failWrite === 'Returned') assert.equal(r.held, true);
  }
});
test('failed reconcile journaling still surfaces ambiguity to the core and caller', async () => {
  const f = fixture({ failWrite: 'ReconcileRequired', cancelUnknown: true }); const r = await f.run();
  assert.ok(f.log.includes('fail:ReconcileRequired')); assert.equal(r.held, true); assert.equal(f.core, 'ownership_unknown');
});
test('origin-only Referer, UA allowlist and basename are the only prepare context', async () => {
  let sent;
  const f = fixture({ beforeReply(t, _, body) { if (t === 'prepare') sent = body.payload; } });
  f.browserItem.filename = 'C:\\Downloads\\a.zip';
  await f.agent.capture({ ...item, filename: 'C:\\Downloads\\a.zip' }, settings,
    { ...context, referer: 'https://page.test/private/TOKEN?secret=TOKEN', user_agent: 'Test Browser', Cookie: 'TOKEN', Authorization: 'TOKEN' }, { requestId: 'capture-7' });
  assert.equal(sent.filename, 'a.zip');
  assert.deepEqual(JSON.parse(sent.context), { referer: 'https://page.test/', user_agent: 'Test Browser' });
});
test('late pause completion cannot leave the returned browser item paused', async () => {
  let release;
  const f = fixture({ beforePause() { return new Promise(r => { release = r; }); } });
  await f.run(); release(); await new Promise(r => setTimeout(r, 10));
  assert.equal(f.browserItem.paused, false); assert.ok(!f.log.includes('cancel'));
});

test('late pause cleanup persists a failed resume hold and recovery retries it', async () => {
  let release;
  const f = fixture({ beforePause() { return new Promise(r => { release = r; }); } });
  await f.run();
  const resume = f.browser.resume;
  f.browser.resume = async () => { throw Error('resume'); };
  release(); await new Promise(r => setTimeout(r, 10));
  assert.equal(f.browserItem.paused, true);
  assert.equal(f.journal.get(7).held, true);
  assert.equal(f.journal.get(7).reason, 'browser_unknown');
  f.browser.resume = resume;
  await f.agent.recover();
  assert.equal(f.browserItem.paused, false);
  assert.equal(f.journal.get(7).held, false);
  assert.equal(f.journal.get(7).reason, 'returned');
  assert.ok(!f.log.includes('cancel'));
});

test('late pause cleanup records definitive removal', async () => {
  let release;
  const f = fixture({ beforePause() { return new Promise(r => { release = r; }); } });
  await f.run(); f.browserItem.erased = true;
  release(); await new Promise(r => setTimeout(r, 10));
  assert.equal(f.journal.get(7).reason, 'browser_item_gone');
  assert.equal(f.journal.get(7).held, false);
});

test('late failed cleanup while abort ACK is pending cannot lose its hold', async () => {
  let releasePause, releaseAbort;
  const f = fixture({ beforePause() { return new Promise(r => { releasePause = r; }); },
    beforeReply(type) { if (type === 'abort') return new Promise(r => { releaseAbort = r; }); } });
  const running = f.run();
  while (!releaseAbort) await new Promise(r => setTimeout(r, 1));
  f.browser.resume = async () => { throw Error('resume'); };
  releasePause(); await new Promise(r => setImmediate(r));
  releaseAbort();
  const r = await running;
  assert.equal(r.held, true); assert.equal(r.reason, 'browser_unknown');
  assert.equal(f.journal.get(7).held, true);
});
test('a lost cancel result that later settles cannot trigger late commit', async () => {
  let release;
  const f = fixture({ onCancel() { return new Promise(r => { release = r; }); } });
  const r = await f.run(); assert.equal(r.state, 'ReconcileRequired');
  release(); await new Promise(r => setImmediate(r));
  assert.ok(!f.log.includes('send:commit')); assert.ok(!f.log.includes('resume'));
});
test('recovery accepts a fresh authenticated session only after checking core receipt', async () => {
  const f = fixture({ recovery: true, reply(_, e) { e.session_id = '4'.repeat(32); return e; } });
  f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state: 'CancelConfirmed', receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.browserItem.state = 'interrupted'; f.core = 'armed';
  await f.agent.recover(); assert.equal(f.journal.get(7).state, 'HandedOff');
  assert.equal(f.journal.get(7).session, '4'.repeat(32)); assert.ok(!f.log.includes('cancel'));
});
for (const state of ['Seen', 'Paused', 'PrepareSent', 'ReceiptStored', 'Returning']) test(`recovery of ${state} can finish abort on a new bridge session`, async () => {
  const f = fixture({ recovery: true, reply(_, e) { e.session_id = '5'.repeat(32); return e; } });
  f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state, receipt: ['ReceiptStored', 'Returning'].includes(state) ? receipt : null, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.core = 'prepared';
  await f.agent.recover(); assert.equal(f.journal.get(7).state, 'Returned');
});
test('wrong receipt on recovery status cannot commit or silently resolve ambiguity', async () => {
  const f = fixture({ recovery: true, reply(t, e) { if (t === 'status') e.body.payload.fingerprint = 'b'.repeat(64); return e; } });
  f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state: 'CancelConfirmed', receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.browserItem.state = 'interrupted'; f.core = 'armed';
  await f.agent.recover(); assert.ok(!f.log.includes('send:commit')); assert.equal(f.journal.get(7).state, 'ReconcileRequired');
});
test('a reused request ID cannot abort another download or overwrite its journal', async () => {
  const f = fixture();
  f.value = { version: 1, records: [{ id: 8, requestId: 'capture-7', state: 'ReceiptStored', receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
  f.core = 'prepared';
  const r = await f.run();
  assert.ok(!f.log.includes('send:abort')); assert.equal(f.core, 'prepared'); assert.equal(r.action, 'keep');
});
test('a corrupt journal never authorizes an abort for an unallocated key', async () => {
  const f = fixture(); f.value = { version: 99, records: [] }; f.core = 'prepared';
  const r = await f.run(); assert.equal(r.held, true); assert.equal(f.core, 'prepared'); assert.ok(!f.log.includes('send:abort'));
});
test('cancel API success with an erased or unconfirmed item is not cancellation proof', async () => {
  for (const erased of [true, false]) {
    let searches = 0;
    const f = fixture({ onSearch(f) { if (++searches === 4) { f.browserItem.erased = erased; f.browserItem.error = 'NETWORK_FAILED'; } } });
    const r = await f.run(); assert.equal(r.state, 'ReconcileRequired'); assert.ok(!f.log.includes('send:commit'));
  }
});
test('a changed durable journal at the final boundary closes the cancel gate', async () => {
  const f = fixture({ async beforeReply(t, f) { if (t === 'status') await f.journal.write({ ...f.journal.get(7), state: 'Returning' }); } });
  await f.run(); assert.ok(!f.log.includes('cancel'));
});
test('pause must be observed before Prepare; mismatched search IDs never authorize capture', async () => {
  const f = fixture({ afterPause(f) { f.browserItem.paused = false; } });
  await f.run(); assert.ok(!f.log.includes('send:prepare')); assert.ok(!f.log.includes('cancel'));
  const g = fixture();
  g.browser.search = async () => [{ id: 999, state: 'in_progress', paused: true }];
  await g.run(); assert.ok(!g.log.includes('send:prepare')); assert.ok(!g.log.includes('cancel'));
});
test('disconnect after pause stops forward journal progress immediately', async () => {
  const f = fixture({ afterPause(f) { f.bridge.state = 'closed'; } });
  await f.run(); assert.ok(!f.log.includes('write:Paused')); assert.ok(!f.log.includes('cancel'));
});
test('a pause lost just before cancel closes the final browser-state gate', async () => {
  let searches = 0;
  const f = fixture({ onSearch(f) { if (++searches === 2) f.browserItem.paused = false; } });
  await f.run(); assert.ok(!f.log.includes('cancel'));
});
test('terminal recovery has no browser or core side effects', async () => {
  for (const state of ['Returned', 'HandedOff']) {
    const f = fixture();
    f.value = { version: 1, records: [{ id: 7, requestId: 'capture-7', state, receipt, session: SID, generation: 1, createdAt: 1, updatedAt: 1 }] };
    await f.agent.recover(); assert.deepEqual(f.log, []);
  }
});
for (const target of ['begin_handoff', 'status', 'commit']) test(`wrong task ID on ${target} cannot authorize ownership`, async () => {
  const f = fixture({ reply(t, e) { if (t === target) e.body.payload.task_id = 99; return e; } });
  await f.run();
  if (target === 'commit') assert.ok(f.log.includes('send:reconcile'));
  else assert.ok(!f.log.includes('cancel'));
});
for (const kind of ['stale_generation', 'payload_mismatch', 'wrong_state', 'not_armed', 'aborted', 'no_destination', 'storage', 'overloaded', 'unauthenticated', 'url_userinfo']) test(`core refusal ${kind} retains browser, never echoes detail`, async () => {
  const f = fixture({ reply(t, e) { if (t === 'prepare') e.body = { type: 'error', payload: { kind, detail: 'PRIVATE_DETAIL_SENTINEL' } }; return e; } });
  const r = await f.run(); assert.ok(!f.log.includes('cancel')); assert.ok(f.log.includes('resume'));
  assert.ok(!JSON.stringify([r, f.agent.status()]).includes('PRIVATE_DETAIL_SENTINEL'));
});
test('bridge unavailable at entry makes no browser or core call', async () => {
  const f = fixture(); f.bridge.state = 'closed';
  assert.deepEqual(await f.run(), { action: 'keep', reason: 'unavailable' }); assert.deepEqual(f.log, []);
});
test('caller mutation across awaits cannot change browser or wire identity', async () => {
  const original = { ...item };
  let sent;
  const f = fixture({ afterWrite(state) { if (state === 'Seen') { original.id = 999; original.url = 'https://evil.test/a.zip'; } }, beforeReply(t, _, body) { if (t === 'prepare') sent = body.payload; } });
  const r = await f.agent.capture(original, settings, context, { requestId: 'capture-7' });
  assert.equal(r.id, 7); assert.equal(r.state, 'HandedOff'); assert.equal(sent.url, item.url);
});
test('an async flow does not pin unrelated caller context payloads across awaits', async () => {
  let release;
  const f = fixture({ beforeReply(t) { if (t === 'prepare') return new Promise(r => { release = r; }); } });
  function start() {
    const ignored = { padding: 'x'.repeat(1024 * 1024) };
    return { weak: new WeakRef(ignored), pending: f.agent.capture({ ...item }, settings, { ...context, ignored }, { requestId: 'capture-7' }) };
  }
  const { weak, pending } = start();
  while (!release) await new Promise(r => setImmediate(r));
  for (let i = 0; i < 5; i++) { globalThis.gc(); await new Promise(r => setImmediate(r)); }
  assert.equal(weak.deref(), undefined);
  release(); await pending;
});
for (const count of [100, 200, 400]) test(`stuck prepares across ${count} attempts retain at most sixteen slots and recover after release`, async () => {
  const releases = []; const log = []; let value; let sent = 0;
  const journal = new Journal({ storage: { get: async () => value, set: async (_, v) => { value = structuredClone(v); } } });
  const bridge = { state: 'ready', async request(body, o) {
    const envelope = b => ({ version: 1, message_id: 'r', generation: 1, session_id: SID, request_id: o.requestId, body: b });
    if (body.type === 'prepare') {
      sent++;
      return new Promise(r => releases.push(() => r(envelope({ type: 'prepared', payload: { ...receipt, state: 'prepared' } }))));
    }
    if (body.type === 'health') return envelope({ type: 'health_reply', payload: { transfer_capable: true } });
    if (body.type === 'abort') return envelope({ type: 'aborted', payload: { task_id: 1, fingerprint: '', state: 'aborted' } });
    throw Error('unexpected');
  } };
  const paused = new Set();
  const browser = { pause: async id => { paused.add(id); }, resume: async id => { paused.delete(id); }, cancel: async () => { log.push('cancel'); }, search: async ({ id }) => [{ ...item, id, paused: paused.has(id) }] };
  const a = new CaptureAgent({ journal, bridge, browser, stepTimeoutMs: 5 });
  let refused = 0;
  for (let i = 0; i < count; i++) {
    const r = await a.capture({ ...item, id: i }, settings, context, { requestId: `capture-${i}` });
    if (r.reason === 'busy') refused++;
  }
  globalThis.gc();
  assert.equal(sent, 16); assert.equal(releases.length, 16); assert.equal(a.liveOperations, 16);
  assert.equal(refused, count - 16); assert.equal(log.length, 0);
  for (const r of releases) r(); releases.length = 0;
  await new Promise(r => setImmediate(r)); globalThis.gc();
  assert.equal(a.liveOperations, 0); assert.equal(log.length, 0);
  const r = await a.capture({ ...item, id: count }, settings, context, { requestId: `after-${count}` });
  assert.notEqual(r.reason, 'busy');
  for (const r of releases) r();
});
test('recovery also caps outstanding operations, including across repeated recover calls', async () => {
  let value = { version: 1, records: Array.from({ length: 40 }, (_, id) => ({ id, requestId: `old-${id}`, state: 'PrepareSent', receipt: null, session: null, generation: 1, createdAt: 1, updatedAt: 1 })) };
  let calls = 0; const releases = [];
  const a = new CaptureAgent({
    journal: new Journal({ storage: { get: async () => value, set: async (_, v) => { value = structuredClone(v); } } }),
    bridge: { state: 'ready', request() { calls++; return new Promise(r => releases.push(r)); } },
    browser: { search: async ({ id }) => [{ id, state: 'in_progress' }], resume: async () => {} }, stepTimeoutMs: 1,
  });
  await a.recover(); await a.recover();
  assert.equal(a.liveOperations, 32); assert.equal(calls, 32);
  for (const r of releases) r({}); await new Promise(r => setImmediate(r));
  assert.equal(a.liveOperations, 0);
});

for (const point of ['prepare', 'begin_handoff', 'status']) test(`danger arriving at ${point} returns to browser`, async () => {
  const f = fixture({ beforeReply(type, f) { if (type === point) f.browserItem.danger = 'dangerous'; } });
  await f.run();
  assert.ok(!f.log.includes('cancel'));
  assert.equal(f.browserItem.paused, false);
});
for (const field of ['url', 'filename', 'byExtensionId', 'error', 'policyBlocked']) test(`fresh ${field} change refuses cancel`, async () => {
  const f = fixture({ beforeReply(type, f) { if (type === 'status') f.browserItem[field] = field === 'policyBlocked' ? true : 'changed'; } });
  await f.run(); assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false);
});

test('a safety event is latched even if subsequent search looks safe again', async () => {
  const f = fixture({ beforeReply(type, f) { if (type === 'begin_handoff') f.agent.browserChanged(7, { danger: { current: 'dangerous' } }); } });
  await f.run(); assert.ok(!f.log.includes('cancel')); assert.equal(f.browserItem.paused, false);
});
test('authenticated health refuses transfer before any browser pause', async () => {
  const f = fixture({ reply(type, e) { if (type === 'health') e.body.payload.transfer_capable = false; return e; } });
  await f.run(); assert.ok(!f.log.includes('pause')); assert.ok(!f.log.includes('cancel')); assert.ok(!f.log.includes('send:prepare'));
});

for (const point of ['prepare', 'begin_handoff', 'status']) test(`engine lost at ${point} after healthy admission keeps browser download`, async () => {
  const f = fixture({ reply(type, e) {
    if (type === point) e.body = { type: 'error', payload: { kind: 'wrong_state', message: 'transfer engine unavailable' } };
    return e;
  } });
  await f.run();
  assert.ok(f.log.includes('send:health'));
  assert.ok(!f.log.includes('cancel'));
  assert.equal(f.browserItem.paused, false);
});
