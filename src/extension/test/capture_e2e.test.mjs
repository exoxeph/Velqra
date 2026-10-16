// SPDX-License-Identifier: GPL-3.0-only
// Usage: cargo build -p velqra-app --bins; node --expose-gc --test test/capture_e2e.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CaptureAgent } from '../src/capture_agent.js';
import { Journal } from '../src/journal.js';
import { ITEM, SETTINGS, CONTEXT, REQUEST, checkTrace } from './capture_harness.mjs';
import { binaries, Processes } from './capture_process.mjs';

const stop = () => new Promise(() => {});
async function scenario(mode, point) {
  const p = new Processes(), log = [], notices = []; let value, agent, receipt, triggered = false, crashResolve;
  const crashed = new Promise(r => { crashResolve = r; }); let worker = 0;
  const b = { ...ITEM, paused: false };
  try {
    const sid = await p.connect(); log.push({ kind: 'ready', value: true }, { kind: 'session', value: sid });
    const create = () => {
      const epoch = worker;
      const timers = new Set();
      const setTimer = (fn, ms) => { const id = setTimeout(fn, ms); timers.add(id); return id; };
      const clearTimer = id => { clearTimeout(id); timers.delete(id); };
      const crash = () => { triggered = true; worker++; log.push({ kind: 'workerRestart' }); for (const t of timers) clearTimeout(t); timers.clear(); crashResolve(); return stop(); };
      const storage = {
        get: async () => structuredClone(value),
        async set(_, v) {
          if (epoch !== worker) return stop();
          value = structuredClone(v); log.push({ kind: 'durable', value: structuredClone(v) });
          if (mode === 'worker' && !triggered && v.records[0].state === point) return crash();
        },
      };
      const browser = {
        async pause() { log.push({ kind: 'call', type: 'pause' }); b.paused = true; },
        async resume() { log.push({ kind: 'call', type: 'resume' }); b.paused = false; },
        async cancel() {
          log.push({ kind: 'call', type: 'cancel', record: structuredClone(value.records[0]) });
          b.state = 'interrupted'; b.error = 'USER_CANCELED';
          if (mode === 'worker' && point === 'AfterCancel' && !triggered) return crash();
          log.push({ kind: 'cancelApplied', ack: true });
        },
        async search() { return [{ ...b }]; },
      };
      const bridge = { get state() { return p.client.state; }, async request(body, opts) {
        if (epoch !== worker) return stop();
        log.push({ kind: 'send', type: body.type, payload: structuredClone(body.payload) });
        const e = await p.client.request(body, opts);
        if (body.type === 'prepare') receipt = { task_id: e.body.payload.task_id, fingerprint: e.body.payload.fingerprint };
        if (!triggered && body.type === point) {
          if (mode === 'core' || mode === 'host') {
            triggered = true;
            // A successful core operation with its reply suppressed, followed by process death.
            if (mode === 'core') p.killCore(); else p.latest.kill();
            p.client.close(); log.push({ kind: 'ready', value: false }); throw Error('connection lost');
          }
          if (mode === 'session') { triggered = true; e.session_id = 'f'.repeat(32); }
        }
        log.push({ kind: 'reply', type: body.type, envelope: structuredClone(e) }); return e;
      } };
      agent = new CaptureAgent({ browser, bridge, journal: new Journal({ storage, timeoutMs: 1000, setTimer, clearTimer }), stepTimeoutMs: 3000, setTimer, clearTimer, onStatus: n => notices.push(n) });
      return agent;
    };
    const a = create();
    let result = await Promise.race([a.capture(ITEM, SETTINGS, CONTEXT, { requestId: REQUEST }), crashed.then(() => ({ crashed: true }))]);
    if (mode !== 'happy') assert.ok(triggered, `${mode}/${point} was not applied`);
    if (mode === 'worker' || mode === 'core' || mode === 'host') {
      log.push({ kind: 'session', value: await p.connect() }, { kind: 'ready', value: true });
      result = await create().recover(); result = result.records?.[0] ?? result;
    }
    const status = await p.client.request({ type: 'status', payload: {} }, { requestId: REQUEST });
    const core = status.body.payload.state;
    checkTrace(log, { result, core, browser: b, notices }, { session: sid, receipt });
    if (mode === 'happy' || (mode === 'worker' && point === 'CancelConfirmed')) assert.equal(result.state, 'HandedOff');
    if (mode === 'session') { assert.ok(!log.some(e => e.kind === 'call' && e.type === 'cancel')); assert.equal(core, 'aborted'); }
    return { mode, point, applied: triggered ? 1 : 0, core, journal: result.state, browser: b.state };
  } finally { await p.close(); }
}

for (const [mode, points] of [
  ['happy', ['none']], ['core', ['prepare', 'begin_handoff', 'commit']], ['host', ['begin_handoff']],
  ['worker', ['ReceiptStored', 'CancelRequested', 'AfterCancel', 'CancelConfirmed']], ['session', ['begin_handoff']],
]) for (const point of points) test(`C5 real host/core ${mode} at ${point}`, { skip: !binaries, timeout: 60000 }, async t => {
  t.diagnostic(JSON.stringify(await scenario(mode, point)));
});

test('without loopback opt-in an unavailable pinned engine leaves browser ownership untouched', { skip: !binaries }, async () => {
  const p = new Processes(false), calls = [], b = { ...ITEM, paused: false }; let value;
  try {
    await p.connect();
    const health = await p.client.request({ type: 'health', payload: {} }, { requestId: 'disabled' });
    assert.equal(health.body.payload.transfer_capable, false); assert.ok(health.body.payload.problem);
    const a = new CaptureAgent({ bridge: p.client, journal: new Journal({ storage: { get: async () => value, set: async (_, v) => { value = structuredClone(v); } } }),
      browser: { search: async () => [{ ...b }], pause: async () => calls.push('pause'), cancel: async () => calls.push('cancel'), resume: async () => calls.push('resume') } });
    await a.capture(ITEM, SETTINGS, CONTEXT, { requestId: 'disabled' });
    assert.deepEqual(calls, []); assert.equal(b.state, 'in_progress');
    const refused = await p.client.request({ type: 'prepare', payload: { download_key: 'disabled', url: ITEM.url, filename: ITEM.filename, context: '' } }, { requestId: 'disabled' });
    assert.equal(refused.body.type, 'error');
  } finally { await p.close(); }
});
