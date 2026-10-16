// SPDX-License-Identifier: GPL-3.0-only
// Independent boundary recorder. No implementation-private fields are inspected.
import assert from 'node:assert/strict';
import { CaptureAgent } from '../src/capture_agent.js';
import { Journal } from '../src/journal.js';

export const SID = '1'.repeat(32), FP = 'a'.repeat(64), REQUEST = 'matrix_7';
export const RECEIPT = { task_id: 1, fingerprint: FP };
export const ITEM = { id: 7, url: 'https://files.test/a.zip', filename: 'a.zip', state: 'in_progress', danger: 'safe' };
export const SETTINGS = { mode: 'on', extensions: ['zip'], allowed_sites: [], excluded_sites: [] };
export const CONTEXT = { method: 'GET', correlated: true, credentialsSeen: false, appReady: true };
const clone = x => structuredClone(x);
const never = () => new Promise(() => {});
const appStates = new Set(['committed', 'transferring', 'done', 'failed']);
const same = (a, b) => a?.task_id === b?.task_id && a?.fingerprint === b?.fingerprint;

export class Clock {
  now = 10; next = 0; timers = new Map();
  set = (fn, ms) => { const id = ++this.next; this.timers.set(id, { fn, at: this.now + ms }); return id; };
  clear = id => this.timers.delete(id);
  tick() {
    const t = [...this.timers].sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
    if (!t) return false;
    this.now = Math.max(this.now, t[1].at); this.timers.delete(t[0]); t[1].fn(); return true;
  }
}

/** Check *prefixes* after the run, so the agent cannot catch an assertion as an API error. */
export function checkTrace(events, final, expected = {}) {
  const writes = new Map(); let armed, receipt, aborted = false, ready = false;
  let cancelled = false, confirmed = false, user = false, submitted = 0, committed = false, expired = false, recovered = false;
  let appEvidence = false, abortEvidence = false, danger = false;
  let session = expected.session ?? SID;
  const request = expected.request ?? REQUEST, identity = expected.receipt ?? RECEIPT;
  const envelopeOK = e => e?.version === 1 && e.generation === 1 && e.request_id === request && e.session_id === session;
  for (const e of events) {
    if (e.kind === 'session') session = e.value;
    // health is the explicit session-binding operation. Its SID is supplied by
    // the already-authenticated bridge, not compared to a prior worker's SID.
    if (e.kind === 'reply' && e.type === 'health' && e.envelope?.version === 1 && e.envelope.generation === 1
      && e.envelope.request_id === request && /^[a-f0-9]{32}$/.test(e.envelope.session_id)
      && e.envelope.body.type === 'health_reply') session = e.envelope.session_id;
    if (e.kind === 'workerRestart') recovered = true;
    if (e.kind === 'deadline') expired = true;
    if (e.kind === 'ready') ready = e.value;
    if (e.kind === 'durable') {
      for (const r of e.value.records) {
        writes.set(r.state, r);
        if (r.state === 'ReceiptStored') receipt = r.receipt;
        if (r.state === 'CancelConfirmed') { assert.ok(cancelled && !user, 'confirmed without live cancel evidence'); confirmed = true; }
        if (r.state === 'HandedOff') assert.ok(appEvidence, 'handoff without matching app reply');
        if (r.state === 'Returned' && aborted) assert.ok(abortEvidence, 'returned without matching abort acknowledgement');
      }
    }
    if (e.kind === 'reply' && envelopeOK(e.envelope)) {
      const b = e.envelope.body;
      if (['committed', 'reconciled', 'status_reply'].includes(b.type) && appStates.has(b.payload.state) && same(b.payload, identity)) appEvidence = true;
      if (b.type === 'aborted' && b.payload.state === 'aborted' && (receipt ? same(b.payload, receipt) : b.payload.task_id > 0 && (b.payload.fingerprint === '' || /^[a-f0-9]{64}$/.test(b.payload.fingerprint)))) abortEvidence = true;
    }
    if (e.kind === 'reply' && e.type === 'begin_handoff') {
      const b = e.envelope.body;
      if (envelopeOK(e.envelope) && b.type === 'armed' && b.payload.state === 'armed' && same(b.payload, receipt)) armed = b.payload;
    }
    if (e.kind === 'send' && e.type === 'abort') aborted = true;
    if (e.kind === 'user') user = true;
    if (e.kind === 'injected' && e.fault === 'danger') danger = true;
    if (e.kind === 'call' && e.type === 'cancel') {
      assert.ok(!danger, 'cancel after danger change');
      assert.ok(ready, 'cancel while not ready');
      assert.ok(!recovered, 'recovery reissued cancel');
      assert.ok(!expired, 'cancel after pre-cancel deadline');
      assert.ok(receipt && same(receipt, identity), 'cancel before matching durable receipt');
      assert.ok(armed && same(armed, receipt), 'cancel before matching Armed reply');
      for (const state of ['ReceiptStored', 'CancelIntentStored', 'CancelRequested']) {
        const r = writes.get(state);
        assert.ok(same(r?.receipt, receipt), `cancel before ${state}`);
        assert.ok(r.id === 7 && r.requestId === request && r.generation === 1 && r.session === session, `cancel with wrong ${state} identity`);
      }
      assert.equal(e.record?.state, 'CancelRequested', 'cancel without current durable gate');
      assert.ok(e.record.id === 7 && e.record.requestId === request && e.record.generation === 1 && e.record.session === session && same(e.record.receipt, receipt), 'cancel with wrong current durable identity');
      assert.ok(!aborted, 'cancel after abort'); assert.ok(!user, 'cancel after user action');
    }
    if (e.kind === 'cancelApplied' && e.ack) cancelled = true;
    if (e.kind === 'send' && e.type === 'commit') {
      assert.ok(cancelled && confirmed && !user, 'commit without confirmed cancel');
      assert.ok(!aborted, 'commit after abort');
      assert.ok(same(e.payload.receipt, receipt), 'commit wrong receipt');
    }
    if (e.kind === 'coreCommit') committed = true;
    if (e.kind === 'submit') { assert.ok(committed, 'engine before commit'); assert.ok(++submitted <= 1, 'double submit'); }
  }
  if (!final) return;
  const app = appStates.has(final.core), browser = ['in_progress', 'complete'].includes(final.browser.state);
  assert.ok(!(app && browser), 'two owners');
  assert.ok(!(user && (submitted || app)), 'user cancel converted to transfer');
  const visible = final.notices.some(n => n.held === true) || final.result?.held === true || final.result?.state === 'ReconcileRequired';
  const gone = events.some(e => e.kind === 'injected' && e.fault === 'erase') && final.browser.erased === true
    && final.result?.state === 'Returned' && final.result.reason === 'browser_item_gone' && final.result.held === false;
  if (final.result?.state === 'Returned' && final.result.reason === 'browser_item_gone') assert.ok(gone, 'gone disposition without erase evidence');
  assert.ok(app || (browser && !final.browser.paused) || (user && !submitted) || visible || gone, 'lost download without visible hold');
  if (!visible && !app && !user && !gone) assert.ok(!final.browser.paused, 'silently paused');
  if (final.result?.state === 'HandedOff') assert.ok(app, 'false handoff');
}

/** Plans address a named boundary and its 1-based occurrence, not a guessed tick. */
export class World {
  constructor(plan = []) {
    this.plan = plan.map(p => ({ ...p, hit: false })); this.points = []; this.counts = new Map();
    this.log = [{ kind: 'ready', value: true }]; this.clock = new Clock(); this.ready = true;
    this.browserItem = { ...ITEM, paused: false }; this.value = undefined;
    this.core = 'none'; this.submits = 0; this.epoch = 0; this.restart = false; this.notices = [];
  }
  async point(name, kinds, epoch) {
    if (epoch !== this.epoch) return never();
    const occurrence = (this.counts.get(name) ?? 0) + 1; this.counts.set(name, occurrence);
    if (this.browserItem.state !== 'in_progress') kinds = kinds.filter(k => k !== 'user');
    const point = { name, occurrence, kinds }; this.points.push(point);
    const p = this.plan.find(p => !p.hit && p.name === name && p.occurrence === occurrence);
    if (!p) return;
    assert.ok(kinds.includes(p.kind), `inapplicable ${p.kind} at ${name}`); p.hit = true;
    this.log.push({ kind: 'injected', name, fault: p.kind });
    if (p.kind === 'restart') { this.log.push({ kind: 'workerRestart' }); this.epoch++; this.restart = true; this.clock.timers.clear(); return never(); }
    if (p.kind === 'offline') { this.ready = false; this.log.push({ kind: 'ready', value: false }); }
    if (p.kind === 'user') { this.browserItem.state = 'interrupted'; this.browserItem.error = 'USER_CANCELED'; this.log.push({ kind: 'user' }); this.agent.userCancel(7); }
    if (p.kind === 'danger') { this.browserItem.danger = 'dangerous'; this.agent.browserChanged(7, { danger: { current: 'dangerous' } }); }
    if (p.kind === 'erase') this.browserItem.erased = true;
    if (p.kind === 'complete' && this.browserItem.state === 'in_progress') { this.browserItem.state = 'complete'; this.browserItem.paused = false; }
    if (p.kind === 'deadline') { this.clock.now += 6000; this.log.push({ kind: 'deadline' }); }
    if (['fail', 'lost', 'notApplied'].includes(p.kind)) throw Error('injected');
    if (p.kind === 'hang') return never();
    return p.kind;
  }
  newAgent() {
    const w = this, epoch = this.epoch;
    const common = ['restart', 'offline', 'erase', 'deadline', 'danger'];
    const boundary = (name, kinds = []) => w.point(name, [...common, ...kinds], epoch);
    const storage = {
      async get() { await boundary('storage.get.before', ['fail']); const v = clone(w.value); await boundary('storage.get.after', ['lost']); return v; },
      async set(_, v) {
        const s = v.records[0].state;
        await boundary(`write.${s}.before`, ['fail', 'hang', 'user']);
        w.value = clone(v); w.log.push({ kind: 'durable', value: clone(v) });
        await boundary(`write.${s}.after`, ['lost', 'user']);
      },
    };
    const browser = {};
    for (const type of ['pause', 'resume', 'cancel', 'search']) browser[type] = async () => {
      w.log.push({ kind: 'call', type, record: clone(w.value?.records[0]) });
      // Invocation is synchronous. Faults *inside* an asynchronous browser call
      // cannot be injected before the agent's no-await final invocation gate.
      await boundary(`browser.${type}.before`, ['fail', 'notApplied', 'user', 'complete']);
      if (type === 'pause' && w.browserItem.state === 'in_progress') w.browserItem.paused = true;
      if (type === 'resume' && w.browserItem.state === 'in_progress') w.browserItem.paused = false;
      if (type === 'cancel' && w.browserItem.state === 'in_progress') { w.browserItem.state = 'interrupted'; w.browserItem.error = 'USER_CANCELED'; }
      const result = type === 'search' ? (w.browserItem.erased ? [] : [clone(w.browserItem)]) : undefined;
      await boundary(`browser.${type}.after`, ['lost', 'hang', 'user', 'complete']);
      if (type === 'cancel') w.log.push({ kind: 'cancelApplied', ack: true });
      return result;
    };
    const bridge = { get state() { return w.ready ? 'ready' : 'closed'; }, async request(body, opts) {
      const type = body.type;
      await boundary(`bridge.${type}.before`, ['fail', 'user']);
      w.log.push({ kind: 'send', type, payload: clone(body.payload) });
      let reply;
      if (type === 'health') reply = { type: 'health_reply', payload: { transfer_capable: true } };
      if (type === 'prepare') {
        if (w.core === 'none') w.core = 'prepared';
        reply = { type: 'prepared', payload: { ...RECEIPT, state: w.core } };
      }
      if (type === 'begin_handoff') {
        if (w.core === 'prepared') w.core = 'armed';
        reply = { type: 'armed', payload: { ...RECEIPT, state: w.core } };
      }
      if (type === 'status') reply = { type: 'status_reply', payload: { ...RECEIPT, state: w.core } };
      if (type === 'commit') {
        if (w.core === 'armed') { w.core = 'committed'; w.log.push({ kind: 'coreCommit' }); w.submits++; w.log.push({ kind: 'submit' }); }
        reply = { type: 'committed', payload: { ...RECEIPT, state: w.core } };
      }
      if (type === 'abort') {
        if (!appStates.has(w.core)) w.core = 'aborted';
        reply = { type: 'aborted', payload: { task_id: 1, fingerprint: body.payload.receipt ? FP : '', state: w.core } };
      }
      if (type === 'reconcile') {
        if (!appStates.has(w.core)) w.core = 'ownership_unknown';
        reply = { type: 'reconciled', payload: { ...RECEIPT, state: w.core } };
      }
      const e = { version: 1, message_id: 'reply', generation: 1, request_id: opts.requestId, session_id: SID, body: reply };
      const kind = await boundary(`bridge.${type}.after`, ['lost', 'hang', 'session', 'request', 'generation', 'kind', ...(type === 'health' ? [] : ['task', 'fingerprint', 'state']), 'user']);
      if (kind === 'session') e.session_id = '2'.repeat(32);
      if (kind === 'request') e.request_id = 'other';
      if (kind === 'generation') e.generation++;
      if (kind === 'kind') e.body.type = 'wrong';
      if (kind === 'task') e.body.payload.task_id = 2;
      if (kind === 'fingerprint') e.body.payload.fingerprint = 'b'.repeat(64);
      if (kind === 'state') e.body.payload.state = 'wrong';
      w.log.push({ kind: 'reply', type, envelope: clone(e) }); return e;
    } };
    const deps = { now: () => w.clock.now, setTimer: w.clock.set, clearTimer: w.clock.clear };
    this.agent = new CaptureAgent({ browser, bridge, journal: new Journal({ storage, ...deps, timeoutMs: 10 }), ...deps, stepTimeoutMs: 10, onStatus: n => w.notices.push(clone(n)) });
    return this.agent;
  }
  async drive(promise) {
    let done = false, value, error;
    promise.then(v => { done = true; value = v; }, e => { done = true; error = e; });
    for (let turns = 0; turns < 100; turns++) {
      // Drain nested async continuations before advancing virtual time.
      for (let i = 0; i < 300; i++) await Promise.resolve();
      if (this.restart || done) { if (error) throw error; return value; }
      assert.ok(this.clock.tick(), 'pending work with no timer');
    }
    throw Error('not quiescent');
  }
  async run() {
    this.newAgent();
    let result = await this.drive(this.agent.capture(ITEM, SETTINGS, CONTEXT, { requestId: REQUEST }));
    while (this.restart) {
      this.restart = false; this.ready = true; this.log.push({ kind: 'ready', value: true });
      this.newAgent(); result = await this.drive(this.agent.recover());
    }
    assert.ok(this.plan.every(p => p.hit), `planned injection never fired: ${JSON.stringify(this.plan.filter(p => !p.hit))}`);
    // A recovery result is a status snapshot; expose its actual record, not guessed disposition.
    result = result?.records?.[0] ?? result;
    const final = { result, core: this.core, browser: clone(this.browserItem), notices: clone(this.notices) };
    checkTrace(this.log, final);
    return { final, points: this.points, log: this.log, plan: this.plan, submits: this.submits };
  }
}

export const injection = (point, kind) => ({ name: point.name, occurrence: point.occurrence, kind });
