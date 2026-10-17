// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// Pure ownership logic; NOT wired into Chrome in 27a. See spec 4 and Rust JState.
// A live cancel promise + observed interrupted item is evidence only if the adapter
// has NOT signalled an independent user cancellation. A bare history event is not.
import { decide } from './eligibility.js';
import { TERMINAL, validReceipt } from './journal.js';

const APP_OWNS = new Set(['committed', 'transferring', 'done', 'failed']);
const AFTER_CANCEL = new Set(['CancelRequested', 'CancelConfirmed', 'CommitSent', 'ReconcileRequired']);
const ref = (/** @type {any} */ r) => ({ task_id: r.task_id, fingerprint: r.fingerprint });
const same = (/** @type {any} */ a, /** @type {any} */ b) => validReceipt(a) && validReceipt(b) && a.task_id === b.task_id && a.fingerprint === b.fingerprint;

/**
 * Dependencies: browser pause/resume/cancel/search promises; authenticated bridge
 * state/request; Journal; now/setTimer/clearTimer. No payloads in status callbacks.
 * At most 16 flows and 32 outstanding external operations, including timed-out ones.
 * A timed-out external operation can settle late but cannot advance this flow.
 * @example new CaptureAgent({ browser, bridge, journal }).recover()
 */
export class CaptureAgent {
  #flows = new Map();
  #live = 0;
  #loading = false;
  /** @param {any} deps */
  constructor(deps) {
    this.d = { now: Date.now, setTimer: (fn, ms) => setTimeout(fn, ms), clearTimer: id => clearTimeout(id), stepTimeoutMs: 1000, preCancelMs: 5000, onStatus: () => {}, ...deps };
  }
  get liveOperations() { return this.#live; }
  /** Bounded, metadata-only view, including unresolved records and storage hold. */
  status() {
    const records = this.d.journal.list();
    return { held: this.d.journal.held || records.some(r => r.held || ['Returning', 'ReconcileRequired'].includes(r.state)), active: this.#flows.size, liveOperations: this.#live, records };
  }
  /** Explicit independent user action; an unclassified USER_CANCELED event is NOT this signal. */
  userCancel(/** @type {number} */ id) { const f = this.#flows.get(id); if (f) f.user = true; }
  browserChanged(id, delta) {
    const f = this.#flows.get(id);
    if (!f || f.post) return;
    if ((delta.danger?.current !== undefined && delta.danger.current !== 'safe') || delta.error?.current
      || delta.policyBlocked?.current === true || ['url', 'finalUrl', 'filename', 'byExtensionId', 'startTime'].some(k => delta[k]?.current !== undefined)) f.invalid = true;
  }
  #safe(f, b, paused) {
    const expected = f.expected;
    if (b?.state === 'complete') throw Error('already_complete');
    if (paused && b?.state === 'in_progress' && b.paused !== true) throw Error('pause_failed');
    if (!b || b.id !== expected.id || b.state !== 'in_progress' || !!b.paused !== paused
      || b.danger !== 'safe' || b.error || b.policyBlocked === true
      || (b.finalUrl || b.url) !== expected.url || b.filename !== expected.filename
      || b.byExtensionId !== expected.byExtensionId || b.startTime !== expected.startTime) throw Error('browser_changed');
  }
  #notify(/** @type {any} */ r) {
    try { this.d.onStatus({ id: r.id, state: r.state, held: !!r.held, reason: r.reason ?? '' }); } catch { /* diagnostics cannot advance ownership */ }
    return structuredClone(r);
  }
  #check(/** @type {any} */ f, deadline = true) {
    if (this.d.bridge.state !== 'ready') throw Error('offline');
    if (f.user) throw Error('user_cancel');
    if (f.invalid) throw Error('browser_changed');
    if (deadline && this.d.now() >= f.deadline) throw Error('deadline');
    if (this.d.journal.held) throw Error('hold');
  }
  async #step(/** @type {() => any} */ fn, ms = this.d.stepTimeoutMs) {
    if (this.#live >= 32) throw Error('overloaded');
    this.#live++;
    let timer;
    // These continuations only release a slot, never inspect or retain a request body.
    let p;
    try { p = Promise.resolve(fn()); }
    catch { this.#live--; throw Error('operation'); }
    const settled = p.then(v => { this.#live--; return v; }, () => { this.#live--; throw Error('operation'); });
    try {
      return await Promise.race([settled, new Promise((_, reject) => { timer = this.d.setTimer(() => reject(Error('timeout')), Math.max(1, ms)); })]);
    } finally { this.d.clearTimer(timer); }
  }
  async #save(/** @type {any} */ f, /** @type {string} */ state, extra = {}) {
    const next = { ...f.r, ...extra, state, updatedAt: this.d.now() };
    // Journal itself bounds the wait and fences late storage completion.
    await this.d.journal.write(next);
    f.r = next;
  }
  #envelope(/** @type {any} */ f, /** @type {any} */ e, bind = false) {
    if (!e || e.version !== 1 || e.generation !== f.r.generation || e.request_id !== f.r.requestId
      || typeof e.session_id !== 'string' || !/^[0-9a-f]{32}$/.test(e.session_id)
      || (!bind && e.session_id !== f.r.session) || !e.body || typeof e.body.type !== 'string') throw Error('identity');
    return e.body;
  }
  async #call(/** @type {any} */ f, /** @type {string} */ type, /** @type {any} */ payload, bind = false, pre = false) {
    if (this.d.bridge.state !== 'ready') throw Error('offline');
    const e = await this.#step(() => this.d.bridge.request({ type, payload }, { requestId: f.r.requestId, timeoutMs: this.d.stepTimeoutMs }), pre ? Math.min(this.d.stepTimeoutMs, f.deadline - this.d.now()) : this.d.stepTimeoutMs);
    if (this.d.bridge.state !== 'ready') throw Error('offline');
    const body = this.#envelope(f, e, bind);
    if (bind) {
      if (body.type !== 'health_reply') throw Error('identity');
      f.r = { ...f.r, session: e.session_id };
    }
    if (body.type === 'error') throw Error('refused'); // never echo remote detail
    return body;
  }
  #receipt(/** @type {any} */ f, /** @type {any} */ b, /** @type {string} */ type, /** @type {Set<string>} */ states, initial = false) {
    if (b.type !== type || !validReceipt(b.payload) || !states.has(b.payload.state) || (!initial && !same(f.r.receipt, b.payload))) throw Error('identity');
    return ref(b.payload);
  }
  async #search(/** @type {any} */ f) {
    const items = await this.#step(() => this.d.browser.search({ id: f.r.id }));
    if (!Array.isArray(items)) return undefined;
    if (items.length === 0) return null; // Definitive removal, unlike ambiguous results.
    if (items.length !== 1 || items[0]?.id !== f.r.id) return undefined;
    return items[0];
  }
  async #resume(/** @type {any} */ f) {
    if (f.user) return 'not_paused'; // Independent user cancellation must not be undone.
    try {
      const b = await this.#search(f);
      if (f.user) return 'not_paused';
      if (b === null) return 'gone';
      if (b?.state === 'complete' || (b?.state === 'in_progress' && b.paused === false)) return 'not_paused';
      if (b?.state !== 'in_progress' || b.paused !== true) return 'unknown';
      await this.#step(() => this.d.browser.resume(f.r.id));
      // An API acknowledgement alone does not prove that the item is unpaused.
      const after = await this.#search(f);
      if (f.user) return 'not_paused';
      if (after === null) return 'gone';
      return after?.state === 'complete' || (after?.state === 'in_progress' && after.paused === false) ? 'resumed' : 'unknown';
    } catch { return 'unknown'; }
  }
  async #pause(/** @type {any} */ f) {
    let expired = false;
    try {
      await this.#step(() => Promise.resolve(this.d.browser.pause(f.r.id)).then(async () => {
        if (!expired) return;
        // A timed-out Chrome pause can take effect after fallback resumed the item.
        // Only clean up this same identity, never act on a newer reused download ID.
        const r = this.d.journal.get(f.r.id);
        if (!r || r.requestId === f.r.requestId) {
          const outcome = await this.#resume(f);
          const current = this.d.journal.get(f.r.id);
          if (current && current.requestId !== f.r.requestId) return;
          f.cleanupOutcome = outcome;
          const cleanup = { r: current ?? f.r };
          if (outcome === 'unknown') {
            // Persist against the current record, never roll a newer state back.
            try { if (current) await this.#save(cleanup, current.state, { held: true, reason: 'browser_unknown' }); }
            catch { /* the notice still exposes a failed journal write */ }
            this.#notify({ ...cleanup.r, held: true, reason: 'browser_unknown' });
          } else if (current?.state === 'Returned') {
            try {
              await this.#save(cleanup, 'Returned', { held: false, reason: outcome === 'gone' ? 'browser_item_gone' : 'returned' });
              this.#notify(cleanup.r);
            } catch { this.#notify({ ...cleanup.r, held: true, reason: 'journal' }); }
          }
        }
      }));
    } catch { expired = true; throw Error('pause_failed'); }
  }
  async #abort(/** @type {any} */ f) {
    // Local fence first; every late success belongs to a dead flow. No cancel on this path.
    f.aborting = true;
    if (!f.owns) {
      // No durable, uniquely allocated identity and no prepare was sent. Never fence
      // a key that might belong to somebody else after a failed initial write/load.
      try { await this.#resume(f); } catch { /* report a hold below */ }
      return this.#notify({ ...f.r, state: 'Returned', held: true, reason: 'journal' });
    }
    try { await this.#save(f, 'Returning'); } catch { f.r = { ...f.r, held: true, reason: 'journal' }; }
    const outcome = await this.#resume(f);
    const returned = { held: outcome === 'unknown', reason: outcome === 'unknown' ? 'browser_unknown' : outcome === 'gone' ? 'browser_item_gone' : 'returned' };
    // Keep unknown browser outcomes nonterminal so normal recovery/retention also
    // retains them. A core abort acknowledgement does not prove browser recovery.
    if (returned.held) f.r = { ...f.r, ...returned };
    try {
      if (!f.r.session) await this.#call(f, 'health', {}, true);
      const b = await this.#call(f, 'abort', { receipt: f.r.receipt });
      if (b.type !== 'aborted' || b.payload?.state !== 'aborted'
        || (f.r.receipt ? !same(f.r.receipt, b.payload) : !(Number.isSafeInteger(b.payload.task_id) && b.payload.task_id > 0 && (b.payload.fingerprint === '' || validReceipt(b.payload))))) throw Error('identity');
      if (f.cleanupOutcome === 'unknown') { returned.held = true; returned.reason = 'browser_unknown'; }
      else if (!returned.held && f.cleanupOutcome === 'gone') returned.reason = 'browser_item_gone';
      await this.#save(f, returned.held ? 'Returning' : 'Returned', returned);
    } catch {
      const reason = returned.held || f.cleanupOutcome === 'unknown' ? 'browser_unknown' : 'abort_pending';
      try { await this.#save(f, 'Returning', { held: true, reason }); }
      catch { f.r = { ...f.r, held: true, reason }; }
    }
    return this.#notify(f.r);
  }
  async #reconcile(/** @type {any} */ f) {
    f.post = true;
    try { await this.#save(f, 'ReconcileRequired', { held: true, reason: 'ownership_unknown' }); }
    catch { f.r = { ...f.r, state: 'ReconcileRequired', held: true, reason: 'journal' }; }
    if (f.r.receipt) {
      try {
        if (!f.r.session) await this.#call(f, 'health', {}, true);
        const b = await this.#call(f, 'reconcile', { owner: 'unknown', receipt: f.r.receipt });
        this.#receipt(f, b, 'reconciled', new Set([...APP_OWNS, 'ownership_unknown']));
        // A live commit acknowledgement was lost. The core can prove existing app ownership.
        if (APP_OWNS.has(b.payload.state)) await this.#save(f, 'HandedOff', { held: false, reason: 'resolved' });
      } catch { /* retain visible ambiguity; reconnect/recover will retry */ }
    }
    return this.#notify(f.r);
  }
  /**
   * requestId must be a collision-free installation/profile/download/start-time identity
   * supplied by the future capture adapter. IDs are never invented from URL alone.
   * @param {any} item @param {any} settings @param {any} context @param {{requestId: string, browserOrigin?: string}} opts
   */
  async capture(item, settings, context, opts) {
    const decision = decide(item, settings, { ...context, appReady: context?.appReady === true && this.d.bridge.state === 'ready' });
    if (decision.action !== 'capture') return decision;
    if (!opts || typeof opts.requestId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(opts.requestId) || this.#loading || this.#flows.has(item.id) || this.#flows.size >= 16 || this.#live >= 16) return { action: 'keep', reason: 'busy' };
    // Snapshot bounded fields before the first await. Neither caller mutation nor
    // an unrelated large context object may change or remain pinned by a flow.
    const wireContext = {};
    try {
      if (typeof context.referer === 'string' && context.referer.length <= 8192) {
        const u = new URL(context.referer);
        if (['http:', 'https:'].includes(u.protocol) && !u.username && !u.password) wireContext.referer = `${u.origin}/`;
      }
    } catch { /* omit invalid optional metadata */ }
    if (typeof context.user_agent === 'string' && /^[\x20-\x7e]{1,512}$/.test(context.user_agent)) wireContext.user_agent = context.user_agent;
    const expected = { id: item.id, url: item.finalUrl || item.url, filename: item.filename, byExtensionId: opts.browserOrigin ?? item.byExtensionId, startTime: item.startTime };
    item = { id: item.id, url: item.url, filename: item.filename.split(/[\\/]/).pop() };
    opts = { requestId: opts.requestId };
    context = null;
    settings = null;
    const f = { expected, r: { id: item.id, requestId: opts.requestId, state: 'Seen', receipt: null, session: null, generation: 1, createdAt: this.d.now(), updatedAt: this.d.now() }, deadline: this.d.now() + this.d.preCancelMs, post: false, user: false, aborting: false, owns: false };
    this.#flows.set(item.id, f);
    try {
      await this.d.journal.load(); this.#check(f);
      const prior = this.d.journal.get(item.id);
      if (prior) return this.#notify(prior); // unresolved identity must be recovered, never replaced
      if (this.d.journal.list().some(r => r.requestId === opts.requestId)) return { action: 'keep', reason: 'identity_conflict' };
      await this.#save(f, 'Seen'); f.owns = true; this.#check(f);
      const health = await this.#call(f, 'health', {}, true, true); this.#check(f);
      if (health.payload?.transfer_capable !== true) throw Error('engine');
      const beforePause = await this.#search(f); this.#check(f); this.#safe(f, beforePause, false);
      await this.#pause(f); this.#check(f);
      let b = await this.#search(f); this.#check(f);
      this.#safe(f, b, true);
      await this.#save(f, 'Paused'); this.#check(f);
      await this.#call(f, 'health', {}, true, true); this.#check(f);
      await this.#save(f, 'PrepareSent'); this.#check(f);
      const prepared = await this.#call(f, 'prepare', { download_key: opts.requestId, url: item.url, filename: item.filename, context: JSON.stringify(wireContext) }, false, true); this.#check(f);
      const receipt = this.#receipt(f, prepared, 'prepared', new Set(['prepared']), true);
      // Keep a returned receipt even when the write fails, so ABORT can still name it.
      f.r = { ...f.r, receipt };
      await this.#save(f, 'ReceiptStored'); this.#check(f);
      const armed = await this.#call(f, 'begin_handoff', receipt, false, true); this.#check(f);
      this.#receipt(f, armed, 'armed', new Set(['armed']));
      await this.#save(f, 'CancelIntentStored'); this.#check(f);
      await this.#save(f, 'CancelRequested'); this.#check(f);

      // BridgeClient deliberately hides its session ID. A final authenticated status
      // reply proves the same session/receipt after all storage/browser awaits.
      const status = await this.#call(f, 'status', {}, false, true); this.#check(f);
      this.#receipt(f, status, 'status_reply', new Set(['armed']));
      b = await this.#search(f); this.#check(f); this.#safe(f, b, true);
      // NO await between this gate and invoking cancel. 'post' fences even a thrown call.
      if (f.aborting || this.d.journal.get(item.id)?.state !== 'CancelRequested') throw Error('gate');
      f.post = true;
      await this.#step(() => this.d.browser.cancel(item.id)); this.#check(f, false);
      b = await this.#search(f); this.#check(f, false);
      if (b?.state === 'complete') { f.post = false; return await this.#abort(f); }
      if (b?.state !== 'interrupted' || b.error !== 'USER_CANCELED') return await this.#reconcile(f);
      await this.#save(f, 'CancelConfirmed'); this.#check(f, false);
      return await this.#commit(f);
    } catch (error) {
      const result = f.post ? await this.#reconcile(f) : await this.#abort(f);
      const diagnostic = f.post ? 'reconcile' : ({ engine: 'engine_not_capable', offline: 'not_ready', already_complete: 'already_complete', pause_failed: 'pause_failed', browser_changed: 'browser_changed' })[error?.message] ?? 'capture_error';
      return { ...result, diagnostic };
    } finally { this.#flows.delete(item.id); }
  }
  async #commit(/** @type {any} */ f) {
    this.#check(f, false);
    await this.#save(f, 'CommitSent'); this.#check(f, false);
    const b = await this.#call(f, 'commit', { cancel: 'confirmed', receipt: f.r.receipt }); this.#check(f, false);
    this.#receipt(f, b, 'committed', APP_OWNS);
    await this.#save(f, 'HandedOff', { held: false, reason: 'resolved' });
    // If transport closes here, the validated commit plus durable HandedOff suffices.
    return this.#notify(f.r);
  }
  /** Recovery never re-issues browser cancel. It queries live browser and core state. */
  async recover() {
    if (this.#loading || this.#flows.size) return { held: true, reason: 'busy' };
    this.#loading = true;
    try {
      await this.d.journal.load();
      for (const record of this.d.journal.list()) {
        if (TERMINAL.includes(record.state) && !(record.state === 'Returned' && record.held && record.reason === 'browser_unknown')) continue;
        const f = { r: record, deadline: 0, post: AFTER_CANCEL.has(record.state), user: false, aborting: false, owns: true };
        this.#flows.set(record.id, f);
        try {
          if (record.state === 'Returned') {
            // Compatibility with a held terminal record: the core already ACKed
            // abort. Retry only browser cleanup, without prepare/cancel/commit.
            const outcome = await this.#resume(f);
            await this.#save(f, 'Returned', { held: outcome === 'unknown', reason: outcome === 'unknown' ? 'browser_unknown' : outcome === 'gone' ? 'browser_item_gone' : 'returned' });
            this.#notify(f.r);
            continue;
          }
          const b = await this.#search(f);
          if (!f.post && record.state !== 'CancelIntentStored') {
            // Restart handshakes use a new session even for a pre-cancel abort.
            // Only recovery may rebind; the receipt still has to match the ACK.
            try { await this.#call(f, 'health', {}, true); } catch { /* return browser even while offline */ }
            await this.#abort(f); continue;
          }
          // A new authenticated session may resume recovery, but no old session reply
          // may authorize a new cancellation. Rebind only here and validate receipt.
          await this.#call(f, 'health', {}, true);
          if (['CancelConfirmed', 'CommitSent'].includes(record.state) && b?.state === 'interrupted') {
            const status = await this.#call(f, 'status', {});
            this.#receipt(f, status, 'status_reply', new Set(['armed', ...APP_OWNS]));
            if (APP_OWNS.has(status.payload.state)) await this.#save(f, 'HandedOff', { held: false, reason: 'resolved' });
            else await this.#commit(f);
          } else if (b?.state === 'in_progress' || b?.state === 'complete' || (!f.post && b?.state === 'interrupted')) {
            await this.#abort(f);
          } else await this.#reconcile(f);
        } catch { if (f.post || record.state === 'CancelIntentStored') await this.#reconcile(f); else await this.#abort(f); }
        finally { this.#flows.delete(record.id); }
      }
      return this.status();
    } catch { return { held: true, reason: 'journal' }; }
    finally { this.#loading = false; }
  }
}
