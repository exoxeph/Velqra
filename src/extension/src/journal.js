// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// One atomic storage key: an injected Chrome adapter must replace the whole value.
// No queued writes. A timed-out operation can complete late: poison this instance
// and require worker restart, rather than let a stale write overwrite a newer one.
export const STATES = Object.freeze(['Seen', 'Paused', 'PrepareSent', 'ReceiptStored', 'CancelIntentStored', 'CancelRequested', 'CancelConfirmed', 'CommitSent', 'HandedOff', 'Returning', 'Returned', 'ReconcileRequired']);
export const TERMINAL = Object.freeze(['HandedOff', 'Returned']);
/** Operations that may wait in the journal's queue (the agent runs at most 16 flows). */
const MAX_PENDING = 16;
const FIELDS = new Set(['id', 'requestId', 'state', 'receipt', 'session', 'generation', 'createdAt', 'updatedAt', 'held', 'reason']);
const copy = (/** @type {any} */ x) => structuredClone(x);

export function validReceipt(/** @type {any} */ r) {
  return !!r && Number.isSafeInteger(r.task_id) && r.task_id > 0 && typeof r.fingerprint === 'string' && /^[a-f0-9]{64}$/.test(r.fingerprint);
}
function valid(/** @type {any} */ r) {
  return r && Object.keys(r).every(k => FIELDS.has(k)) && Number.isSafeInteger(r.id) && r.id >= 0
    && typeof r.requestId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(r.requestId)
    && STATES.includes(r.state) && r.generation === 1
    && (r.receipt === null || (validReceipt(r.receipt) && Object.keys(r.receipt).every(k => ['task_id', 'fingerprint'].includes(k))))
    && (r.session === null || (typeof r.session === 'string' && /^[0-9a-f]{32}$/.test(r.session)))
    && Number.isSafeInteger(r.createdAt) && Number.isSafeInteger(r.updatedAt)
    && (r.held === undefined || typeof r.held === 'boolean')
    && (r.reason === undefined || (typeof r.reason === 'string' && /^[a-z_]{1,40}$/.test(r.reason)))
    && (!['ReceiptStored', 'CancelIntentStored', 'CancelRequested', 'CancelConfirmed', 'CommitSent', 'HandedOff'].includes(r.state) || (r.receipt !== null && r.session !== null));
}

export class Journal {
  #records = new Map();
  #loaded = false;
  #busy = false;
  #poison = false;
  #failures = 0;
  // Operations run one at a time, in arrival order: each sees the result of the one before it, so
  // simultaneous downloads cannot overwrite each other's record. The queue is bounded.
  #tail = Promise.resolve();
  #pending = 0;
  /** @param {any} deps */
  constructor(deps) {
    this.d = { key: 'velqra-capture-v1', maxRecords: 256, maxBytes: 256 * 1024, retentionMs: 30 * 86400000, now: Date.now, timeoutMs: 1000, setTimer: setTimeout, clearTimer: clearTimeout, ...deps };
    if (!Number.isSafeInteger(this.d.maxRecords) || this.d.maxRecords < 1 || this.d.maxRecords > 256) throw Error('limits');
  }
  get held() { return this.#poison || this.#failures >= 5; }
  get(/** @type {number} */ id) { const r = this.#records.get(id); return r ? copy(r) : undefined; }
  list() { return [...this.#records.values()].map(copy); }
  /** Bound the wait; a timed-out storage operation permanently fences this instance. */
  async #io(/** @type {() => Promise<any>} */ fn) {
    if (this.#poison) throw Error('hold');
    if (this.#busy) throw Error('busy');
    this.#busy = true;
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(fn),
        new Promise((_, reject) => { timer = this.d.setTimer(() => { this.#poison = true; reject(Error('storage_timeout')); }, this.d.timeoutMs); }),
      ]);
    } catch {
      this.#failures++;
      throw Error(this.#poison ? 'storage_timeout' : 'storage');
    } finally {
      this.d.clearTimer(timer);
      this.#busy = false;
    }
  }
  #enqueue(/** @type {() => Promise<any>} */ fn) {
    if (this.#pending >= MAX_PENDING) return Promise.reject(Error('busy'));
    this.#pending++;
    const run = () => fn().finally(() => { this.#pending--; });
    const p = this.#tail.then(run, run);
    this.#tail = p.then(() => {}, () => {});
    return p;
  }
  load() { return this.#enqueue(() => this.#loadNow()); }
  async #loadNow() {
    if (this.#loaded) return;
    const value = await this.#io(() => this.d.storage.get(this.d.key));
    if (value !== undefined) {
      if (!value || value.version !== 1 || !Array.isArray(value.records) || value.records.length > this.d.maxRecords
        || JSON.stringify(value).length > this.d.maxBytes || !value.records.every(valid) || new Set(value.records.map(r => r.id)).size !== value.records.length
        || new Set(value.records.map(r => r.requestId)).size !== value.records.length) {
        this.#poison = true;
        throw Error('corrupt');
      }
      this.#records = new Map(value.records.map(r => [r.id, copy(r)]));
    }
    this.#loaded = true;
  }
  /** @param {any} record */
  write(record) { return this.#enqueue(() => this.#writeNow(record)); }
  async #writeNow(/** @type {any} */ record) {
    if (this.held) throw Error('hold');
    if (!valid(record)) throw Error('record');
    await this.#loadNow();
    const next = new Map(this.#records);
    if (!next.has(record.id) && next.size >= this.d.maxRecords) {
      const terminal = [...next.values()].filter(r => TERMINAL.includes(r.state) && this.d.now() - r.updatedAt >= this.d.retentionMs).sort((a, b) => a.updatedAt - b.updatedAt)[0];
      if (!terminal) throw Error('full');
      next.delete(terminal.id);
    }
    const prior = next.get(record.id);
    if (prior && (prior.requestId !== record.requestId || (TERMINAL.includes(prior.state) && prior.state !== record.state))) throw Error('record');
    if ([...next.values()].some(r => r.id !== record.id && r.requestId === record.requestId)) throw Error('record');
    next.set(record.id, copy(record));
    const value = { version: 1, records: [...next.values()] };
    if (JSON.stringify(value).length > this.d.maxBytes) throw Error('full');
    await this.#io(() => this.d.storage.set(this.d.key, value));
    this.#records = next;
    this.#failures = 0;
  }
}
