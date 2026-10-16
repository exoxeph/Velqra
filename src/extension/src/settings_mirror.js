// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { BoundedSteps } from './bounded.js';

const pattern = /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
function valid(s) {
  return s && ['on', 'per_site', 'off'].includes(s.mode)
    && Array.isArray(s.extensions) && s.extensions.length <= 256 && s.extensions.every(x => typeof x === 'string' && /^[a-z0-9]{1,16}$/.test(x))
    && ['allowed_sites', 'excluded_sites'].every(k => Array.isArray(s[k]) && s[k].length <= 256 && s[k].every(x => typeof x === 'string' && pattern.test(x)))
    && (s.problem === null || (typeof s.problem === 'string' && s.problem.length <= 512));
}

/** Read-only, session-bound snapshot. Never merge a refused reply with old policy. */
export class SettingsMirror {
  #snapshot = null;
  #busy = false;
  #serial = 0;
  #epoch = 0;
  version = 0;
  problem = 'Settings unavailable; downloads stay in the browser.';
  constructor({ bridge, timeoutMs = 1000 }) { this.bridge = bridge; this.steps = new BoundedSteps(1, timeoutMs); }
  get snapshot() { return this.bridge.state === 'ready' && this.#snapshot ? structuredClone(this.#snapshot) : null; }
  invalidate() { this.#snapshot = null; this.#epoch++; }
  async refresh() {
    if (this.#busy) return false;
    this.#busy = true; this.invalidate();
    const epoch = this.#epoch;
    const requestId = `settings_${++this.#serial}`;
    try {
      if (this.bridge.state !== 'ready') throw Error('offline');
      const call = type => this.steps.run(() => this.bridge.request({ type, payload: {} }, { requestId }));
      const health = await call('health');
      if (epoch !== this.#epoch || this.bridge.state !== 'ready' || !this.#identity(health, requestId) || health.body?.type !== 'health_reply') throw Error('identity');
      const e = await call('settings_get');
      if (epoch !== this.#epoch || this.bridge.state !== 'ready' || !this.#identity(e, requestId) || e.session_id !== health.session_id || e.body?.type !== 'settings_reply' || !valid(e.body.payload)) throw Error('identity');
      this.#snapshot = structuredClone(e.body.payload); this.version++;
      this.problem = this.#snapshot.problem ?? health.body.payload?.problem ?? '';
      if (health.body.payload?.transfer_capable !== true || this.#snapshot.transfer_capable !== true) {
        this.#snapshot = null;
        this.problem ||= 'Transfer engine unavailable; downloads stay in the browser.';
      }
      return true;
    } catch { this.problem = 'Settings unavailable; downloads stay in the browser.'; return false; }
    finally { this.#busy = false; }
  }
  #identity(e, requestId) {
    return e?.version === 1 && e.generation === 1 && e.request_id === requestId && typeof e.session_id === 'string' && /^[a-f0-9]{32}$/.test(e.session_id);
  }
}
