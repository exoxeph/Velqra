// SPDX-License-Identifier: GPL-3.0-only
// Metadata only. Diagnostics never participate in download ownership.
export const DIAGNOSTICS_KEY = 'velqra-capture-diagnostics-v1';
const reasons = new Set(['pending', 'captured', 'unseen_request', 'ambiguous_request', 'time_mismatch',
  'missing_headers', 'unsupported_provenance', 'request_changed', 'credentials', 'ineligible_suffix',
  'ineligible_type', 'not_ready', 'engine_not_capable', 'pause_failed', 'already_complete', 'bypass',
  'excluded', 'mode_off', 'busy', 'blocked', 'other_owner', 'browser_changed', 'already_paused',
  'capture_pending', 'capture_error', 'reconcile', 'filename', 'interrupted', 'invalid', 'minimum',
  'scheme', 'method', 'replay_risk', 'identity_conflict', 'journal', 'returned']);
const aliases = { unavailable: 'not_ready', disabled: 'mode_off', complete: 'already_complete',
  extension: 'other_owner', type: 'ineligible_suffix', site: 'excluded', request_ambiguous: 'ambiguous_request' };
export const reasonCode = value => reasons.has(value) ? value : typeof value === 'string' && Object.hasOwn(aliases, value) ? aliases[value] : 'capture_error';
const integer = (n, max, fallback = 0) => Number.isSafeInteger(n) && n >= 0 ? Math.min(n, max) : fallback;
function safe(row) {
  return { id: integer(row.id, Number.MAX_SAFE_INTEGER), at: integer(row.at, Number.MAX_SAFE_INTEGER),
    event: ['created', 'changed', 'filename', 'decision'].includes(row.event) ? row.event : 'decision',
    decision: ['keep', 'capture'].includes(row.decision) ? row.decision : 'pending', reason: reasonCode(row.reason),
    candidateCount: integer(row.candidateCount, 4096), timeGapBucket: integer(row.timeGapBucket, 5, -1),
    urlsCount: integer(row.urlsCount, 8) };
}
export class CaptureDiagnostics {
  #rows = [];
  #writing = false;
  #loaded = false;
  #dirty = false;
  constructor(storage) { this.storage = storage; }
  record(row) {
    this.#rows.push(safe({ ...row, at: Date.now() }));
    this.#rows = this.#rows.slice(-50);
    this.#dirty = true;
    if (!this.#writing) void this.#flush();
  }
  async #flush() {
    this.#writing = true;
    try {
      if (!this.#loaded) {
        this.#loaded = true;
        const old = (await this.storage?.get(DIAGNOSTICS_KEY))?.[DIAGNOSTICS_KEY];
        if (Array.isArray(old)) this.#rows = [...old.slice(-50).filter(x => x && typeof x === 'object').map(safe), ...this.#rows].slice(-50);
      }
      while (this.#dirty) {
        this.#dirty = false;
        await this.storage?.set({ [DIAGNOSTICS_KEY]: this.#rows.slice() });
      }
    } catch { this.#dirty = false; /* no remote errors or private data retained */ }
    finally { this.#writing = false; }
  }
}
