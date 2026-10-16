// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// Count the REAL outstanding operation, not just the timeout wrapper. No retry
// can accumulate promises behind a storage/browser call that never settles.
export class BoundedSteps {
  live = 0;
  constructor(limit = 16, timeoutMs = 1000) { this.limit = limit; this.timeoutMs = timeoutMs; }
  async run(fn) {
    if (this.live >= this.limit) throw Error('busy');
    this.live++;
    let p, timer;
    try { p = Promise.resolve(fn()); } catch { this.live--; throw Error('operation'); }
    const done = p.then(v => { this.live--; return v; }, () => { this.live--; throw Error('operation'); });
    try { return await Promise.race([done, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('timeout')), this.timeoutMs); })]); }
    finally { clearTimeout(timer); }
  }
}
