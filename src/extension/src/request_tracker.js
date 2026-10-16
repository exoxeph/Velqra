// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// Transient metadata only: never retain header values for Cookie/Authorization.
// A redirect consumes its own clean-header observation. Missing evidence fails closed.
const http = s => { try { return typeof s === 'string' && s.length <= 8192 && ['http:', 'https:'].includes(new URL(s).protocol); } catch { return false; } };
const login = s => { try { return /\/(?:login|signin|sign-in|oauth|authorize)(?:\/|$)/i.test(new URL(s).pathname); } catch { return true; } };
const oneUse = s => { try { return [...new URL(s).searchParams.keys()].some(k => /token|signature|expires|credential/i.test(k)); } catch { return true; } };
export class RequestTracker {
  #entries = new Map();
  constructor({ now = () => performance.now(), perTab = 1000, maxEntries = 4096, onConflict = () => {} } = {}) { this.now = now; this.perTab = perTab; this.maxEntries = maxEntries; this.onConflict = onConflict; }
  get size() { return this.#entries.size; }
  has(id) { return this.#entries.has(id); }
  pin(id) { const r = this.#entries.get(id); if (r) r.pinned = true; }
  unpin(id) { const r = this.#entries.get(id); if (r) r.pinned = false; }
  // At most 8,192 UTF-16 JSON code units per entry (under 16 MiB per
  // 1,000-entry tab). This is an encoded-metadata budget, not a JS heap claim.
  #bound(r, prior) {
    if (JSON.stringify(r).length <= 8192) return true;
    if (prior) { const credentials = r.credentials || prior.credentials; Object.assign(r, prior, { credentials, invalid: true }); }
    return false;
  }
  prune() { for (const [id, r] of this.#entries) if (!r.pinned && this.now() - r.at >= 120000) this.#entries.delete(id); }
  before(d) {
    this.prune();
    if (!http(d.url) || typeof d.requestId !== 'string' || d.requestId.length > 128 || !Number.isInteger(d.tabId) || !Number.isInteger(d.frameId) || typeof d.method !== 'string' || d.method.length > 16) return;
    let r = this.#entries.get(d.requestId);
    if (r) {
      // Redirect events and request IDs must agree on the next URL and identity.
      if (r.tabId !== d.tabId || r.frameId !== d.frameId || r.urls.at(-1) !== d.url || r.method !== d.method) r.invalid = true;
      return;
    }
    const tabEntries = () => [...this.#entries.values()].filter(x => x.tabId === d.tabId);
    while (this.#entries.size >= this.maxEntries || tabEntries().length >= this.perTab) {
      const sameTab = tabEntries().length >= this.perTab;
      const victim = [...this.#entries.values()].find(x => !x.pinned && (!sameTab || x.tabId === d.tabId));
      if (!victim) return; // NEVER trade unresolved receipt evidence for a new request.
      this.#entries.delete(victim.id);
    }
    r = { id: d.requestId, tabId: d.tabId, frameId: d.frameId, documentId: typeof d.documentId === 'string' ? d.documentId.slice(0, 128) : '',
      type: d.type, method: d.method, at: this.now(), wall: d.timeStamp, urls: [d.url], headersSeen: false, credentials: !!(new URL(d.url).username || new URL(d.url).password), login: false, oneUse: oneUse(d.url), invalid: false, pinned: false, referer: '', user_agent: '' };
    if (this.#bound(r, null)) this.#entries.set(d.requestId, r);
  }
  headers(d) {
    const r = this.#entries.get(d.requestId); if (!r || !Array.isArray(d.requestHeaders)) return;
    const prior = { ...r, urls: [...r.urls] };
    if (d.url && d.url !== r.urls.at(-1)) { r.invalid = true; return; }
    r.headersSeen = true;
    for (const h of d.requestHeaders) {
      const name = String(h.name).toLowerCase();
      if (name === 'cookie' || name === 'authorization' || name === 'proxy-authorization') r.credentials = true;
      if (name === 'referer' && http(h.value)) r.referer = `${new URL(h.value).origin}/`;
      if (name === 'user-agent' && typeof h.value === 'string' && /^[\x20-\x7e]{1,512}$/.test(h.value)) r.user_agent = h.value;
    }
    this.#bound(r, prior);
  }
  redirect(d) {
    const r = this.#entries.get(d.requestId); if (!r) return;
    const prior = { ...r, urls: [...r.urls] };
    if (!r.headersSeen || !http(d.redirectUrl) || r.urls.length >= 8 || r.urls.reduce((n, u) => n + u.length, 0) + d.redirectUrl.length > 8192) r.invalid = true;
    if (http(d.redirectUrl)) { r.login ||= login(d.redirectUrl); r.oneUse ||= oneUse(d.redirectUrl); r.credentials ||= !!(new URL(d.redirectUrl).username || new URL(d.redirectUrl).password); }
    if (r.urls.length < 8 && typeof d.redirectUrl === 'string' && r.urls.reduce((n, u) => n + u.length, 0) + d.redirectUrl.length <= 8192) r.urls.push(d.redirectUrl);
    r.headersSeen = false;
    this.#bound(r, prior);
  }
  end(d) { const r = this.#entries.get(d.requestId); if (r && (d.error || d.fromCache === true)) r.invalid = true; }
  match(item, { excludeId, peek = false } = {}) {
    this.prune();
    const final = item.finalUrl || item.url;
    const start = Date.parse(item.startTime);
    const found = [...this.#entries.values()].filter(r => r.id !== excludeId && r.urls[0] === item.url && r.urls.at(-1) === final && Number.isFinite(start) && Number.isFinite(r.wall) && (peek ? Math.abs(start - r.wall) <= 1000 : Math.floor(start) === Math.floor(r.wall)));
    if (found.length !== 1) return null;
    const r = found[0];
    // DownloadItem timestamps have millisecond precision. Capture only the same
    // millisecond bucket; no evidence justifies borrowing an older observation.
    if (!['main_frame', 'sub_frame'].includes(r.type) || r.tabId < 0) return null;
    if (!peek) {
      if (!Number.isSafeInteger(item.id)) return null;
      const owner = `${item.id}:${item.startTime}`;
      if (r.binding && r.binding !== owner) {
        r.invalid = true;
        this.onConflict(r.downloadId);
        return null;
      }
      if (!r.binding && JSON.stringify(r).length + owner.length + 64 > 8192) { r.invalid = true; return null; }
      r.binding = owner; r.downloadId = item.id;
    }
    return { id: r.id, tabId: r.tabId, frameId: r.frameId, documentId: r.documentId, method: r.method, correlated: !r.invalid && r.headersSeen, credentialsSeen: r.headersSeen ? r.credentials : undefined,
      loginRedirect: r.login, suspectedOneUse: r.oneUse, referer: r.referer, user_agent: r.user_agent };
  }
}
