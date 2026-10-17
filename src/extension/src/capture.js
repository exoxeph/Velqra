// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { CaptureAgent } from './capture_agent.js';
import { Journal, TERMINAL } from './journal.js';
import { decide } from './eligibility.js';
import { RequestTracker } from './request_tracker.js';
import { SettingsMirror } from './settings_mirror.js';
import { BoundedSteps } from './bounded.js';
import { CaptureDiagnostics, reasonCode } from './capture_diagnostics.js';

const shortItem = i => ({ id: i.id, url: typeof i.url === 'string' ? i.url.slice(0, 8193) : '', finalUrl: typeof i.finalUrl === 'string' ? i.finalUrl.slice(0, 8193) : '',
  filename: typeof i.filename === 'string' ? i.filename.slice(0, 32769) : '', startTime: typeof i.startTime === 'string' ? i.startTime.slice(0, 64) : '',
  state: i.state, danger: i.danger, totalBytes: i.totalBytes, byExtensionId: i.byExtensionId, error: i.error, paused: i.paused, policyBlocked: i.policyBlocked === true });
const hex = () => [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');

/** Install synchronously. All async initialization is fail-closed; no top-level await.
 * Toolbar bypass: top frame (0) only, one use, 60 seconds, cleared by worker
 * restart. No keyboard assumptions or content-script message authority.
 */
export function installCapture({ chrome, bridge, journal, agent, now = () => performance.now(), timeoutMs = 1000 }) {
  const storage = { get: async k => (await chrome.storage.local.get(k))[k], set: (k, v) => chrome.storage.local.set({ [k]: v }) };
  journal ??= new Journal({ storage });
  const tracker = new RequestTracker({ now, onConflict: id => agent?.browserChanged?.(id, { error: { current: 'request_ambiguous' } }) });
  const steps = new BoundedSteps(16, timeoutMs);
  const initSteps = new BoundedSteps(1, timeoutMs);
  const browserSteps = new BoundedSteps(16, timeoutMs);
  const mirror = new SettingsMirror({ bridge, timeoutMs });
  const created = new Map(), active = new Map(), pins = new Map(), ownCancel = new Set(), manual = new Map();
  const intents = new Set();
  const liveIntent = m => m && m.epoch === epoch && now() - m.at < 60000;
  const intentFor = i => { const m = manual.get(i.id); return liveIntent(m) && m.url === i.url && i.byExtensionId === chrome.runtime.id ? m : undefined; };
  const diagnostics = new CaptureDiagnostics(chrome.storage.session);
  let ready = false, refreshing = null, identity = null, identityLoad = null, bypass = null, lastReason = '', menuMade = false, epoch = 0;
  function notice(reason, text = `Kept in browser: ${reasonCode(reason)}. Open Velqra options for capture status.`) {
    lastReason = reason;
    const safe = text.slice(0, 600);
    void steps.run(() => chrome.action.setTitle({ title: safe })).catch(() => {});
    void steps.run(() => chrome.action.setBadgeText({ text: reason ? '!' : '' })).catch(() => {});
  }
  function record(i, event, reason = 'pending', facts = tracker.facts(i)) {
    const entry = created.get(i.id);
    const code = entry?.firstReason ?? (reason === 'pending' ? entry?.lastDecision ?? 'pending' : reasonCode(reason));
    if (entry && !entry.firstReason && code !== 'pending' && code !== 'captured' && code !== 'capture_pending') entry.firstReason = code;
    if (entry && code !== 'pending') entry.lastDecision = code;
    diagnostics.record({ id: i.id, event, ...facts, reason: code, decision: code === 'pending' || code === 'capture_pending' ? 'pending' : code === 'captured' ? 'capture' : 'keep' });
  }
  const browser = {
    pause: id => chrome.downloads.pause(id), resume: id => chrome.downloads.resume(id), search: q => chrome.downloads.search(q),
    cancel: id => { ownCancel.add(id); return chrome.downloads.cancel(id); },
  };
  agent ??= new CaptureAgent({ browser, bridge, journal, onStatus: r => { if (r.held) notice('reconcile', 'Download ownership needs review in Velqra.'); } });
  function prune() {
    tracker.prune();
    for (const [id, v] of created) if (!active.has(id) && now() - v.at >= 120000) created.delete(id);
    for (const [id, v] of manual) if (now() - v.at >= 60000) manual.delete(id);
    for (const m of intents) if (!liveIntent(m)) intents.delete(m);
    const records = journal.list();
    for (const [id, request] of pins) {
      if (!active.has(id) && !records.some(r => r.id === id && r.receipt && !TERMINAL.includes(r.state))) { tracker.unpin(request); pins.delete(id); }
    }
  }
  async function loadIdentity() {
    if (!identityLoad) identityLoad = initSteps.run(async () => {
      let v = await storage.get('velqra-capture-identity');
      if (v === undefined) { v = { install: hex(), profile: hex() }; await storage.set('velqra-capture-identity', v); }
      if (!v || !/^[0-9a-f]{32}$/.test(v.install) || !/^[0-9a-f]{32}$/.test(v.profile)) throw Error('identity');
      return { install: v.install, profile: v.profile };
    });
    identity = await identityLoad;
  }
  function requestId(i) {
    const start = Date.parse(i.startTime);
    if (!identity || !Number.isSafeInteger(i.id) || i.id < 0 || !Number.isSafeInteger(start) || start < 0) throw Error('identity');
    return `v1_${identity.install}_${identity.profile}_${i.id}_${start}`;
  }
  function refresh() {
    if (refreshing) return refreshing;
    ready = false;
    const generation = epoch;
    refreshing = (async () => {
      try {
        // Called on EVERY worker evaluation, including an offline startup.
        await loadIdentity();
        if (generation !== epoch) throw Error('offline');
        await steps.run(() => agent.recover());
        if (generation !== epoch || bridge.state !== 'ready' || !(await mirror.refresh()) || generation !== epoch || bridge.state !== 'ready') throw Error('unavailable');
        ready = mirror.snapshot?.transfer_capable === true;
        if (mirror.problem) notice('settings', mirror.problem);
        return true;
      } catch { mirror.invalidate(); notice('unavailable'); return false; }
      finally { refreshing = null; prune(); }
    })();
    return refreshing;
  }
  function context(i, excludeId, intent) {
    const observed = tracker.match(i, { excludeId, manualKey: intent?.key });
    if (!observed) return { appReady: bridge.state === 'ready', correlated: false };
    const useBypass = !!bypass && now() - bypass.at < 60000 && bypass.tabId === (intent?.tabId ?? observed.tabId) && (intent?.frameId ?? observed.frameId) === 0;
    if (useBypass) bypass = null;
    return { ...observed, appReady: bridge.state === 'ready', bypass: useBypass };
  }
  async function process(i) {
    // Chrome may emit created/filename before downloads.download resolves its ID.
    // Wait for the bounded API call; URL alone never grants self-origin authority.
    if (i.byExtensionId === chrome.runtime.id) {
      const pending = [...intents].filter(m => liveIntent(m) && m.url === i.url && m.id === null);
      if (pending.length) await Promise.all(pending.map(m => m.bound));
    }
    const originalUrl = i.url;
    const report = reason => { record(i, 'decision', reason, tracker.facts({ ...i, url: originalUrl })); notice(reasonCode(reason)); };
    // i is a bounded allowlisted snapshot; never retain the browser event object.
    if (!ready || bridge.state !== 'ready') { report(bridge.state === 'ready' && /engine/i.test(mirror.problem) ? 'engine_not_capable' : 'not_ready'); return; }
    if (created.get(i.id)?.ambiguous) { report('ambiguous_request'); return; }
    const m = intentFor(i);
    const excludeId = undefined;
    const c = context(i, excludeId, m), settings = mirror.snapshot;
    // Only an explicitly returned downloads.download ID may bypass self-origin.
    if (m) { i.byExtensionId = undefined; manual.delete(i.id); intents.delete(m); }
    // Leading-dot-only names deliberately stay in Chrome (core category differs).
    if (/^\.[^.]+$/.test(i.filename.split(/[\\/]/).pop() ?? '')) { report('ineligible_suffix'); return; }
    i.url = i.finalUrl || i.url; // GET replay uses final URL, after full-chain checks.
    const decision = decide(i, settings, c);
    if (decision.action !== 'capture' || i.paused === true) {
      report(decision.action === 'capture' ? 'already_paused' : !c.correlated && ['method', 'correlation'].includes(decision.reason) ? tracker.facts({ ...i, url: originalUrl }, { excludeId }).reason : decision.reason); return;
    }
    if (active.size >= 16 || pins.size >= 256) { report('busy'); return; }
    const key = requestId(i);
    tracker.pin(c.id); pins.set(i.id, c.id);
    const id = i.id;
    // Keep a slot until the real agent settles even if the timeout has fired.
    const generation = epoch;
    const p = Promise.resolve().then(async () => {
      let found, settled = false;
      const suffix = name => (name.split(/[\\/]/).pop() ?? '').split('.').at(-1)?.toLowerCase();
      // suggest() releases naming. Chrome may still report an empty target until
      // its filename change event; the proposed basename is not the final path.
      // Wait only within a bounded preflight, before the agent can pause anything.
      for (let attempt = 0; attempt < 21; attempt++) {
        found = await browserSteps.run(() => chrome.downloads.search({ id }));
        if (generation !== epoch || !ready || bridge.state !== 'ready') { report('not_ready'); return; }
        const candidate = Array.isArray(found) && found.length === 1 ? found[0] : null;
        if (!candidate || candidate.state !== 'in_progress') break;
        if (candidate.filename) {
          if (suffix(candidate.filename) !== suffix(i.filename)) { report('browser_changed'); return; }
          if (created.get(id)?.item.filename === candidate.filename) { settled = true; break; }
        }
        if (attempt < 20) await new Promise(resolve => setTimeout(resolve, 25));
      }
      if (created.get(id)?.ambiguous) { report('ambiguous_request'); return; }
      if (generation !== epoch || !ready || bridge.state !== 'ready') { report('not_ready'); return; }
      if (!Array.isArray(found) || found.length !== 1 || found[0].id !== id) { record(i, 'decision', 'other_owner'); notice('other_owner'); return; }
      const current = found[0];
      if (current.state === 'complete') { report('already_complete'); return; }
      if (current.state !== 'in_progress' || (current.byExtensionId && !(m && current.byExtensionId === chrome.runtime.id))) { report('other_owner'); return; }
      if (current.paused || current.danger !== 'safe' || current.error) { report('blocked'); return; }
      if (!settled || (current.finalUrl || current.url) !== i.url) { report('browser_changed'); return; }
      // Reapply all policy to the finalized name; no rename is proposed by us.
      i.filename = current.filename;
      if ((i.filename.split(/[\\/]/).pop() ?? '').startsWith('.')) { report('ineligible_suffix'); return; }
      // Credentials may have appeared while search was pending. Re-read the same
      // chain before the agent can pause; do not consume a second bypass gesture.
      if (m && !liveIntent(m)) { report('request_changed'); return; }
      const fresh = tracker.match({ ...i, url: originalUrl }, { excludeId, manualKey: m?.key });
      const checked = { ...fresh, appReady: bridge.state === 'ready', bypass: c.bypass };
      if (decide(i, settings, checked).action !== 'capture') { report('request_changed'); return; }
      const result = await agent.capture(i, settings, checked, { requestId: key, ...(m ? { browserOrigin: chrome.runtime.id } : {}) });
      const reason = result?.state === 'HandedOff' ? 'captured' : result?.diagnostic ?? result?.reason ?? 'capture_pending';
      record(i, 'decision', reason, tracker.facts({ ...i, url: originalUrl }, { excludeId }));
      if (reason === 'captured') { notice('', 'Captured by Velqra.'); } else notice(reasonCode(reason));
      return result;
    });
    active.set(id, p);
    p.then(() => { active.delete(id); ownCancel.delete(id); prune(); }, () => { active.delete(id); ownCancel.delete(id); prune(); });
    try { await steps.run(() => p); }
    catch { report('capture_pending'); }
  }
  chrome.webRequest.onBeforeRequest.addListener(d => {
    const matching = [...intents].filter(m => liveIntent(m) && m.url === d.url);
    tracker.before(d, { manualKey: matching.length === 1 ? matching[0].key : undefined });
  }, { urls: ['http://*/*', 'https://*/*'] });
  chrome.webRequest.onBeforeSendHeaders.addListener(d => tracker.headers(d), { urls: ['http://*/*', 'https://*/*'] }, ['requestHeaders', 'extraHeaders']);
  chrome.webRequest.onBeforeRedirect.addListener(d => tracker.redirect(d), { urls: ['http://*/*', 'https://*/*'] });
  chrome.webRequest.onHeadersReceived.addListener(d => tracker.response(d), { urls: ['http://*/*', 'https://*/*'] });
  chrome.webRequest.onCompleted.addListener(d => tracker.end(d), { urls: ['http://*/*', 'https://*/*'] });
  chrome.webRequest.onErrorOccurred.addListener(d => tracker.end(d), { urls: ['http://*/*', 'https://*/*'] });
  chrome.downloads.onCreated.addListener(i => {
    prune();
    record(shortItem(i), 'created');
    if (!Number.isSafeInteger(i.id) || created.size >= 256 || created.has(i.id)) return;
    const entry = { at: now(), item: shortItem(i), ambiguous: false };
    // A redirect may leave finalUrl unknown at onCreated. Refuse competing
    // original-URL/timestamp identities before either can reach destructive admission.
    for (const [id, prior] of created) {
      if (prior.item.url === i.url && Number.isFinite(Date.parse(i.startTime)) && Date.parse(prior.item.startTime) === Date.parse(i.startTime)) {
        prior.ambiguous = true; entry.ambiguous = true;
        agent.browserChanged?.(id, { error: { current: 'request_ambiguous' } });
      }
    }
    created.set(i.id, entry);
    tracker.match(i); // bind once at creation; concurrent claimants invalidate the observation.
  });
  chrome.downloads.onChanged.addListener(d => {
    agent.browserChanged?.(d.id, d);
    const v = created.get(d.id);
    if (v) for (const k of ['filename', 'state', 'error', 'danger', 'paused']) if (d[k]?.current !== undefined) v.item[k] = d[k].current;
    record(v?.item ?? { id: d.id }, 'changed');
    if (d.error?.current === 'USER_CANCELED' && !ownCancel.has(d.id)) agent.userCancel(d.id);
  });
  chrome.downloads.onDeterminingFilename.addListener((i, suggest) => {
    record(shortItem(i), 'filename');
    // Release Chrome unconditionally BEFORE starting the async ownership flow.
    // We never propose a name. A tiny completion is handled by agent.pause/search.
    try { suggest(); } catch { record(shortItem(i), 'decision', 'filename'); notice('filename'); return true; }
    const v = created.get(i.id);
    if (!v || v.used || active.has(i.id)) { if (!v) { record(shortItem(i), 'decision', 'unseen_request'); notice('unseen_request'); } return true; }
    v.used = true;
    const snapshot = shortItem({ ...i, startTime: v.item.startTime, state: v.item.state === 'interrupted' ? 'interrupted' : i.state, error: v.item.error || i.error });
    void process(snapshot).catch(() => { record(snapshot, 'decision', 'capture_error'); notice('capture_error'); });
    return true;
  });
  chrome.action.onClicked.addListener(tab => {
    if (!Number.isSafeInteger(tab?.id) || tab.id < 0) return;
    bypass = bypass?.tabId === tab.id ? null : { tabId: tab.id, frameId: 0, at: now(), url: typeof tab.url === 'string' ? tab.url : '' };
    notice('bypass', bypass ? 'The next top-frame download in this tab stays in the browser (60 seconds).' : 'One-shot browser bypass cleared.');
  });
  // Menu creation belongs to onInstalled: creating the same ID on every worker
  // wake would report a duplicate. The listener itself is always installed now.
  chrome.runtime.onInstalled.addListener(details => {
    if (!menuMade) { menuMade = true; try { chrome.contextMenus.create({ id: 'velqra-download', title: 'Download with Velqra', contexts: ['link'] }); } catch { notice('menu'); } }
    if (details?.reason === 'install') void steps.run(() => chrome.runtime.openOptionsPage()).catch(() => {});
  });
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId !== 'velqra-download') return;
    void manualEntry({ linkUrl: typeof info.linkUrl === 'string' ? info.linkUrl.slice(0, 8193) : '', frameId: info.frameId }, { id: tab?.id }).catch(() => notice('manual', 'Kept in browser: this link could not be safely captured.'));
  });
  async function manualEntry(info, tab) {
    prune();
    if (!ready || bridge.state !== 'ready' || intents.size >= 16) { notice('not_ready'); return; }
    // A user gesture asks Chrome to download; only LIVE evidence can authorize
    // core ownership. Reserve the bounded intent before Chrome emits any events.
    const url = typeof info.linkUrl === 'string' ? info.linkUrl : '';
    try { if (url.length > 8192 || !['http:', 'https:'].includes(new URL(url).protocol)) throw Error('url'); } catch { notice('scheme'); return; }
    let release;
    const m = { url, at: now(), key: hex(), epoch, tabId: tab?.id, frameId: info.frameId ?? 0, id: null, bound: new Promise(resolve => { release = resolve; }) };
    intents.add(m);
    try {
      const id = await steps.run(() => chrome.downloads.download({ url }));
      if (bridge.state !== 'ready' || !Number.isSafeInteger(id) || id < 0 || !liveIntent(m) || manual.has(id)) throw Error('manual');
      m.id = id; manual.set(id, m);
    } catch { intents.delete(m); notice('not_ready'); }
    finally { release(); }
  }
  queueMicrotask(() => { void refresh(); });
  return {
    refresh,
    disconnected() { epoch++; ready = false; mirror.invalidate(); notice('unavailable'); },
    status() { prune(); return { ready: ready && bridge.state === 'ready', settingsVersion: mirror.version, problem: mirror.problem, reason: lastReason, observations: tracker.size, created: created.size, active: active.size, pinned: pins.size, manual: manual.size, liveOperations: steps.live }; },
  };
}
