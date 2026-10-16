// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installCapture } from '../src/capture.js';
import { RequestTracker } from '../src/request_tracker.js';
import { SettingsMirror } from '../src/settings_mirror.js';
import { BoundedSteps } from '../src/bounded.js';

const settings = { mode: 'on', extensions: ['zip'], allowed_sites: [], excluded_sites: [], transfer_capable: true, problem: null };
const sid = 'a'.repeat(32);

test('unavailable transfer engine keeps the browser untouched and exposes its problem', async () => {
  const f = setup();
  const original = f.bridge.request;
  f.bridge.request = async (...args) => {
    const e = await original(...args);
    e.body.payload.transfer_capable = false;
    e.body.payload.problem = 'Pinned transfer engine unavailable.';
    return e;
  };
  await f.app.refresh(); f.observe(); await f.filename();
  assert.equal(f.log.some(x => ['capture', 'pause', 'cancel'].includes(x[0])), false);
  assert.match(f.app.status().problem, /Pinned transfer engine unavailable/);
});
const event = () => { const listeners = []; return { listeners, addListener(f, ...args) { listeners.push(f); this.args = args; }, fire(...a) { return listeners.map(f => f(...a)); } }; };
const tick = async () => { for (let i = 0; i < 25; i++) await new Promise(r => setImmediate(r)); };
const item = (extra = {}) => ({ id: 7, url: 'https://files.test/a.zip', finalUrl: 'https://files.test/a.zip', filename: 'a.zip', state: 'in_progress', danger: 'safe', startTime: new Date().toISOString(), totalBytes: 5000, ...extra });
function setup(options = {}) {
  const log = [], values = {}, items = new Map();
  const chrome = {
    runtime: { id: 'v'.repeat(32), onInstalled: event(), openOptionsPage: async () => { log.push('options'); } },
    storage: { local: { get: async k => ({ [k]: values[k] }), set: async v => { Object.assign(values, structuredClone(v)); } } },
    downloads: { onCreated: event(), onChanged: event(), onDeterminingFilename: event(),
      pause: async id => { log.push(['pause', id]); }, resume: async id => { log.push(['resume', id]); }, cancel: async id => { log.push(['cancel', id]); },
      search: async ({ id }) => items.has(id) ? [items.get(id)] : [], download: async o => { log.push(['download', o]); return 99; } },
    webRequest: Object.fromEntries(['onBeforeRequest', 'onBeforeSendHeaders', 'onBeforeRedirect', 'onCompleted', 'onErrorOccurred'].map(k => [k, event()])),
    action: { onClicked: event(), setTitle: async o => log.push(['title', o.title]), setBadgeText: async o => log.push(['badge', o.text]) },
    contextMenus: { onClicked: event(), create: o => log.push(['menu', o]) },
  };
  const bridge = { state: 'ready', async request(body, { requestId }) { log.push(body.type); return { version: 1, generation: 1, request_id: requestId, session_id: sid, body: { type: body.type === 'health' ? 'health_reply' : 'settings_reply', payload: structuredClone(settings) } }; } };
  const journal = { list: () => [], load: async () => {} };
  const agent = { async recover() { log.push('recover'); }, async capture(i, s, c, o) { log.push(['capture', structuredClone(i), structuredClone(s), structuredClone(c), o]); }, userCancel: id => log.push(['user', id]) };
  const app = installCapture({ chrome, bridge, journal, agent, timeoutMs: 20, ...options });
  function observe(i = item(), extra = {}) {
    const d = { requestId: 'r1', url: i.url, method: 'GET', tabId: 3, frameId: 0, documentId: 'doc1', timeStamp: Date.parse(i.startTime), type: 'main_frame', ...extra };
    chrome.webRequest.onBeforeRequest.fire(d);
    chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: [] });
    items.set(i.id, i);
    chrome.downloads.onCreated.fire(i);
    return d;
  }
  async function filename(i = items.get(7) ?? item()) { let calls = 0; const ret = chrome.downloads.onDeterminingFilename.fire(i, (...a) => { calls++; assert.deepEqual(a, []); }); await tick(); return { calls, ret }; }
  return { chrome, bridge, journal, agent, app, log, values, items, observe, filename };
}

test('all Chrome listeners register synchronously; recovery precedes capture; filename is suggested exactly once', async () => {
  const f = setup();
  for (const e of Object.values(f.chrome.webRequest)) assert.equal(e.listeners.length, 1);
  for (const k of ['onCreated', 'onChanged', 'onDeterminingFilename']) assert.equal(f.chrome.downloads[k].listeners.length, 1);
  assert.deepEqual(f.chrome.webRequest.onBeforeSendHeaders.args[1], ['requestHeaders', 'extraHeaders']);
  await f.app.refresh();
  f.observe(); assert.equal(f.log.some(x => x[0] === 'capture'), false);
  assert.deepEqual(await f.filename(), { calls: 1, ret: [true] });
  assert.ok(f.log.indexOf('recover') >= 0 && f.log.indexOf('recover') < f.log.findIndex(x => x[0] === 'capture'));
});

for (const [name, change, headers] of [
  ['complete', { state: 'complete' }], ['interrupted', { state: 'interrupted', error: 'USER_CANCELED' }],
  ['other extension', { byExtensionId: 'other' }], ['danger', { danger: 'dangerous' }],
  ['unsupported suffix', { filename: 'a.txt' }], ['leading-dot file deliberately stays browser', { filename: '.zip' }],
  ['Cookie', {}, [{ name: 'cOoKiE', value: 'secret' }]], ['Authorization', {}, [{ name: 'Authorization', value: 'secret' }]],
]) test(`keeps ${name} without handing off or changing filename`, async () => {
  const f = setup(); await f.app.refresh(); const i = item(change); const d = f.observe(i);
  if (headers) f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: headers });
  assert.equal((await f.filename(i)).calls, 1);
  assert.equal(f.log.some(x => x[0] === 'capture' || x[0] === 'pause' || x[0] === 'cancel'), false);
});

test('unseen and ambiguous requests fail closed', async () => {
  for (const ambiguous of [false, true]) {
    const f = setup(); await f.app.refresh(); const i = item();
    if (ambiguous) { f.observe(i); f.observe(i, { requestId: 'r2' }); } else f.chrome.downloads.onCreated.fire(i);
    await f.filename(i); assert.equal(f.log.some(x => x[0] === 'capture'), false);
  }
});

test('redirects use finalUrl for prepare and all hops must have clean headers', async () => {
  for (const credential of [false, true]) {
    const f = setup(); await f.app.refresh(); const i = item({ finalUrl: 'https://cdn.test/b.zip' }); const d = f.observe(i);
    if (credential) f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: [{ name: 'Cookie', value: 'never-export' }] });
    f.chrome.webRequest.onBeforeRedirect.fire({ ...d, redirectUrl: i.finalUrl });
    f.chrome.webRequest.onBeforeRequest.fire({ ...d, url: i.finalUrl });
    f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, url: i.finalUrl, requestHeaders: [] });
    f.items.set(i.id, i);
    await f.filename(i); const call = f.log.find(x => x[0] === 'capture');
    assert.equal(!!call, !credential); if (call) assert.equal(call[1].url, i.finalUrl);
    assert.equal(JSON.stringify(f.app.status()).includes('never-export'), false);
  }
});

test('bypass is one-shot, tab and frame scoped and expires', async () => {
  for (const [tabId, frameId, elapsed, bypass] of [[3, 0, 0, true], [4, 0, 0, false], [3, 1, 0, false], [3, 0, 60001, false]]) {
    let now = 0; const f = setup({ now: () => now }); await f.app.refresh();
    f.chrome.action.onClicked.fire({ id: 3 }); now = elapsed;
    f.observe(item(), { tabId, frameId }); await f.filename();
    assert.equal(f.log.some(x => x[0] === 'capture'), !bypass);
  }
  const f = setup(); await f.app.refresh(); f.chrome.action.onClicked.fire({ id: 3 }); f.observe(); await f.filename();
  f.observe(item({ id: 8, url: 'https://files.test/b.zip', finalUrl: 'https://files.test/b.zip' }), { requestId: 'r2' });
  await f.filename(item({ id: 8, url: 'https://files.test/b.zip', finalUrl: 'https://files.test/b.zip' }));
  assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
});

test('filename event releases exactly once despite hung agent, thrown callback or unavailable initialization', async () => {
  for (const scenario of ['hung', 'throw', 'offline', 'recover']) {
    const f = setup();
    if (scenario === 'recover') f.agent.recover = () => new Promise(() => {});
    else await f.app.refresh();
    if (scenario === 'hung') f.agent.capture = () => new Promise(() => {});
    if (scenario === 'throw') f.agent.capture = () => { throw Error('secret'); };
    if (scenario === 'offline') f.bridge.state = 'closed';
    f.observe(); assert.equal((await f.filename()).calls, 1);
    await new Promise(r => setTimeout(r, 25));
  }
});

test('stable installation/profile/download/start-time request identity survives adapter restart', async () => {
  const f = setup(); await f.app.refresh(); f.observe(); await f.filename();
  const a = f.log.find(x => x[0] === 'capture')[4].requestId;
  const i = item(); i.startTime = f.items.get(7).startTime;
  const second = installCapture({ chrome: f.chrome, bridge: f.bridge, journal: f.journal, agent: f.agent });
  await second.refresh();
  // Drive only the second adapter's listeners; a worker restart has no old listeners.
  const d = { requestId: 'new', url: i.url, method: 'GET', tabId: 3, frameId: 0, type: 'main_frame', timeStamp: Date.parse(i.startTime) };
  f.chrome.webRequest.onBeforeRequest.listeners.at(-1)(d); f.chrome.webRequest.onBeforeSendHeaders.listeners.at(-1)({ ...d, requestHeaders: [] });
  f.chrome.downloads.onCreated.listeners.at(-1)(i); f.chrome.downloads.onDeterminingFilename.listeners.at(-1)(i, () => {}); await tick();
  assert.equal(f.log.filter(x => x[0] === 'capture').at(-1)[4].requestId, a);
});

test('independent cancellation only before our own cancel invocation', async () => {
  const f = setup(); await f.app.refresh(); f.observe();
  f.chrome.downloads.onChanged.fire({ id: 7, error: { current: 'USER_CANCELED' }, state: { current: 'interrupted' } });
  assert.deepEqual(f.log.filter(x => x[0] === 'user'), [['user', 7]]);
});

test('tracker caps entries and lifetime while never evicting pinned receipt evidence', () => {
  let now = 0; const t = new RequestTracker({ now: () => now, perTab: 2, maxEntries: 3 });
  const add = (id, tabId = 1) => { t.before({ requestId: id, tabId, frameId: 0, method: 'GET', url: `https://f.test/${id}.zip`, timeStamp: Date.now() }); t.headers({ requestId: id, requestHeaders: [] }); };
  add('a'); t.pin('a'); add('b'); add('c'); assert.equal(t.size, 2); assert.ok(t.has('a')); assert.equal(t.has('b'), false);
  now = 120001; t.prune(); assert.equal(t.size, 1); assert.ok(t.has('a'));
  t.unpin('a'); t.prune(); assert.equal(t.size, 0);
});

test('settings reply identity and mode fail closed; cached version advances only on validated replies', async () => {
  const f = setup(); const m = new SettingsMirror({ bridge: f.bridge, timeoutMs: 10 });
  assert.equal(m.snapshot, null); assert.equal(await m.refresh(), true); assert.equal(m.version, 1);
  assert.equal(m.snapshot.mode, 'on');
  const original = f.bridge.request.bind(f.bridge);
  for (const corrupt of [e => e.request_id = 'other', e => e.session_id = 'b'.repeat(32), e => e.generation = 2, e => e.body.payload.mode = 'bad', e => e.body.type = 'error']) {
    f.bridge.request = async (...a) => { const e = await original(...a); if (a[0].type !== 'health') corrupt(e); return e; };
    assert.equal(await m.refresh(), false); assert.equal(m.snapshot, null); assert.equal(m.version, 1);
  }
});

test('manual entry refuses unsupported/unseen links with a short visible notice; no permission request', async () => {
  const f = setup(); await f.app.refresh();
  for (const linkUrl of ['javascript:alert(1)', 'https://files.test/unseen.zip', 'https://files.test/a.txt']) f.chrome.contextMenus.onClicked.fire({ menuItemId: 'velqra-download', linkUrl, frameId: 0 }, { id: 3 });
  await tick(); assert.equal(f.log.some(x => x[0] === 'download'), false); assert.ok(f.log.some(x => x[0] === 'title' && x[1].includes('browser')));
});

export { setup, item, tick, settings };

for (const [mode, allowed_sites, captures] of [['off', [], false], ['per_site', [], false], ['per_site', ['files.test'], true], ['on', [], true]]) test(`snapshot mode ${mode}/${allowed_sites} is enforced`, async () => {
  const f = setup(); const original = f.bridge.request.bind(f.bridge);
  f.bridge.request = async (...args) => { const e = await original(...args); if (e.body.type === 'settings_reply') e.body.payload = { ...settings, mode, allowed_sites }; return e; };
  await f.app.refresh(); f.observe(); await f.filename(); assert.equal(f.log.some(x => x[0] === 'capture'), captures);
});

for (const scenario of ['missing-headers', 'login-redirect', 'signed-final', 'post', 'failed-request', 'wrong-hop', 'missing-created']) test(`negative request evidence: ${scenario}`, async () => {
  const f = setup(); await f.app.refresh(); let i = item();
  if (scenario === 'missing-headers') {
    f.chrome.webRequest.onBeforeRequest.fire({ requestId: 'r1', tabId: 3, frameId: 0, url: i.url, method: 'GET', timeStamp: Date.now() }); f.chrome.downloads.onCreated.fire(i);
  } else {
    const d = f.observe(i, scenario === 'post' ? { method: 'POST' } : {});
    if (scenario === 'login-redirect' || scenario === 'signed-final') {
      i = item({ finalUrl: scenario === 'login-redirect' ? 'https://files.test/login/file.zip' : 'https://files.test/a.zip?token=secret' });
      f.chrome.webRequest.onBeforeRedirect.fire({ ...d, redirectUrl: i.finalUrl });
      f.chrome.webRequest.onBeforeRequest.fire({ ...d, url: i.finalUrl });
      f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, url: i.finalUrl, requestHeaders: [] });
      f.items.set(i.id, i);
    }
    if (scenario === 'failed-request') f.chrome.webRequest.onErrorOccurred.fire({ ...d, error: 'net::ERR_FAILED' });
    if (scenario === 'wrong-hop') f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, url: 'https://wrong.test/a', requestHeaders: [] });
    if (scenario === 'missing-created') i = item({ id: 99 });
  }
  await f.filename(i); assert.equal(f.log.some(x => x[0] === 'capture'), false);
});

test('first-run explanation and menu creation do not request optional permission or modify another extension', async () => {
  const f = setup();
  f.chrome.runtime.onInstalled.fire({ reason: 'install' }); await tick();
  assert.equal(f.log.filter(x => x[0] === 'menu').length, 1); assert.equal(f.log.filter(x => x === 'options').length, 1);
  f.chrome.runtime.onInstalled.fire({ reason: 'update' }); await tick(); assert.equal(f.log.filter(x => x === 'options').length, 1);
});

test('disconnect during settings await fences the old initializer, including same-ready reconnect', async () => {
  const f = setup(); let release;
  const original = f.bridge.request.bind(f.bridge);
  f.bridge.request = async (...args) => { const e = await original(...args); if (args[0].type === 'settings_get') await new Promise(r => { release = r; }); return e; };
  const pending = f.app.refresh(); await tick(); f.app.disconnected(); release();
  assert.equal(await pending, false); assert.equal(f.app.status().ready, false);
  f.bridge.request = original; assert.equal(await f.app.refresh(), true);
});

test('invalidated settings mirror cannot publish a late old-session snapshot', async () => {
  const f = setup(); await f.app.refresh(); const m = new SettingsMirror({ bridge: f.bridge }); const original = f.bridge.request.bind(f.bridge); let release;
  f.bridge.request = async (...args) => { const e = await original(...args); if (args[0].type === 'settings_get') await new Promise(r => { release = r; }); return e; };
  const pending = m.refresh(); await tick(); m.invalidate(); release(); assert.equal(await pending, false); assert.equal(m.snapshot, null);
});

test('correlation pins unresolved receipts through expiry and overflow; terminal records release evidence', async () => {
  let now = 0; const f = setup({ now: () => now }); await f.app.refresh(); f.agent.capture = async () => {}; f.journal.list = () => [{ id: 7, receipt: { task_id: 1 }, state: 'ReconcileRequired' }];
  f.observe(); await f.filename(); assert.equal(f.app.status().pinned, 1);
  now = 120001; assert.equal(f.app.status().observations, 1);
  f.journal.list = () => [{ id: 7, receipt: { task_id: 1 }, state: 'HandedOff' }];
  f.app.status(); assert.equal(f.app.status().observations, 0);
});

test('tracker enforces global cap even across many tabs; all-pinned budget refuses new evidence', () => {
  const t = new RequestTracker({ maxEntries: 3, perTab: 2 });
  for (let n = 0; n < 3; n++) { t.before({ requestId: `${n}`, tabId: n, frameId: 0, method: 'GET', url: `https://x.test/${n}`, timeStamp: Date.now() }); t.pin(`${n}`); }
  t.before({ requestId: 'new', tabId: 5, frameId: 0, method: 'GET', url: 'https://x.test/new', timeStamp: Date.now() }); assert.equal(t.size, 3); assert.equal(t.has('new'), false);
});

test('redirect overflow, missing prior headers, and chain identity mismatch fail closed', () => {
  for (const mode of ['overflow', 'missing', 'identity']) {
    const t = new RequestTracker(); const i = item(); const d = { requestId: 'r', url: i.url, method: 'GET', tabId: 3, frameId: 0, type: 'main_frame', timeStamp: Date.parse(i.startTime) };
    t.before(d);
    if (mode !== 'missing') t.headers({ ...d, requestHeaders: [] });
    if (mode === 'overflow') for (let n = 0; n < 10; n++) { t.redirect({ ...d, redirectUrl: i.url }); t.headers({ ...d, requestHeaders: [] }); }
    if (mode === 'missing') { t.redirect({ ...d, redirectUrl: i.url }); t.headers({ ...d, requestHeaders: [] }); }
    if (mode === 'identity') t.before({ ...d, frameId: 1 });
    assert.notEqual(t.match(i)?.correlated, true);
  }
});

test('manual capture is a new browser action; the resulting request must independently pass credentials and identity checks', async () => {
  const f = setup(); await f.app.refresh(); f.observe();
  f.chrome.contextMenus.onClicked.fire({ menuItemId: 'velqra-download', linkUrl: item().url, frameId: 0 }, { id: 3 }); await tick();
  assert.deepEqual(f.log.find(x => x[0] === 'download'), ['download', { url: item().url }]);
  // An extension-origin result cannot pass without its exact returned ID, even for our ID.
  const i = item({ id: 98, byExtensionId: f.chrome.runtime.id }); f.chrome.downloads.onCreated.fire(i); await f.filename(i);
  assert.equal(f.log.some(x => x[0] === 'capture'), false);
});

test('a stuck agent cannot retain more than sixteen flows or accumulate with traffic', async () => {
  const f = setup(); await f.app.refresh(); let calls = 0, releases = [];
  f.agent.capture = () => { calls++; return new Promise(r => releases.push(r)); };
  for (let n = 0; n < 100; n++) {
    const i = item({ id: n, url: `https://files.test/${n}.zip`, finalUrl: `https://files.test/${n}.zip` }); f.observe(i, { requestId: `r${n}` });
    f.chrome.downloads.onDeterminingFilename.fire(i, () => {});
    assert.ok(f.app.status().active <= 16);
  }
  await tick(); assert.equal(calls, 16); assert.equal(f.app.status().active, 16);
  for (const release of releases) release(); await tick(); assert.equal(f.app.status().active, 0);
});

function realSetup() {
  const f = setup({ agent: undefined, journal: undefined });
  const oldRequest = f.bridge.request.bind(f.bridge); const receipts = new Map();
  f.bridge.request = async (body, opts) => {
    if (['health', 'settings_get'].includes(body.type)) return oldRequest(body, opts);
    f.log.push(['wire', body.type, structuredClone(body.payload)]);
    if (!receipts.has(opts.requestId)) receipts.set(opts.requestId, { task_id: receipts.size + 1, fingerprint: 'f'.repeat(64) });
    const types = { prepare: ['prepared', 'prepared'], begin_handoff: ['armed', 'armed'], status: ['status_reply', 'armed'], commit: ['committed', 'committed'], abort: ['aborted', 'aborted'], reconcile: ['reconciled', 'ownership_unknown'] };
    const [type, state] = types[body.type];
    return { version: 1, generation: 1, session_id: sid, request_id: opts.requestId, body: { type, payload: { ...receipts.get(opts.requestId), state } } };
  };
  f.chrome.downloads.pause = async id => { f.log.push(['pause', id]); const i = f.items.get(id); if (i.state === 'in_progress') i.paused = true; };
  f.chrome.downloads.resume = async id => { f.log.push(['resume', id]); f.items.get(id).paused = false; };
  f.chrome.downloads.cancel = async id => {
    f.log.push(['cancel', id]); const i = f.items.get(id); i.state = 'interrupted'; i.error = 'USER_CANCELED';
    f.chrome.downloads.onChanged.fire({ id, state: { current: 'interrupted' }, error: { current: 'USER_CANCELED' } });
  };
  const set = f.chrome.storage.local.set;
  f.chrome.storage.local.set = async v => { await set(v); for (const r of v['velqra-capture-v1']?.records ?? []) f.log.push(['durable', r.id, r.state]); };
  return f;
}

test('real agent through Chrome adapter: durable markers and Armed precede cancel; confirmed precedes commit', async () => {
  const f = realSetup(); await f.app.refresh(); f.observe(); await f.filename();
  const pos = (kind, value) => f.log.findIndex(x => x[0] === kind && (kind === 'durable' ? x[2] === value : x[1] === value));
  assert.ok(pos('wire', 'prepare') > pos('pause', 7));
  for (const state of ['ReceiptStored', 'CancelIntentStored', 'CancelRequested']) assert.ok(pos('durable', state) >= 0 && pos('durable', state) < pos('cancel', 7));
  assert.ok(pos('wire', 'begin_handoff') < pos('cancel', 7));
  assert.ok(pos('durable', 'CancelConfirmed') >= 0 && pos('durable', 'CancelConfirmed') < pos('wire', 'commit'));
  assert.ok(pos('durable', 'HandedOff') > pos('wire', 'commit'));
  assert.equal(f.values['velqra-capture-v1'].records[0].state, 'HandedOff');
  assert.equal(JSON.stringify(f.values).includes('files.test'), false);
});

test('tiny file completes before confirmed pause: real agent never prepares or replays it', async () => {
  const f = realSetup(); await f.app.refresh(); f.chrome.downloads.pause = async id => { f.log.push(['pause', id]); f.items.get(id).state = 'complete'; };
  f.observe(); await f.filename(); assert.equal(f.log.some(x => x[0] === 'wire' && ['prepare', 'commit'].includes(x[1])), false);
  assert.equal(f.log.some(x => x[0] === 'cancel'), false);
});

test('two simultaneous real-agent handoffs retain both journal records (27a queue fix preserved)', async () => {
  const f = realSetup(); await f.app.refresh();
  for (let n = 7; n < 9; n++) { const i = item({ id: n, url: `https://files.test/${n}.zip`, finalUrl: `https://files.test/${n}.zip` }); f.observe(i, { requestId: `r${n}` }); f.chrome.downloads.onDeterminingFilename.fire(i, () => {}); }
  await tick(); assert.equal(f.values['velqra-capture-v1'].records.length, 2); assert.ok(f.values['velqra-capture-v1'].records.every(r => r.state === 'HandedOff'));
});

for (const state of ['gone', 'other-extension', 'complete', 'interrupted', 'danger', 'renamed', 'redirected', 'already-paused']) test(`fresh browser preflight respects another owner: ${state}`, async () => {
  const f = setup(); await f.app.refresh(); f.observe();
  if (state === 'gone') f.items.clear();
  else Object.assign(f.items.get(7), {
    'other-extension': { byExtensionId: 'other' }, complete: { state: 'complete' }, interrupted: { state: 'interrupted', error: 'USER_CANCELED' },
    danger: { danger: 'dangerous' }, renamed: { filename: 'changed.txt' }, redirected: { finalUrl: 'https://other.test/a.zip' }, 'already-paused': { paused: true },
  }[state]);
  // Filename event is an earlier snapshot; search observes the fresh race result.
  await f.filename(item()); assert.equal(f.log.some(x => x[0] === 'capture' || x[0] === 'pause' || x[0] === 'cancel'), false); assert.ok(f.app.status().reason);
  if (state === 'gone') assert.equal(f.app.status().reason, 'other_owner');
});

test('credentials arriving during preflight and disconnect during preflight cannot start the agent', async () => {
  for (const scenario of ['credential', 'disconnect']) {
    const f = setup(); await f.app.refresh(); const d = f.observe(); let release;
    f.chrome.downloads.search = () => new Promise(r => { release = r; });
    f.chrome.downloads.onDeterminingFilename.fire(item(), () => {}); await tick();
    if (scenario === 'credential') f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: [{ name: 'Authorization', value: 'secret' }] });
    else f.app.disconnected();
    release([item()]); await tick(); assert.equal(f.log.some(x => x[0] === 'capture'), false);
  }
});

test('identity storage failure or corruption cannot capture; no URL or header persisted', async () => {
  for (const mode of ['failure', 'corrupt']) {
    const f = setup();
    if (mode === 'failure') f.chrome.storage.local.get = async () => { throw Error('secret'); };
    else f.values['velqra-capture-identity'] = { install: 'bad', profile: 'bad' };
    assert.equal(await f.app.refresh(), false); f.observe(); await f.filename(); assert.equal(f.log.some(x => x[0] === 'capture'), false);
  }
});

test('bounds count actual stuck operations after timeout and release slots only after settlement', async () => {
  const steps = new BoundedSteps(2, 2); let release;
  await assert.rejects(steps.run(() => new Promise(r => { release = r; })), /timeout/);
  await assert.rejects(steps.run(() => new Promise(() => {})), /timeout/);
  let called = false; await assert.rejects(steps.run(() => { called = true; }), /busy/); assert.equal(called, false); assert.equal(steps.live, 2);
  release(); await tick(); assert.equal(steps.live, 1);
  assert.equal(await steps.run(() => 7), 7); assert.equal(steps.live, 1);
  await assert.rejects(steps.run(() => { throw Error('secret'); }), /operation/); assert.equal(steps.live, 1);
  await assert.rejects(steps.run(() => Promise.reject(Error('secret'))), /operation/); assert.equal(steps.live, 1);
});

test('created-event metadata is capped and ages out; duplicate filename event never starts twice', async () => {
  let now = 0; const f = setup({ now: () => now }); await f.app.refresh();
  f.observe(); await f.filename(); await f.filename(); assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
  for (let n = 0; n < 400; n++) f.chrome.downloads.onCreated.fire(item({ id: n }));
  assert.equal(f.app.status().created, 256); now = 120001; assert.equal(f.app.status().created, 0);
});

test('suggest callback that throws is attempted once and does not begin capture', async () => {
  const f = setup(); await f.app.refresh(); f.observe(); let calls = 0;
  assert.deepEqual(f.chrome.downloads.onDeterminingFilename.fire(item(), () => { calls++; throw Error('callback'); }), [true]);
  await tick(); assert.equal(calls, 1); assert.equal(f.log.some(x => x[0] === 'capture'), false);
});

test('toolbar second click clears bypass; a mismatched frame does not consume it', async () => {
  const f = setup(); await f.app.refresh();
  f.chrome.action.onClicked.fire({ id: 3 }); f.chrome.action.onClicked.fire({ id: 3 }); f.observe(); await f.filename(); assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
  f.chrome.action.onClicked.fire({ id: 3 });
  const next = item({ id: 8, url: 'https://files.test/8.zip', finalUrl: 'https://files.test/8.zip' }); f.observe(next, { requestId: 'r8', frameId: 1 }); await f.filename(next);
  const top = item({ id: 9, url: 'https://files.test/9.zip', finalUrl: 'https://files.test/9.zip' }); f.observe(top, { requestId: 'r9' }); await f.filename(top);
  assert.equal(f.log.filter(x => x[0] === 'capture').length, 2);
});

for (const corrupt of ['extensions-shape', 'extensions-count', 'extensions-value', 'allowed-sites', 'excluded-sites', 'problem', 'health-kind', 'health-session', 'health-request', 'version', 'generation']) test(`malformed settings cannot arm capture: ${corrupt}`, async () => {
  const f = setup(); const original = f.bridge.request.bind(f.bridge);
  f.bridge.request = async (...args) => {
    const e = await original(...args);
    if (args[0].type === 'health') {
      if (corrupt === 'health-kind') e.body.type = 'settings_reply';
      if (corrupt === 'health-request') e.request_id = 'other';
    } else {
      const s = e.body.payload;
      if (corrupt === 'extensions-shape') s.extensions = 'zip';
      if (corrupt === 'extensions-count') s.extensions = Array(257).fill('zip');
      if (corrupt === 'extensions-value') s.extensions = ['ZIP'];
      if (corrupt === 'allowed-sites') s.allowed_sites = ['*.UPPER.test'];
      if (corrupt === 'excluded-sites') s.excluded_sites = null;
      if (corrupt === 'problem') s.problem = 'x'.repeat(513);
      if (corrupt === 'version') e.version = 2;
      if (corrupt === 'generation') e.generation = 2;
    }
    if (corrupt === 'health-session') e.session_id = 'invalid';
    return e;
  };
  assert.equal(await f.app.refresh(), false); f.observe(); await f.filename(); assert.equal(f.log.some(x => x[0] === 'capture'), false);
});

test('settings problem is surfaced verbatim as text, not silently discarded', async () => {
  const f = setup(); const original = f.bridge.request.bind(f.bridge);
  f.bridge.request = async (...a) => { const e = await original(...a); if (a[0].type === 'settings_get') e.body.payload.problem = 'the settings file could not be read'; return e; };
  await f.app.refresh(); await tick(); assert.ok(f.log.some(x => x[0] === 'title' && x[1] === 'the settings file could not be read'));
});

test('tracker rejects URL credentials, missing final headers, excessive chains and stale correlation', () => {
  for (const mode of ['original-userinfo', 'redirect-userinfo', 'no-final-headers', 'old-time', 'too-large', 'method-change']) {
    let now = 0; const t = new RequestTracker({ now: () => now });
    let i = item(); if (mode === 'original-userinfo') i.url = i.finalUrl = 'https://user:pass@files.test/a.zip';
    const d = { requestId: 'r', url: i.url, method: 'GET', tabId: 1, frameId: 0, type: 'main_frame', timeStamp: Date.parse(i.startTime) }; t.before(d); t.headers({ ...d, requestHeaders: [] });
    if (mode === 'redirect-userinfo') { i.finalUrl = 'https://user:pass@files.test/b.zip'; t.redirect({ ...d, redirectUrl: i.finalUrl }); t.headers({ ...d, url: i.finalUrl, requestHeaders: [] }); }
    if (mode === 'no-final-headers') { i.finalUrl = 'https://files.test/b.zip'; t.redirect({ ...d, redirectUrl: i.finalUrl }); }
    if (mode === 'old-time') now = 120001;
    if (mode === 'too-large') { i.finalUrl = 'https://files.test/' + 'x'.repeat(8192); t.redirect({ ...d, redirectUrl: i.finalUrl }); }
    if (mode === 'method-change') t.before({ ...d, method: 'POST' });
    const c = t.match(i); assert.ok(!c || !c.correlated || c.credentialsSeen !== false);
  }
});

test('final URL correspondence and request timestamp must both match the observed chain', () => {
  const t = new RequestTracker(); const i = item(); const d = { requestId: 'r', url: i.url, method: 'GET', tabId: 1, frameId: 0, type: 'main_frame', timeStamp: Date.parse(i.startTime) };
  t.before(d); t.headers({ ...d, requestHeaders: [] });
  assert.equal(t.match({ ...i, finalUrl: 'https://wrong.test/a.zip' }), null);
  assert.equal(t.match({ ...i, startTime: new Date(Date.now() + 120001).toISOString() }), null);
});

test('disconnect during storage initialization cannot publish readiness after reconnect', async () => {
  const f = setup(); let release;
  f.chrome.storage.local.get = () => new Promise(r => { release = r; });
  const pending = f.app.refresh(); await tick(); f.app.disconnected(); release({});
  assert.equal(await pending, false); assert.equal(f.app.status().ready, false);
});

test('manual checks reject credentials, POST, excluded host, wrong tab/frame and disabled settings', async () => {
  for (const mode of ['credentials', 'POST', 'excluded', 'tab', 'frame', 'off']) {
    const f = setup();
    const original = f.bridge.request.bind(f.bridge);
    f.bridge.request = async (...a) => { const e = await original(...a); if (a[0].type === 'settings_get') { if (mode === 'excluded') e.body.payload.excluded_sites = ['files.test']; if (mode === 'off') e.body.payload.mode = 'off'; } return e; };
    await f.app.refresh(); const d = f.observe(item(), mode === 'POST' ? { method: 'POST' } : {});
    if (mode === 'credentials') f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: [{ name: 'Cookie', value: 'secret' }] });
    f.chrome.contextMenus.onClicked.fire({ menuItemId: 'velqra-download', linkUrl: item().url, frameId: mode === 'frame' ? 1 : 0 }, { id: mode === 'tab' ? 8 : 3 });
    await tick(); assert.equal(f.log.some(x => x[0] === 'download'), false); assert.equal(f.app.status().reason, 'manual');
  }
});

test('manual intents have a hard cap, expire, and reject an invalid browser download ID', async () => {
  let now = 0; const f = setup({ now: () => now }); await f.app.refresh(); f.observe(); let calls = 0;
  f.chrome.downloads.download = async () => ++calls;
  const click = () => f.chrome.contextMenus.onClicked.fire({ menuItemId: 'velqra-download', linkUrl: item().url, frameId: 0 }, { id: 3 });
  for (let n = 0; n < 25; n++) { click(); await tick(); }
  assert.equal(calls, 16); assert.equal(f.app.status().manual, 16);
  now = 60001; assert.equal(f.app.status().manual, 0);
  f.chrome.downloads.download = async () => NaN; click(); await tick(); assert.equal(f.app.status().manual, 0); assert.equal(f.app.status().reason, 'manual');
});

test('invalid toolbar tab is ignored; duplicate created events never reset a processed download', async () => {
  const f = setup(); await f.app.refresh(); const before = f.log.length;
  f.chrome.action.onClicked.fire({}); f.chrome.action.onClicked.fire({ id: -1 }); await tick(); assert.equal(f.log.length, before);
  f.observe(); await f.filename(); f.chrome.downloads.onCreated.fire(item()); await f.filename(); assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
});

test('tracker does not borrow evidence from a different original URL and sanitizes optional metadata', () => {
  const t = new RequestTracker(); const i = item(); const d = { requestId: 'r', url: 'https://other.test/a.zip', method: 'GET', tabId: 1, frameId: 0, type: 'main_frame', timeStamp: Date.parse(i.startTime) };
  t.before(d); t.headers({ ...d, requestHeaders: [] }); t.redirect({ ...d, redirectUrl: i.finalUrl });
  t.headers({ ...d, url: i.finalUrl, requestHeaders: [{ name: 'User-Agent', value: 'x'.repeat(1000) }, { name: 'Referer', value: 'https://ref.test/path?secret=never' }] });
  assert.equal(t.match(i), null);
  const c = t.match({ ...i, url: d.url }); assert.equal(c.user_agent, ''); assert.equal(c.referer, 'https://ref.test/');
});

test('settings refresh is single-flight rather than invalidating a pending valid reply', async () => {
  const f = setup(); await f.app.refresh(); const m = new SettingsMirror({ bridge: f.bridge }); const original = f.bridge.request.bind(f.bridge); let release;
  f.bridge.request = async (...a) => { const e = await original(...a); if (a[0].type === 'settings_get') await new Promise(r => { release = r; }); return e; };
  const first = m.refresh(); await tick(); assert.equal(await m.refresh(), false); release(); assert.equal(await first, true); assert.equal(m.version, 1);
});

test('an unrelated context-menu click cannot initiate a download', async () => {
  const f = setup(); await f.app.refresh(); f.observe();
  f.chrome.contextMenus.onClicked.fire({ menuItemId: 'different-menu', linkUrl: item().url, frameId: 0 }, { id: 3 });
  await tick(); assert.equal(f.log.some(x => x[0] === 'download'), false);
});

test('per-entry metadata budget rejects oversized new records and fences oversized updates without dropping receipt evidence', () => {
  const t = new RequestTracker();
  const d = { requestId: 'r', tabId: 1, frameId: 0, method: 'GET', url: 'https://f.test/' + 'x'.repeat(7900), documentId: '\\'.repeat(128), timeStamp: Date.now() };
  t.before(d); assert.equal(t.size, 0);
  const i = item({ url: 'https://f.test/' + 'x'.repeat(7400), finalUrl: 'https://f.test/' + 'x'.repeat(7400) });
  const small = { ...d, url: i.url, documentId: 'doc' }; t.before(small); t.pin('r'); assert.equal(t.size, 1);
  t.headers({ ...small, requestHeaders: [{ name: 'User-Agent', value: 'x'.repeat(512) }, { name: 'Referer', value: 'https://' + 'z'.repeat(1000) + '.test/' }] });
  assert.ok(t.has('r')); assert.notEqual(t.match(i)?.correlated, true);
});

test('manual no-tab results conservatively stay in browser even with a clean new request', async () => {
  for (const mode of ['clean', 'cookie', 'missing', 'ambiguous']) {
    const f = setup(); await f.app.refresh(); f.observe();
    f.chrome.contextMenus.onClicked.fire({ menuItemId: 'velqra-download', linkUrl: item().url, frameId: 0 }, { id: 3 }); await tick();
    const i = item({ id: 99, byExtensionId: f.chrome.runtime.id });
    if (mode === 'missing') f.chrome.downloads.onCreated.fire(i);
    else {
      const d = f.observe(i, { requestId: 'new-manual', tabId: -1 });
      if (mode === 'cookie') f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, requestHeaders: [{ name: 'Cookie', value: 'secret' }] });
      if (mode === 'ambiguous') f.observe(item({ id: 100 }), { requestId: 'third', tabId: -1 });
    }
    await f.filename(i); const calls = f.log.filter(x => x[0] === 'capture'); assert.equal(calls.length, 0);
  }
});

test('borrowed clean-prefetch evidence cannot authorize a later unobserved download', () => {
  const t = new RequestTracker();
  const i = item({ startTime: new Date(1100).toISOString() });
  const d = { requestId: 'clean-prefetch', url: i.url, method: 'GET', tabId: 3, frameId: 0, type: 'other', timeStamp: 1000 };
  t.before(d); t.headers({ ...d, requestHeaders: [] });
  assert.notEqual(t.match(i)?.correlated, true);
});
test('one clean request cannot justify two downloads, including concurrent claimants', async () => {
  const f = setup(); await f.app.refresh(); const i = item(); f.observe(i);
  const second = { ...i, id: 8 };
  f.items.set(8, second); f.chrome.downloads.onCreated.fire(second);
  await f.filename(i); await f.filename(second);
  assert.equal(f.log.some(x => x[0] === 'capture'), false);
});
test('a consumed observation never authorizes a later download', async () => {
  const f = setup(); await f.app.refresh(); const i = item(); f.observe(i); await f.filename(i);
  assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
  const second = { ...i, id: 8 }; f.items.set(8, second); f.chrome.downloads.onCreated.fire(second); await f.filename(second);
  assert.equal(f.log.filter(x => x[0] === 'capture').length, 1);
});

for (const [name, type, offset, cache] of [['old main-frame observation', 'main_frame', 100, false], ['same-time prefetch', 'other', 0, false], ['cached response', 'main_frame', 0, true]]) test(`provenance refuses ${name}`, () => {
  const t = new RequestTracker(), i = item({ startTime: new Date(1000 + offset).toISOString() });
  const d = { requestId: 'r', url: i.url, method: 'GET', tabId: 3, frameId: 0, type, timeStamp: 1000 };
  t.before(d); t.headers({ ...d, requestHeaders: [] }); if (cache) t.end({ ...d, fromCache: true });
  assert.notEqual(t.match(i)?.correlated, true);
});

for (const denied of ['health', 'settings_get']) test(`readiness requires independent capability in ${denied}`, async () => {
  const f = setup(), original = f.bridge.request;
  f.bridge.request = async (body, opts) => {
    const e = await original(body, opts);
    if (body.type === denied) e.body.payload.transfer_capable = false;
    return e;
  };
  await f.app.refresh(); f.observe(); await f.filename();
  assert.equal(f.app.status().ready, false);
  assert.equal(f.log.some(x => x[0] === 'capture'), false);
  const mirror = new SettingsMirror({ bridge: f.bridge }); await mirror.refresh(); assert.equal(mirror.snapshot, null);
});

test('adapter latches a danger change during prepare even when the next search is safe', async () => {
  const f = realSetup(); await f.app.refresh();
  const original = f.bridge.request;
  f.bridge.request = async (body, opts) => {
    const e = await original(body, opts);
    if (body.type === 'prepare') f.chrome.downloads.onChanged.fire({ id: 7, danger: { current: 'dangerous' } });
    return e;
  };
  f.observe(); await f.filename();
  assert.equal(f.items.get(7).paused, false);
  assert.equal(f.log.some(x => x[0] === 'cancel'), false);
});

test('two created downloads with unfinished redirect identities cannot claim one observation', async () => {
  const f = setup(); await f.app.refresh();
  const first = item(), second = { ...first, id: 8 }, target = 'https://cdn.test/a.zip';
  const d = f.observe({ ...first, finalUrl: '' });
  f.chrome.webRequest.onBeforeRedirect.fire({ ...d, redirectUrl: target });
  f.chrome.webRequest.onBeforeRequest.fire({ ...d, url: target });
  f.chrome.webRequest.onBeforeSendHeaders.fire({ ...d, url: target, requestHeaders: [] });
  f.chrome.downloads.onCreated.fire({ ...second, finalUrl: '' });
  for (const i of [first, second]) { i.finalUrl = target; f.items.set(i.id, i); }
  await f.filename(first); await f.filename(second);
  assert.equal(f.log.some(x => x[0] === 'capture'), false);
});
