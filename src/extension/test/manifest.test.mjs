// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const read = (/** @type {string} */ p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const manifest = JSON.parse(read('../manifest.json'));
const devKey = JSON.parse(read('../dev-key.json'));

/** Chrome derives an extension ID from the public key: SHA-256, first 32 hex digits mapped 0-f to a-p. */
const idFromKey = (/** @type {string} */ key) =>
  [...createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex').slice(0, 32)]
    .map((c) => String.fromCharCode(97 + parseInt(c, 16)))
    .join('');

test('the manifest pins C3/C4 permissions exactly; management stays optional and cookies absent', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(), ['alarms', 'contextMenus', 'downloads', 'nativeMessaging', 'storage', 'webRequest']);
  assert.deepEqual(manifest.host_permissions, ['http://*/*', 'https://*/*']);
  assert.deepEqual(manifest.optional_permissions, ['management']);
  assert.equal(manifest.options_page, 'options.html');
  assert.ok(manifest.action && !manifest.action.default_popup, 'toolbar click implements bypass');
  for (const field of ['optional_host_permissions', 'content_scripts', 'externally_connectable', 'web_accessible_resources', 'commands', 'devtools_page']) {
    assert.equal(manifest[field], undefined, `${field} must not be present in M1a`);
  }
});

test('the manifest key yields the extension ID that the Rust host and core trust', () => {
  assert.equal(manifest.key, devKey.key);
  const id = idFromKey(manifest.key);
  assert.equal(id, devKey.id);
  const rust = read('../../crates/velqra-app/src/paths.rs');
  const m = rust.match(/DEV_EXTENSION_ORIGIN: &str = "chrome-extension:\/\/([a-p]{32})\/"/);
  assert.ok(m, 'the Rust constant was not found');
  assert.equal(m[1], id, 'the allowlist in Rust and the key in the manifest disagree');
});

test('the source API allowlist deliberately includes only the C3/C4 APIs', () => {
  // runtime=native bridge/lifecycle/options; storage=journal/identity;
  // alarms=recovery watchdog; downloads=observe/pause/resume/cancel/manual;
  // webRequest=GET/redirect/credential evidence; action=bypass/status;
  // contextMenus=manual entry; permissions=user-gesture optional management;
  // management=read-only coexistence enumeration from the local options button.
  const used = new Set();
  for (const f of readdirSync(new URL('../src/', import.meta.url))) {
    for (const m of read(`../src/${f}`).matchAll(/\bchrome\.(\w+)/g)) used.add(m[1]);
  }
  assert.deepEqual([...used].sort(), ['action', 'alarms', 'contextMenus', 'downloads', 'management', 'permissions', 'runtime', 'storage', 'webRequest']);
});

test('no source file contains a network address', () => {
  const NL = String.fromCharCode(10);
  for (const f of readdirSync(new URL('../src/', import.meta.url))) {
    const code = read(`../src/${f}`).split(NL).filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join(NL);
    // The only all-site strings are webRequest filters, not network destinations.
    const withoutFilters = code.replaceAll("'http://*/*'", "''").replaceAll("'https://*/*'", "''");
    assert.ok(!/https?:\/\//.test(withoutFilters), `${f} contains a network destination`);
    assert.ok(!/localhost|127\.0\.0\.1/.test(code), `${f} contains a loopback address`);
  }
});

test('the worker registers its listeners synchronously and starts the bridge', async () => {
  /** @type {Record<string, number>} */
  const listeners = { onStartup: 0, onInstalled: 0, onAlarm: 0 };
  const event = () => ({ addListener() {} });
  let connects = 0;
  /** @type {any} */ (globalThis).chrome = {
    runtime: {
      id: 'a'.repeat(32),
      onStartup: { addListener: () => listeners.onStartup++ },
      onInstalled: { addListener: () => listeners.onInstalled++ },
      connectNative: () => {
        connects++;
        return { onMessage: { addListener() {} }, onDisconnect: { addListener() {} }, postMessage() {}, disconnect() {} };
      },
    },
    storage: { local: { get: async () => ({}), set: async () => {} } },
    alarms: { create: () => {}, onAlarm: { addListener: () => listeners.onAlarm++ } },
    downloads: { onCreated: event(), onChanged: event(), onDeterminingFilename: event(), search: async () => [] },
    webRequest: Object.fromEntries(['onBeforeRequest', 'onBeforeSendHeaders', 'onBeforeRedirect', 'onHeadersReceived', 'onCompleted', 'onErrorOccurred'].map(k => [k, event()])),
    action: { onClicked: event(), setTitle: async () => {}, setBadgeText: async () => {} },
    contextMenus: { onClicked: event() },
  };
  const { client } = await import('../src/worker.js');
  assert.deepEqual(listeners, { onStartup: 1, onInstalled: 2, onAlarm: 1 });
  await new Promise((r) => setImmediate(r));
  assert.equal(connects, 1, 'the worker did not try to reach the host');
  client.close();
});

test('the worker has no top-level await, so every listener is registered during the first evaluation', () => {
  const NL = String.fromCharCode(10);
  const lines = readdirSync(new URL('../src/', import.meta.url)).filter(f => f.endsWith('.js')).flatMap(f => read(`../src/${f}`).split(NL));
  const offenders = lines.filter((l) => /^(?=\S).*\bawait\b/.test(l) && !/^\s*(\/\/|\/\*|\*)/.test(l));
  assert.deepEqual(offenders, [], 'a listener registered after an await would miss the events that started the worker');
});
