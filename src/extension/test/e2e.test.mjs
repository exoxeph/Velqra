// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// The JavaScript client against the REAL Rust host and core, over Chrome's native-messaging framing.
// Needs the binaries (`cargo build -p velqra-app` from src/); it is skipped, loudly, when they are absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BridgeClient, BridgeError } from '../src/bridge.js';

const BIN = fileURLToPath(new URL('../../target/debug/', import.meta.url));
const HOST = join(BIN, 'velqra-host.exe');
const APP = join(BIN, 'velqra-app.exe');
const devKey = JSON.parse(readFileSync(new URL('../dev-key.json', import.meta.url), 'utf8'));
const ORIGIN = `chrome-extension://${devKey.id}/`;
const have = existsSync(HOST) && existsSync(APP);
if (!have) console.warn(`SKIPPED: build the binaries first (${HOST})`);

let counter = 0;

function environment() {
  const home = mkdtempSync(join(tmpdir(), 'velqra-js-e2e-'));
  const suffix = `js-e2e-${process.pid}-${++counter}`;
  const env = { ...process.env, VELQRA_HOME: home, VELQRA_PIPE: suffix, VELQRA_APP: APP };
  delete env.VELQRA_ALLOWED_ORIGINS;
  return { home, env };
}

/** A chrome.runtime.Port look-alike over a child process speaking native-messaging frames. */
function hostPort(/** @type {NodeJS.ProcessEnv} */ env) {
  const child = spawn(HOST, [ORIGIN, '--parent-window=0'], { env, stdio: ['pipe', 'pipe', 'ignore'] });
  /** @type {((m: any) => void)[]} */ const onMessage = [];
  /** @type {(() => void)[]} */ const onDisconnect = [];
  let buf = Buffer.alloc(0);
  let gone = false;
  child.stdout.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32LE(0);
      if (buf.length < 4 + len) break;
      const message = JSON.parse(buf.subarray(4, 4 + len).toString('utf8'));
      buf = buf.subarray(4 + len);
      onMessage.forEach((l) => l(message));
    }
  });
  child.on('exit', () => {
    if (!gone) {
      gone = true;
      onDisconnect.forEach((l) => l());
    }
  });
  return {
    onMessage: { addListener: (/** @type {any} */ l) => onMessage.push(l) },
    onDisconnect: { addListener: (/** @type {any} */ l) => onDisconnect.push(l) },
    postMessage(/** @type {any} */ o) {
      const body = Buffer.from(JSON.stringify(o));
      const head = Buffer.alloc(4);
      head.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([head, body]));
    },
    disconnect() {
      gone = true;
      child.stdin.end();
      child.kill();
    },
  };
}

function memoryStorage(/** @type {Record<string,string>} */ data = {}) {
  return {
    data,
    get: async (/** @type {string} */ k) => data[k],
    set: async (/** @type {string} */ k, /** @type {string} */ v) => {
      data[k] = v;
    },
  };
}

function killCore(/** @type {string} */ home) {
  try {
    const pid = readFileSync(join(home, 'velqra-app.pid'), 'utf8').trim();
    spawnSync('taskkill', ['/F', '/PID', pid], { stdio: 'ignore' });
  } catch {
    /* it was never started */
  }
}

async function until(/** @type {() => boolean} */ ok, /** @type {number} */ ms, /** @type {string} */ what) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (ok()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const prepareBody = {
  type: 'prepare',
  payload: { download_key: 'd1', url: 'https://x.test/a.zip', filename: 'a.zip', context: 'S3CR3T-JS-CONTEXT' },
};

test('pairing, handshake and a full hand-off against the real host and core', { skip: !have }, async () => {
  const { home, env } = environment();
  const storage = memoryStorage();
  const client = new BridgeClient({ connectNative: () => hostPort(env), storage, origin: ORIGIN });
  try {
    await client.connect(); // first run: pairs (the host starts the core), then the mutual handshake
    assert.equal(client.state, 'ready');
    assert.ok(storage.data.secret, 'the secret was stored after pairing');

    const health = await client.request({ type: 'health', payload: {} }, { requestId: 'req-1' });
    assert.equal(health.body.type, 'health_reply');
    assert.equal(health.body.payload.engine, 'loopback');

    const prepared = await client.request(prepareBody, { requestId: 'req-1' });
    assert.equal(prepared.body.type, 'prepared');
    const receipt = { task_id: prepared.body.payload.task_id, fingerprint: prepared.body.payload.fingerprint };
    const armed = await client.request({ type: 'begin_handoff', payload: receipt }, { requestId: 'req-1' });
    assert.equal(armed.body.payload.state, 'armed');
    const committed = await client.request({ type: 'commit', payload: { cancel: 'confirmed', receipt } }, { requestId: 'req-1' });
    assert.equal(committed.body.type, 'committed');
    assert.ok(['committed', 'transferring', 'done'].includes(committed.body.payload.state), committed.body.payload.state);
  } finally {
    client.close();
    killCore(home);
    rmSync(home, { recursive: true, force: true });
  }
});

test('a client holding the wrong secret refuses the real core and is never authenticated', { skip: !have }, async () => {
  const { home, env } = environment();
  const wrong = Buffer.alloc(32, 9).toString('base64');
  const client = new BridgeClient({ connectNative: () => hostPort(env), storage: memoryStorage({ secret: wrong }), origin: ORIGIN });
  try {
    await assert.rejects(client.connect(), (e) => e instanceof BridgeError && e.code === 'bad_server_mac');
    assert.equal(client.state, 'closed');
    await assert.rejects(client.request({ type: 'health', payload: {} }, { requestId: 'r' }), (e) => e instanceof BridgeError && e.code === 'kept_in_browser');
  } finally {
    client.close();
    killCore(home);
    rmSync(home, { recursive: true, force: true });
  }
});

test('when the core dies the client falls back, then reconnects on its own and finds its receipt', { skip: !have }, async () => {
  const { home, env } = environment();
  const client = new BridgeClient({ connectNative: () => hostPort(env), storage: memoryStorage(), origin: ORIGIN });
  try {
    await client.connect();
    const prepared = await client.request(prepareBody, { requestId: 'req-1' });
    const before = prepared.body.payload;
    killCore(home);
    await until(() => client.state !== 'ready', 15000, 'the client to notice the core is gone');
    await assert.rejects(client.request({ type: 'health', payload: {} }, { requestId: 'r' }), (e) => e instanceof BridgeError && e.code === 'kept_in_browser');
    // the watchdog/backoff path: the next attempt makes the host start the core again
    await until(() => client.state === 'ready', 30000, 'the automatic reconnect');
    const status = await client.request({ type: 'status', payload: {} }, { requestId: 'req-1' });
    assert.equal(status.body.type, 'status_reply');
    assert.equal(status.body.payload.task_id, before.task_id);
    assert.equal(status.body.payload.fingerprint, before.fingerprint);
    assert.equal(status.body.payload.state, 'prepared');
  } finally {
    client.close();
    killCore(home);
    rmSync(home, { recursive: true, force: true });
  }
});
