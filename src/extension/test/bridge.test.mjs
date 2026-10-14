// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// BridgeClient against a scripted fake core. The fake implements the server side of the handshake
// with the same primitives; real compatibility with the Rust core is proven in e2e.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { BridgeClient, BridgeError, MAX_LIVE_DRAINS, buildEnvelope, reconnectDelay } from '../src/bridge.js';
import { b64Encode, b64Decode, mac, verifyMac, LABEL_SERVER, LABEL_CLIENT } from '../src/handshake.js';

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
const SECRET = /** @type {Uint8Array} */ (b64Decode(vectors.secret_b64));
const ORIGIN = vectors.origin;
const SID = '0123456789abcdef0123456789abcdef';

const settle = async () => {
  for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r));
};

class Timers {
  constructor() {
    this.now = 0;
    this.n = 0;
    /** @type {{id:number, at:number, fn:()=>void}[]} */
    this.queue = [];
    /** @type {number[]} */
    this.delays = [];
  }
  /** @param {()=>void} fn @param {number} ms */
  set = (fn, ms) => {
    const id = ++this.n;
    this.delays.push(ms);
    this.queue.push({ id, at: this.now + ms, fn });
    return id;
  };
  /** @param {number} id */
  clear = (id) => {
    this.queue = this.queue.filter((t) => t.id !== id);
  };
  /** @param {number} ms */
  async advance(ms) {
    const target = this.now + ms;
    for (;;) {
      this.queue.sort((a, b) => a.at - b.at);
      const next = this.queue[0];
      if (!next || next.at > target) break;
      this.queue.shift();
      this.now = next.at;
      next.fn();
      await settle();
    }
    this.now = target;
    await settle();
  }
}

/** A scripted core. `opts.serverSecret` lets a test impersonate a core that does not know the secret. */
function makeCore(opts = {}) {
  const o = { serverSecret: SECRET, pairRefused: false, silentHello: false, silentPair: false, rejectHello: null, ...opts };
  /** @type {any[]} */
  const posted = [];
  const ports = [];
  let opened = 0;
  const core = {
    posted,
    ports,
    get opened() {
      return opened;
    },
    disconnectedByClient: 0,
    connectNative() {
      opened++;
      /** @type {((m:any)=>void)[]} */
      const onMsg = [];
      /** @type {(()=>void)[]} */
      const onDisc = [];
      let cn = new Uint8Array(0);
      let closed = false;
      const send = (/** @type {any} */ m) => {
        if (!closed) queueMicrotask(() => onMsg.forEach((l) => l(structuredClone(m))));
      };
      const port = {
        onMessage: { addListener: (/** @type {any} */ l) => onMsg.push(l) },
        onDisconnect: { addListener: (/** @type {any} */ l) => onDisc.push(l) },
        postMessage: (/** @type {any} */ m) => {
          posted.push(structuredClone(m));
          void (async () => {
            if (m.t === 'pair') {
              if (o.silentPair) return;
              send(o.pairRefused ? { t: 'reject', code: 'no_secret' } : { t: 'paired', secret: b64Encode(SECRET) });
            } else if (m.t === 'hello') {
              if (o.silentHello) return;
              if (o.rejectHello) return send({ t: 'reject', code: o.rejectHello });
              cn = /** @type {Uint8Array} */ (b64Decode(m.cn));
              const sn = new Uint8Array(16).fill(2);
              const core16 = new Uint8Array(16).fill(3);
              const sm = await mac(o.serverSecret, LABEL_SERVER, { cn, sn, origin: ORIGIN, core: core16 });
              send({ t: 'challenge', v: 1, sn: b64Encode(sn), core: b64Encode(core16), sm: b64Encode(sm) });
            } else if (m.t === 'auth') {
              const fields = { cn, sn: new Uint8Array(16).fill(2), origin: ORIGIN, core: new Uint8Array(16).fill(3) };
              const ok = await verifyMac(SECRET, LABEL_CLIENT, fields, /** @type {Uint8Array} */ (b64Decode(m.cm)));
              send(ok ? { t: 'ready', sid: SID } : { t: 'reject', code: 'bad_auth' });
            } else if (m.body) {
              if (core.onEnvelope) core.onEnvelope(m, send);
              else if (m.body.type === 'health') {
                send({
                  version: 1, message_id: 'r-' + m.message_id, session_id: m.session_id, request_id: m.request_id, generation: 1,
                  body: { type: 'health_reply', payload: { core_instance: 'c', versions: [1], engine: 'fake' } },
                });
              }
            }
          })();
        },
        disconnect: () => {
          core.disconnectedByClient++;
          closed = true;
        },
      };
      const sendNow = (/** @type {any} */ m) => {
        if (!closed) onMsg.forEach((l) => l(structuredClone(m)));
      };
      const forceDeliver = (/** @type {any} */ m) => onMsg.forEach((l) => l(structuredClone(m)));
      // hands over the very object (no clone) so a test can watch it with a WeakRef
      const deliverRaw = (/** @type {any} */ m) => onMsg.forEach((l) => l(m));
      ports.push({ port, send, sendNow, forceDeliver, deliverRaw, dropConnection: () => { closed = true; onDisc.forEach((l) => l()); } });
      return port;
    },
    /** @type {null | ((m:any, send:(x:any)=>void)=>void)} */
    onEnvelope: null,
    last: () => ports[ports.length - 1],
  };
  return core;
}

function storage(initial = {}) {
  /** @type {Record<string,string>} */
  const data = { ...initial };
  return {
    data,
    get: async (/** @type {string} */ k) => data[k],
    set: async (/** @type {string} */ k, /** @type {string} */ v) => {
      data[k] = v;
    },
  };
}

function make(coreOpts = {}, stored = {}, extra = {}) {
  const core = makeCore(coreOpts);
  const timers = new Timers();
  const store = storage(stored);
  let ctr = 0;
  const client = new BridgeClient({
    connectNative: () => core.connectNative(),
    storage: store,
    origin: ORIGIN,
    setTimer: timers.set,
    clearTimer: timers.clear,
    random: () => 0.5,
    randomBytes: (n) => new Uint8Array(n).fill(++ctr),
    requestTimeoutMs: 1000,
    handshakeTimeoutMs: 5000,
    ...extra,
  });
  return { core, timers, store, client };
}

const health = { type: 'health', payload: {} };

test('the first run pairs, stores the secret, completes the handshake and answers a request', async () => {
  const { core, store, client } = make();
  const p = client.connect();
  await settle();
  await p;
  assert.equal(client.state, 'ready');
  assert.equal(core.posted[0].t, 'pair', 'pairing comes first');
  assert.equal(store.data.secret, vectors.secret_b64);
  const r = await client.request(health, { requestId: 'req-1' });
  assert.equal(r.body.type, 'health_reply');
});

test('with a stored secret the client does not pair again', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  assert.ok(!core.posted.some((m) => m.t === 'pair'));
  assert.equal(core.posted[0].t, 'hello');
});

test('a core that cannot prove it knows the secret is abandoned before auth is sent', async () => {
  const wrong = SECRET.slice();
  wrong[0] ^= 1;
  const { core, client } = make({ serverSecret: wrong }, { secret: vectors.secret_b64 });
  await assert.rejects(client.connect(), (e) => e instanceof BridgeError && e.code === 'bad_server_mac');
  assert.ok(!core.posted.some((m) => m.t === 'auth'), 'auth was sent to an unproven core');
  assert.equal(client.state, 'closed');
  assert.equal(core.disconnectedByClient, 1);
});

test('a reject from the core during the handshake surfaces its code', async () => {
  const { client } = make({ rejectHello: 'bad_origin' }, { secret: vectors.secret_b64 });
  await assert.rejects(client.connect(), (e) => e instanceof BridgeError && e.code === 'bad_origin');
  assert.equal(client.state, 'closed');
});

test('a refused pairing surfaces no_secret and nothing is stored', async () => {
  const { client, store } = make({ pairRefused: true });
  await assert.rejects(client.connect(), (e) => e instanceof BridgeError && e.code === 'no_secret');
  assert.equal(store.data.secret, undefined);
});

test('a silent core hits the handshake timeout', async () => {
  const { client, timers } = make({ silentHello: true }, { secret: vectors.secret_b64 });
  const p = client.connect();
  const caught = p.catch((e) => e);
  await settle();
  await timers.advance(5000);
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'timeout', String(e));
  assert.equal(client.state, 'closed');
});

test('requests are refused locally, and nothing is posted, unless the bridge is ready', async () => {
  const { core, client } = make();
  await assert.rejects(client.request(health, { requestId: 'r' }), (e) => e instanceof BridgeError && e.code === 'kept_in_browser');
  assert.equal(core.posted.length, 0);
  assert.equal(client.state, 'idle');
});

test('replies for another session, request or message id are never believed', async () => {
  const { core, timers, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  const forged = [
    { session_id: 'f'.repeat(32), request_id: 'req-1', message_id: 'r-m1' },
    { session_id: SID, request_id: 'req-OTHER', message_id: 'r-m1' },
    { session_id: SID, request_id: 'req-1', message_id: 'r-m99' },
    { session_id: SID, request_id: 'req-1', message_id: 'zzm1' },
  ];
  core.onEnvelope = (_m, send) => {
    for (const f of forged) {
      send({ version: 1, ...f, generation: 1, body: { type: 'health_reply', payload: { core_instance: 'x', versions: [1], engine: 'evil' } } });
    }
  };
  const p = client.request(health, { requestId: 'req-1' });
  const caught = p.catch((e) => e);
  await settle();
  await timers.advance(1000);
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'timeout', 'a forged reply resolved the request');
});

test('the 101st request in flight is refused before anything is sent', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = () => {}; // never answers
  const sentBefore = core.posted.length;
  const pending = Array.from({ length: 100 }, (_, i) => client.request(health, { requestId: `r${i}` }).catch(() => {}));
  await settle();
  assert.equal(core.posted.length - sentBefore, 100);
  await assert.rejects(client.request(health, { requestId: 'r100' }), (e) => e instanceof BridgeError && e.code === 'overloaded');
  assert.equal(core.posted.length - sentBefore, 100, 'the refused request was posted anyway');
  client.close();
  await Promise.all(pending);
});

test('a dropped connection rejects pending requests, late replies resolve nothing, and capture falls back', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = () => {};
  const p = client.request(health, { requestId: 'req-1' });
  const caught = p.catch((e) => e);
  await settle();
  const link = core.last();
  link.dropConnection();
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'disconnected');
  link.send({ version: 1, message_id: 'r-m1', session_id: SID, request_id: 'req-1', generation: 1, body: { type: 'health_reply', payload: {} } });
  await settle();
  assert.equal(client.state, 'closed');
  await assert.rejects(client.request(health, { requestId: 'r2' }), (x) => x instanceof BridgeError && x.code === 'kept_in_browser');
});

test('a reject frame during a session closes it and fails what was pending', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = () => {};
  const caught = client.request(health, { requestId: 'req-1' }).catch((e) => e);
  await settle();
  core.last().send({ t: 'reject', code: 'bad_session' });
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'bad_session', String(e));
  assert.equal(client.state, 'closed');
});

test('reconnect delays double up to a cap, carry jitter, and restart after a success', async () => {
  assert.equal(reconnectDelay(1, () => 0), 500);
  assert.equal(reconnectDelay(2, () => 0), 1000);
  assert.equal(reconnectDelay(5, () => 0), 8000);
  assert.equal(reconnectDelay(40, () => 0), 30000, 'capped');
  assert.equal(reconnectDelay(1, () => 1), 750, 'jitter adds up to half');
  for (let a = 1; a < 50; a++) {
    const d = reconnectDelay(a, Math.random);
    assert.ok(d >= Math.min(30000, 500 * 2 ** (a - 1)) && d <= 45000, `attempt ${a}: ${d}`);
  }
  const { core, timers, client } = make({ rejectHello: 'bad_origin' }, { secret: vectors.secret_b64 });
  await client.connect().catch(() => {});
  await client.connect().catch(() => {});
  assert.ok(core.opened >= 2);
  assert.ok(timers.delays.some((d) => d >= 500 && d <= 30000 * 1.5), 'a reconnect was scheduled with a bounded delay');
});

test('the secret appears only in storage and in the one pairing reply, never in a message the client sends', async () => {
  const { core, client } = make();
  await client.connect();
  await client.request(health, { requestId: 'req-1' });
  const text = JSON.stringify(core.posted);
  assert.ok(!text.includes(vectors.secret_b64), 'the secret was sent to the core');
  const wrong = SECRET.slice();
  wrong[0] ^= 1;
  const bad = make({ serverSecret: wrong }, { secret: vectors.secret_b64 });
  const e = await bad.client.connect().catch((x) => x);
  assert.ok(!String(e.message).includes(vectors.secret_b64) && !String(e.stack).includes(vectors.secret_b64));
  assert.equal(e.message, e.code, 'error text is the fixed code only');
});

test('the envelopes the client builds equal the ones Rust produced', () => {
  const rr = { task_id: 7, fingerprint: 'ab'.repeat(32) };
  const body = (/** @type {string} */ type, /** @type {any} */ payload) => ({ type, payload });
  const e = (/** @type {string} */ id, /** @type {any} */ b) => buildEnvelope(SID, id, 'req-1', b);
  assert.deepEqual(e('m1', body('prepare', { download_key: 'd1', url: 'https://x.test/a.zip', filename: 'a.zip', context: 'ctx' })), vectors.envelopes.prepare);
  assert.deepEqual(e('m2', body('begin_handoff', rr)), vectors.envelopes.begin_handoff);
  assert.deepEqual(e('m3', body('commit', { cancel: 'confirmed', receipt: rr })), vectors.envelopes.commit);
  assert.deepEqual(e('m4', body('abort', { receipt: rr })), vectors.envelopes.abort);
  assert.deepEqual(e('m5', body('abort', { receipt: null })), vectors.envelopes.abort_unknown);
  assert.deepEqual(e('m6', body('reconcile', { owner: 'unknown', receipt: rr })), vectors.envelopes.reconcile);
  assert.deepEqual(e('m7', body('status', {})), vectors.envelopes.status);
  assert.deepEqual(e('m8', body('health', {})), vectors.envelopes.health);
});

test('message ids are never reused within a client', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  for (let i = 0; i < 5; i++) await client.request(health, { requestId: 'req-1' });
  const ids = core.posted.filter((m) => m.body).map((m) => m.message_id);
  assert.equal(new Set(ids).size, ids.length);
});

test('simultaneous connect calls share one attempt', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await Promise.all([client.connect(), client.connect(), client.connect()]);
  assert.equal(core.opened, 1);
});

test('after a drop the in-flight count starts again from zero on the next connection', async () => {
  const { core, client, timers } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = () => {};
  const lost = Array.from({ length: 100 }, (_, i) => client.request(health, { requestId: `a${i}` }).catch((e) => e));
  await settle();
  core.last().dropConnection();
  const errors = await Promise.all(lost);
  assert.ok(errors.every((e) => e instanceof BridgeError && e.code === 'disconnected'));
  await timers.advance(60000); // the scheduled reconnect fires
  assert.equal(client.state, 'ready');
  core.onEnvelope = null;
  const again = await client.request(health, { requestId: 'b0' });
  assert.equal(again.body.type, 'health_reply', 'stale pending entries blocked a new request');
});

test('closing on purpose hangs up the port and never reconnects', async () => {
  const { core, client, timers } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  client.close();
  assert.equal(core.disconnectedByClient, 1, 'the port was left open');
  await timers.advance(120000);
  assert.equal(core.opened, 1, 'reconnected after an intentional close');
  assert.equal(client.state, 'closed');
});

test('a host that cannot even be opened fails cleanly and is retried later', async () => {
  const timers = new Timers();
  let calls = 0;
  const client = new BridgeClient({
    connectNative: () => {
      calls++;
      throw new Error('Specified native messaging host not found. S3CR3T-DETAIL');
    },
    storage: storage({ secret: vectors.secret_b64 }),
    origin: ORIGIN,
    setTimer: timers.set,
    clearTimer: timers.clear,
    random: () => 0,
  });
  const e = await client.connect().catch((x) => x);
  assert.ok(e instanceof BridgeError && e.code === 'host_unavailable', String(e));
  assert.ok(!String(e.message).includes('S3CR3T-DETAIL'), 'the platform error text leaked into ours');
  assert.equal(client.state, 'closed');
  assert.deepEqual(timers.delays, [500], 'a bounded retry was not scheduled');
  await timers.advance(500);
  assert.equal(calls, 2, 'the retry did not happen');
  client.close();
});

test('a storage failure also fails cleanly instead of hanging in idle', async () => {
  const timers = new Timers();
  const client = new BridgeClient({
    connectNative: () => makeCore().connectNative(),
    storage: { get: async () => { throw new Error('quota'); }, set: async () => {} },
    origin: ORIGIN,
    setTimer: timers.set,
    clearTimer: timers.clear,
    random: () => 0,
  });
  const e = await client.connect().catch((x) => x);
  assert.ok(e instanceof BridgeError && e.code === 'host_unavailable', String(e));
  assert.equal(client.state, 'closed');
  client.close();
});

/** A store whose `set` never completes until released, to hold the client inside an async step. */
function stalledStorage() {
  let release = () => {};
  const gate = new Promise((r) => {
    release = r;
  });
  return {
    release,
    storage: {
      get: async () => undefined,
      set: async () => {
        await gate;
      },
    },
  };
}

test('an inbound burst while an async step is stalled is bounded: the port is closed with a fixed code', async () => {
  const { release, storage: slow } = stalledStorage();
  const { core, client } = make({}, {}, { storage: slow });
  const attempt = client.connect().catch((e) => e);
  await settle(); // the client sent {t:'pair'}; the fake core's reply is now stuck in storage.set
  const link = core.last();
  let peak = 0;
  for (let i = 0; i < 10000; i++) {
    link.sendNow({ t: 'noise', pad: 'x'.repeat(1024), i }); // delivered synchronously, like a fast peer
    peak = Math.max(peak, client.inboxSize);
  }
  await settle();
  assert.ok(peak <= 64, `the inbound queue reached ${peak} messages`);
  assert.equal(client.state, 'closed');
  assert.ok(core.disconnectedByClient >= 1, 'the flooded port was not closed');
  release();
  const e = await attempt;
  assert.ok(e instanceof BridgeError && e.code === 'overloaded', String(e));
  assert.equal(client.inboxSize, 0, 'queued work survived the close');
});

test('the inbound queue also has a byte budget, not only a message count', async () => {
  const { release, storage: slow } = stalledStorage();
  const { core, client } = make({}, {}, { storage: slow });
  const attempt = client.connect().catch((e) => e);
  await settle();
  const link = core.last();
  for (let i = 0; i < 30; i++) link.send({ t: 'noise', pad: 'y'.repeat(200 * 1024), i }); // 6 MB in 30 messages
  await settle();
  assert.equal(client.state, 'closed', 'a few very large messages were accepted without limit');
  release();
  const e = await attempt;
  assert.ok(e instanceof BridgeError && e.code === 'overloaded', String(e));
});

test('a stalled step from a closed connection cannot act on the next connection', async () => {
  // storage.set stalls only the first time, so connection 2 can finish pairing while connection 1 is stuck
  let release = () => {};
  const gate = new Promise((r) => {
    release = r;
  });
  let calls = 0;
  const data = /** @type {Record<string,string>} */ ({});
  const storage = {
    get: async (/** @type {string} */ k) => data[k],
    set: async (/** @type {string} */ k, /** @type {string} */ v) => {
      if (++calls === 1) await gate;
      data[k] = v;
    },
  };
  const { core, client } = make({ silentHello: true }, {}, { storage });
  const first = client.connect().catch((e) => e);
  await settle(); // connection 1: the pairing reply is stuck in storage.set
  client.close();
  await first;
  const second = client.connect().catch((e) => e);
  await settle(); // connection 2: paired, hello sent, waiting for a challenge that never comes
  const helloBefore = core.posted.filter((m) => m.t === 'hello').length;
  assert.equal(helloBefore, 1);
  release(); // connection 1's continuation now runs
  await settle();
  assert.equal(core.posted.filter((m) => m.t === 'hello').length, helloBefore, 'the dead connection sent a hello on the live one');
  assert.equal(client.state, 'hello');
  client.close();
  await second;
});

test('closing while the crypto is still working means no auth is ever posted', async () => {
  const { core, client } = make({ silentHello: true }, { secret: vectors.secret_b64 });
  const attempt = client.connect().catch((e) => e);
  await new Promise((r) => setImmediate(r));
  const hello = core.posted.find((m) => m.t === 'hello');
  assert.ok(hello, 'the client did not say hello');
  // a VALID challenge: if the client carried on after being closed it would go on to post auth
  const parts = { cn: /** @type {Uint8Array} */ (b64Decode(hello.cn)), sn: new Uint8Array(16).fill(2), origin: ORIGIN, core: new Uint8Array(16).fill(3) };
  const sm = await mac(SECRET, LABEL_SERVER, parts);
  core.last().sendNow({ t: 'challenge', v: 1, sn: b64Encode(parts.sn), core: b64Encode(parts.core), sm: b64Encode(sm) });
  client.close(); // same turn: WebCrypto has not finished yet
  await settle();
  assert.equal(core.posted.filter((m) => m.t === 'auth').length, 0, 'auth was posted for a connection that was closed');
  assert.equal(client.state, 'closed', 'the dead connection moved the state on');
  await attempt;
});

test('messages arriving late on a port we already left are ignored, not queued', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  const link = core.last();
  client.close();
  link.forceDeliver({ t: 'noise' });
  link.forceDeliver({ t: 'noise' });
  assert.equal(client.inboxSize, 0, 'late messages from a dead port were queued');
  assert.equal(client.state, 'closed');
});

test('a stalled loop on the old connection does not swallow messages queued on the new one', async () => {
  let release1 = () => {};
  let release2 = () => {};
  const gate1 = new Promise((r) => {
    release1 = r;
  });
  const gate2 = new Promise((r) => {
    release2 = r;
  });
  let calls = 0;
  const data = /** @type {Record<string,string>} */ ({});
  const storage = {
    get: async (/** @type {string} */ k) => data[k],
    set: async (/** @type {string} */ k, /** @type {string} */ v) => {
      const n = ++calls;
      if (n === 1) await gate1;
      if (n === 2) await gate2;
      data[k] = v;
    },
  };
  const { core, client } = make({ silentHello: true }, {}, { storage });
  const first = client.connect().catch((e) => e);
  await settle(); // connection 1 stuck in storage.set (gate 1)
  client.close();
  await first;
  const second = client.connect().catch((e) => e);
  await settle(); // connection 2 stuck in its own storage.set (gate 2)
  core.last().sendNow({ t: 'noise' }); // queued behind connection 2's stalled step
  assert.equal(client.inboxSize, 1);
  release1(); // connection 1's loop wakes up and must not touch the new connection's queue
  await settle();
  assert.equal(client.inboxSize, 1, "the old connection's loop consumed the new connection's message");
  release2();
  await settle();
  // connection 2 carried on, then processed the queued message, which is not valid here: bad_frame
  assert.equal(client.state, 'closed', 'the queued message was lost');
  await second.catch(() => {});
});

test('a reject code that is not one of ours never becomes error text', async () => {
  const { client } = make({ rejectHello: 'tok_S3CR3T-REMOTE-TEXT' }, { secret: vectors.secret_b64 });
  const e = await client.connect().catch((x) => x);
  assert.ok(e instanceof BridgeError && e.code === 'bad_frame', String(e));
  assert.ok(!String(e.message).includes('S3CR3T') && !String(e.stack).includes('S3CR3T'));
  for (const known of ['bad_frame', 'bad_origin', 'bad_version', 'bad_auth', 'bad_session', 'replay', 'timeout', 'busy', 'no_secret']) {
    const c = make({ rejectHello: known }, { secret: vectors.secret_b64 });
    const err = await c.client.connect().catch((x) => x);
    assert.equal(err.code, known === 'timeout' ? 'timeout' : known);
  }
});

test('a session reject with a foreign code is mapped to bad_frame too', async () => {
  const { core, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = () => {};
  const caught = client.request(health, { requestId: 'req-1' }).catch((e) => e);
  await settle();
  core.last().send({ t: 'reject', code: 'leak-me-S3CR3T' });
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'bad_frame' && !e.message.includes('S3CR3T'), String(e));
});

test('replies with another protocol version or generation are not believed', async () => {
  const { core, timers, client } = make({}, { secret: vectors.secret_b64 });
  await client.connect();
  core.onEnvelope = (m, send) => {
    for (const bad of [{ version: 999, generation: 1 }, { version: 1, generation: 999 }, { version: 1, generation: 1, body: 'not an object' }]) {
      send({ version: 1, generation: 1, message_id: 'r-' + m.message_id, session_id: m.session_id, request_id: m.request_id, body: { type: 'health_reply', payload: {} }, ...bad });
    }
  };
  const caught = client.request(health, { requestId: 'req-1' }).catch((e) => e);
  await settle();
  await timers.advance(1000);
  const e = await caught;
  assert.ok(e instanceof BridgeError && e.code === 'timeout', 'a malformed reply resolved the request');
});

test('a challenge with the wrong shape is rejected before any MAC work', async () => {
  const shapes = [
    { v: 2 },
    { sn: b64Encode(new Uint8Array(15)) },
    { core: b64Encode(new Uint8Array(17)) },
    { sm: b64Encode(new Uint8Array(31)) },
  ];
  for (const bad of shapes) {
    const { core, client } = make({ silentHello: true }, { secret: vectors.secret_b64 });
    const p = client.connect().catch((e) => e);
    await settle();
    const good = { t: 'challenge', v: 1, sn: b64Encode(new Uint8Array(16)), core: b64Encode(new Uint8Array(16)), sm: b64Encode(new Uint8Array(32)) };
    core.last().sendNow({ ...good, ...bad });
    const e = await p;
    assert.ok(e instanceof BridgeError && e.code === 'bad_frame', `${JSON.stringify(Object.keys(bad))}: ${e}`);
    assert.equal(core.posted.filter((m) => m.t === 'auth').length, 0);
  }
});

test('stuck operations on closed connections are bounded: reconnecting backs off instead of piling up', async () => {
  const { release, storage: slow } = stalledStorage();
  const { core, client, timers } = make({}, {}, { storage: slow });
  let refused = 0;
  for (let i = 0; i < 40; i++) {
    const attempt = client.connect().catch((e) => e);
    await settle(); // the pairing reply arrives and sticks in storage.set
    client.close();
    const e = await attempt;
    if (e instanceof BridgeError && e.code === 'overloaded') refused++;
  }
  assert.equal(core.opened, MAX_LIVE_DRAINS, 'exactly the tolerated number of stuck operations, no more and no fewer');
  assert.ok(refused > 0, 'nothing refused the extra attempts');
  // handshake timeouts are 5000 ms here; a backoff retry is 500 ms plus jitter
  assert.ok(timers.delays.some((d) => d >= 500 && d < 5000), 'a refused attempt must schedule a later retry, or the client would never come back');
  release();
  await settle();
  await client.connect(); // once the old operations settle, work resumes
  assert.equal(client.state, 'ready');
});

test('a stuck operation does not keep the inbound message alive', async () => {
  assert.equal(typeof globalThis.gc, 'function', 'run with node --expose-gc (npm test does)');
  const { release, storage: slow } = stalledStorage();
  const { core, client } = make({ silentPair: true }, {}, { storage: slow });
  const attempt = client.connect().catch((e) => e);
  await settle();
  const link = core.last();
  /** @type {any} */
  let message = { t: 'paired', secret: vectors.secret_b64, pad: 'x'.repeat(128 * 1024) };
  const ref = new WeakRef(message);
  link.deliverRaw(message);
  message = null;
  await settle(); // the message is being processed and is stuck in storage.set
  client.close();
  await attempt;
  for (let i = 0; i < 6; i++) {
    globalThis.gc?.();
    await new Promise((r) => setImmediate(r));
  }
  assert.equal(ref.deref(), undefined, 'the stuck operation still holds the 128 KiB inbound message');
  release();
});
