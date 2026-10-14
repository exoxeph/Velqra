// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// The extension side of the bridge: pairing, the mutual handshake, and request/reply correlation.
// Capture code must call `request` and treat `kept_in_browser` as "leave the download alone".

import { b64Encode, b64Decode, mac, verifyMac, LABEL_SERVER, LABEL_CLIENT } from './handshake.js';

export const MAX_IN_FLIGHT = 100;
/** Inbound messages waiting for an async step (storage, WebCrypto) are bounded by count and by bytes. */
export const MAX_INBOX_MESSAGES = 64;
export const MAX_INBOX_BYTES = 4 * 1024 * 1024;
/** Operations stuck on closed connections that are tolerated before new connections are refused. */
export const MAX_LIVE_DRAINS = 8;
const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30000;
const SESSION_ID = /^[0-9a-f]{32}$/;
/** The only reject codes the core and host send. Anything else is remote text and is never repeated. */
const REJECT_CODES = new Set(['bad_frame', 'bad_origin', 'bad_version', 'bad_auth', 'bad_session', 'replay', 'timeout', 'busy', 'no_secret']);

/** @param {any} code */
const rejectCode = (code) => (typeof code === 'string' && REJECT_CODES.has(code) ? code : 'bad_frame');

/** Errors carry a fixed code and nothing else: no detail text from the core, no secrets. */
export class BridgeError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = 'BridgeError';
    this.code = code;
  }
}

/**
 * The few small fields a handshake step needs. A step that waits (storage, WebCrypto) holds only this,
 * never the raw inbound object, so a stuck step cannot pin a large message in memory.
 * @param {any} m
 */
function slim(m) {
  /** @type {Record<string, string | number>} */
  const out = {};
  for (const k of ['t', 'secret', 'v', 'sn', 'core', 'sm', 'sid', 'code']) {
    const v = m?.[k];
    if (typeof v === 'number' || (typeof v === 'string' && v.length <= 4096)) out[k] = v;
  }
  return out;
}

/**
 * Exponential backoff with jitter, capped. `random` returns a number in [0, 1].
 * @param {number} attempt 1 for the first retry
 * @param {() => number} random
 */
export function reconnectDelay(attempt, random) {
  const d = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (attempt - 1));
  return d + random() * d * 0.5;
}

/**
 * @param {string} sessionId
 * @param {string} messageId
 * @param {string} requestId
 * @param {{type: string, payload: any}} body
 */
export function buildEnvelope(sessionId, messageId, requestId, body) {
  return { version: 1, message_id: messageId, session_id: sessionId, request_id: requestId, generation: 1, body };
}

/**
 * @typedef {{
 *   connectNative: (host: string) => any,
 *   storage: { get: (key: string) => Promise<string | undefined>, set: (key: string, value: string) => Promise<void> },
 *   origin: string,
 *   hostName?: string,
 *   setTimer?: (fn: () => void, ms: number) => any,
 *   clearTimer?: (handle: any) => void,
 *   random?: () => number,
 *   randomBytes?: (n: number) => Uint8Array,
 *   requestTimeoutMs?: number,
 *   handshakeTimeoutMs?: number,
 * }} Deps
 */

export class BridgeClient {
  /** @type {'idle'|'pairing'|'hello'|'authenticating'|'ready'|'closed'} */
  #state = 'idle';
  #port = null;
  #sid = '';
  #counter = 0;
  #attempt = 0;
  #userClosed = false;
  /** @type {Promise<void> | null} */
  #connecting = null;
  /** @type {{resolve: () => void, reject: (e: Error) => void, timer: any, secret: Uint8Array | null, cn: Uint8Array} | null} */
  #hs = null;
  /** @type {Map<string, {resolve: (e: any) => void, reject: (e: Error) => void, timer: any, requestId: string}>} */
  #pending = new Map();
  #reconnectTimer = null;
  /** @type {{m: any, size: number}[]} */
  #inbox = [];
  #inboxBytes = 0;
  /** One drain loop per connection: a stalled step on a dead connection must not block the next one. */
  #draining = new WeakSet();
  /** Drain loops still running, including ones stuck on connections that have since closed. */
  #liveDrains = 0;

  /** @param {Deps} deps */
  constructor(deps) {
    this.d = {
      hostName: 'com.velqra.host',
      setTimer: (/** @type {() => void} */ fn, /** @type {number} */ ms) => setTimeout(fn, ms),
      clearTimer: (/** @type {any} */ h) => clearTimeout(h),
      random: Math.random,
      randomBytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
      requestTimeoutMs: 20000,
      handshakeTimeoutMs: 10000,
      ...deps,
    };
  }

  get state() {
    return this.#state;
  }

  /** Inbound messages currently waiting to be processed (bounded; exposed for tests and diagnostics). */
  get inboxSize() {
    return this.#inbox.length;
  }

  /** Resolves when the bridge is ready. Concurrent calls share one attempt. */
  connect() {
    if (this.#state === 'ready') return Promise.resolve();
    if (this.#connecting) return this.#connecting;
    this.#userClosed = false;
    if (this.#reconnectTimer !== null) {
      this.d.clearTimer(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    if (this.#liveDrains >= MAX_LIVE_DRAINS) {
      // too many operations are stuck on closed connections: do not pile more on, try again later
      this.#scheduleReconnect();
      return Promise.reject(new BridgeError('overloaded'));
    }
    this.#connecting = this.#open()
      .catch((e) => {
        if (e instanceof BridgeError) throw e;
        // the platform refused to open the host (or storage failed): our own fixed code, never its text
        this.#port = null;
        this.#state = 'closed';
        this.#scheduleReconnect();
        throw new BridgeError('host_unavailable');
      })
      .finally(() => {
        this.#connecting = null;
      });
    return this.#connecting;
  }

  /**
   * Sends one request and resolves with the reply that answers it. Rejects with `kept_in_browser`
   * when the bridge is not ready, so the caller leaves the browser download alone.
   * @param {{type: string, payload: any}} body
   * @param {{requestId: string, timeoutMs?: number}} opts
   */
  request(body, opts) {
    if (this.#state !== 'ready') return Promise.reject(new BridgeError('kept_in_browser'));
    if (this.#pending.size >= MAX_IN_FLIGHT) return Promise.reject(new BridgeError('overloaded'));
    const id = `m${++this.#counter}`;
    const envelope = buildEnvelope(this.#sid, id, opts.requestId, body);
    return new Promise((resolve, reject) => {
      const timer = this.d.setTimer(() => {
        this.#pending.delete(id);
        reject(new BridgeError('timeout'));
      }, opts.timeoutMs ?? this.d.requestTimeoutMs);
      this.#pending.set(id, { resolve, reject, timer, requestId: opts.requestId });
      this.#port.postMessage(envelope);
    });
  }

  /** Closes on purpose: no reconnect. */
  close() {
    this.#userClosed = true;
    if (this.#reconnectTimer !== null) {
      this.d.clearTimer(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    if (this.#port) this.#fail(this.#port, new BridgeError('disconnected'));
  }

  async #open() {
    const stored = await this.d.storage.get('secret');
    const secret = stored ? b64Decode(stored) : null;
    const port = this.d.connectNative(this.d.hostName);
    this.#port = port;
    port.onMessage.addListener((/** @type {any} */ m) => this.#enqueue(port, m));
    port.onDisconnect.addListener(() => this.#onDisconnect(port));
    return new Promise((resolve, reject) => {
      const timer = this.d.setTimer(() => this.#fail(port, new BridgeError('timeout')), this.d.handshakeTimeoutMs);
      this.#hs = { resolve, reject, timer, secret: secret && secret.length === 32 ? secret : null, cn: new Uint8Array(0) };
      if (this.#hs.secret) {
        this.#sendHello();
      } else {
        this.#state = 'pairing';
        port.postMessage({ t: 'pair' });
      }
    });
  }

  /**
   * Every inbound message passes through here before any async work, so a stalled step plus a fast
   * peer cannot make the queue grow without limit: past the budget the port is closed.
   * @param {any} port
   * @param {any} m
   */
  #enqueue(port, m) {
    if (port !== this.#port) return; // a connection we already left
    let size = Infinity;
    try {
      size = JSON.stringify(m).length;
    } catch {
      /* not serialisable: treated as over budget */
    }
    if (this.#inbox.length >= MAX_INBOX_MESSAGES || this.#inboxBytes + size > MAX_INBOX_BYTES) {
      this.#fail(port, new BridgeError('overloaded'));
      return;
    }
    this.#inbox.push({ m, size });
    this.#inboxBytes += size;
    void this.#drain(port);
  }

  /** @param {any} port */
  async #drain(port) {
    if (this.#draining.has(port)) return;
    this.#draining.add(port);
    this.#liveDrains += 1;
    try {
      // the inbox only ever holds the current connection's messages (enqueue ignores other ports and
      // failing a connection clears it), so the loop simply stops once its connection is no longer current
      while (port === this.#port && this.#inbox.length > 0) {
        const item = /** @type {{m: any, size: number}} */ (this.#inbox.shift());
        this.#inboxBytes -= item.size;
        // before the session is ready a step may wait, so it gets the slim view; afterwards handling is synchronous
        const view = this.#state === 'ready' ? item.m : slim(item.m);
        item.m = undefined;
        try {
          await this.#onMessage(port, view);
        } catch {
          this.#fail(port, new BridgeError('bad_frame'));
        }
      }
    } finally {
      this.#draining.delete(port);
      this.#liveDrains -= 1;
    }
  }

  #sendHello() {
    const hs = /** @type {NonNullable<typeof this.#hs>} */ (this.#hs);
    hs.cn = this.d.randomBytes(16);
    this.#state = 'hello';
    this.#port.postMessage({ t: 'hello', v: [1], cn: b64Encode(hs.cn) });
  }

  /** @param {any} port @param {any} m */
  async #onMessage(port, m) {
    if (port !== this.#port || !m || typeof m !== 'object') return;
    if (this.#state === 'ready') return this.#onSessionMessage(m);
    const hs = this.#hs;
    if (!hs) return;
    if (m.t === 'reject') return this.#fail(port, new BridgeError(rejectCode(m.code)));
    if (this.#state === 'pairing' && m.t === 'paired') {
      const secret = typeof m.secret === 'string' ? b64Decode(m.secret) : null;
      if (!secret || secret.length !== 32) return this.#fail(port, new BridgeError('bad_frame'));
      await this.d.storage.set('secret', m.secret);
      if (port !== this.#port || this.#hs !== hs) return; // the connection ended while storage was busy
      hs.secret = secret;
      return this.#sendHello();
    }
    if (this.#state === 'hello' && m.t === 'challenge' && hs.secret) {
      const sn = typeof m.sn === 'string' ? b64Decode(m.sn) : null;
      const core = typeof m.core === 'string' ? b64Decode(m.core) : null;
      const sm = typeof m.sm === 'string' ? b64Decode(m.sm) : null;
      // exact shape, as the Rust side demands of the client: version 1, 16-byte nonces, 32-byte MAC
      if (m.v !== 1 || sn?.length !== 16 || core?.length !== 16 || sm?.length !== 32) {
        return this.#fail(port, new BridgeError('bad_frame'));
      }
      const fields = { cn: hs.cn, sn, origin: this.d.origin, core };
      // one await point, one re-check: nothing below may act for a connection that has ended meanwhile
      const [proven, cm] = await Promise.all([
        verifyMac(hs.secret, LABEL_SERVER, fields, sm),
        mac(hs.secret, LABEL_CLIENT, fields),
      ]);
      if (port !== this.#port || this.#hs !== hs) return;
      // a core that cannot prove it knows the secret never receives our proof
      if (!proven) return this.#fail(port, new BridgeError('bad_server_mac'));
      this.#state = 'authenticating';
      port.postMessage({ t: 'auth', cm: b64Encode(cm) });
      return;
    }
    if (this.#state === 'authenticating' && m.t === 'ready') {
      if (typeof m.sid !== 'string' || !SESSION_ID.test(m.sid)) return this.#fail(port, new BridgeError('bad_frame'));
      this.#sid = m.sid;
      this.#state = 'ready';
      this.#attempt = 0;
      this.d.clearTimer(hs.timer);
      this.#hs = null;
      hs.resolve();
      return;
    }
    this.#fail(port, new BridgeError('bad_frame'));
  }

  /** @param {any} m */
  #onSessionMessage(m) {
    if (m.t === 'reject') return this.#fail(this.#port, new BridgeError(rejectCode(m.code)));
    // a reply is believed only if it names this session, a request we sent, and that request's own id
    if (m.version !== 1 || m.generation !== 1 || !m.body || typeof m.body !== 'object' || typeof m.body.type !== 'string') return;
    if (m.session_id !== this.#sid || typeof m.message_id !== 'string' || !/^[re]-/.test(m.message_id)) return;
    const pending = this.#pending.get(m.message_id.slice(2));
    if (!pending || m.request_id !== pending.requestId) return;
    this.#pending.delete(m.message_id.slice(2));
    this.d.clearTimer(pending.timer);
    pending.resolve(m);
  }

  /** @param {any} port */
  #onDisconnect(port) {
    this.#fail(port, new BridgeError('disconnected'), false);
  }

  /**
   * @param {any} port
   * @param {BridgeError} err
   * @param {boolean} [hangUp]
   */
  #fail(port, err, hangUp = true) {
    if (port !== this.#port) return;
    this.#port = null;
    this.#state = 'closed';
    this.#inbox.length = 0; // everything queued belonged to this connection
    this.#inboxBytes = 0;
    if (hangUp) {
      try {
        port.disconnect();
      } catch {
        /* already gone */
      }
    }
    const hs = this.#hs;
    this.#hs = null;
    if (hs) {
      this.d.clearTimer(hs.timer);
      hs.reject(err);
    }
    for (const p of this.#pending.values()) {
      this.d.clearTimer(p.timer);
      p.reject(err.code === 'disconnected' || err.code === 'timeout' ? new BridgeError('disconnected') : err);
    }
    this.#pending.clear();
    this.#scheduleReconnect();
  }

  #scheduleReconnect() {
    if (this.#userClosed || this.#reconnectTimer !== null) return;
    this.#attempt += 1;
    this.#reconnectTimer = this.d.setTimer(() => {
      this.#reconnectTimer = null;
      this.connect().catch(() => {});
    }, reconnectDelay(this.#attempt, this.d.random));
  }
}
